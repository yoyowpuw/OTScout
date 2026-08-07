package cli

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/probe"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

type probeOptions struct {
	*Options
	safety safetyFlags

	targetFile     string
	templates      []string
	knownPath      string
	onlyKnownPorts bool
	port           int
	output         string
}

// newProbeCommand builds the only command in this tool that sends anything.
func newProbeCommand(opts *Options) *cobra.Command {
	p := &probeOptions{Options: opts}

	cmd := &cobra.Command{
		Use:   "probe [targets...]",
		Short: "Actively fingerprint targets under the safety engine",
		Long: `Send read-only identification requests to industrial equipment and build an
inventory from the replies.

This is the only command that puts packets on your network. Everything it can
send is a standard identification call defined by the protocol for that purpose,
chosen from a fixed set compiled into the binary. There is no encoder in this
build for a write, a reset or a stop.

Read docs/SAFETY.md before the first run. The short version is that active
scanning of a control network is done deliberately, in a maintenance window, with
plant staff informed, or not at all.

Targets may be single addresses, CIDR prefixes, or inclusive first-last ranges.
Host names are refused, because the audit log records what was contacted rather
than what was typed.

Start with --dry-run. It opens no socket and prints the exact bytes that would go
to each target, which is the document to attach to a change request.

  otscout probe 10.10.0.0/24 --dry-run

Then run it for real, which requires saying why and keeping a record:

  otscout probe 10.10.0.0/24 \
    --reason "asset inventory for change CR-4417" \
    --audit runs/2026-08-07-cr4417.jsonl \
    --out assets-active.json

If you already have a passive inventory, pass it. Templates are then limited to
ports that were actually seen open, and the deny list can refuse the first packet
to a safety controller instead of the second:

  otscout probe --targets-from hosts.txt --known assets.json --only-known-ports \
    --reason "..." --audit runs/today.jsonl` + riskFlagHelp,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return p.run(cmd, args)
		},
	}

	flags := cmd.Flags()
	flags.StringVar(&p.targetFile, "targets-from", "", "read target specifications from a file, one per line")
	flags.StringSliceVar(&p.templates, "template", nil,
		"template ids to run; repeat the flag or separate with commas. Default is every template")
	flags.StringVar(&p.knownPath, "known", "", "an inventory from a previous run, usually from ingest")
	flags.BoolVar(&p.onlyKnownPorts, "only-known-ports", false,
		"only run a template against a target whose inventory entry already shows that port open")
	flags.IntVar(&p.port, "port", 0,
		"run the selected templates against this port instead of their own, for a protocol reached "+
			"on a non-standard port")
	flags.StringVar(&p.output, "out", "assets-active.json", "where to write the inventory")

	p.safety.registerRun(cmd)
	return cmd
}

func (p *probeOptions) run(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	policy, err := p.safety.policy()
	if err != nil {
		return err
	}
	if err := p.safety.requireAccountability(); err != nil {
		return err
	}

	specs := args
	if p.targetFile != "" {
		fromFile, err := probe.ReadTargetFile(p.targetFile)
		if err != nil {
			return err
		}
		specs = append(specs, fromFile...)
	}
	if len(specs) == 0 {
		return fmt.Errorf("no targets given. Name them as arguments or with --targets-from")
	}

	targets, err := probe.ExpandTargets(specs)
	if err != nil {
		return err
	}

	library, err := probe.DefaultLibrary()
	if err != nil {
		return err
	}
	templates, err := library.Select(p.templates)
	if err != nil {
		return err
	}

	var known *asset.Inventory
	if p.knownPath != "" {
		known, err = asset.LoadInventory(p.knownPath)
		if err != nil {
			return fmt.Errorf("read the inventory named by --known: %w", err)
		}
	}
	if p.onlyKnownPorts && known == nil {
		return fmt.Errorf("--only-known-ports needs an inventory to read the open ports from; pass --known")
	}

	plan, err := probe.BuildPlan(probe.PlanRequest{
		Targets:        targets,
		Templates:      templates,
		Known:          known,
		OnlyKnownPorts: p.onlyKnownPorts,
		Port:           p.port,
		Reason:         p.safety.reason,
		Invocation:     append([]string{"otscout", "probe"}, os.Args[2:]...),
	})
	if err != nil {
		return err
	}

	if p.safety.dryRun {
		return safety.RenderPlan(out, policy, plan)
	}

	auditor, err := p.safety.openAuditor()
	if err != nil {
		return err
	}
	defer auditor.Close()

	denyList, err := safety.DefaultDenyList()
	if err != nil {
		return err
	}

	interpreter := probe.NewInterpreter()
	engine, err := safety.NewEngine(policy, probe.NetDialer{},
		safety.WithAuditor(auditor),
		safety.WithDenyList(denyList),
		safety.WithInterpreter(interpreter),
	)
	if err != nil {
		return err
	}

	p.announce(out, policy, plan, auditor.Path())

	// A run against equipment has to stop when the operator says stop, and stop
	// cleanly enough to leave a readable audit file. Interrupt cancels the
	// context, the engine finishes recording, and a second interrupt kills the
	// process outright for anyone who cannot wait.
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()

	result, runErr := engine.Run(ctx, plan)
	if runErr != nil {
		return runErr
	}

	inventory := probe.BuildInventory(interpreter.Observations(), time.Now().UTC())
	if err := inventory.Save(p.output); err != nil {
		return err
	}

	p.report(out, result, inventory)
	return nil
}

// announce says what is about to happen before it happens.
//
// This is printed rather than logged because the moment before the first packet
// is the last moment an operator can press control-C, and they should not have
// to read a file to find out what they just started.
func (p *probeOptions) announce(w io.Writer, policy safety.Policy, plan safety.Plan, auditPath string) {
	if p.Quiet {
		return
	}
	hosts := make(map[string]bool)
	for _, ex := range plan.Exchanges {
		hosts[ex.Target.Host] = true
	}
	packets := probe.EstimatePackets(plan, policy.AllowedRisk)

	fmt.Fprintf(w, "Sending %s to %s.\n", plural(packets, "request"), plural(len(hosts), "target"))
	for _, item := range policy.Describe() {
		fmt.Fprintf(w, "  %s\n", item)
	}
	fmt.Fprintf(w, "  audit trail: %s\n", auditPath)
	fmt.Fprintln(w, "Press control-C to stop. The audit file stays readable if you do.")
	fmt.Fprintln(w)
}

func (p *probeOptions) report(w io.Writer, result safety.Result, inventory *asset.Inventory) {
	if result.Aborted {
		fmt.Fprintf(w, "\nThe run stopped early: %s\n", result.AbortReason)
	}

	// Skips are printed rather than summarised. A template that was refused is
	// the most useful thing this command has to say, and burying it under a
	// count is how an operator concludes a safety controller is not there.
	if len(result.Skips) > 0 {
		fmt.Fprintf(w, "\nNot sent:\n")
		for _, skip := range dedupeSkips(result.Skips) {
			fmt.Fprintf(w, "  %s %s: %s\n", skip.Exchange.Target.Address(), skip.Exchange.TemplateID, skip.Reason)
		}
	}

	stats := inventory.Stats()
	fmt.Fprintf(w, "\n%d of %d packets answered. %s identified, written to %s.\n",
		result.Answered, result.Sent, plural(stats.Assets, "device"), p.output)
	if result.Failed > 0 {
		fmt.Fprintf(w, "%d went unanswered, which for a target that is simply not there is normal.\n", result.Failed)
	}
}

// dedupeSkips collapses the same refusal repeated across many targets, since a
// deny rule that fires on a hundred addresses does not need a hundred lines.
func dedupeSkips(skips []safety.Skip) []safety.Skip {
	seen := make(map[string]bool, len(skips))
	var out []safety.Skip
	for _, skip := range skips {
		key := skip.Exchange.TemplateID + "|" + skip.Reason
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, skip)
	}
	return out
}

// newTemplatesCommand lists what the active path can ask a device.
func newTemplatesCommand(opts *Options) *cobra.Command {
	var showBytes bool

	cmd := &cobra.Command{
		Use:   "templates",
		Short: "Inspect the fingerprint template library",
		Long: `List the identification probes this build can send, with the risk rating and
the requests each one makes.

Nothing is sent and no file is written. Pass --bytes to see the exact request
each step would put on the wire.` + riskFlagHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			library, err := probe.DefaultLibrary()
			if err != nil {
				return err
			}
			return printTemplates(cmd.OutOrStdout(), library.All(), showBytes)
		},
	}

	cmd.Flags().BoolVar(&showBytes, "bytes", false, "print a hex dump of every request")
	return cmd
}

func printTemplates(w io.Writer, templates []probe.Template, showBytes bool) error {
	for idx, tmpl := range templates {
		if idx > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s\n", tmpl.ID)
		fmt.Fprintf(w, "  %s\n", collapse(tmpl.Summary))
		fmt.Fprintf(w, "  %s on %s/%d, risk %s, %s\n",
			tmpl.Protocol, tmpl.Transport, tmpl.Port, tmpl.Risk, plural(tmpl.Packets(), "packet"))
		if tmpl.RiskNote != "" {
			fmt.Fprintf(w, "  why %s: %s\n", tmpl.Risk, collapse(tmpl.RiskNote))
		}
		for stepIdx, step := range tmpl.Steps {
			fmt.Fprintf(w, "  %d. %s [%s]\n", stepIdx+1, step.Purpose, step.Request)
			if !showBytes {
				continue
			}
			request, err := tmpl.StepBytes(stepIdx)
			if err != nil {
				return err
			}
			for _, line := range strings.Split(strings.TrimRight(asset.HexBytes(request).HexDump(), "\n"), "\n") {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
		for _, ref := range tmpl.References {
			fmt.Fprintf(w, "  see: %s\n", ref)
		}
	}
	return nil
}
