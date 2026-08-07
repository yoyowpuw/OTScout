package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/safety"
)

// newSafetyCommand prints what the active path would be allowed to do, without
// doing any of it.
//
// This exists so that the safety settings can be read before a scan is planned
// rather than only inside the output of one. An operator writing a change request
// needs the numbers, and a reviewer asked to approve the tool at all needs to see
// the deny list without reading Go.
func newSafetyCommand() *cobra.Command {
	flags := &safetyFlags{}

	cmd := &cobra.Command{
		Use:   "safety",
		Short: "Print the active scan limits and the fragile device deny list",
		Long: `Print the safety settings that would apply to an active scan, and the
list of devices that are refused particular probes or all of them.

Nothing is sent and no file is written. Pass the same pacing flags you intend to
use with probe to see the settings they produce, including a rejection if any of
them is out of bounds.` + riskFlagHelp,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			policy, err := flags.policy()
			if err != nil {
				return err
			}
			return printSafety(cmd.OutOrStdout(), policy)
		},
	}

	flags.registerPacing(cmd)
	return cmd
}

func printSafety(w io.Writer, policy safety.Policy) error {
	fmt.Fprintln(w, "Limits that would apply to an active scan:")
	for _, item := range policy.Describe() {
		fmt.Fprintf(w, "  %s\n", item)
	}

	list, err := safety.DefaultDenyList()
	if err != nil {
		return err
	}
	rules := list.Rules()

	fmt.Fprintf(w, "\nFragile device deny list, %s:\n", plural(len(rules), "rule"))
	for _, rule := range rules {
		fmt.Fprintf(w, "\n  %s\n", rule.ID)
		fmt.Fprintf(w, "    matches: %s\n", describeMatch(rule))
		fmt.Fprintf(w, "    denies:  %s\n", describeDenial(rule))
		fmt.Fprintf(w, "    reason:  %s\n", collapse(rule.Reason))
		for _, ref := range rule.References {
			fmt.Fprintf(w, "    see:     %s\n", ref)
		}
	}

	fmt.Fprintln(w, "\nThe deny list is consulted after a device has been identified, so it can only")
	fmt.Fprintln(w, "stop the probes that follow the first. Run ingest first and pass the inventory")
	fmt.Fprintln(w, "to probe, and it applies from the first packet instead.")
	return nil
}

func describeMatch(rule safety.DenyRule) string {
	var parts []string
	if rule.Vendor != "" {
		parts = append(parts, "vendor "+rule.Vendor)
	}
	if rule.Family != "" {
		parts = append(parts, "family containing "+rule.Family)
	}
	if rule.Product != "" {
		parts = append(parts, "product containing "+rule.Product)
	}
	return strings.Join(parts, ", ")
}

func describeDenial(rule safety.DenyRule) string {
	switch {
	case len(rule.Templates) > 0 && len(rule.Protocols) > 0:
		return fmt.Sprintf("templates %s and everything over %s",
			strings.Join(rule.Templates, ", "), strings.Join(rule.Protocols, ", "))
	case len(rule.Templates) > 0:
		return "templates " + strings.Join(rule.Templates, ", ")
	case len(rule.Protocols) > 0:
		return "everything over " + strings.Join(rule.Protocols, ", ")
	default:
		return "every active probe"
	}
}

// collapse folds the wrapped YAML reason onto one line, since the terminal will
// wrap it again and the file's line breaks are an artefact of editing it.
func collapse(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
