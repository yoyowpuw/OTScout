package safety

import (
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"
)

// RenderPlan writes a review document for a plan: the exact bytes, per target,
// that a run would put on the wire.
//
// This is what --dry-run prints, and it is written to be pasted into a change
// request rather than to be pretty in a terminal. The audience is a control
// engineer who has been asked to approve traffic to their plant and is entitled
// to see it in full instead of being told it is safe. Nothing is elided, no
// counts stand in for content, and the hex dump is the real request rather than
// a description of one.
func RenderPlan(w io.Writer, policy Policy, plan Plan) error {
	out := &writer{w: w}

	out.line("OTScout active scan, dry run. No packets have been sent.")
	out.blank()

	if plan.Reason != "" {
		out.line("Reason given: %s", plan.Reason)
	}
	if len(plan.Invocation) > 0 {
		out.line("Invocation: %s", strings.Join(plan.Invocation, " "))
	}
	out.blank()

	out.line("Safety settings in force:")
	for _, item := range policy.Describe() {
		out.line("  %s", item)
	}
	out.blank()

	hosts, byHost := groupByHost(plan.Exchanges)
	packets := 0
	for _, ex := range plan.Exchanges {
		if ex.Risk.AtMost(policy.AllowedRisk) {
			packets += ex.Packets()
		}
	}

	scope := fmt.Sprintf("Scope: %s, %s", plural(len(hosts), "target"), plural(packets, "request"))
	if estimate := estimateDuration(policy, packets); estimate > 0 {
		scope += fmt.Sprintf(", %s estimated", estimate)
	}
	out.line("%s.", scope)
	out.blank()

	for _, host := range hosts {
		out.line("%s", host)
		for _, ex := range byHost[host] {
			renderExchange(out, policy, ex)
		}
		out.blank()
	}

	out.line("End of plan. Re-run without --dry-run to send this.")
	return out.err
}

func renderExchange(out *writer, policy Policy, ex Exchange) {
	header := fmt.Sprintf("  %s %s to %s/%d, risk %s, %s",
		ex.TemplateID, ex.Protocol, ex.Target.Transport, ex.Target.Port, ex.Risk,
		plural(ex.Packets(), "packet"))
	if !ex.Risk.AtMost(policy.AllowedRisk) {
		// A skipped template is still listed, with its bytes. The reviewer is
		// deciding what this tool may do, and a request that would run under a
		// different flag is part of that decision.
		header += fmt.Sprintf(" (NOT SENT: above the allowed risk of %s)", policy.AllowedRisk)
	}
	out.line("%s", header)

	// Every step is shown, including the ones that only establish a session.
	// Three packets reaching a CPU is three packets, and a reviewer counting
	// what will hit their network should not have to know that S7comm needs a
	// handshake before it will answer.
	for idx, step := range ex.Steps {
		label := fmt.Sprintf("    step %d of %d", idx+1, len(ex.Steps))
		if step.Purpose != "" {
			label += ": " + step.Purpose
		}
		out.line("%s", label)
		out.line("      %d bytes", len(step.Request))
		for _, dumpLine := range strings.Split(strings.TrimRight(hex.Dump(step.Request), "\n"), "\n") {
			out.line("      %s", dumpLine)
		}
	}
}

// estimateDuration is the pacing arithmetic made visible.
//
// It is the interval the engine will actually use, times the number of packets,
// which is deliberately the same calculation rather than a separate guess. An
// estimate that could drift from the pacing would be worse than none, because the
// number in a change request is the one people plan a maintenance window around.
func estimateDuration(policy Policy, packets int) time.Duration {
	if packets <= 1 {
		return 0
	}
	interval := policy.InterPacketDelay
	if policy.PacketsPerSecond > 0 {
		if rateGap := time.Duration(float64(time.Second) / policy.PacketsPerSecond); rateGap > interval {
			interval = rateGap
		}
	}
	total := time.Duration(packets-1) * interval
	return total.Round(time.Second)
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// writer keeps the first write error so that the rendering code above can read
// as a sequence of lines rather than a sequence of error checks.
type writer struct {
	w   io.Writer
	err error
}

func (o *writer) line(format string, args ...any) {
	if o.err != nil {
		return
	}
	_, o.err = fmt.Fprintf(o.w, format+"\n", args...)
}

func (o *writer) blank() { o.line("") }
