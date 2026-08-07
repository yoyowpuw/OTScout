package safety

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// realModbusExchange carries the bytes a Read Device Identification request
// actually consists of, because the point of this document is the hex dump and a
// placeholder would not test it.
func realModbusExchange(host string) Exchange {
	return Exchange{
		Target:     Target{Host: host, Port: 502, Transport: "tcp"},
		TemplateID: "modbus-device-id",
		Protocol:   "modbus",
		Risk:       RiskSafe,
		Steps: []Step{{
			Purpose: "read the device identification objects",
			Request: []byte{0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x01, 0x2b, 0x0e, 0x01, 0x00},
		}},
	}
}

// TestTheDryRunShowsTheActualBytes is the review document doing its job.
//
// The audience is a control engineer deciding whether to approve traffic to their
// plant. A summary that says how many packets would be sent asks them to take the
// contents on trust, which is the opposite of the point.
func TestTheDryRunShowsTheActualBytes(t *testing.T) {
	var out bytes.Buffer
	plan := Plan{
		Reason:     "pre-approval for change CR-4417",
		Invocation: []string{"otscout", "probe", "10.0.0.1", "--dry-run"},
		Exchanges:  []Exchange{realModbusExchange("10.0.0.1")},
	}

	if err := RenderPlan(&out, DefaultPolicy(), plan); err != nil {
		t.Fatalf("render: %v", err)
	}
	rendered := out.String()

	for _, want := range []string{
		"No packets have been sent",
		"pre-approval for change CR-4417",
		"otscout probe 10.0.0.1 --dry-run",
		"10.0.0.1",
		"modbus-device-id",
		"read the device identification objects",
		"11 bytes",
		// The hex dump of the request itself. Unit id 1 followed by function
		// 43, which is where a reviewer checks that this is an identification
		// read and not something else.
		"01 2b",
		"Scope: 1 target, 1 request",
		"1 host, 1 connection",
		"highest risk allowed: safe",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the review document does not contain %q:\n%s", want, rendered)
		}
	}
}

// TestTheDryRunListsWhatItWouldNotSend keeps the document complete.
//
// A reviewer is deciding what this tool may do, not only what it is about to do,
// so a template held back by the risk gate is shown with its bytes and the reason
// it is held back.
func TestTheDryRunListsWhatItWouldNotSend(t *testing.T) {
	var out bytes.Buffer
	held := realModbusExchange("10.0.0.1")
	held.TemplateID = "modbus-extended-id"
	held.Risk = RiskCaution

	plan := Plan{Exchanges: []Exchange{realModbusExchange("10.0.0.1"), held}}

	if err := RenderPlan(&out, DefaultPolicy(), plan); err != nil {
		t.Fatalf("render: %v", err)
	}
	rendered := out.String()

	if !strings.Contains(rendered, "modbus-extended-id") {
		t.Errorf("a template above the allowed risk was left out of the review document:\n%s", rendered)
	}
	if !strings.Contains(rendered, "NOT SENT") {
		t.Errorf("the document does not distinguish what would be sent from what would not:\n%s", rendered)
	}
	// The count is of packets that would actually go out, so a reviewer planning
	// a window is not given a number inflated by templates that will not run.
	if !strings.Contains(rendered, "1 target, 1 request") {
		t.Errorf("the scope line counts templates that would not be sent:\n%s", rendered)
	}
}

// TestTheEstimateMatchesThePacingTheEngineWillUse keeps the number in a change
// request from being a separate guess.
//
// A maintenance window gets planned around this figure, so it is computed from
// the same two controls the engine paces with rather than from an approximation
// that could drift away from them.
func TestTheEstimateMatchesThePacingTheEngineWillUse(t *testing.T) {
	cases := map[string]struct {
		policy  func(Policy) Policy
		packets int
		want    time.Duration
	}{
		"nothing to send": {
			func(p Policy) Policy { return p }, 0, 0,
		},
		"a single packet waits for nothing": {
			func(p Policy) Policy { return p }, 1, 0,
		},
		"the defaults, four per second": {
			func(p Policy) Policy { return p }, 41, 10 * time.Second,
		},
		"a slower rate stretches the window": {
			func(p Policy) Policy { p.PacketsPerSecond = 1; return p }, 11, 10 * time.Second,
		},
		"a longer delay stretches it too": {
			func(p Policy) Policy { p.InterPacketDelay = time.Second; return p }, 11, 10 * time.Second,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			policy := tc.policy(DefaultPolicy())
			if err := policy.Validate(); err != nil {
				t.Fatalf("the test policy is out of bounds: %v", err)
			}
			if got := estimateDuration(policy, tc.packets); got != tc.want {
				t.Errorf("estimated %s for %d packets, want %s", got, tc.packets, tc.want)
			}
		})
	}
}

// TestEveryStepOfAMultiStepTemplateIsShown keeps the document from understating
// what will hit the network.
//
// Three packets reaching a CPU is three packets. A reviewer counting them should
// not have to know that S7comm needs a handshake before it answers anything, so
// the setup steps are dumped in full alongside the one that asks a question.
func TestEveryStepOfAMultiStepTemplateIsShown(t *testing.T) {
	var out bytes.Buffer
	plan := Plan{Exchanges: []Exchange{
		steps("10.0.0.1", "s7comm-identify", "s7comm",
			RiskSafe, "cotp-connect", "setup-communication", "read-szl"),
	}}

	if err := RenderPlan(&out, DefaultPolicy(), plan); err != nil {
		t.Fatalf("render: %v", err)
	}
	rendered := out.String()

	for _, want := range []string{
		"3 packets",
		"step 1 of 3",
		"step 2 of 3",
		"step 3 of 3",
		// The scope line counts packets rather than templates, since that is
		// what a maintenance window is planned around.
		"Scope: 1 target, 3 requests",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the review document does not contain %q:\n%s", want, rendered)
		}
	}
}

// TestTheDryRunGroupsByHost matches the document to the order the engine will
// work in, so a reviewer reading top to bottom is reading the run.
func TestTheDryRunGroupsByHost(t *testing.T) {
	var out bytes.Buffer
	plan := Plan{Exchanges: []Exchange{
		exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
		exchange("10.0.0.2", "modbus-device-id", "modbus", RiskSafe),
		exchange("10.0.0.1", "enip-list-identity", "enip", RiskSafe),
	}}

	if err := RenderPlan(&out, DefaultPolicy(), plan); err != nil {
		t.Fatalf("render: %v", err)
	}
	rendered := out.String()

	firstHost := strings.Index(rendered, "\n10.0.0.1\n")
	secondHost := strings.Index(rendered, "\n10.0.0.2\n")
	enip := strings.Index(rendered, "enip-list-identity")
	if firstHost < 0 || secondHost < 0 || enip < 0 {
		t.Fatalf("the document is missing a host or a template:\n%s", rendered)
	}
	if !(firstHost < enip && enip < secondHost) {
		t.Errorf("both probes for the first host should appear before the second host:\n%s", rendered)
	}
	if !strings.Contains(rendered, "Scope: 2 targets, 3 requests, 1s estimated") {
		t.Errorf("the scope line is wrong:\n%s", rendered)
	}
}
