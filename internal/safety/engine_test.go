package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// recorder is a dialer that reaches no network and remembers what it was asked
// to send.
//
// The engine never inspects request bytes, so the exchange helpers below make
// each request the readable name of the step that produced it. That keeps the
// fake from needing to know anything the real transport would not, and makes an
// assertion about what went out read like the plan that produced it.
type recorder struct {
	// sent holds one line per packet, "host template/step", so a multi step
	// template shows up as the several packets it actually is.
	sent    []string
	dialed  []Target
	closed  int
	replies map[string][]byte
	fail    map[string]error
	// failDial refuses the connection rather than the first packet.
	failDial map[string]error
	// at is when each packet went out by the engine's clock, so the spacing can
	// be checked without waiting for it.
	at    []time.Duration
	clock *fakeClock
}

func (r *recorder) Dial(_ context.Context, ex Exchange, _ Timeouts) (Conn, error) {
	r.dialed = append(r.dialed, ex.Target)
	if err, bad := r.failDial[ex.Target.Host]; bad {
		return nil, err
	}
	return &recorderConn{owner: r, target: ex.Target}, nil
}

type recorderConn struct {
	owner  *recorder
	target Target
}

func (c *recorderConn) Exchange(_ context.Context, request []byte, _ time.Duration) ([]byte, error) {
	r := c.owner
	name := string(request)
	r.sent = append(r.sent, c.target.Host+" "+name)
	if r.clock != nil {
		r.at = append(r.at, r.clock.elapsed())
	}

	if err, bad := r.fail[c.target.Host+"/"+name]; bad {
		return nil, err
	}
	if err, bad := r.fail[c.target.Host]; bad {
		return nil, err
	}
	if reply, ok := r.replies[c.target.Host+"/"+name]; ok {
		return reply, nil
	}
	return []byte{0x01}, nil
}

func (c *recorderConn) Close() error {
	c.owner.closed++
	return nil
}

// fakeClock advances only when the engine sleeps, so a test can describe minutes
// of pacing and run in microseconds.
type fakeClock struct {
	start time.Time
	now   time.Time
	slept []time.Duration
}

func newFakeClock() *fakeClock {
	start := time.Date(2026, 3, 2, 9, 0, 0, 0, time.UTC)
	return &fakeClock{start: start, now: start}
}

func (c *fakeClock) Now() time.Time         { return c.now }
func (c *fakeClock) elapsed() time.Duration { return c.now.Sub(c.start) }

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.slept = append(c.slept, d)
	c.now = c.now.Add(d)
	return nil
}

// exchange builds a single step template whose request bytes are its own name.
func exchange(host, template, protocol string, risk Risk) Exchange {
	return steps(host, template, protocol, risk, template)
}

// steps builds a template that needs several packets on one connection, which is
// what S7comm actually requires.
func steps(host, template, protocol string, risk Risk, names ...string) Exchange {
	ex := Exchange{
		Target:     Target{Host: host, Port: 502, Transport: "tcp"},
		TemplateID: template,
		Protocol:   protocol,
		Risk:       risk,
	}
	for _, name := range names {
		ex.Steps = append(ex.Steps, Step{Purpose: "ask for " + name, Request: []byte(name)})
	}
	return ex
}

func newTestEngine(t *testing.T, policy Policy, dialer Dialer, opts ...Option) (*Engine, *fakeClock) {
	t.Helper()
	clock := newFakeClock()
	opts = append(opts, withClock(clock.Now, clock.Sleep))
	engine, err := NewEngine(policy, dialer, opts...)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	if r, ok := dialer.(*recorder); ok {
		r.clock = clock
	}
	return engine, clock
}

// TestARunSendsOnlyWhatTheOperatorAllowed is the default deny rule.
//
// Nothing above the allowed tier goes out, and the exchange is reported as
// skipped with the flag that would include it, so an operator who wanted it
// learns how to ask rather than concluding the template is broken.
func TestARunSendsOnlyWhatTheOperatorAllowed(t *testing.T) {
	sender := &recorder{}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender)

	result, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
		exchange("10.0.0.1", "modbus-extended-id", "modbus", RiskCaution),
		exchange("10.0.0.1", "modbus-poke", "modbus", RiskLabOnly),
	}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if want := []string{"10.0.0.1 modbus-device-id"}; !slices.Equal(sender.sent, want) {
		t.Fatalf("sent %v, want only the safe one, %v", sender.sent, want)
	}
	if result.Skipped != 2 {
		t.Errorf("skipped %d, want 2", result.Skipped)
	}
	for _, skip := range result.Skips {
		if skip.Outcome != OutcomeSkippedRisk {
			t.Errorf("%s was skipped as %s, want %s", skip.Exchange.TemplateID, skip.Outcome, OutcomeSkippedRisk)
		}
		if !strings.Contains(skip.Reason, "--allow-risk") {
			t.Errorf("the skip reason does not say how to include it:\n%s", skip.Reason)
		}
	}
}

func TestRaisingTheAllowedRiskLetsTheProbeThrough(t *testing.T) {
	sender := &recorder{}
	policy := DefaultPolicy()
	policy.AllowedRisk = RiskCaution
	engine, _ := newTestEngine(t, policy, sender)

	if _, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		exchange("10.0.0.1", "modbus-extended-id", "modbus", RiskCaution),
		exchange("10.0.0.1", "modbus-poke", "modbus", RiskLabOnly),
	}}); err != nil {
		t.Fatalf("run: %v", err)
	}

	if want := []string{"10.0.0.1 modbus-extended-id"}; !slices.Equal(sender.sent, want) {
		t.Fatalf("allowing caution should let exactly the caution probe through, got %v", sender.sent)
	}
}

// TestAHostIsFinishedBeforeItsNeighbourIsTouched pins the sequencing, which is
// what keeps a device from competing with the one beside it for the segment.
func TestAHostIsFinishedBeforeItsNeighbourIsTouched(t *testing.T) {
	sender := &recorder{}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender)

	// Interleaved on the way in, because a caller building a plan per template
	// rather than per host is the ordinary case.
	if _, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
		exchange("10.0.0.2", "modbus-device-id", "modbus", RiskSafe),
		exchange("10.0.0.1", "enip-list-identity", "enip", RiskSafe),
		exchange("10.0.0.2", "enip-list-identity", "enip", RiskSafe),
	}}); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := []string{
		"10.0.0.1 modbus-device-id",
		"10.0.0.1 enip-list-identity",
		"10.0.0.2 modbus-device-id",
		"10.0.0.2 enip-list-identity",
	}
	if !slices.Equal(sender.sent, want) {
		t.Errorf("sends came out as\n  %s\nwant\n  %s",
			strings.Join(sender.sent, ", "), strings.Join(want, ", "))
	}
}

// TestAMultiStepTemplateSharesOneConnection is the reason exchanges hold steps.
//
// An S7 CPU answers a Read SZL only after a COTP connection and a negotiated PDU
// size, so the three packets have to arrive on the same socket in order. What
// this pins is that they do, that the socket is opened once and closed once, and
// that the steps are still paced individually rather than sprayed at the device
// as fast as the stack will take them.
func TestAMultiStepTemplateSharesOneConnection(t *testing.T) {
	sender := &recorder{}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender)

	if _, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		steps("10.0.0.1", "s7comm-identify", "s7comm",
			RiskSafe, "cotp-connect", "setup-communication", "read-szl"),
	}}); err != nil {
		t.Fatalf("run: %v", err)
	}

	want := []string{
		"10.0.0.1 cotp-connect",
		"10.0.0.1 setup-communication",
		"10.0.0.1 read-szl",
	}
	if !slices.Equal(sender.sent, want) {
		t.Errorf("the handshake came out as %v, want %v", sender.sent, want)
	}
	if len(sender.dialed) != 1 {
		t.Errorf("the exchange opened %d connections, want 1", len(sender.dialed))
	}
	if sender.closed != 1 {
		t.Errorf("the connection was closed %d times, want once", sender.closed)
	}
	for idx := 1; idx < len(sender.at); idx++ {
		if gap := sender.at[idx] - sender.at[idx-1]; gap != DefaultInterPacketDelay {
			t.Errorf("step %d followed the one before after %s, want the full %s",
				idx+1, gap, DefaultInterPacketDelay)
		}
	}
}

// TestAFailedStepEndsTheExchange stops the engine asking a device that has just
// stopped answering to answer something else.
func TestAFailedStepEndsTheExchange(t *testing.T) {
	var trail bytes.Buffer
	sender := &recorder{fail: map[string]error{"10.0.0.1/setup-communication": ErrNoAnswer}}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender, WithAuditor(NewAuditorTo(&trail)))

	result, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		steps("10.0.0.1", "s7comm-identify", "s7comm",
			RiskSafe, "cotp-connect", "setup-communication", "read-szl"),
	}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	want := []string{"10.0.0.1 cotp-connect", "10.0.0.1 setup-communication"}
	if !slices.Equal(sender.sent, want) {
		t.Errorf("packets sent were %v, want the run to stop after the failure: %v", sender.sent, want)
	}
	if sender.closed != 1 {
		t.Errorf("the connection was closed %d times, want once even on failure", sender.closed)
	}
	if result.Failed != 1 {
		t.Errorf("counted %d failures, want 1", result.Failed)
	}

	// The step that never ran is in the file, so a reader sees a session that
	// died halfway rather than a template that was never tried.
	records := decodeTrail(t, trail.Bytes())
	last := records[len(records)-2]
	if last["outcome"] != string(OutcomeSkippedAborted) {
		t.Errorf("the unrun step was recorded as %v, want %s", last["outcome"], OutcomeSkippedAborted)
	}
	if last["step"] != 3.0 {
		t.Errorf("the unrun step is numbered %v, want 3", last["step"])
	}
}

// TestARefusedConnectionCostsOnePacketNotThree keeps the abort arithmetic honest
// for multi step templates.
//
// A host that will not accept a connection has not received three packets, so
// counting three failures against the error rate would make one dead address
// look like three and abort a run that is going fine.
func TestARefusedConnectionCostsOnePacketNotThree(t *testing.T) {
	sender := &recorder{failDial: map[string]error{"10.0.0.1": ErrUnreachable}}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender)

	result, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		steps("10.0.0.1", "s7comm-identify", "s7comm",
			RiskSafe, "cotp-connect", "setup-communication", "read-szl"),
	}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sender.sent) != 0 {
		t.Errorf("%d packets went out over a connection that was refused", len(sender.sent))
	}
	if result.Sent != 1 || result.Failed != 1 {
		t.Errorf("a refused connection counted as %d sent and %d failed, want 1 and 1", result.Sent, result.Failed)
	}
}

// TestPacketsAreSpacedByTheStricterOfTheTwoControls checks the arithmetic that
// the change request estimate also depends on.
func TestPacketsAreSpacedByTheStricterOfTheTwoControls(t *testing.T) {
	cases := map[string]struct {
		delay time.Duration
		rate  float64
		want  time.Duration
	}{
		"the defaults, where both agree": {DefaultInterPacketDelay, DefaultPacketsPerSecond, 250 * time.Millisecond},
		"a slower rate binds harder":     {DefaultInterPacketDelay, 1, time.Second},
		"a longer delay binds harder":    {2 * time.Second, DefaultPacketsPerSecond, 2 * time.Second},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			policy := DefaultPolicy()
			policy.InterPacketDelay = tc.delay
			policy.PacketsPerSecond = tc.rate

			sender := &recorder{}
			engine, _ := newTestEngine(t, policy, sender)
			if _, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
				exchange("10.0.0.1", "a", "modbus", RiskSafe),
				exchange("10.0.0.1", "b", "modbus", RiskSafe),
				exchange("10.0.0.1", "c", "modbus", RiskSafe),
			}}); err != nil {
				t.Fatalf("run: %v", err)
			}

			if len(sender.at) != 3 {
				t.Fatalf("sent %d packets, want 3", len(sender.at))
			}
			// The first packet is not delayed: a run is not made safer by
			// pausing before it has done anything.
			if sender.at[0] != 0 {
				t.Errorf("the first packet waited %s", sender.at[0])
			}
			for idx := 1; idx < len(sender.at); idx++ {
				if gap := sender.at[idx] - sender.at[idx-1]; gap != tc.want {
					t.Errorf("packet %d came %s after the one before, want %s", idx+1, gap, tc.want)
				}
			}
		})
	}
}

// TestTheRunStopsWhenDevicesStopAnswering is the abort.
//
// The scenario is the one that matters: a scan that has begun to provoke
// failures. Continuing is the worst available action, so the engine stops
// without being told to and records why.
func TestTheRunStopsWhenDevicesStopAnswering(t *testing.T) {
	sender := &recorder{fail: map[string]error{}}
	var exchanges []Exchange
	for idx := 0; idx < 20; idx++ {
		host := fmt.Sprintf("10.0.0.%d", idx+1)
		exchanges = append(exchanges, exchange(host, "modbus-device-id", "modbus", RiskSafe))
		if idx >= 2 {
			sender.fail[host] = fmt.Errorf("dial %s: %w", host, ErrUnreachable)
		}
	}

	engine, _ := newTestEngine(t, DefaultPolicy(), sender)
	result, err := engine.Run(context.Background(), Plan{Exchanges: exchanges})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if !result.Aborted {
		t.Fatal("17 of 20 hosts stopped answering and the run continued to the end")
	}
	if len(sender.sent) >= len(exchanges) {
		t.Errorf("the abort sent %d of %d exchanges, so it did not stop anything", len(sender.sent), len(exchanges))
	}
	if !strings.Contains(result.AbortReason, "failure rate") {
		t.Errorf("the abort reason does not give the arithmetic:\n%s", result.AbortReason)
	}
	// What was not done is reported, so a partial inventory is not mistaken for
	// a complete one.
	if result.Skipped == 0 {
		t.Error("the exchanges after the abort were dropped rather than recorded as skipped")
	}
}

// TestOneUnreachableHostIsNotAnAbort keeps the abort from firing on the ordinary
// case of an address with nothing behind it.
func TestOneUnreachableHostIsNotAnAbort(t *testing.T) {
	sender := &recorder{fail: map[string]error{"10.0.0.1": ErrUnreachable}}
	var exchanges []Exchange
	for idx := 0; idx < 10; idx++ {
		exchanges = append(exchanges, exchange(fmt.Sprintf("10.0.0.%d", idx+1), "modbus-device-id", "modbus", RiskSafe))
	}

	engine, _ := newTestEngine(t, DefaultPolicy(), sender)
	result, err := engine.Run(context.Background(), Plan{Exchanges: exchanges})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Aborted {
		t.Fatalf("one dead address out of ten aborted the run: %s", result.AbortReason)
	}
	if result.Sent != 10 {
		t.Errorf("sent %d of 10", result.Sent)
	}
}

// identifier is an interpreter that returns a fixed identity for one template,
// standing in for the decoders the probe command will supply.
type identifier struct {
	when string
	as   asset.Identity
}

func (i identifier) Interpret(ex Exchange, _ Step, _ []byte) asset.Identity {
	if ex.TemplateID == i.when {
		return i.as
	}
	return asset.Identity{}
}

// TestTheDenyListStopsTheProbeThatFollowsTheOneThatIdentifiedTheDevice is the
// deny list working the only way it can.
//
// Recognising a fragile device requires asking it something, so the first probe
// always goes out. What the list buys is everything after that.
func TestTheDenyListStopsTheProbeThatFollowsTheOneThatIdentifiedTheDevice(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("deny list: %v", err)
	}

	sender := &recorder{}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender,
		WithDenyList(list),
		WithInterpreter(identifier{
			when: "s7comm-identify",
			as:   asset.Identity{Vendor: "siemens", Family: "SIMATIC S7-300", Product: "CPU 315-2 PN/DP"},
		}),
	)

	result, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
		exchange("10.0.0.1", "s7comm-identify", "s7comm", RiskSafe),
		exchange("10.0.0.1", "s7comm-read-szl", "s7comm", RiskSafe),
		exchange("10.0.0.1", "s7comm-read-szl-modules", "s7comm", RiskSafe),
	}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(sender.sent) != 1 {
		t.Fatalf("sent %d exchanges to an S7-300, want only the first: %+v", len(sender.sent), sender.sent)
	}
	if len(result.Skips) != 2 {
		t.Fatalf("recorded %d skips, want 2", len(result.Skips))
	}
	for _, skip := range result.Skips {
		if skip.Outcome != OutcomeSkippedDenied {
			t.Errorf("%s was skipped as %s", skip.Exchange.TemplateID, skip.Outcome)
		}
		if !strings.Contains(skip.Reason, "siemens-s7-300-repeated-iso-tsap") {
			t.Errorf("the skip does not name the rule that caused it, so nobody could argue with it:\n%s", skip.Reason)
		}
	}
}

// TestAKnownIdentityStopsEvenTheFirstPacket is why Plan.Known exists.
//
// An operator who ran the passive path first already knows which address is a
// safety controller. Feeding that in moves the deny list from stopping the second
// packet to stopping all of them, which for a safety instrumented system is the
// difference that matters.
func TestAKnownIdentityStopsEvenTheFirstPacket(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("deny list: %v", err)
	}

	sender := &recorder{}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender, WithDenyList(list))

	result, err := engine.Run(context.Background(), Plan{
		Exchanges: []Exchange{
			exchange("10.0.0.9", "modbus-device-id", "modbus", RiskSafe),
			exchange("10.0.0.9", "enip-list-identity", "enip", RiskSafe),
		},
		Known: map[string]asset.Identity{
			"10.0.0.9": {Vendor: "schneider-electric", Product: "Triconex Tricon"},
		},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}

	if len(sender.sent) != 0 {
		t.Fatalf("%d packets were sent to a safety instrumented system", len(sender.sent))
	}
	if result.Skipped != 2 {
		t.Errorf("skipped %d, want 2", result.Skipped)
	}
}

// TestADryRunOpensNoSocket is layer four, and it is checked by handing the engine
// no sender at all. If anything tried to send, the test would panic rather than
// quietly pass.
func TestADryRunOpensNoSocket(t *testing.T) {
	var trail bytes.Buffer
	engine, _ := newTestEngine(t, DefaultPolicy(), nil,
		WithDryRun(true),
		WithAuditor(NewAuditorTo(&trail)),
	)

	result, err := engine.Run(context.Background(), Plan{
		Reason: "pre-approval for change CR-4417",
		Exchanges: []Exchange{
			exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
			exchange("10.0.0.2", "modbus-device-id", "modbus", RiskSafe),
		},
	})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if result.Sent != 0 {
		t.Fatalf("a dry run sent %d packets", result.Sent)
	}

	records := decodeTrail(t, trail.Bytes())
	if len(records) != 4 {
		t.Fatalf("the trail holds %d lines, want a header, two records and a summary", len(records))
	}
	if records[0]["dry_run"] != true {
		t.Error("the audit header does not say this was a dry run, so the file could be mistaken for a real one")
	}
	for _, record := range records[1:3] {
		if record["outcome"] != string(OutcomeDryRun) {
			t.Errorf("outcome is %v, want %s", record["outcome"], OutcomeDryRun)
		}
		if _, sent := record["response"]; sent {
			t.Error("a dry run record carries a response")
		}
	}
}

// TestANonDryRunWithoutASenderIsRefused catches the mistake at construction
// rather than as a panic partway through a run against live equipment.
func TestANonDryRunWithoutASenderIsRefused(t *testing.T) {
	if _, err := NewEngine(DefaultPolicy(), nil); err == nil {
		t.Fatal("an engine that will send but has nothing to send with was accepted")
	}
	if _, err := NewEngine(DefaultPolicy(), nil, WithDryRun(true)); err != nil {
		t.Fatalf("a dry run needs no sender: %v", err)
	}
}

func TestAnOutOfBoundsPolicyIsRefusedAtConstruction(t *testing.T) {
	policy := DefaultPolicy()
	policy.PacketsPerSecond = 500
	if _, err := NewEngine(policy, &recorder{}); err == nil {
		t.Fatal("the engine accepted a policy its own validator rejects")
	}
}

// TestTheAuditTrailAccountsForEveryExchange is the promise that the honest answer
// to what this tool did is a file.
func TestTheAuditTrailAccountsForEveryExchange(t *testing.T) {
	var trail bytes.Buffer
	sender := &recorder{
		replies: map[string][]byte{"10.0.0.1/modbus-device-id": {0xde, 0xad}},
		fail:    map[string]error{"10.0.0.2": ErrNoAnswer},
	}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender, WithAuditor(NewAuditorTo(&trail)))

	if _, err := engine.Run(context.Background(), Plan{
		Reason:     "quarterly inventory, work order 8812",
		Invocation: []string{"otscout", "probe", "10.0.0.0/29"},
		Exchanges: []Exchange{
			exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
			exchange("10.0.0.2", "modbus-device-id", "modbus", RiskSafe),
			exchange("10.0.0.3", "modbus-poke", "modbus", RiskLabOnly),
		},
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	records := decodeTrail(t, trail.Bytes())
	if len(records) != 5 {
		t.Fatalf("the trail holds %d lines, want a header, three records and a summary", len(records))
	}

	header := records[0]
	if header["reason"] != "quarterly inventory, work order 8812" {
		t.Error("the header does not record why the network was touched")
	}
	if header["policy"] == nil {
		t.Error("the header does not record the settings, so the file cannot be read without knowing this build's defaults")
	}

	answered := records[1]
	if answered["outcome"] != string(OutcomeAnswered) {
		t.Errorf("outcome is %v, want %s", answered["outcome"], OutcomeAnswered)
	}
	// The bytes both ways are in the file, which is what makes it evidence
	// rather than a claim.
	if answered["request"] == "" || answered["response"] != "dead" {
		t.Errorf("the record does not hold both directions: %v", answered)
	}

	if records[2]["outcome"] != string(OutcomeNoAnswer) {
		t.Errorf("a silent target was recorded as %v", records[2]["outcome"])
	}
	if records[3]["outcome"] != string(OutcomeSkippedRisk) {
		t.Errorf("a skipped template was recorded as %v", records[3]["outcome"])
	}

	summary := records[4]
	if summary["kind"] != "summary" {
		t.Fatalf("the last line is %v, want a summary so a truncated file is visibly truncated", summary["kind"])
	}
	if summary["attempted"] != 3.0 || summary["sent"] != 2.0 || summary["skipped"] != 1.0 {
		t.Errorf("the summary does not add up: %v", summary)
	}
}

// TestCancellingTheRunStopsIt covers the operator hitting the stop button, which
// the web interface will drive through the same context.
func TestCancellingTheRunStopsIt(t *testing.T) {
	sender := &recorder{}
	engine, _ := newTestEngine(t, DefaultPolicy(), sender)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := engine.Run(ctx, Plan{Exchanges: []Exchange{
		exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
		exchange("10.0.0.2", "modbus-device-id", "modbus", RiskSafe),
	}})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sender.sent) != 0 {
		t.Fatalf("%d packets went out after cancellation", len(sender.sent))
	}
	if !result.Aborted || result.AbortReason != "cancelled" {
		t.Errorf("the run did not record the cancellation: aborted=%v reason=%q", result.Aborted, result.AbortReason)
	}
}

// TestAMalformedExchangeIsRefusedBeforeAnythingIsSent stops a partial run.
//
// Validation happens over the whole plan first, so a mistake in the last target
// does not leave a plant half scanned with no explanation for where it stopped.
func TestAMalformedExchangeIsRefusedBeforeAnythingIsSent(t *testing.T) {
	cases := map[string]func(*Exchange){
		"a host that is not an address": func(e *Exchange) { e.Target.Host = "plc-1.plant.example" },
		"a transport nobody speaks":     func(e *Exchange) { e.Target.Transport = "sctp" },
		"a port out of range":           func(e *Exchange) { e.Target.Port = 70000 },
		"no template to attribute it":   func(e *Exchange) { e.TemplateID = "" },
		"a risk rating that is not one": func(e *Exchange) { e.Risk = "probably fine" },
		"no steps at all":               func(e *Exchange) { e.Steps = nil },
		"a step with no bytes to send":  func(e *Exchange) { e.Steps[0].Request = nil },
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			bad := exchange("10.0.0.2", "modbus-device-id", "modbus", RiskSafe)
			breakIt(&bad)

			sender := &recorder{}
			engine, _ := newTestEngine(t, DefaultPolicy(), sender)
			_, err := engine.Run(context.Background(), Plan{Exchanges: []Exchange{
				exchange("10.0.0.1", "modbus-device-id", "modbus", RiskSafe),
				bad,
			}})
			if err == nil {
				t.Fatal("the plan was accepted")
			}
			if len(sender.sent) != 0 {
				t.Errorf("%d packets went out before the plan was rejected", len(sender.sent))
			}
		})
	}
}

func decodeTrail(t *testing.T, raw []byte) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("the audit trail is not JSON Lines, which is the one thing it has to be: %v\n%s", err, line)
		}
		out = append(out, record)
	}
	return out
}

func TestClassifyingASendError(t *testing.T) {
	cases := map[string]struct {
		err     error
		outcome Outcome
	}{
		"an answer":             {nil, OutcomeAnswered},
		"silence":               {ErrNoAnswer, OutcomeNoAnswer},
		"wrapped silence":       {fmt.Errorf("read from 10.0.0.1: %w", ErrNoAnswer), OutcomeNoAnswer},
		"no route":              {ErrUnreachable, OutcomeUnreachable},
		"something unexplained": {errors.New("connection reset"), OutcomeUnreachable},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			outcome, _ := classify(tc.err)
			if outcome != tc.outcome {
				t.Errorf("classified as %s, want %s", outcome, tc.outcome)
			}
			if tc.err != nil && !outcome.Failed() {
				t.Error("a failed send does not count against the error rate")
			}
			if tc.err == nil && outcome.Failed() {
				t.Error("a successful send counts against the error rate")
			}
		})
	}
}

// TestASkipIsNotAFailure keeps a run full of deliberately skipped templates from
// aborting itself.
func TestASkipIsNotAFailure(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeSkippedRisk, OutcomeSkippedDenied, OutcomeSkippedAborted, OutcomeDryRun} {
		if outcome.Failed() {
			t.Errorf("%s counts against the error rate, so a cautious run would abort itself", outcome)
		}
		if outcome.Sent() {
			t.Errorf("%s counts as a packet on the wire", outcome)
		}
	}
}
