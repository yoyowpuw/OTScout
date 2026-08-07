package safety

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// ErrUnreachable means no connection could be established to the target.
var ErrUnreachable = errors.New("target could not be reached")

// ErrNoAnswer means the target accepted a connection, or the datagram left, and
// nothing came back within the read timeout.
var ErrNoAnswer = errors.New("target did not answer")

// Timeouts are the deadlines a sender must honour.
type Timeouts struct {
	Connect time.Duration
	Read    time.Duration
}

// Sender puts one exchange on the wire.
//
// This is the only interface in the project that opens a socket to equipment,
// and it is an interface so that everything above it can be tested without one.
// A sender must not retry: retrying is a pacing decision, and pacing decisions
// belong to the engine.
type Sender interface {
	Send(ctx context.Context, ex Exchange, timeouts Timeouts) ([]byte, error)
}

// Interpreter turns a reply into what the run now knows about the device.
//
// The engine needs this for one reason only: the deny list matches on identity,
// so a device has to be recognised before the rules protecting it can apply.
type Interpreter interface {
	Interpret(ex Exchange, response []byte) asset.Identity
}

// Plan is everything one run intends to do.
type Plan struct {
	// Exchanges in the order the caller wants them attempted. The engine groups
	// them by host but preserves this order within a host, so a template that
	// establishes identity can be listed before ones that depend on it.
	Exchanges []Exchange

	// Known is what a previous passive run already established, keyed by host.
	//
	// Seeding this matters more than it looks. The deny list can otherwise only
	// act from the second probe onward, because it needs an identity to match.
	// An operator who ran ingest first already knows which address is a safety
	// controller, and passing that in here is what stops the first packet rather
	// than the second.
	Known map[string]asset.Identity

	// Reason is the operator's stated purpose, recorded in the audit header.
	Reason string

	// Invocation is the command line, recorded in the audit header.
	Invocation []string
}

// Result is what a run did.
type Result struct {
	Attempted   int
	Sent        int
	Answered    int
	Failed      int
	Skipped     int
	Aborted     bool
	AbortReason string
	Duration    time.Duration

	// Replies holds what came back, in the order received. The engine does not
	// interpret these beyond handing them to the Interpreter.
	Replies []Reply

	// Skips explains every exchange that was not attempted, so that a run which
	// sent nothing can say why rather than looking like it found nothing.
	Skips []Skip
}

// Reply is one answer received.
type Reply struct {
	Exchange Exchange
	Response []byte
	Duration time.Duration
}

// Skip is one exchange that was not sent, and the reason.
type Skip struct {
	Exchange Exchange
	Outcome  Outcome
	Reason   string
}

// Engine runs a plan under a policy.
type Engine struct {
	policy   Policy
	sender   Sender
	auditor  *Auditor
	denyList *DenyList
	interp   Interpreter
	dryRun   bool

	// now and sleep are seams so that tests can exercise the pacing arithmetic
	// without spending the wall clock time it describes.
	now   func() time.Time
	sleep func(ctx context.Context, d time.Duration) error
}

// Option configures an engine.
type Option func(*Engine)

// WithAuditor writes the trail. A run without one is allowed, because a dry run
// has nothing to account for, but a run that sends should always have one.
func WithAuditor(a *Auditor) Option { return func(e *Engine) { e.auditor = a } }

// WithDenyList supplies the fragile device rules.
func WithDenyList(d *DenyList) Option { return func(e *Engine) { e.denyList = d } }

// WithInterpreter lets the engine recognise devices as it goes, so that deny
// rules can apply to the probes that follow the first.
func WithInterpreter(i Interpreter) Option { return func(e *Engine) { e.interp = i } }

// WithDryRun renders every request and sends none.
func WithDryRun(on bool) Option { return func(e *Engine) { e.dryRun = on } }

func withClock(now func() time.Time, sleep func(context.Context, time.Duration) error) Option {
	return func(e *Engine) { e.now = now; e.sleep = sleep }
}

// NewEngine builds an engine, refusing a policy that is out of bounds.
//
// A nil sender is only valid for a dry run. Requiring the caller to supply one
// otherwise means the mistake of forgetting it is caught here rather than as a
// panic partway through a run against live equipment.
func NewEngine(policy Policy, sender Sender, opts ...Option) (*Engine, error) {
	if err := policy.Validate(); err != nil {
		return nil, fmt.Errorf("safety policy: %w", err)
	}

	e := &Engine{
		policy: policy,
		sender: sender,
		now:    time.Now,
		sleep:  sleepContext,
	}
	for _, opt := range opts {
		opt(e)
	}
	if sender == nil && !e.dryRun {
		return nil, errors.New("a run that is not a dry run needs a sender")
	}
	return e, nil
}

func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run executes the plan.
//
// Exchanges are grouped by host and the hosts are taken one at a time, which is
// what keeps a device from competing with its neighbour for the segment. Within
// a host the caller's order is preserved, because identity usually comes from
// the first exchange and the deny list needs it before the second.
func (e *Engine) Run(ctx context.Context, plan Plan) (Result, error) {
	started := e.now()
	var result Result

	for idx, ex := range plan.Exchanges {
		if err := ex.Validate(); err != nil {
			return result, fmt.Errorf("exchange %d: %w", idx, err)
		}
	}

	if err := e.writeHeader(plan); err != nil {
		return result, err
	}

	// interval is the pause between packets, and it is the stricter of the two
	// controls rather than their sum: the delay protects one device and the
	// ceiling protects the segment they share, so whichever binds harder wins.
	interval := e.policy.InterPacketDelay
	if e.policy.PacketsPerSecond > 0 {
		if rateGap := time.Duration(float64(time.Second) / e.policy.PacketsPerSecond); rateGap > interval {
			interval = rateGap
		}
	}

	var lastSend time.Time
	known := make(map[string]asset.Identity, len(plan.Known))
	for host, identity := range plan.Known {
		known[host] = identity
	}

	hosts, byHost := groupByHost(plan.Exchanges)
	for _, host := range hosts {
		for _, ex := range byHost[host] {
			result.Attempted++

			if result.Aborted {
				e.recordSkip(&result, ex, OutcomeSkippedAborted, result.AbortReason)
				continue
			}
			if err := ctx.Err(); err != nil {
				e.recordSkip(&result, ex, OutcomeSkippedAborted, "the run was cancelled")
				result.Aborted = true
				result.AbortReason = "cancelled"
				continue
			}

			if !ex.Risk.AtMost(e.policy.AllowedRisk) {
				e.recordSkip(&result, ex, OutcomeSkippedRisk, fmt.Sprintf(
					"template is rated %s and this run allows up to %s; re-run with --allow-risk %s to include it",
					ex.Risk, e.policy.AllowedRisk, ex.Risk))
				continue
			}

			if rule := e.denyList.Check(known[host], ex); rule != nil {
				e.recordSkip(&result, ex, OutcomeSkippedDenied, fmt.Sprintf("%s: %s", rule.ID, rule.Reason))
				continue
			}

			if e.dryRun {
				if err := e.record(Record{
					Timestamp:  e.now(),
					Target:     ex.Target.Address(),
					Transport:  ex.Target.Transport,
					TemplateID: ex.TemplateID,
					Protocol:   ex.Protocol,
					Risk:       ex.Risk,
					Purpose:    ex.Purpose,
					Outcome:    OutcomeDryRun,
					Request:    ex.Request,
				}); err != nil {
					return result, err
				}
				result.Skipped++
				continue
			}

			if err := e.pace(ctx, lastSend, interval); err != nil {
				e.recordSkip(&result, ex, OutcomeSkippedAborted, "the run was cancelled")
				result.Aborted = true
				result.AbortReason = "cancelled"
				continue
			}

			sendStarted := e.now()
			response, sendErr := e.sender.Send(ctx, ex, Timeouts{
				Connect: e.policy.ConnectTimeout,
				Read:    e.policy.ReadTimeout,
			})
			elapsed := e.now().Sub(sendStarted)
			lastSend = e.now()

			outcome, detail := classify(sendErr)
			result.Sent++
			if outcome.Failed() {
				result.Failed++
			} else {
				result.Answered++
				result.Replies = append(result.Replies, Reply{Exchange: ex, Response: response, Duration: elapsed})
				if e.interp != nil {
					identity := known[host]
					identity.Merge(e.interp.Interpret(ex, response))
					known[host] = identity
				}
			}

			if err := e.record(Record{
				Timestamp:  sendStarted,
				Target:     ex.Target.Address(),
				Transport:  ex.Target.Transport,
				TemplateID: ex.TemplateID,
				Protocol:   ex.Protocol,
				Risk:       ex.Risk,
				Purpose:    ex.Purpose,
				Outcome:    outcome,
				Request:    ex.Request,
				Response:   response,
				DurationMS: elapsed.Milliseconds(),
				Detail:     detail,
			}); err != nil {
				return result, err
			}

			if reason, stop := e.shouldAbort(result); stop {
				result.Aborted = true
				result.AbortReason = reason
			}
		}
	}

	result.Duration = e.now().Sub(started)
	if err := e.writeSummary(result); err != nil {
		return result, err
	}
	return result, nil
}

// pace waits out whatever is left of the interval since the previous packet.
func (e *Engine) pace(ctx context.Context, lastSend time.Time, interval time.Duration) error {
	if lastSend.IsZero() {
		// Nothing has been sent yet, so there is nothing to wait behind. The
		// first packet of a run is not made safer by delaying it.
		return ctx.Err()
	}
	if wait := interval - e.now().Sub(lastSend); wait > 0 {
		return e.sleep(ctx, wait)
	}
	return ctx.Err()
}

// shouldAbort decides whether the run has started to do harm.
func (e *Engine) shouldAbort(r Result) (string, bool) {
	if r.Sent < e.policy.MinAttemptsBeforeAbort {
		return "", false
	}
	rate := float64(r.Failed) / float64(r.Sent)
	if rate <= e.policy.ErrorRateAbort {
		return "", false
	}
	return fmt.Sprintf(
		"%d of %d packets went unanswered, a failure rate of %.0f percent against a threshold of %.0f percent; "+
			"a scan that has begun to provoke failures is the worst thing to continue",
		r.Failed, r.Sent, rate*100, e.policy.ErrorRateAbort*100), true
}

func classify(err error) (Outcome, string) {
	switch {
	case err == nil:
		return OutcomeAnswered, ""
	case errors.Is(err, ErrNoAnswer):
		return OutcomeNoAnswer, err.Error()
	default:
		// Anything the sender could not explain is treated as unreachable. Both
		// count against the error rate identically, so the classification only
		// affects what the audit file says, and unreachable is the honest label
		// for a failure whose cause is unknown.
		return OutcomeUnreachable, err.Error()
	}
}

func (e *Engine) recordSkip(result *Result, ex Exchange, outcome Outcome, reason string) {
	result.Skipped++
	result.Skips = append(result.Skips, Skip{Exchange: ex, Outcome: outcome, Reason: reason})
	// A failure to write the audit trail for a skip is not worth ending the run
	// over, since nothing was sent, but the record is still attempted so the file
	// shows what was declined.
	_ = e.record(Record{
		Timestamp:  e.now(),
		Target:     ex.Target.Address(),
		Transport:  ex.Target.Transport,
		TemplateID: ex.TemplateID,
		Protocol:   ex.Protocol,
		Risk:       ex.Risk,
		Purpose:    ex.Purpose,
		Outcome:    outcome,
		Detail:     reason,
	})
}

func (e *Engine) record(r Record) error {
	if e.auditor == nil {
		return nil
	}
	return e.auditor.WriteRecord(r)
}

func (e *Engine) writeHeader(plan Plan) error {
	if e.auditor == nil {
		return nil
	}
	return e.auditor.WriteHeader(Header{
		Timestamp:  e.now(),
		Reason:     plan.Reason,
		Invocation: plan.Invocation,
		Policy:     e.policy.Describe(),
		DryRun:     e.dryRun,
	})
}

func (e *Engine) writeSummary(r Result) error {
	if e.auditor == nil {
		return nil
	}
	return e.auditor.WriteSummary(Summary{
		Timestamp:   e.now(),
		Attempted:   r.Attempted,
		Sent:        r.Sent,
		Answered:    r.Answered,
		Failed:      r.Failed,
		Skipped:     r.Skipped,
		Aborted:     r.Aborted,
		AbortReason: r.AbortReason,
		DurationMS:  r.Duration.Milliseconds(),
	})
}

// groupByHost collects the exchanges per host, keeping both the order the hosts
// first appear in and the caller's order within each one.
//
// Grouping is what makes the run sequential in the sense that matters: a device
// is finished with before its neighbour is touched. The order is the caller's
// rather than sorted, because the operator wrote the target list and reordering
// it is not this function's decision. The order within a host matters too, since
// identity usually comes from the first exchange and the deny list needs it
// before the second.
//
// A single pass rather than a filter per host, because a plan over a /16 with a
// handful of templates is an ordinary thing to ask for and scanning the whole
// slice once per address is not.
func groupByHost(exchanges []Exchange) ([]string, map[string][]Exchange) {
	order := make([]string, 0, len(exchanges))
	byHost := make(map[string][]Exchange, len(exchanges))
	for _, ex := range exchanges {
		host := ex.Target.Host
		if _, seen := byHost[host]; !seen {
			order = append(order, host)
		}
		byHost[host] = append(byHost[host], ex)
	}
	return order, byHost
}
