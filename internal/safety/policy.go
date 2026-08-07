package safety

import (
	"errors"
	"fmt"
	"time"
)

// Policy is the pacing and abort configuration for one run.
//
// Every field can be made stricter than its default and none can be made
// arbitrarily looser. That asymmetry is the point. An operator who wants to be
// gentler than this tool's authors thought necessary knows something about their
// plant that the authors do not, and should be allowed to act on it. An operator
// who wants to be rougher is usually in a hurry, and a tool that lets a hurry
// override a safety margin has no business on a control network.
//
// There is no concurrency setting. The engine sends one packet at a time, to one
// host at a time, over one connection. Parallelism is the single change most
// likely to turn a survey into an outage, so it is not a knob that can be turned
// by accident, or at all. Adding one later would be a deliberate change with its
// own review, which is the correct amount of friction for it.
type Policy struct {
	// InterPacketDelay is the pause after each packet, which leaves a device's
	// scan cycle room to breathe between requests.
	InterPacketDelay time.Duration

	// PacketsPerSecond bounds the total load this run places on a segment,
	// independently of the delay. The delay protects a single device and this
	// protects the network the devices share.
	PacketsPerSecond float64

	ConnectTimeout time.Duration
	ReadTimeout    time.Duration

	// ErrorRateAbort stops the run when this fraction of attempts has failed.
	//
	// This matters more than it looks. If a scan has begun to provoke failures,
	// continuing is the worst available action, and the engine is in a far better
	// position to notice than a person watching output scroll past.
	ErrorRateAbort float64

	// MinAttemptsBeforeAbort keeps the error rate from firing on the first
	// unreachable host, since one failure out of one attempt is a rate of 100
	// percent and means nothing.
	MinAttemptsBeforeAbort int

	// AllowedRisk is the highest rating a template may carry and still run.
	AllowedRisk Risk
}

// Defaults, which are also the loosest values Validate will accept for the
// fields where looser means riskier.
const (
	DefaultInterPacketDelay       = 250 * time.Millisecond
	DefaultPacketsPerSecond       = 4.0
	DefaultConnectTimeout         = 3 * time.Second
	DefaultReadTimeout            = 3 * time.Second
	DefaultErrorRateAbort         = 0.20
	DefaultMinAttemptsBeforeAbort = 5
)

// Bounds on how far each setting may be moved.
//
// The floors exist because a setting can be tightened into uselessness as easily
// as it can be loosened into danger: a one millisecond delay is not caution, and
// an error rate abort of zero stops the run before it starts.
//
// The delay floor is the one place a setting may be loosened at all, and it is
// bounded rather than open because the packet ceiling is the real limit: at the
// default of four per second the engine waits far longer than 50ms anyway, so
// lowering the delay alone buys nothing and cannot be used to hurry a run.
const (
	minInterPacketDelay = 50 * time.Millisecond
	maxInterPacketDelay = 10 * time.Second

	minPacketsPerSecond = 0.1

	minTimeout = 250 * time.Millisecond
	maxTimeout = 30 * time.Second

	minErrorRateAbort = 0.01
)

// DefaultPolicy returns the settings a run uses when the operator asks for
// nothing in particular.
func DefaultPolicy() Policy {
	return Policy{
		InterPacketDelay:       DefaultInterPacketDelay,
		PacketsPerSecond:       DefaultPacketsPerSecond,
		ConnectTimeout:         DefaultConnectTimeout,
		ReadTimeout:            DefaultReadTimeout,
		ErrorRateAbort:         DefaultErrorRateAbort,
		MinAttemptsBeforeAbort: DefaultMinAttemptsBeforeAbort,
		AllowedRisk:            RiskSafe,
	}
}

// Validate reports every way a policy is out of bounds, rather than the first.
//
// An operator adjusting several settings at once should learn about all the
// rejected ones in a single run, not discover them one failed invocation at a
// time.
func (p Policy) Validate() error {
	var problems []error

	switch {
	case p.InterPacketDelay < minInterPacketDelay:
		problems = append(problems, fmt.Errorf(
			"inter-packet delay %s is below the %s floor: the default is %s and it exists to leave a device's scan cycle room between requests",
			p.InterPacketDelay, minInterPacketDelay, DefaultInterPacketDelay))
	case p.InterPacketDelay > maxInterPacketDelay:
		problems = append(problems, fmt.Errorf(
			"inter-packet delay %s is longer than the %s ceiling, which is long enough that a run would look like a hang",
			p.InterPacketDelay, maxInterPacketDelay))
	}

	switch {
	case p.PacketsPerSecond > DefaultPacketsPerSecond:
		problems = append(problems, fmt.Errorf(
			"packet rate %.2f per second is above the default ceiling of %.0f, which may not be raised",
			p.PacketsPerSecond, DefaultPacketsPerSecond))
	case p.PacketsPerSecond < minPacketsPerSecond:
		problems = append(problems, fmt.Errorf(
			"packet rate %.2f per second is below the %.2f floor, which is slow enough to be indistinguishable from a hang",
			p.PacketsPerSecond, minPacketsPerSecond))
	}

	problems = append(problems, validateTimeout("connect timeout", p.ConnectTimeout)...)
	problems = append(problems, validateTimeout("read timeout", p.ReadTimeout)...)

	switch {
	case p.ErrorRateAbort > DefaultErrorRateAbort:
		problems = append(problems, fmt.Errorf(
			"error rate abort %.2f is above the default of %.2f: tolerating more failures than that means continuing a scan that has started to provoke them",
			p.ErrorRateAbort, DefaultErrorRateAbort))
	case p.ErrorRateAbort < minErrorRateAbort:
		problems = append(problems, fmt.Errorf(
			"error rate abort %.2f is below the %.2f floor, which would stop the run on the first unreachable host",
			p.ErrorRateAbort, minErrorRateAbort))
	}

	if p.MinAttemptsBeforeAbort < 1 {
		problems = append(problems, errors.New(
			"the abort threshold must wait for at least one attempt, since a rate over zero attempts is not a rate"))
	}

	if err := p.AllowedRisk.Validate(); err != nil {
		problems = append(problems, err)
	}

	return errors.Join(problems...)
}

// validateTimeout applies the same bounds to both timeouts.
//
// A long timeout is not the safe direction here, which is why this is bounded on
// both sides while the delay is not. Holding a socket open against a device with
// a small connection table is itself a way of causing trouble, so waiting longer
// is a risk rather than a courtesy.
func validateTimeout(name string, d time.Duration) []error {
	switch {
	case d < minTimeout:
		return []error{fmt.Errorf("%s %s is below the %s floor and would fail against any device on a slow link", name, d, minTimeout)}
	case d > maxTimeout:
		return []error{fmt.Errorf("%s %s is above the %s ceiling: holding a socket open that long is itself a load on a small stack", name, d, maxTimeout)}
	}
	return nil
}

// Describe renders the effective settings for the audit log and for the line the
// probe command prints before it starts.
//
// This is written out in full on every run rather than only when it differs from
// the default, because the question the audit file has to answer later is what
// the settings were, not whether anybody changed them.
func (p Policy) Describe() []string {
	return []string{
		"concurrency: 1 host, 1 connection, 1 packet at a time",
		fmt.Sprintf("inter-packet delay: %s", p.InterPacketDelay),
		fmt.Sprintf("packet ceiling: %.2f per second", p.PacketsPerSecond),
		fmt.Sprintf("connect timeout: %s", p.ConnectTimeout),
		fmt.Sprintf("read timeout: %s", p.ReadTimeout),
		fmt.Sprintf("abort when %.0f percent of at least %d attempts fail",
			p.ErrorRateAbort*100, p.MinAttemptsBeforeAbort),
		fmt.Sprintf("highest risk allowed: %s", p.AllowedRisk),
	}
}
