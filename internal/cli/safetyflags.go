package cli

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/safety"
)

// safetyFlags are the controls every command that can emit a packet shares.
//
// They live in one place because they must not diverge. A second command with
// its own idea of what --dry-run means, or with a rate limit flag the first one
// lacks, is how a safety guarantee becomes a safety guarantee in one code path.
type safetyFlags struct {
	dryRun    bool
	reason    string
	auditPath string
	allowRisk string

	delay          time.Duration
	packetsPerSec  float64
	connectTimeout time.Duration
	readTimeout    time.Duration
	errorRate      float64
}

// registerPacing adds the flags that describe how a scan would be paced.
//
// These are separate from the accountability flags because a command can
// meaningfully answer questions about the limits without being a command that
// runs anything, and offering it --audit would suggest it records something.
func (f *safetyFlags) registerPacing(cmd *cobra.Command) {
	flags := cmd.Flags()
	defaults := safety.DefaultPolicy()

	flags.StringVar(&f.allowRisk, "allow-risk", string(defaults.AllowedRisk),
		"highest template risk rating to run: safe, caution or lab-only")

	flags.DurationVar(&f.delay, "delay", defaults.InterPacketDelay,
		"pause between packets; may be raised but not lowered far")
	flags.Float64Var(&f.packetsPerSec, "rate", defaults.PacketsPerSecond,
		"global packet ceiling per second; may be lowered but not raised")
	flags.DurationVar(&f.connectTimeout, "connect-timeout", defaults.ConnectTimeout,
		"how long to wait for a connection")
	flags.DurationVar(&f.readTimeout, "read-timeout", defaults.ReadTimeout,
		"how long to wait for a response")
	flags.Float64Var(&f.errorRate, "abort-error-rate", defaults.ErrorRateAbort,
		"stop the run when this fraction of attempts has failed; may be lowered but not raised")
}

// registerRun adds the pacing flags plus the ones a command needs before it may
// put a packet on a wire.
func (f *safetyFlags) registerRun(cmd *cobra.Command) {
	f.registerPacing(cmd)

	flags := cmd.Flags()
	flags.BoolVar(&f.dryRun, "dry-run", false,
		"print the exact bytes that would be sent to each target and exit without opening a socket")
	flags.StringVar(&f.reason, "reason", "",
		"why this scan is being run, recorded in the audit log (required unless --dry-run)")
	flags.StringVar(&f.auditPath, "audit", "",
		"write the JSON Lines audit trail here (required unless --dry-run)")
}

// policy turns the flags into a validated policy.
//
// The validation is the policy's own, not a second copy of the rules here. A
// bound enforced in two places is a bound that will eventually be enforced in
// one.
func (f *safetyFlags) policy() (safety.Policy, error) {
	risk, err := safety.ParseRisk(f.allowRisk)
	if err != nil {
		return safety.Policy{}, err
	}

	policy := safety.DefaultPolicy()
	policy.AllowedRisk = risk
	policy.InterPacketDelay = f.delay
	policy.PacketsPerSecond = f.packetsPerSec
	policy.ConnectTimeout = f.connectTimeout
	policy.ReadTimeout = f.readTimeout
	policy.ErrorRateAbort = f.errorRate

	if err := policy.Validate(); err != nil {
		return safety.Policy{}, err
	}
	return policy, nil
}

// requireAccountability refuses a run that sends packets without saying why or
// leaving a record.
//
// Both are demanded rather than defaulted. An audit file this tool named itself
// is one the operator does not know exists, and a reason this tool invented is
// not a reason. Neither applies to a dry run, which sends nothing and is often
// the thing being run to produce the change request that supplies both.
func (f *safetyFlags) requireAccountability() error {
	if f.dryRun {
		return nil
	}

	var problems []error
	if strings.TrimSpace(f.reason) == "" {
		problems = append(problems, errors.New(
			"--reason is required: the audit file has to say why this network was touched, "+
				"and the person reading it later will not be you"))
	}
	if strings.TrimSpace(f.auditPath) == "" {
		problems = append(problems, errors.New(
			"--audit is required: an active scan with no record of what it sent is not something "+
				"this tool will run. Use --dry-run to review the plan without one"))
	}
	return errors.Join(problems...)
}

// openAuditor returns the trail for this run, or nil for a dry run that was not
// asked to keep one.
func (f *safetyFlags) openAuditor() (*safety.Auditor, error) {
	if f.auditPath == "" {
		return nil, nil
	}
	auditor, err := safety.NewAuditor(f.auditPath)
	if err != nil {
		return nil, fmt.Errorf("%w\n\nAudit files are never overwritten. Choose another name or move the existing one", err)
	}
	return auditor, nil
}

// riskFlagHelp is appended to the long help of any command that can send, so the
// tiers are explained where the decision is made rather than only in the docs.
const riskFlagHelp = `
Risk ratings

  safe      A standard identification request that the protocol defines for this
            purpose, widely implemented, with no known adverse reports. This is
            the only tier that runs by default.
  caution   A legitimate read that some implementations handle poorly. Include it
            with --allow-risk caution.
  lab-only  Useful for research and not appropriate for production equipment.
            Include it with --allow-risk lab-only.

Every setting can be made stricter than its default. None can be made
meaningfully looser, and there is no concurrency setting at all: one host, one
connection and one packet at a time is not negotiable.`
