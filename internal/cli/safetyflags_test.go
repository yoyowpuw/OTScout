package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/safety"
)

// parseFlags runs a set of command line arguments through the real flag
// definitions, so that these tests exercise what an operator would actually
// type rather than a struct built by hand.
func parseFlags(t *testing.T, args ...string) (*safetyFlags, error) {
	t.Helper()
	flags := &safetyFlags{}
	cmd := &cobra.Command{Use: "probe", RunE: func(*cobra.Command, []string) error { return nil }}
	flags.registerRun(cmd)
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	return flags, cmd.Execute()
}

func TestTheDefaultFlagsProduceTheDefaultPolicy(t *testing.T) {
	flags, err := parseFlags(t)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	policy, err := flags.policy()
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	if policy != safety.DefaultPolicy() {
		t.Errorf("typing no flags produced %+v, want the documented defaults %+v", policy, safety.DefaultPolicy())
	}
}

// TestALoosenedFlagIsRejectedWithAnExplanation checks that the bound is enforced
// where the operator meets it, and that the refusal says which control and why.
func TestALoosenedFlagIsRejectedWithAnExplanation(t *testing.T) {
	cases := map[string]struct {
		args []string
		says string
	}{
		"a faster rate":             {[]string{"--rate", "500"}, "packet rate"},
		"no delay":                  {[]string{"--delay", "0"}, "inter-packet delay"},
		"never aborting":            {[]string{"--abort-error-rate", "1.0"}, "error rate abort"},
		"a risk tier that is not":   {[]string{"--allow-risk", "whatever"}, "risk rating"},
		"an absurd read timeout":    {[]string{"--read-timeout", "10m"}, "read timeout"},
		"an absurd connect timeout": {[]string{"--connect-timeout", "10m"}, "connect timeout"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			flags, err := parseFlags(t, tc.args...)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			_, err = flags.policy()
			if err == nil {
				t.Fatal("the flags were accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("the refusal does not name %q:\n%v", tc.says, err)
			}
		})
	}
}

func TestATightenedFlagIsAccepted(t *testing.T) {
	flags, err := parseFlags(t, "--delay", "2s", "--rate", "0.5", "--abort-error-rate", "0.05")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	policy, err := flags.policy()
	if err != nil {
		t.Fatalf("a stricter set of flags was rejected: %v", err)
	}
	if policy.InterPacketDelay != 2*time.Second || policy.PacketsPerSecond != 0.5 || policy.ErrorRateAbort != 0.05 {
		t.Errorf("the flags did not reach the policy: %+v", policy)
	}
}

// TestASendingRunMustSayWhyAndKeepARecord is the accountability rule.
//
// Neither is defaulted. An audit path this tool chose is one the operator does
// not know about, and a reason this tool invented is not a reason.
func TestASendingRunMustSayWhyAndKeepARecord(t *testing.T) {
	cases := map[string]struct {
		args    []string
		refused bool
		says    []string
	}{
		"nothing given at all": {
			nil, true, []string{"--reason", "--audit"},
		},
		"a reason but no record": {
			[]string{"--reason", "work order 8812"}, true, []string{"--audit"},
		},
		"a record but no reason": {
			[]string{"--audit", "scan.jsonl"}, true, []string{"--reason"},
		},
		"both given": {
			[]string{"--reason", "work order 8812", "--audit", "scan.jsonl"}, false, nil,
		},
		"a dry run needs neither": {
			[]string{"--dry-run"}, false, nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			flags, err := parseFlags(t, tc.args...)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			err = flags.requireAccountability()
			if tc.refused && err == nil {
				t.Fatal("the run was allowed to proceed")
			}
			if !tc.refused && err != nil {
				t.Fatalf("the run was refused: %v", err)
			}
			for _, want := range tc.says {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the refusal does not mention %s:\n%v", want, err)
				}
			}
		})
	}
}

// TestTheAuditFileIsNotClobberedAndTheErrorSaysSo checks the message as well as
// the refusal, because an operator who hits this needs to know it is deliberate.
func TestTheAuditFileIsNotClobberedAndTheErrorSaysSo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("seed an existing trail: %v", err)
	}

	flags, err := parseFlags(t, "--audit", path, "--reason", "work order 8812")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := flags.openAuditor(); err == nil {
		t.Fatal("an existing audit file was opened for writing")
	} else if !strings.Contains(err.Error(), "never overwritten") {
		t.Errorf("the error does not explain that this is deliberate:\n%v", err)
	}
}

func TestNoAuditPathMeansNoTrail(t *testing.T) {
	flags, err := parseFlags(t, "--dry-run")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	auditor, err := flags.openAuditor()
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if auditor != nil {
		t.Error("a dry run with no --audit was given a trail it did not ask for")
	}
}

// TestTheSafetyCommandSendsNothingAndSaysWhatItWould covers the command an
// operator runs while writing a change request.
func TestTheSafetyCommandSendsNothingAndSaysWhatItWould(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"safety", "--delay", "1s"})

	if err := root.Execute(); err != nil {
		t.Fatalf("run: %v\n%s", err, out.String())
	}

	rendered := out.String()
	for _, want := range []string{
		"1 host, 1 connection, 1 packet at a time",
		"inter-packet delay: 1s",
		"highest risk allowed: safe",
		"siemens-s7-300-repeated-iso-tsap",
		"every active probe",
		"https://www.cisa.gov/news-events/ics-advisories/icsa-15-064-04",
	} {
		if !strings.Contains(rendered, want) {
			t.Errorf("the output does not contain %q:\n%s", want, rendered)
		}
	}
}

func TestTheSafetyCommandRefusesFlagsItCannotHonour(t *testing.T) {
	var out bytes.Buffer
	root := NewRootCommand()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"safety", "--rate", "1000"})

	if err := root.Execute(); err == nil {
		t.Fatalf("a rate above the ceiling was described as if it would apply:\n%s", out.String())
	}
}
