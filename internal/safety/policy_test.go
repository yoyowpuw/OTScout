package safety

import (
	"strings"
	"testing"
	"time"
)

func TestTheDefaultPolicyIsValid(t *testing.T) {
	if err := DefaultPolicy().Validate(); err != nil {
		t.Fatalf("the defaults this tool ships with are rejected by its own validator: %v", err)
	}
}

// TestNoSettingCanBeLoosened is the test that makes the promise in docs/SAFETY.md
// mean something.
//
// Each case takes the defaults and moves one control in the dangerous direction.
// If any of them is accepted, an operator in a hurry can turn this into an
// ordinary IT scanner one flag at a time.
func TestNoSettingCanBeLoosened(t *testing.T) {
	cases := map[string]func(*Policy){
		"a faster packet rate": func(p *Policy) {
			p.PacketsPerSecond = DefaultPacketsPerSecond * 10
		},
		"a packet rate barely above the ceiling": func(p *Policy) {
			p.PacketsPerSecond = DefaultPacketsPerSecond + 0.01
		},
		"no delay between packets": func(p *Policy) {
			p.InterPacketDelay = 0
		},
		"a delay below the floor": func(p *Policy) {
			p.InterPacketDelay = minInterPacketDelay - time.Millisecond
		},
		"tolerating more failures before aborting": func(p *Policy) {
			p.ErrorRateAbort = 0.9
		},
		"never aborting at all": func(p *Policy) {
			p.ErrorRateAbort = 1
		},
		"holding sockets open far longer": func(p *Policy) {
			p.ConnectTimeout = maxTimeout + time.Second
		},
		"waiting for a read far longer": func(p *Policy) {
			p.ReadTimeout = maxTimeout + time.Second
		},
		"a risk rating that is not one": func(p *Policy) {
			p.AllowedRisk = "none"
		},
		"aborting before any attempt has been made": func(p *Policy) {
			p.MinAttemptsBeforeAbort = 0
		},
	}

	for name, loosen := range cases {
		t.Run(name, func(t *testing.T) {
			policy := DefaultPolicy()
			loosen(&policy)
			if err := policy.Validate(); err == nil {
				t.Fatal("the policy was accepted, so this control can be turned off")
			}
		})
	}
}

// TestEverySettingCanBeTightened is the other half of the promise. A site that
// wants to be gentler than this tool's authors thought necessary knows something
// about their plant, and must not be argued with.
func TestEverySettingCanBeTightened(t *testing.T) {
	cases := map[string]func(*Policy){
		"a longer delay between packets": func(p *Policy) {
			p.InterPacketDelay = 5 * time.Second
		},
		"a slower packet rate": func(p *Policy) {
			p.PacketsPerSecond = 0.5
		},
		"aborting on fewer failures": func(p *Policy) {
			p.ErrorRateAbort = 0.05
		},
		"aborting sooner": func(p *Policy) {
			p.MinAttemptsBeforeAbort = 2
		},
		"shorter timeouts": func(p *Policy) {
			p.ConnectTimeout = time.Second
			p.ReadTimeout = time.Second
		},
	}

	for name, tighten := range cases {
		t.Run(name, func(t *testing.T) {
			policy := DefaultPolicy()
			tighten(&policy)
			if err := policy.Validate(); err != nil {
				t.Fatalf("a stricter policy was rejected: %v", err)
			}
		})
	}
}

// TestRaisingTheAllowedRiskIsPermitted separates the risk gate from the pacing
// controls, because it is the one setting the operator is meant to raise.
//
// The gate is not there to stop a `caution` probe from ever running. It is there
// so that running one is a sentence somebody typed, which is why it defaults to
// the lowest tier and accepts being moved up.
func TestRaisingTheAllowedRiskIsPermitted(t *testing.T) {
	if DefaultPolicy().AllowedRisk != RiskSafe {
		t.Fatal("the default run must allow only the safest tier")
	}
	for _, risk := range Risks() {
		policy := DefaultPolicy()
		policy.AllowedRisk = risk
		if err := policy.Validate(); err != nil {
			t.Errorf("allowing risk %s was rejected: %v", risk, err)
		}
	}
}

// TestValidateReportsEveryProblemAtOnce keeps an operator adjusting several
// settings from discovering the rejections one failed run at a time.
func TestValidateReportsEveryProblemAtOnce(t *testing.T) {
	policy := DefaultPolicy()
	policy.PacketsPerSecond = 100
	policy.ErrorRateAbort = 0.99
	policy.ReadTimeout = time.Hour

	err := policy.Validate()
	if err == nil {
		t.Fatal("three loosened settings were accepted")
	}
	for _, want := range []string{"packet rate", "error rate abort", "read timeout"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q, so the operator would have to find it on the next run:\n%v", want, err)
		}
	}
}

// TestDescribeStatesTheConcurrencyItDoesNotOffer keeps the audit file honest
// about a control that has no field.
//
// Sequential execution is the strongest guarantee this engine makes and the one
// most easily assumed to be absent, since there is no setting for it. Saying so
// in the effective settings is how a reader of the audit file learns it.
func TestDescribeStatesTheConcurrencyItDoesNotOffer(t *testing.T) {
	described := strings.Join(DefaultPolicy().Describe(), "\n")
	for _, want := range []string{"1 host", "1 connection", "250ms", "highest risk allowed: safe"} {
		if !strings.Contains(described, want) {
			t.Errorf("the effective settings do not mention %q:\n%s", want, described)
		}
	}
}
