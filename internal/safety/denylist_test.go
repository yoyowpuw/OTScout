package safety

import (
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

func TestTheEmbeddedDenyListParses(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("parse the embedded deny list: %v", err)
	}
	if len(list.Rules()) == 0 {
		t.Fatal("the deny list is empty, which is either a parsing bug or a claim that no equipment anywhere is fragile")
	}
}

// TestEveryRuleCitesSomethingOrExplainsWhyNot holds the list to the standard its
// own header sets.
//
// A rule silently removes a device from every scan, which from the outside looks
// exactly like the device not being there. So a rule has to say what it rests on:
// either a published report, or a stated policy about a class of equipment.
func TestEveryRuleCitesSomethingOrExplainsWhyNot(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("parse the embedded deny list: %v", err)
	}

	for _, rule := range list.Rules() {
		t.Run(rule.ID, func(t *testing.T) {
			if len(rule.References) > 0 {
				return
			}
			// A rule with no reference is only acceptable when it denies the
			// device outright, since that is a policy about a class of equipment
			// rather than a claim about a defect. A rule that narrows to specific
			// probes is claiming those probes cause trouble, and that needs a
			// source.
			if len(rule.Templates) > 0 || len(rule.Protocols) > 0 {
				t.Error("this rule claims specific probes are harmful but cites nothing. " +
					"Either add a reference or widen it to a refusal to probe the device at all.")
			}
			if !strings.Contains(strings.ToLower(rule.Reason), "safety instrumented system") {
				t.Error("this rule cites nothing and is not a refusal to probe a safety instrumented system, " +
					"so a reader cannot tell what it rests on")
			}
		})
	}
}

func TestAMalformedDenyListIsRefused(t *testing.T) {
	cases := map[string]string{
		"a rule with no id": `
version: 1
rules:
  - vendor: siemens
    reason: it falls over
`,
		"a rule with no reason": `
version: 1
rules:
  - id: mystery
    vendor: siemens
`,
		"a rule that matches every device": `
version: 1
rules:
  - id: everything
    reason: this would silently empty every scan
`,
		"two rules with the same id": `
version: 1
rules:
  - id: same
    vendor: siemens
    reason: first
  - id: same
    vendor: abb
    reason: second
`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseDenyList([]byte(raw)); err == nil {
				t.Fatal("the list was accepted")
			}
		})
	}
}

// TestAnUnidentifiedDeviceMatchesNothing is the rule that keeps the deny list
// from denying the first probe to everything.
//
// A rule leaves fields blank to mean "any", so a blank vendor would match a host
// nothing is known about yet. Every host starts that way, so the mistake would
// stop the scan entirely while looking like a scan that found nothing.
func TestAnUnidentifiedDeviceMatchesNothing(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("parse the embedded deny list: %v", err)
	}
	ex := Exchange{TemplateID: "any", Protocol: "s7comm"}
	if rule := list.Check(asset.Identity{}, ex); rule != nil {
		t.Fatalf("an unknown device was denied by rule %s", rule.ID)
	}
}

func TestTheSiemensRuleStopsFurtherPortOneOhTwoTraffic(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("parse the embedded deny list: %v", err)
	}

	s7300 := asset.Identity{Vendor: "siemens", Family: "SIMATIC S7-300", Product: "CPU 315-2 PN/DP"}

	denied := list.Check(s7300, Exchange{TemplateID: "s7comm-read-szl", Protocol: "s7comm"})
	if denied == nil {
		t.Fatal("an S7-300 was offered another port 102 probe, which the advisories say can put it in defect mode")
	}
	if !strings.Contains(denied.Reason, "cold restart") {
		t.Errorf("the reason does not say what happens to the device:\n%s", denied.Reason)
	}

	// The rule is about port 102, so it must not quietly remove the device from
	// every other protocol. An S7-300 with a Modbus gateway is still worth asking.
	if rule := list.Check(s7300, Exchange{TemplateID: "modbus-device-id", Protocol: "modbus"}); rule != nil {
		t.Errorf("rule %s also denied an unrelated protocol", rule.ID)
	}
}

func TestSafetyControllersAreDeniedEveryProbe(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("parse the embedded deny list: %v", err)
	}

	controllers := map[string]asset.Identity{
		"Triconex":  {Vendor: "schneider-electric", Product: "Triconex Tricon"},
		"ProSafe":   {Vendor: "yokogawa", Product: "ProSafe-RS"},
		"Honeywell": {Vendor: "honeywell", Product: "Safety Manager"},
		"HIMax":     {VendorRaw: "HIMA", Product: "HIMax X-CPU 01"},
	}

	for name, identity := range controllers {
		t.Run(name, func(t *testing.T) {
			for _, proto := range []string{"modbus", "enip", "s7comm", "bacnet"} {
				ex := Exchange{TemplateID: proto + "-identify", Protocol: proto}
				if list.Check(identity, ex) == nil {
					t.Errorf("a %s probe to a safety instrumented system was allowed", proto)
				}
			}
		})
	}
}

// TestARuleDoesNotMatchAnUnrelatedVendor guards the substring matching, which is
// loose on purpose and therefore worth pinning.
func TestARuleDoesNotMatchAnUnrelatedVendor(t *testing.T) {
	list, err := DefaultDenyList()
	if err != nil {
		t.Fatalf("parse the embedded deny list: %v", err)
	}

	unrelated := []asset.Identity{
		{Vendor: "siemens", Family: "SIMATIC S7-1500", Product: "CPU 1516-3 PN/DP"},
		{Vendor: "rockwell-automation", Product: "1756-L71"},
		{Vendor: "schneider-electric", Product: "Modicon M340"},
		{Vendor: "wago", Product: "750-881"},
	}

	for _, identity := range unrelated {
		ex := Exchange{TemplateID: "s7comm-read-szl", Protocol: "s7comm"}
		if rule := list.Check(identity, ex); rule != nil {
			t.Errorf("%s was denied by rule %s", identity.Label(), rule.ID)
		}
	}
}
