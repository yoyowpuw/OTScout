package probe

import (
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/golden"
	"github.com/yoyowpuw/OTScout/internal/safety"
)

func mustLibrary(t *testing.T) *Library {
	t.Helper()
	library, err := DefaultLibrary()
	if err != nil {
		t.Fatalf("load the template library: %v", err)
	}
	return library
}

// TestTheEmbeddedLibraryParses is the whole of template validation applied to
// the templates this build ships with.
//
// Parsing builds every request, so a parameter that does not fit its field fails
// here rather than partway through a scan against equipment.
func TestTheEmbeddedLibraryParses(t *testing.T) {
	library := mustLibrary(t)
	if len(library.All()) == 0 {
		t.Fatal("the library is empty")
	}
	for _, tmpl := range library.All() {
		if err := tmpl.Validate(); err != nil {
			t.Errorf("template %s: %v", tmpl.ID, err)
		}
	}
}

// TestEveryTemplateRequestIsRebuildableAndStable pins the bytes.
//
// A template is only reviewable if the same file produces the same packet every
// time. Building each step twice and comparing catches a builder that has picked
// up a clock, a random value or a counter, any of which would make the bytes in a
// change request differ from the bytes that get sent.
func TestEveryTemplateRequestIsRebuildableAndStable(t *testing.T) {
	for _, tmpl := range mustLibrary(t).All() {
		for idx := range tmpl.Steps {
			first, err := tmpl.StepBytes(idx)
			if err != nil {
				t.Fatalf("template %s step %d: %v", tmpl.ID, idx+1, err)
			}
			second, err := tmpl.StepBytes(idx)
			if err != nil {
				t.Fatalf("template %s step %d: %v", tmpl.ID, idx+1, err)
			}
			if string(first) != string(second) {
				t.Errorf("template %s step %d builds different bytes each time, so a dry run "+
					"would not show what a real run sends", tmpl.ID, idx+1)
			}
			if len(first) == 0 {
				t.Errorf("template %s step %d builds nothing", tmpl.ID, idx+1)
			}
		}
	}
}

// TestEveryTemplateStepHasBeenAnsweredBySomething is the corpus doing the job it
// exists for.
//
// A template step names a request. If no fixture in the corpus records a device
// answering that request, then nothing in CI has ever seen what comes back, and
// the step's first real test is somebody's plant floor. Requiring a recorded
// answer per step is what lets a contributor change a template without owning a
// PLC, and it is why adding a template means adding a fixture.
func TestEveryTemplateStepHasBeenAnsweredBySomething(t *testing.T) {
	corpus, err := golden.Load()
	if err != nil {
		t.Fatalf("load the corpus: %v", err)
	}

	answered := make(map[string][]string)
	for _, fixture := range corpus {
		if fixture.Request == nil {
			continue
		}
		answered[fixture.Request.Builder] = append(answered[fixture.Request.Builder], fixture.ID)
	}

	for _, tmpl := range mustLibrary(t).All() {
		for idx, step := range tmpl.Steps {
			if len(answered[step.Request]) == 0 {
				t.Errorf("template %s step %d sends %s and no fixture records a device answering it. "+
					"Add one to internal/golden/corpus, or this step gets tested for the first time "+
					"against real equipment.", tmpl.ID, idx+1, step.Request)
			}
		}
	}
}

// TestEveryTemplateProtocolIsRepresentedInTheCorpus keeps a protocol from being
// added to the library with nothing to test it against.
//
// A template nobody can exercise in CI is a template that gets its first
// verification on somebody's plant floor.
func TestEveryTemplateProtocolIsRepresentedInTheCorpus(t *testing.T) {
	corpus, err := golden.Load()
	if err != nil {
		t.Fatalf("load the corpus: %v", err)
	}

	recorded := make(map[string]bool)
	for _, fixture := range corpus {
		recorded[fixture.Expect.Protocol] = true
	}

	for _, tmpl := range mustLibrary(t).All() {
		if !recorded[tmpl.Protocol] {
			t.Errorf("template %s speaks %s and the corpus has no %s fixture, so nothing in CI "+
				"exercises what it will do to a device", tmpl.ID, tmpl.Protocol, tmpl.Protocol)
		}
	}
}

// TestARiskyTemplateHasToJustifyItself keeps the tiers meaningful.
func TestARiskyTemplateHasToJustifyItself(t *testing.T) {
	for _, tmpl := range mustLibrary(t).All() {
		if tmpl.Risk == safety.RiskSafe {
			continue
		}
		if len(strings.Fields(tmpl.RiskNote)) < 10 {
			t.Errorf("template %s is rated %s with a note of %d words. The note is what somebody "+
				"revising the rating later has to work from", tmpl.ID, tmpl.Risk, len(strings.Fields(tmpl.RiskNote)))
		}
	}
}

// TestEveryTemplateCitesTheSpecification is how a reviewer checks that a request
// is the standard identification call it claims to be.
func TestEveryTemplateCitesTheSpecification(t *testing.T) {
	for _, tmpl := range mustLibrary(t).All() {
		if len(tmpl.References) == 0 {
			t.Errorf("template %s cites nothing, so the claim that its request is a standard "+
				"identification call cannot be checked", tmpl.ID)
		}
	}
}

// TestABadTemplateIsRefusedAtParseTime lists the ways a contributed template can
// be wrong, and checks that each is caught before a scan rather than during one.
func TestABadTemplateIsRefusedAtParseTime(t *testing.T) {
	cases := map[string]string{
		"an id with spaces": `
version: 1
templates:
  - id: modbus device id
    summary: reads the identification objects
    protocol: modbus
    port: 502
    transport: tcp
    risk: safe
    steps:
      - purpose: read
        request: modbus.read-device-identification`,

		"a request this build cannot send": `
version: 1
templates:
  - id: modbus-write-coil
    summary: writes a coil
    protocol: modbus
    port: 502
    transport: tcp
    risk: safe
    steps:
      - purpose: write
        request: modbus.write-single-coil`,

		"a parameter too large for its field": `
version: 1
templates:
  - id: modbus-bad-unit
    summary: reads the identification objects
    protocol: modbus
    port: 502
    transport: tcp
    risk: safe
    steps:
      - purpose: read
        request: modbus.read-device-identification
        params:
          unit_id: "999"`,

		"a protocol with no decoder": `
version: 1
templates:
  - id: dnp3-identify
    summary: reads the identification objects
    protocol: dnp3
    port: 20000
    transport: tcp
    risk: safe
    steps:
      - purpose: read
        request: modbus.read-device-identification`,

		"a risk rating with no reason": `
version: 1
templates:
  - id: modbus-extended
    summary: reads the extended stream
    protocol: modbus
    port: 502
    transport: tcp
    risk: caution
    steps:
      - purpose: read
        request: modbus.read-device-identification`,

		"a step with no purpose": `
version: 1
templates:
  - id: modbus-quiet
    summary: reads the identification objects
    protocol: modbus
    port: 502
    transport: tcp
    risk: safe
    steps:
      - request: modbus.read-device-identification`,

		"no steps at all": `
version: 1
templates:
  - id: modbus-nothing
    summary: does nothing
    protocol: modbus
    port: 502
    transport: tcp
    risk: safe`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseTemplates([]byte(raw)); err == nil {
				t.Errorf("a template with %s was accepted", name)
			}
		})
	}
}

// TestSelectingAMisspelledTemplateIsAnError matters more than it looks.
//
// An operator who mistypes a template name and gets a clean run with no findings
// has been told something false about their network.
func TestSelectingAMisspelledTemplateIsAnError(t *testing.T) {
	library := mustLibrary(t)
	if _, err := library.Select([]string{"modbus-device-idd"}); err == nil {
		t.Fatal("a misspelled template name ran as if it were nothing")
	}
	if selected, err := library.Select(nil); err != nil || len(selected) == 0 {
		t.Fatalf("selecting nothing should mean everything, got %d templates and %v", len(selected), err)
	}
}
