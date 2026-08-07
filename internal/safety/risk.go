package safety

import "fmt"

// Risk is how much trouble a probe is thought to be capable of causing.
//
// The rating lives on the template rather than in this package, so the judgement
// travels with the probe and can be revised by whoever learns something new about
// a device family. What lives here is the ordering and the refusal to run
// anything the operator did not ask for.
type Risk string

const (
	// RiskSafe is a standard identification request that the protocol defines
	// for this purpose, widely implemented, with no known adverse reports.
	RiskSafe Risk = "safe"

	// RiskCaution is a legitimate read that some implementations handle poorly.
	//
	// The usual shape of this is a request that is correct by the specification
	// and that a particular vendor's stack answers badly, which is common enough
	// in this field that it needs its own tier rather than a footnote.
	RiskCaution Risk = "caution"

	// RiskLabOnly is useful for research and not appropriate for production
	// equipment.
	RiskLabOnly Risk = "lab-only"
)

// riskOrder ranks the tiers. Anything not listed is not a rating.
var riskOrder = map[Risk]int{
	RiskSafe:    0,
	RiskCaution: 1,
	RiskLabOnly: 2,
}

// Risks lists the tiers from least to most dangerous, for help text and for
// tests that must cover all of them.
func Risks() []Risk { return []Risk{RiskSafe, RiskCaution, RiskLabOnly} }

// Validate rejects a rating this package does not define.
//
// An unrecognised rating is refused rather than treated as the most dangerous
// tier. Both are safe, but refusing says plainly that a template is malformed,
// where silently demoting it would let a typo sit in the library looking like a
// deliberate choice.
func (r Risk) Validate() error {
	if _, ok := riskOrder[r]; !ok {
		return fmt.Errorf("risk rating %q is not one of %v", r, Risks())
	}
	return nil
}

// AtMost reports whether r is within the ceiling the operator allowed.
func (r Risk) AtMost(ceiling Risk) bool {
	mine, ok := riskOrder[r]
	if !ok {
		return false
	}
	limit, ok := riskOrder[ceiling]
	if !ok {
		return false
	}
	return mine <= limit
}

// ParseRisk reads a rating from a command line flag.
func ParseRisk(raw string) (Risk, error) {
	r := Risk(raw)
	if err := r.Validate(); err != nil {
		return "", err
	}
	return r, nil
}
