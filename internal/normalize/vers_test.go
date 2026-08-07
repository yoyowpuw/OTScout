package normalize

import "testing"

func TestParseConstraintReadsVERSRanges(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		kind  ConstraintKind
		lower string
		upper string
		lowIn bool
		upIn  bool
	}{
		{
			// This is what most of the CISA corpus now looks like. Reading it as
			// an unparsed range would leave the matcher mute about most advisories.
			name: "every version", raw: "vers:all/*", kind: ConstraintAll,
		},
		{name: "upper exclusive", raw: "vers:generic/<2.9.2", kind: ConstraintLT, upper: "2.9.2"},
		{name: "upper inclusive", raw: "vers:generic/<=2.9.2", kind: ConstraintLTE, upper: "2.9.2", upIn: true},
		{name: "lower exclusive", raw: "vers:generic/>1.0", kind: ConstraintGT, lower: "1.0"},
		{name: "lower inclusive", raw: "vers:generic/>=1.0", kind: ConstraintGTE, lower: "1.0", lowIn: true},
		{name: "explicit equality", raw: "vers:generic/=4.5", kind: ConstraintEQ, lower: "4.5", upper: "4.5", lowIn: true, upIn: true},
		{name: "bare version means equality", raw: "vers:generic/4.5", kind: ConstraintEQ, lower: "4.5", upper: "4.5", lowIn: true, upIn: true},
		{
			name: "half open interval", raw: "vers:semver/>=1.0.0|<2.0.0",
			kind: ConstraintBetween, lower: "1.0.0", upper: "2.0.0", lowIn: true,
		},
		{
			// The order the publisher wrote the two bounds in carries no meaning,
			// so reading them the wrong way round would invert the range.
			name: "bounds written upper first", raw: "vers:semver/<2.0.0|>=1.0.0",
			kind: ConstraintBetween, lower: "1.0.0", upper: "2.0.0", lowIn: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseConstraint(tc.raw)
			if got.Kind != tc.kind {
				t.Fatalf("kind = %q, want %q", got.Kind, tc.kind)
			}
			if got.Lower != tc.lower || got.Upper != tc.upper {
				t.Errorf("bounds = %q..%q, want %q..%q", got.Lower, got.Upper, tc.lower, tc.upper)
			}
			if got.LowerInclusive != tc.lowIn || got.UpperInclusive != tc.upIn {
				t.Errorf("inclusivity = %v/%v, want %v/%v",
					got.LowerInclusive, got.UpperInclusive, tc.lowIn, tc.upIn)
			}
			if got.Raw != tc.raw {
				t.Errorf("raw = %q, the original text must survive for the evidence view", got.Raw)
			}
		})
	}
}

func TestParseConstraintRefusesVERSFormsItCannotHold(t *testing.T) {
	// Each of these is more expressive than the Constraint model. Approximating
	// one produces a confident wrong answer about whether a plant device is
	// vulnerable, which is worse than admitting the range was not understood.
	for _, raw := range []string{
		"vers:generic/!=1.2.3",
		"vers:semver/>=1.0.0|<2.0.0|>=3.0.0",
		"vers:semver/>=1.0.0|!=1.5.0",
		"vers:generic/",
		"vers:generic",
		"vers:generic/<",
		"vers:semver/<1.0.0|<2.0.0",
	} {
		if got := ParseConstraint(raw); got.Kind != ConstraintUnknown {
			t.Errorf("%q parsed as %q, want it refused", raw, got.Kind)
		}
	}
}

func TestVERSEvaluatesAgainstAFirmwareStringOffTheWire(t *testing.T) {
	c := ParseConstraint("vers:generic/<2.9.2")
	cmp := ComparatorFor("generic")

	if eval := c.Evaluate("2.8.1", cmp); eval.Result != EvalAffected {
		t.Errorf("2.8.1 gave %q, want affected: %s", eval.Result, eval.Explanation)
	}
	if eval := c.Evaluate("2.9.2", cmp); eval.Result != EvalNotAffected {
		t.Errorf("2.9.2 gave %q, want not affected: %s", eval.Result, eval.Explanation)
	}

	all := ParseConstraint("vers:all/*")
	if eval := all.Evaluate("anything", cmp); eval.Result != EvalAffected {
		t.Errorf("a vers:all range gave %q, want affected", eval.Result)
	}
}

func TestParseConstraintReadsTheLabelledFirmwareStringsAdvisoriesActuallyCarry(t *testing.T) {
	// Every one of these came out of the CISA corpus. A vendor writing its
	// firmware as T_45.8.0.3-r9 is not a malformed range, it is how that vendor
	// prints a version, and refusing it costs real coverage.
	cases := []struct {
		raw   string
		kind  ConstraintKind
		upper string
	}{
		{"<=T_45.8.0.3-r9", ConstraintLTE, "t_45.8.0.3-r9"},
		{"<=T_61.8.0.4_LPR-r3", ConstraintLTE, "t_61.8.0.4_lpr-r3"},
		{"<firmware_2.4.2.157", ConstraintLT, "firmware_2.4.2.157"},
		{"<=Ver.2.60", ConstraintLTE, "ver.2.60"},
		{"<=FX_14.10.10", ConstraintLTE, "fx_14.10.10"},
		{"<2.9.2", ConstraintLT, "2.9.2"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got := ParseConstraint(tc.raw)
			if got.Kind != tc.kind || got.Upper != tc.upper {
				t.Errorf("got %q upper %q, want %q upper %q", got.Kind, got.Upper, tc.kind, tc.upper)
			}
		})
	}
}

func TestParseConstraintRefusesARevisionLetterWithNoOrdering(t *testing.T) {
	// "<=LG" is a hardware revision letter. There is no ordering this tool can
	// defend for it, so claiming one would be inventing an answer.
	for _, raw := range []string{"<=LG", "<=FM", "<=BB", "<TLS_"} {
		if got := ParseConstraint(raw); got.Kind != ConstraintUnknown {
			t.Errorf("%q parsed as %q with upper %q, want it refused", raw, got.Kind, got.Upper)
		}
	}
}

func TestParseConstraintLeavesNonVERSStringsToThePhraseParser(t *testing.T) {
	// The VERS check runs first, so it has to keep its hands off anything that
	// only looks a little like it.
	got := ParseConstraint("versions prior to 4.5")
	if got.Kind != ConstraintLT || got.Upper != "4.5" {
		t.Errorf("got %q %q, want a plain upper bound", got.Kind, got.Upper)
	}
}
