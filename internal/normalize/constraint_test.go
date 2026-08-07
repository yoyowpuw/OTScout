package normalize

import "testing"

func TestParseConstraintOperatorForms(t *testing.T) {
	cases := []struct {
		raw            string
		kind           ConstraintKind
		lower, upper   string
		lowerInc, upIn bool
	}{
		{raw: "<R15A", kind: ConstraintLT, upper: "r15a"},
		{raw: "< V4.5", kind: ConstraintLT, upper: "v4.5"},
		{raw: "<=1.2.3", kind: ConstraintLTE, upper: "1.2.3", upIn: true},
		{raw: ">2.0", kind: ConstraintGT, lower: "2.0"},
		{raw: ">=2.0", kind: ConstraintGTE, lower: "2.0", lowerInc: true},
		{raw: "=3.1", kind: ConstraintEQ, lower: "3.1", upper: "3.1", lowerInc: true, upIn: true},
		{raw: ">=2.0 <3.0", kind: ConstraintBetween, lower: "2.0", upper: "3.0", lowerInc: true},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got := ParseConstraint(tc.raw)
			if got.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", got.Kind, tc.kind)
			}
			if got.Lower != tc.lower {
				t.Errorf("Lower = %q, want %q", got.Lower, tc.lower)
			}
			if got.Upper != tc.upper {
				t.Errorf("Upper = %q, want %q", got.Upper, tc.upper)
			}
			if got.LowerInclusive != tc.lowerInc {
				t.Errorf("LowerInclusive = %v, want %v", got.LowerInclusive, tc.lowerInc)
			}
			if got.UpperInclusive != tc.upIn {
				t.Errorf("UpperInclusive = %v, want %v", got.UpperInclusive, tc.upIn)
			}
		})
	}
}

func TestParseConstraintPhraseForms(t *testing.T) {
	cases := []struct {
		raw   string
		kind  ConstraintKind
		lower string
		upper string
	}{
		{"All versions prior to 4.5", ConstraintLT, "", "4.5"},
		{"versions before V2.9.4", ConstraintLT, "", "v2.9.4"},
		{"earlier than R15A", ConstraintLT, "", "r15a"},
		{"up to and including 2.5", ConstraintLTE, "", "2.5"},
		{"3.1 and prior", ConstraintLTE, "", "3.1"},
		{"3.1 or earlier", ConstraintLTE, "", "3.1"},
		{"2.0 and later", ConstraintGTE, "2.0", ""},
		{"2.0 or newer", ConstraintGTE, "2.0", ""},
		{"all versions after 7.0", ConstraintGT, "7.0", ""},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			got := ParseConstraint(tc.raw)
			if got.Kind != tc.kind {
				t.Fatalf("Kind = %q, want %q", got.Kind, tc.kind)
			}
			if got.Lower != tc.lower {
				t.Errorf("Lower = %q, want %q", got.Lower, tc.lower)
			}
			if got.Upper != tc.upper {
				t.Errorf("Upper = %q, want %q", got.Upper, tc.upper)
			}
		})
	}
}

func TestParseConstraintRangeForms(t *testing.T) {
	for _, raw := range []string{"V1.0 to V2.0", "between 1.0 and 2.0", "1.0 - 2.0", "1.0 through 2.0"} {
		t.Run(raw, func(t *testing.T) {
			got := ParseConstraint(raw)
			if got.Kind != ConstraintBetween {
				t.Fatalf("Kind = %q, want between", got.Kind)
			}
			if got.Lower == "" || got.Upper == "" {
				t.Errorf("both bounds must be set, got %+v", got)
			}
			if !got.LowerInclusive || !got.UpperInclusive {
				t.Error("a stated range is inclusive at both ends")
			}
		})
	}
}

func TestParseConstraintAllAndWildcard(t *testing.T) {
	if got := ParseConstraint("All versions"); got.Kind != ConstraintAll {
		t.Errorf("All versions -> %q, want all", got.Kind)
	}
	if got := ParseConstraint("all"); got.Kind != ConstraintAll {
		t.Errorf("all -> %q, want all", got.Kind)
	}
	got := ParseConstraint("2.1.x")
	if got.Kind != ConstraintPrefix || got.Prefix != "2.1" {
		t.Errorf("2.1.x -> kind %q prefix %q, want prefix 2.1", got.Kind, got.Prefix)
	}
}

func TestParseConstraintBareVersionIsEquality(t *testing.T) {
	got := ParseConstraint("R16B_PC4")
	if got.Kind != ConstraintEQ {
		t.Fatalf("Kind = %q, want eq", got.Kind)
	}
	if got.Lower != "r16b_pc4" {
		t.Errorf("Lower = %q", got.Lower)
	}
}

func TestParseConstraintUnknownStaysUnknown(t *testing.T) {
	// Inventing an interpretation here would produce fabricated findings, so
	// anything unrecognised has to stay unknown.
	for _, raw := range []string{"", "see vendor advisory", "contact support"} {
		if got := ParseConstraint(raw); got.Kind != ConstraintUnknown {
			t.Errorf("ParseConstraint(%q) = %q, want unknown", raw, got.Kind)
		}
	}
}

func TestEvaluateFoxmanScenario(t *testing.T) {
	// The advisory that motivated this project: Hitachi Energy FOXMAN-UN with a
	// product_version_range of "<R15A", against devices reporting the ABB
	// release scheme.
	constraint := ParseConstraint("<R15A")
	cmp := ComparatorFor("abb")

	cases := []struct {
		version string
		want    EvalResult
	}{
		{"R14B", EvalAffected},
		{"R14B_PC2", EvalAffected},
		{"R15A", EvalNotAffected},
		{"R15B", EvalNotAffected},
		{"R16B_PC4", EvalNotAffected},
	}
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			eval := constraint.Evaluate(tc.version, cmp)
			if eval.Result != tc.want {
				t.Errorf("Evaluate(%q) = %q, want %q (%s)", tc.version, eval.Result, tc.want, eval.Explanation)
			}
			if eval.Explanation == "" {
				t.Error("every evaluation must explain itself")
			}
			if eval.Comparator != "abb" {
				t.Errorf("Comparator = %q, want abb", eval.Comparator)
			}
		})
	}
}

func TestEvaluateUnknownFirmwareIsIndeterminate(t *testing.T) {
	// Claiming either answer without a firmware version would be fabrication.
	eval := ParseConstraint("<R15A").Evaluate("", ComparatorFor("abb"))
	if eval.Result != EvalIndeterminate {
		t.Fatalf("Result = %q, want indeterminate", eval.Result)
	}
	if eval.Explanation == "" {
		t.Error("the explanation must say why it could not be decided")
	}
}

func TestEvaluateUnparseableRangeIsIndeterminate(t *testing.T) {
	eval := ParseConstraint("see vendor advisory").Evaluate("4.5", ComparatorFor("generic"))
	if eval.Result != EvalIndeterminate {
		t.Errorf("Result = %q, want indeterminate", eval.Result)
	}
}

func TestEvaluateAllVersionsAffectsEverything(t *testing.T) {
	eval := ParseConstraint("All versions").Evaluate("9.9.9", ComparatorFor("generic"))
	if eval.Result != EvalAffected {
		t.Errorf("Result = %q, want affected", eval.Result)
	}
}

func TestEvaluateBetweenBounds(t *testing.T) {
	constraint := ParseConstraint(">=2.0 <3.0")
	cmp := ComparatorFor("generic")
	cases := map[string]EvalResult{
		"1.9":   EvalNotAffected,
		"2.0":   EvalAffected,
		"2.5":   EvalAffected,
		"2.9.9": EvalAffected,
		"3.0":   EvalNotAffected,
		"3.1":   EvalNotAffected,
	}
	for version, want := range cases {
		if got := constraint.Evaluate(version, cmp); got.Result != want {
			t.Errorf("Evaluate(%q) = %q, want %q (%s)", version, got.Result, want, got.Explanation)
		}
	}
}

func TestEvaluatePrefixMatchesReleaseLine(t *testing.T) {
	constraint := ParseConstraint("2.1.x")
	cmp := ComparatorFor("generic")
	if got := constraint.Evaluate("2.1.4", cmp); got.Result != EvalAffected {
		t.Errorf("2.1.4 should be in the 2.1 line, got %q", got.Result)
	}
	// A prefix compare must be token aware so that 2.10 is not read as 2.1.
	if got := constraint.Evaluate("2.10.0", cmp); got.Result != EvalNotAffected {
		t.Errorf("2.10.0 must not match the 2.1 line, got %q", got.Result)
	}
}

func TestEvaluateIncomparablePairIsIndeterminate(t *testing.T) {
	eval := ParseConstraint("<3.0").Evaluate("build alpha", ComparatorFor("generic"))
	if eval.Result != EvalIndeterminate {
		t.Errorf("Result = %q, want indeterminate", eval.Result)
	}
}

func TestConstraintDescribeIsReadable(t *testing.T) {
	cases := map[string]string{
		"<R15A":        "versions below r15a",
		"<=2.5":        "versions up to and including 2.5",
		">=2.0":        "versions from 2.0 onward",
		"All versions": "all versions",
	}
	for raw, want := range cases {
		if got := ParseConstraint(raw).Describe(); got != want {
			t.Errorf("Describe(%q) = %q, want %q", raw, got, want)
		}
	}
}
