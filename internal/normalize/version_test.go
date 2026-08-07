package normalize

import "testing"

func TestGenericComparatorOrdering(t *testing.T) {
	cmp := ComparatorFor("generic")
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"1.2", "1.10", -1},
		{"V4.5", "V4.5.1", -1},
		{"v4.5.1", "4.5.1", 0},
		{"4.5", "4.5.0", -1},
		// Rockwell writes the minor with leading zeros, so 20.011 is 20.11 and
		// must not be read as 20.011 being smaller than 20.11.
		{"20.011", "20.11", 0},
		{"20.011", "20.012", -1},
		{"32.011", "20.011", 1},
	}
	for _, tc := range cases {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			got, ok := cmp.Compare(tc.a, tc.b)
			if !ok {
				t.Fatalf("Compare(%q, %q) reported indeterminate", tc.a, tc.b)
			}
			if got != tc.want {
				t.Errorf("Compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestGenericComparatorReportsIndeterminate(t *testing.T) {
	cmp := ComparatorFor("generic")
	// A numeric run has no honest ordering against an alphabetic one.
	if _, ok := cmp.Compare("1.a", "1.2"); ok {
		t.Error("comparing an alpha run against a numeric run must be indeterminate")
	}
	if _, ok := cmp.Compare("", "1.0"); ok {
		t.Error("an empty version must be indeterminate")
	}
	if _, ok := cmp.Compare("no digits here", "1.0"); ok {
		t.Error("a string with no version components must be indeterminate")
	}
}

func TestABBComparatorLeavesOrdinaryDottedVersionsToTheGenericOne(t *testing.T) {
	// ABB publishes both schemes. Reading 2.8.0 as release 2 with the rest thrown
	// away made it compare equal to 2.5.2, which turned an unaffected AC500 into a
	// confirmed finding against an advisory covering versions up to 2.5.2.
	cmp := ComparatorFor("abb")
	result, ok := cmp.Compare("2.8.0", "2.5.2")
	if !ok {
		t.Fatal("two dotted versions must be comparable")
	}
	if result <= 0 {
		t.Errorf("Compare(2.8.0, 2.5.2) = %d, want it greater", result)
	}

	if eval := ParseConstraint("<=2.5.2").Evaluate("2.8.0", cmp); eval.Result != EvalNotAffected {
		t.Errorf("2.8.0 against <=2.5.2 = %q, want not_affected: %s", eval.Result, eval.Explanation)
	}
}

func TestABBComparatorRejectsAStringWithTokensItCannotAccountFor(t *testing.T) {
	// A version this scheme only half understands is more dangerous than one it
	// rejects outright, because the discarded half is where the ordering lives.
	for _, version := range []string{"2.8.0", "1.2.3.4", "4.5 SP2", "20.011"} {
		if parseABBVersion(version).valid {
			t.Errorf("parseABBVersion(%q) claimed the ABB scheme", version)
		}
	}
	for _, version := range []string{"R15A", "R16B_PC4", "15A", "R14"} {
		if !parseABBVersion(version).valid {
			t.Errorf("parseABBVersion(%q) did not recognise the ABB scheme", version)
		}
	}
}

func TestABBComparatorHandlesReleaseAndPatchCollection(t *testing.T) {
	cmp := ComparatorFor("abb")
	// This is the exact ordering from the Hitachi Energy FOXMAN-UN advisory that
	// motivated the project: R15A, R15B, R15B_PC4, R16A, R16B, R16B_PC2.
	ordered := []string{"R15A", "R15B", "R15B_PC4", "R15B_PC5", "R16A", "R16B", "R16B_PC2", "R16B_PC3"}
	for idx := 0; idx+1 < len(ordered); idx++ {
		a, b := ordered[idx], ordered[idx+1]
		got, ok := cmp.Compare(a, b)
		if !ok {
			t.Fatalf("Compare(%q, %q) reported indeterminate", a, b)
		}
		if got != -1 {
			t.Errorf("Compare(%q, %q) = %d, want -1", a, b, got)
		}
	}
}

func TestABBComparatorEquality(t *testing.T) {
	cmp := ComparatorFor("abb")
	if got, ok := cmp.Compare("R16B_PC4", "R16B_PC4"); !ok || got != 0 {
		t.Errorf("identical releases must compare equal, got %d ok=%v", got, ok)
	}
	// A bare release precedes any patch collection on top of it.
	if got, ok := cmp.Compare("R16B", "R16B_PC1"); !ok || got != -1 {
		t.Errorf("Compare(R16B, R16B_PC1) = %d ok=%v, want -1", got, ok)
	}
}

func TestABBComparatorDescribeExplainsTheScheme(t *testing.T) {
	desc := ComparatorFor("abb").Describe("R16B_PC4")
	want := "release 16, revision B, patch collection 4"
	if desc != want {
		t.Errorf("Describe(R16B_PC4) = %q, want %q", desc, want)
	}
}

func TestSiemensComparatorHandlesServicePackAndUpdate(t *testing.T) {
	cmp := ComparatorFor("siemens")
	ordered := []string{"V4.5", "V4.5 SP1", "V4.5 SP2", "V4.5 SP2 Update 1", "V4.5 SP2 Update 3", "V4.6"}
	for idx := 0; idx+1 < len(ordered); idx++ {
		a, b := ordered[idx], ordered[idx+1]
		got, ok := cmp.Compare(a, b)
		if !ok {
			t.Fatalf("Compare(%q, %q) reported indeterminate", a, b)
		}
		if got != -1 {
			t.Errorf("Compare(%q, %q) = %d, want -1", a, b, got)
		}
	}
}

func TestSiemensComparatorDescribe(t *testing.T) {
	desc := ComparatorFor("siemens").Describe("V4.5 SP2 Update 3")
	want := "version 4.5, service pack 2, update 3"
	if desc != want {
		t.Errorf("Describe = %q, want %q", desc, want)
	}
}

func TestRockwellComparatorNumericOnly(t *testing.T) {
	cmp := ComparatorFor("rockwell")
	if got, ok := cmp.Compare("20.011", "32.011"); !ok || got != -1 {
		t.Errorf("Compare(20.011, 32.011) = %d ok=%v, want -1", got, ok)
	}
	desc := cmp.Describe("20.011")
	if desc != "major 20, minor 11" {
		t.Errorf("Describe(20.011) = %q", desc)
	}
}

func TestComparatorForFallsBackToGeneric(t *testing.T) {
	if got := ComparatorFor("a scheme from the future").Name(); got != "generic" {
		t.Errorf("unknown scheme should fall back to generic, got %q", got)
	}
	if got := ComparatorFor("").Name(); got != "generic" {
		t.Errorf("empty scheme should fall back to generic, got %q", got)
	}
}

func TestTokenizeVersionDropsPrefixAndSeparators(t *testing.T) {
	tokens := tokenizeVersion("V4.5 SP2")
	if len(tokens) != 4 {
		t.Fatalf("expected 4 tokens, got %d: %v", len(tokens), tokens)
	}
	if tokens[0].kind != tokenNumber || tokens[0].num != 4 {
		t.Errorf("first token = %v, want number 4", tokens[0])
	}
	if tokens[2].kind != tokenAlpha || tokens[2].text != "sp" {
		t.Errorf("third token = %v, want alpha sp", tokens[2])
	}
}
