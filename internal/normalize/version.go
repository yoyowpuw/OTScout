package normalize

import (
	"fmt"
	"strconv"
	"strings"
)

// Comparator orders two firmware version strings from one vendor.
//
// A separate interface per vendor exists because industrial firmware versions are
// not semantic versions and cannot be compared by a single algorithm. Hitachi
// Energy ships R15A, R15B_PC4 and R16A. Rockwell ships 20.011 and 32.011.
// Siemens ships V4.5 SP2 Update 3. Feeding any of those to a semver parser
// produces either an error or, worse, a confident wrong answer.
type Comparator interface {
	// Name identifies the comparator in the evidence trail.
	Name() string
	// Compare returns -1, 0 or 1. ok is false when the two strings cannot be
	// meaningfully ordered, which the matcher treats as indeterminate rather
	// than guessing.
	Compare(a, b string) (result int, ok bool)
	// Describe explains how the comparator read a version, so the evidence view
	// can show its interpretation next to the raw string.
	Describe(version string) string
}

// tokenKind distinguishes numeric and alphabetic runs in a version string.
type tokenKind int

const (
	tokenNumber tokenKind = iota
	tokenAlpha
)

type token struct {
	kind tokenKind
	num  int
	text string
}

func (t token) String() string {
	if t.kind == tokenNumber {
		return strconv.Itoa(t.num)
	}
	return t.text
}

// tokenizeVersion splits a version into alternating numeric and alphabetic runs,
// discarding separators. A leading v or V is dropped because vendors use it
// inconsistently for the same release.
func tokenizeVersion(version string) []token {
	s := strings.TrimSpace(strings.ToLower(version))
	s = strings.TrimPrefix(s, "version ")
	s = strings.TrimSpace(s)
	if len(s) > 1 && s[0] == 'v' && (s[1] >= '0' && s[1] <= '9') {
		s = s[1:]
	}

	tokens := make([]token, 0, 8)
	idx := 0
	for idx < len(s) {
		c := s[idx]
		switch {
		case c >= '0' && c <= '9':
			start := idx
			for idx < len(s) && s[idx] >= '0' && s[idx] <= '9' {
				idx++
			}
			// Leading zeros carry no ordering information: Rockwell writes the
			// minor as 011, meaning 11.
			value, err := strconv.Atoi(s[start:idx])
			if err != nil {
				// Only reachable for a run longer than an int can hold, which
				// is not a version number.
				return nil
			}
			tokens = append(tokens, token{kind: tokenNumber, num: value})
		case c >= 'a' && c <= 'z':
			start := idx
			for idx < len(s) && s[idx] >= 'a' && s[idx] <= 'z' {
				idx++
			}
			tokens = append(tokens, token{kind: tokenAlpha, text: s[start:idx]})
		default:
			idx++
		}
	}
	return tokens
}

// compareTokens orders two token sequences. It reports ok=false when a numeric
// run has to be compared against an alphabetic one, because there is no honest
// ordering between "sp" and "3".
func compareTokens(a, b []token) (int, bool) {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for idx := 0; idx < limit; idx++ {
		left, right := a[idx], b[idx]
		if left.kind != right.kind {
			return 0, false
		}
		if left.kind == tokenNumber {
			if left.num != right.num {
				return sign(left.num - right.num), true
			}
			continue
		}
		if left.text != right.text {
			return strings.Compare(left.text, right.text), true
		}
	}
	// A shorter version that is otherwise identical is the earlier release:
	// V4.5 precedes V4.5.1, and R15B precedes R15B_PC4.
	return sign(len(a) - len(b)), true
}

func sign(v int) int {
	switch {
	case v < 0:
		return -1
	case v > 0:
		return 1
	default:
		return 0
	}
}

// genericComparator handles the majority of vendors by comparing numeric and
// alphabetic runs positionally.
type genericComparator struct{}

func (genericComparator) Name() string { return "generic" }

func (genericComparator) Compare(a, b string) (int, bool) {
	ta, tb := tokenizeVersion(a), tokenizeVersion(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0, false
	}
	return compareTokens(ta, tb)
}

func (genericComparator) Describe(version string) string {
	tokens := tokenizeVersion(version)
	if len(tokens) == 0 {
		return "no version components could be read"
	}
	parts := make([]string, len(tokens))
	for idx, tk := range tokens {
		parts[idx] = tk.String()
	}
	return "components " + strings.Join(parts, ".")
}

// abbComparator handles the ABB and Hitachi Energy release scheme, where a
// release looks like R15A, R16B or R16B_PC4. The trailing PC number is a patch
// collection and orders after the bare release.
type abbComparator struct{}

func (abbComparator) Name() string { return "abb" }

type abbVersion struct {
	release int
	rev     string
	patch   int
	hasPC   bool
	valid   bool
}

func parseABBVersion(version string) abbVersion {
	tokens := tokenizeVersion(version)
	out := abbVersion{}

	idx := 0
	// An optional leading "r" marks the release in this scheme.
	sawR := idx < len(tokens) && tokens[idx].kind == tokenAlpha && tokens[idx].text == "r"
	if sawR {
		idx++
	}
	if idx >= len(tokens) || tokens[idx].kind != tokenNumber {
		return out
	}
	out.release = tokens[idx].num
	idx++

	if idx < len(tokens) && tokens[idx].kind == tokenAlpha && tokens[idx].text != "pc" {
		out.rev = tokens[idx].text
		idx++
	}
	if idx+1 < len(tokens) && tokens[idx].kind == tokenAlpha && tokens[idx].text == "pc" && tokens[idx+1].kind == tokenNumber {
		out.patch = tokens[idx+1].num
		out.hasPC = true
		idx += 2
	}

	// Every token has to be accounted for, and the string has to actually look
	// like this scheme rather than merely start like it.
	//
	// Without both checks a plain dotted version such as 2.8.0 is read as release
	// 2 with the 8 and the 0 thrown away, which makes it compare equal to 2.5.2
	// and turns an unaffected device into a confirmed finding. Vendors that use
	// this scheme for some products use ordinary dotted versions for others, so
	// this is not a hypothetical: ABB publishes both. Anything outside the scheme
	// is left to the generic comparator, which can order it correctly.
	if idx != len(tokens) || (!sawR && out.rev == "") {
		return abbVersion{}
	}
	out.valid = true
	return out
}

func (c abbComparator) Compare(a, b string) (int, bool) {
	va, vb := parseABBVersion(a), parseABBVersion(b)
	if !va.valid || !vb.valid {
		return genericComparator{}.Compare(a, b)
	}
	if va.release != vb.release {
		return sign(va.release - vb.release), true
	}
	if va.rev != vb.rev {
		return strings.Compare(va.rev, vb.rev), true
	}
	return sign(va.patch - vb.patch), true
}

func (c abbComparator) Describe(version string) string {
	v := parseABBVersion(version)
	if !v.valid {
		return genericComparator{}.Describe(version)
	}
	desc := fmt.Sprintf("release %d", v.release)
	if v.rev != "" {
		desc += fmt.Sprintf(", revision %s", strings.ToUpper(v.rev))
	}
	if v.hasPC {
		desc += fmt.Sprintf(", patch collection %d", v.patch)
	} else {
		desc += ", no patch collection"
	}
	return desc
}

// siemensComparator handles the Siemens scheme, which appends service pack and
// update counters after a dotted version, as in V4.5 SP2 Update 3.
type siemensComparator struct{}

func (siemensComparator) Name() string { return "siemens" }

// siemensVersion flattens a Siemens version into a comparable vector. Absent
// service pack and update counters become zero, which is correct: V4.5 is the
// release before V4.5 SP1.
type siemensVersion struct {
	parts  []int
	sp     int
	update int
	valid  bool
}

func parseSiemensVersion(version string) siemensVersion {
	tokens := tokenizeVersion(version)
	out := siemensVersion{}

	idx := 0
	for idx < len(tokens) && tokens[idx].kind == tokenNumber {
		out.parts = append(out.parts, tokens[idx].num)
		idx++
	}
	if len(out.parts) == 0 {
		return out
	}
	out.valid = true

	for idx < len(tokens) {
		if tokens[idx].kind != tokenAlpha {
			idx++
			continue
		}
		label := tokens[idx].text
		value := 0
		if idx+1 < len(tokens) && tokens[idx+1].kind == tokenNumber {
			value = tokens[idx+1].num
			idx++
		}
		switch label {
		case "sp", "servicepack":
			out.sp = value
		case "update", "upd":
			out.update = value
		}
		idx++
	}
	return out
}

func (c siemensComparator) Compare(a, b string) (int, bool) {
	va, vb := parseSiemensVersion(a), parseSiemensVersion(b)
	if !va.valid || !vb.valid {
		return genericComparator{}.Compare(a, b)
	}
	limit := len(va.parts)
	if len(vb.parts) < limit {
		limit = len(vb.parts)
	}
	for idx := 0; idx < limit; idx++ {
		if va.parts[idx] != vb.parts[idx] {
			return sign(va.parts[idx] - vb.parts[idx]), true
		}
	}
	if len(va.parts) != len(vb.parts) {
		return sign(len(va.parts) - len(vb.parts)), true
	}
	if va.sp != vb.sp {
		return sign(va.sp - vb.sp), true
	}
	return sign(va.update - vb.update), true
}

func (c siemensComparator) Describe(version string) string {
	v := parseSiemensVersion(version)
	if !v.valid {
		return genericComparator{}.Describe(version)
	}
	parts := make([]string, len(v.parts))
	for idx, num := range v.parts {
		parts[idx] = strconv.Itoa(num)
	}
	desc := "version " + strings.Join(parts, ".")
	if v.sp > 0 {
		desc += fmt.Sprintf(", service pack %d", v.sp)
	}
	if v.update > 0 {
		desc += fmt.Sprintf(", update %d", v.update)
	}
	return desc
}

// rockwellComparator handles the Rockwell major.minor scheme, where the minor is
// written with leading zeros as in 20.011.
type rockwellComparator struct{}

func (rockwellComparator) Name() string { return "rockwell" }

func (rockwellComparator) Compare(a, b string) (int, bool) {
	ta, tb := tokenizeVersion(a), tokenizeVersion(b)
	if len(ta) == 0 || len(tb) == 0 {
		return 0, false
	}
	// Rockwell versions are purely numeric once the optional v prefix is gone.
	for _, tk := range append(append([]token{}, ta...), tb...) {
		if tk.kind != tokenNumber {
			return genericComparator{}.Compare(a, b)
		}
	}
	return compareTokens(ta, tb)
}

func (rockwellComparator) Describe(version string) string {
	tokens := tokenizeVersion(version)
	if len(tokens) < 2 || tokens[0].kind != tokenNumber || tokens[1].kind != tokenNumber {
		return genericComparator{}.Describe(version)
	}
	desc := fmt.Sprintf("major %d, minor %d", tokens[0].num, tokens[1].num)
	if len(tokens) > 2 && tokens[2].kind == tokenNumber {
		desc += fmt.Sprintf(", build %d", tokens[2].num)
	}
	return desc
}

var comparators = map[string]Comparator{
	"generic":  genericComparator{},
	"abb":      abbComparator{},
	"siemens":  siemensComparator{},
	"rockwell": rockwellComparator{},
}

// ComparatorFor returns the comparator for a scheme name, falling back to the
// generic one. An unknown scheme is not an error, because a vendor entry may name
// a comparator that a future release adds.
func ComparatorFor(scheme string) Comparator {
	if cmp, ok := comparators[scheme]; ok {
		return cmp
	}
	return comparators["generic"]
}

// ComparatorForVendor picks the comparator configured for a vendor id.
func (t *VendorTable) ComparatorForVendor(vendorID string) Comparator {
	return ComparatorFor(t.VersionSchemeFor(vendorID))
}

// ComparatorNames lists the registered schemes, used by the templates command.
func ComparatorNames() []string {
	names := make([]string, 0, len(comparators))
	for name := range comparators {
		names = append(names, name)
	}
	return names
}
