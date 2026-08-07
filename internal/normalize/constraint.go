package normalize

import (
	"fmt"
	"regexp"
	"strings"
)

// ConstraintKind is the shape of a parsed version range.
type ConstraintKind string

const (
	// ConstraintAll covers advisories that name no version at all, which in
	// practice means every version is affected.
	ConstraintAll ConstraintKind = "all"
	// ConstraintEQ is a single product_version node rather than a range.
	ConstraintEQ ConstraintKind = "eq"
	// ConstraintPrefix covers wildcard forms such as 2.1.x.
	ConstraintPrefix  ConstraintKind = "prefix"
	ConstraintLT      ConstraintKind = "lt"
	ConstraintLTE     ConstraintKind = "lte"
	ConstraintGT      ConstraintKind = "gt"
	ConstraintGTE     ConstraintKind = "gte"
	ConstraintBetween ConstraintKind = "between"
	// ConstraintUnknown means the string could not be understood. The matcher
	// treats this as indeterminate and says so, rather than assuming either
	// answer.
	ConstraintUnknown ConstraintKind = "unknown"
)

// Constraint is a parsed CSAF version range.
//
// CSAF puts these strings in product_version_range nodes with no grammar, so the
// corpus contains everything from "<R15A" to "All versions prior to 4.5" to
// "V1.0 to V2.0". This parser covers the forms actually observed and reports
// ConstraintUnknown for anything else instead of guessing.
type Constraint struct {
	Raw            string         `json:"raw"`
	Kind           ConstraintKind `json:"kind"`
	Lower          string         `json:"lower,omitempty"`
	LowerInclusive bool           `json:"lower_inclusive,omitempty"`
	Upper          string         `json:"upper,omitempty"`
	UpperInclusive bool           `json:"upper_inclusive,omitempty"`
	Prefix         string         `json:"prefix,omitempty"`
}

// versionToken matches a version-looking run: an optional letter prefix such as
// the V in V4.5 or the R in R15A, then at least one digit.
var versionToken = regexp.MustCompile(`[a-z]*[0-9][0-9a-z._\-]*`)

// operatorPair matches an explicit comparison operator and the value after it.
//
// The value is matched loosely, allowing the label prefixes vendors attach to a
// firmware string: real advisories carry "<=T_45.8.0.3-r9" and
// "<firmware_2.4.2.157" as well as plain "<2.9.2". Requiring a bare number here
// would leave those unparsed, so the shape is checked afterwards instead, by
// insisting the value contain a digit. That rejects "<=LG", which is a hardware
// revision letter with no ordering this tool can defend.
var operatorPair = regexp.MustCompile(`(<=|>=|==|<|>|=)\s*([a-z][0-9a-z._\-]*[0-9][0-9a-z._\-]*|[0-9][0-9a-z._\-]*)`)

// Phrase rules are grouped by where the version sits relative to the phrase.
// "prior to 4.5" puts it after, while "4.5 and prior" puts it before, and
// reading the wrong side inverts the constraint.
//
// Within each group longer phrases come first, because a shorter phrase is often
// a substring of a longer one with the opposite meaning: "up to but not
// including" must never be matched as "up to".
var (
	// Version follows the phrase, exclusive upper bound.
	upperExclusiveAfter = []string{
		"up to but not including",
		"all versions prior to",
		"all versions before",
		"all versions earlier than",
		"versions prior to",
		"versions before",
		"earlier than",
		"older than",
		"prior to",
		"before",
	}
	// Version follows the phrase, inclusive upper bound.
	upperInclusiveAfter = []string{
		"up to and including",
		"through",
		"up to",
	}
	// Version precedes the phrase, inclusive upper bound.
	upperInclusiveBefore = []string{
		"and all prior versions",
		"and prior versions",
		"and earlier versions",
		"and prior",
		"and earlier",
		"and below",
		"and older",
		"or earlier",
		"or below",
		"or older",
	}
	// Version follows the phrase, exclusive lower bound.
	lowerExclusiveAfter = []string{
		"all versions after",
		"versions after",
		"later than",
		"newer than",
		"after",
	}
	// Version precedes the phrase, inclusive lower bound.
	lowerInclusiveBefore = []string{
		"and later versions",
		"and newer versions",
		"and subsequent versions",
		"and later",
		"and above",
		"and newer",
		"and subsequent",
		"or later",
		"or above",
		"or newer",
	}
)

// ParseConstraint reads a CSAF version range string.
func ParseConstraint(raw string) Constraint {
	c := Constraint{Raw: raw, Kind: ConstraintUnknown}

	text := strings.ToLower(strings.TrimSpace(raw))
	text = strings.Join(strings.Fields(text), " ")
	if text == "" {
		return c
	}

	// VERS is checked first because it has an actual grammar. Letting the phrase
	// parser near it would strip the scheme and read the remainder as prose.
	if versConstraint, ok := parseVERS(text); ok {
		return withRaw(versConstraint, raw)
	}

	// Explicit operators are unambiguous, so they win over phrase matching.
	if pairs := operatorPair.FindAllStringSubmatch(text, -1); len(pairs) > 0 {
		return constraintFromOperators(c, pairs)
	}

	// Wildcards such as 2.1.x describe a release line.
	if prefix, ok := wildcardPrefix(text); ok {
		c.Kind = ConstraintPrefix
		c.Prefix = prefix
		return c
	}

	// "all versions" with no version token means everything is affected.
	tokens := versionToken.FindAllString(text, -1)
	if strings.Contains(text, "all versions") && len(tokens) == 0 {
		c.Kind = ConstraintAll
		return c
	}
	if len(tokens) == 0 {
		if text == "all" || text == "any" || text == "*" {
			c.Kind = ConstraintAll
		}
		return c
	}

	// Two versions joined by a range word describe an interval.
	if rangeConstraint, ok := constraintFromRangePhrase(text); ok {
		return withRaw(rangeConstraint, raw)
	}

	// Exclusive bounds are checked before inclusive ones, because
	// "up to but not including" contains the inclusive phrase "up to".
	for _, phrase := range upperExclusiveAfter {
		if version, ok := versionAfterPhrase(text, phrase); ok {
			c.Kind = ConstraintLT
			c.Upper = version
			return c
		}
	}
	for _, phrase := range lowerExclusiveAfter {
		if version, ok := versionAfterPhrase(text, phrase); ok {
			c.Kind = ConstraintGT
			c.Lower = version
			return c
		}
	}
	for _, phrase := range upperInclusiveAfter {
		if version, ok := versionAfterPhrase(text, phrase); ok {
			c.Kind = ConstraintLTE
			c.Upper = version
			c.UpperInclusive = true
			return c
		}
	}
	for _, phrase := range upperInclusiveBefore {
		if version, ok := versionBeforePhrase(text, phrase); ok {
			c.Kind = ConstraintLTE
			c.Upper = version
			c.UpperInclusive = true
			return c
		}
	}
	for _, phrase := range lowerInclusiveBefore {
		if version, ok := versionBeforePhrase(text, phrase); ok {
			c.Kind = ConstraintGTE
			c.Lower = version
			c.LowerInclusive = true
			return c
		}
	}

	// A bare version string is a single affected version.
	if len(tokens) == 1 && tokens[0] == text {
		c.Kind = ConstraintEQ
		c.Lower = tokens[0]
		c.Upper = tokens[0]
		c.LowerInclusive = true
		c.UpperInclusive = true
		return c
	}

	return c
}

func withRaw(c Constraint, raw string) Constraint {
	c.Raw = raw
	return c
}

func constraintFromOperators(c Constraint, pairs [][]string) Constraint {
	for _, pair := range pairs {
		op, version := pair[1], pair[2]
		switch op {
		case "<":
			c.Upper, c.UpperInclusive = version, false
		case "<=":
			c.Upper, c.UpperInclusive = version, true
		case ">":
			c.Lower, c.LowerInclusive = version, false
		case ">=":
			c.Lower, c.LowerInclusive = version, true
		case "=", "==":
			c.Lower, c.LowerInclusive = version, true
			c.Upper, c.UpperInclusive = version, true
		}
	}

	switch {
	case c.Lower != "" && c.Upper != "" && c.Lower == c.Upper && c.LowerInclusive && c.UpperInclusive:
		c.Kind = ConstraintEQ
	case c.Lower != "" && c.Upper != "":
		c.Kind = ConstraintBetween
	case c.Upper != "" && c.UpperInclusive:
		c.Kind = ConstraintLTE
	case c.Upper != "":
		c.Kind = ConstraintLT
	case c.Lower != "" && c.LowerInclusive:
		c.Kind = ConstraintGTE
	case c.Lower != "":
		c.Kind = ConstraintGT
	}
	return c
}

var rangeSeparators = []string{" to ", " through ", " until ", " and ", " - ", "-"}

// constraintFromRangePhrase recognises an interval written as two versions joined
// by a range word.
//
// The ordering check at the end is what keeps this honest. A hyphen appears both
// between two versions, as in "1.0 - 2.0", and inside a single version, as in
// "1.0-rc1". Requiring that the left side actually orders below the right side
// separates the two cases without a pile of special rules.
func constraintFromRangePhrase(text string) (Constraint, bool) {
	trimmed := strings.TrimPrefix(text, "between ")

	for _, sep := range rangeSeparators {
		idx := strings.Index(trimmed, sep)
		if idx < 0 {
			continue
		}
		left := lastVersionToken(trimmed[:idx])
		right := versionToken.FindString(trimmed[idx+len(sep):])
		if left == "" || right == "" || left == right {
			continue
		}
		order, ok := genericComparator{}.Compare(left, right)
		if !ok || order >= 0 {
			continue
		}
		return Constraint{
			Kind:           ConstraintBetween,
			Lower:          left,
			LowerInclusive: true,
			Upper:          right,
			UpperInclusive: true,
		}, true
	}
	return Constraint{}, false
}

func lastVersionToken(text string) string {
	matches := versionToken.FindAllString(text, -1)
	if len(matches) == 0 {
		return ""
	}
	return matches[len(matches)-1]
}

func wildcardPrefix(text string) (string, bool) {
	for _, suffix := range []string{".x", ".*", "x", "*"} {
		if !strings.HasSuffix(text, suffix) {
			continue
		}
		head := strings.TrimSuffix(text, suffix)
		head = strings.TrimSuffix(head, ".")
		if head == "" {
			return "", false
		}
		if !strings.ContainsAny(head, "0123456789") {
			return "", false
		}
		// Reject strings that also carry words, since those are phrases rather
		// than wildcards.
		if strings.Contains(head, " ") {
			return "", false
		}
		return head, true
	}
	return "", false
}

func versionAfterPhrase(text, phrase string) (string, bool) {
	idx := strings.Index(text, phrase)
	if idx < 0 {
		return "", false
	}
	rest := text[idx+len(phrase):]
	version := versionToken.FindString(rest)
	if version == "" {
		return "", false
	}
	return version, true
}

func versionBeforePhrase(text, phrase string) (string, bool) {
	idx := strings.Index(text, phrase)
	if idx < 0 {
		return "", false
	}
	head := text[:idx]
	matches := versionToken.FindAllString(head, -1)
	if len(matches) == 0 {
		return "", false
	}
	return matches[len(matches)-1], true
}

// EvalResult is the verdict of checking a version against a constraint.
type EvalResult string

const (
	EvalAffected      EvalResult = "affected"
	EvalNotAffected   EvalResult = "not_affected"
	EvalIndeterminate EvalResult = "indeterminate"
)

// Evaluation carries the verdict together with the reasoning, which is what the
// evidence view renders beside the raw strings.
type Evaluation struct {
	Result      EvalResult `json:"result"`
	Comparator  string     `json:"comparator"`
	Explanation string     `json:"explanation"`
}

// Evaluate checks whether version falls inside the constraint.
//
// Indeterminate is a first class answer. An unknown firmware version or an
// unparseable range must not be reported as either affected or safe, because both
// of those claims would be fabricated.
func (c Constraint) Evaluate(version string, cmp Comparator) Evaluation {
	if cmp == nil {
		cmp = ComparatorFor("generic")
	}
	eval := Evaluation{Comparator: cmp.Name()}

	if c.Kind == ConstraintAll {
		eval.Result = EvalAffected
		eval.Explanation = "the advisory names no version, so every version is affected"
		return eval
	}

	if strings.TrimSpace(version) == "" {
		eval.Result = EvalIndeterminate
		eval.Explanation = "the device did not report a firmware version, so the range could not be checked"
		return eval
	}

	if c.Kind == ConstraintUnknown {
		eval.Result = EvalIndeterminate
		eval.Explanation = fmt.Sprintf("the advisory range %q could not be parsed", c.Raw)
		return eval
	}

	if c.Kind == ConstraintPrefix {
		if versionHasPrefix(version, c.Prefix) {
			eval.Result = EvalAffected
			eval.Explanation = fmt.Sprintf("%s is in the %s release line", version, c.Prefix)
		} else {
			eval.Result = EvalNotAffected
			eval.Explanation = fmt.Sprintf("%s is not in the %s release line", version, c.Prefix)
		}
		return eval
	}

	reading := cmp.Describe(version)

	if c.Lower != "" {
		result, ok := cmp.Compare(version, c.Lower)
		if !ok {
			eval.Result = EvalIndeterminate
			eval.Explanation = fmt.Sprintf("%s could not be ordered against %s using the %s comparator", version, c.Lower, cmp.Name())
			return eval
		}
		if result < 0 || (result == 0 && !c.LowerInclusive) {
			eval.Result = EvalNotAffected
			eval.Explanation = fmt.Sprintf("%s (%s) is below the affected range starting at %s", version, reading, c.Lower)
			return eval
		}
	}

	if c.Upper != "" {
		result, ok := cmp.Compare(version, c.Upper)
		if !ok {
			eval.Result = EvalIndeterminate
			eval.Explanation = fmt.Sprintf("%s could not be ordered against %s using the %s comparator", version, c.Upper, cmp.Name())
			return eval
		}
		if result > 0 || (result == 0 && !c.UpperInclusive) {
			eval.Result = EvalNotAffected
			eval.Explanation = fmt.Sprintf("%s (%s) is above the affected range ending at %s", version, reading, c.Upper)
			return eval
		}
	}

	eval.Result = EvalAffected
	eval.Explanation = fmt.Sprintf("%s (%s) falls inside %s", version, reading, c.Describe())
	return eval
}

// Describe renders the constraint in words for the evidence view.
func (c Constraint) Describe() string {
	switch c.Kind {
	case ConstraintAll:
		return "all versions"
	case ConstraintEQ:
		return fmt.Sprintf("exactly %s", c.Lower)
	case ConstraintPrefix:
		return fmt.Sprintf("the %s release line", c.Prefix)
	case ConstraintLT:
		return fmt.Sprintf("versions below %s", c.Upper)
	case ConstraintLTE:
		return fmt.Sprintf("versions up to and including %s", c.Upper)
	case ConstraintGT:
		return fmt.Sprintf("versions above %s", c.Lower)
	case ConstraintGTE:
		return fmt.Sprintf("versions from %s onward", c.Lower)
	case ConstraintBetween:
		lower, upper := "(", ")"
		if c.LowerInclusive {
			lower = "["
		}
		if c.UpperInclusive {
			upper = "]"
		}
		return fmt.Sprintf("versions in %s%s, %s%s", lower, c.Lower, c.Upper, upper)
	default:
		return fmt.Sprintf("an unparsed range (%q)", c.Raw)
	}
}

// versionHasPrefix compares tokenized versions so that 2.1.4 matches the 2.1
// line while 2.10.0 does not.
func versionHasPrefix(version, prefix string) bool {
	vt := tokenizeVersion(version)
	pt := tokenizeVersion(prefix)
	if len(pt) == 0 || len(vt) < len(pt) {
		return false
	}
	for idx := range pt {
		if vt[idx].kind != pt[idx].kind {
			return false
		}
		if vt[idx].kind == tokenNumber && vt[idx].num != pt[idx].num {
			return false
		}
		if vt[idx].kind == tokenAlpha && vt[idx].text != pt[idx].text {
			return false
		}
	}
	return true
}
