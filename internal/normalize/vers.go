package normalize

import (
	"strings"
)

// VERS is the version range specifier from the package URL project, written as
// "vers:<scheme>/<constraint>|<constraint>". CISA has moved most of its CSAF
// product tree onto it, and the overwhelming majority of what it publishes is
// "vers:all/*", meaning every version of the product is affected. Reading that as
// an unparsed range would leave the matcher unable to say anything about most of
// the corpus, so it is worth handling properly rather than hoping the phrase
// parser stumbles onto it.
//
// The specification is more expressive than the Constraint model: it can express
// a union of disjoint ranges and it can exclude individual versions. Those forms
// are refused rather than approximated, because an approximation here produces a
// confident wrong answer about whether a plant device is vulnerable.

const versPrefix = "vers:"

// parseVERS reads a VERS range. The second return value reports whether the
// string was VERS at all, so a caller can fall through to the phrase parser.
func parseVERS(text string) (Constraint, bool) {
	if !strings.HasPrefix(text, versPrefix) {
		return Constraint{}, false
	}

	_, body, found := strings.Cut(strings.TrimPrefix(text, versPrefix), "/")
	if !found {
		// The scheme and the constraints are separated by a slash. Without one
		// there is nothing to read, and guessing which half is which would be
		// inventing data.
		return Constraint{Kind: ConstraintUnknown}, true
	}

	body = strings.TrimSpace(body)
	if body == "" {
		return Constraint{Kind: ConstraintUnknown}, true
	}
	if body == "*" {
		return Constraint{Kind: ConstraintAll}, true
	}

	parts := strings.Split(body, "|")
	constraints := make([]versConstraint, 0, len(parts))
	for _, part := range parts {
		parsed, ok := parseVERSConstraint(part)
		if !ok {
			return Constraint{Kind: ConstraintUnknown}, true
		}
		constraints = append(constraints, parsed)
	}

	switch len(constraints) {
	case 1:
		return versSingle(constraints[0])
	case 2:
		return versPair(constraints[0], constraints[1])
	default:
		// Three or more constraints describe a union of ranges, which this model
		// cannot hold. Saying so is better than silently keeping one of them.
		return Constraint{Kind: ConstraintUnknown}, true
	}
}

type versConstraint struct {
	op      string
	version string
}

func parseVERSConstraint(raw string) (versConstraint, bool) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return versConstraint{}, false
	}
	// A bare version with no comparator means equality, and the wildcard is
	// handled by the caller, so seeing one here is a malformed range.
	if text == "*" {
		return versConstraint{}, false
	}

	for _, op := range []string{"<=", ">=", "!=", "<", ">", "="} {
		if strings.HasPrefix(text, op) {
			version := strings.TrimSpace(strings.TrimPrefix(text, op))
			if version == "" {
				return versConstraint{}, false
			}
			return versConstraint{op: op, version: version}, true
		}
	}
	return versConstraint{op: "=", version: text}, true
}

func versSingle(c versConstraint) (Constraint, bool) {
	switch c.op {
	case "=":
		return Constraint{
			Kind:  ConstraintEQ,
			Lower: c.version, LowerInclusive: true,
			Upper: c.version, UpperInclusive: true,
		}, true
	case "<":
		return Constraint{Kind: ConstraintLT, Upper: c.version}, true
	case "<=":
		return Constraint{Kind: ConstraintLTE, Upper: c.version, UpperInclusive: true}, true
	case ">":
		return Constraint{Kind: ConstraintGT, Lower: c.version}, true
	case ">=":
		return Constraint{Kind: ConstraintGTE, Lower: c.version, LowerInclusive: true}, true
	default:
		// A lone exclusion means every version except one. That is the opposite
		// of a range and cannot be stored as one.
		return Constraint{Kind: ConstraintUnknown}, true
	}
}

func versPair(first, second versConstraint) (Constraint, bool) {
	lower, upper := first, second
	if isVERSUpper(first.op) {
		lower, upper = second, first
	}
	if !isVERSLower(lower.op) || !isVERSUpper(upper.op) {
		return Constraint{Kind: ConstraintUnknown}, true
	}
	return Constraint{
		Kind:           ConstraintBetween,
		Lower:          lower.version,
		LowerInclusive: lower.op == ">=",
		Upper:          upper.version,
		UpperInclusive: upper.op == "<=",
	}, true
}

func isVERSLower(op string) bool { return op == ">" || op == ">=" }
func isVERSUpper(op string) bool { return op == "<" || op == "<=" }
