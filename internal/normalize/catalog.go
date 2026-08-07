package normalize

import (
	"sort"
	"strings"
)

// CatalogResult is what a catalog number parser recovered from an order code.
//
// Order codes matter more in OT than in IT. A Siemens PLC will happily report
// its MLFB when asked and may report nothing else useful, and that MLFB encodes
// the exact model. Recovering the family and model from it converts an otherwise
// opaque string into something an advisory can be matched against.
type CatalogResult struct {
	Parser      string  `json:"parser"`
	VendorID    string  `json:"vendor_id,omitempty"`
	Family      string  `json:"family,omitempty"`
	Model       string  `json:"model,omitempty"`
	Series      string  `json:"series,omitempty"`
	Normalized  string  `json:"normalized,omitempty"`
	Confidence  float64 `json:"confidence"`
	Explanation string  `json:"explanation,omitempty"`
}

// CatalogParser recovers structure from one vendor's order code scheme.
type CatalogParser interface {
	Name() string
	// Parse returns false when the input is not in this vendor's scheme, which
	// lets the registry try the next parser without producing a wrong answer.
	Parse(raw string) (CatalogResult, bool)
}

var catalogParsers = map[string]CatalogParser{}

func registerCatalogParser(p CatalogParser) {
	catalogParsers[p.Name()] = p
}

// CatalogParserNames lists the registered parsers for the templates command and
// for the contributor docs.
func CatalogParserNames() []string {
	names := make([]string, 0, len(catalogParsers))
	for name := range catalogParsers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// CatalogKey normalizes an order code for comparison: uppercase, with spaces and
// separators removed. Vendors and operators write the same code many ways, so
// "6ES7 214-1AG40-0XB0" and "6ES7214-1AG40-0XB0" must reduce to one key.
func CatalogKey(raw string) string {
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, r := range strings.ToUpper(raw) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// ParseCatalog tries every registered parser and returns the most confident
// result. Trying all of them is safe because each parser rejects codes outside
// its own scheme.
func ParseCatalog(raw string) (CatalogResult, bool) {
	names := CatalogParserNames()
	best := CatalogResult{}
	found := false
	for _, name := range names {
		result, ok := catalogParsers[name].Parse(raw)
		if !ok {
			continue
		}
		if !found || result.Confidence > best.Confidence {
			best, found = result, true
		}
	}
	return best, found
}

// ParseCatalogWith runs only the named parsers, in order. Callers that already
// know the vendor use this so that a code cannot be claimed by another vendor's
// scheme.
func ParseCatalogWith(raw string, parsers []string) (CatalogResult, bool) {
	for _, name := range parsers {
		parser, ok := catalogParsers[name]
		if !ok {
			continue
		}
		if result, ok := parser.Parse(raw); ok {
			return result, true
		}
	}
	return CatalogResult{}, false
}

// ParseCatalogForVendor uses the parsers configured for a vendor id, falling back
// to trying every parser when the vendor declares none.
func (t *VendorTable) ParseCatalogForVendor(vendorID, raw string) (CatalogResult, bool) {
	if parsers := t.CatalogParsersFor(vendorID); len(parsers) > 0 {
		return ParseCatalogWith(raw, parsers)
	}
	return ParseCatalog(raw)
}
