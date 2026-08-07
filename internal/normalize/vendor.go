// Package normalize turns the free text identity strings found in advisories and
// on the wire into comparable values.
//
// This is the layer that makes correlation possible at all. CISA publishes its
// ICS advisories in CSAF 2.0 but fills in no CPE and no
// product_identification_helper, so an advisory identifies its products with
// nothing but a vendor name, a product family name and version strings in
// whatever scheme the vendor happens to use. Devices on the wire are no better.
// Both sides therefore need the same treatment, which is why discovery and
// correlation share this package rather than each carrying its own guesses.
package normalize

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var dataFS embed.FS

// VendorRecord is one entry in the vendor alias table.
type VendorRecord struct {
	ID             string   `yaml:"id"`
	Display        string   `yaml:"display"`
	Aliases        []string `yaml:"aliases"`
	VersionScheme  string   `yaml:"version_scheme"`
	CatalogParsers []string `yaml:"catalog_parsers"`
}

type vendorFile struct {
	Version int            `yaml:"version"`
	Vendors []VendorRecord `yaml:"vendors"`
}

// MatchMethod records how a vendor string was resolved. It is carried into the
// evidence trail so an operator can see whether a match rested on an exact name
// or on a looser token match.
type MatchMethod string

const (
	MatchExact       MatchMethod = "exact"
	MatchSuffixTrim  MatchMethod = "suffix_trimmed"
	MatchTokenSubset MatchMethod = "token_subset"
	MatchNone        MatchMethod = "none"
)

// VendorMatch is the result of resolving a vendor string.
type VendorMatch struct {
	ID      string
	Display string
	// Matched is the index key that resolved, which is not always the input.
	Matched string
	Method  MatchMethod
	Record  *VendorRecord
}

// Exact reports whether the resolution was a direct name match rather than a
// heuristic one.
func (m VendorMatch) Exact() bool {
	return m.Method == MatchExact || m.Method == MatchSuffixTrim
}

// VendorTable is an index over the alias table.
type VendorTable struct {
	records []VendorRecord
	byID    map[string]*VendorRecord
	byKey   map[string]*VendorRecord
	// keysByLength lets the token fallback prefer the longest match, so that
	// "delta controls" does not resolve through the shorter "delta".
	keysByLength []string
}

var (
	defaultTableOnce sync.Once
	defaultTable     *VendorTable
	defaultTableErr  error
)

// DefaultVendorTable returns the embedded alias table, parsed once.
func DefaultVendorTable() (*VendorTable, error) {
	defaultTableOnce.Do(func() {
		data, err := dataFS.ReadFile("data/vendors.yaml")
		if err != nil {
			defaultTableErr = fmt.Errorf("read embedded vendor table: %w", err)
			return
		}
		defaultTable, defaultTableErr = ParseVendorTable(data)
	})
	return defaultTable, defaultTableErr
}

// ParseVendorTable builds a table from YAML, validating it. Duplicate ids and
// aliases that resolve to two different vendors are errors rather than warnings,
// because a silently ambiguous alias produces findings attributed to the wrong
// company.
func ParseVendorTable(data []byte) (*VendorTable, error) {
	var file vendorFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse vendor table: %w", err)
	}
	if len(file.Vendors) == 0 {
		return nil, fmt.Errorf("vendor table contains no vendors")
	}

	table := &VendorTable{
		records: file.Vendors,
		byID:    make(map[string]*VendorRecord, len(file.Vendors)),
		byKey:   make(map[string]*VendorRecord, len(file.Vendors)*4),
	}

	for idx := range table.records {
		rec := &table.records[idx]
		if rec.ID == "" {
			return nil, fmt.Errorf("vendor entry %d has no id", idx)
		}
		if rec.Display == "" {
			return nil, fmt.Errorf("vendor %q has no display name", rec.ID)
		}
		if _, exists := table.byID[rec.ID]; exists {
			return nil, fmt.Errorf("duplicate vendor id %q", rec.ID)
		}
		table.byID[rec.ID] = rec

		keys := append([]string{rec.ID, rec.Display}, rec.Aliases...)
		for _, key := range keys {
			norm := VendorKey(key)
			if norm == "" {
				continue
			}
			if existing, exists := table.byKey[norm]; exists && existing.ID != rec.ID {
				return nil, fmt.Errorf("alias %q is claimed by both %q and %q", norm, existing.ID, rec.ID)
			}
			table.byKey[norm] = rec
		}
	}

	table.keysByLength = make([]string, 0, len(table.byKey))
	for key := range table.byKey {
		table.keysByLength = append(table.keysByLength, key)
	}
	sort.Slice(table.keysByLength, func(i, j int) bool {
		if len(table.keysByLength[i]) != len(table.keysByLength[j]) {
			return len(table.keysByLength[i]) > len(table.keysByLength[j])
		}
		return table.keysByLength[i] < table.keysByLength[j]
	})

	return table, nil
}

// Records returns every vendor in the table, for the templates listing and docs.
func (t *VendorTable) Records() []VendorRecord { return t.records }

// ByID looks a vendor up by canonical id.
func (t *VendorTable) ByID(id string) (*VendorRecord, bool) {
	rec, ok := t.byID[id]
	return rec, ok
}

// corporateSuffixes are legal form tokens that carry no identifying information.
// They are stripped only from the end of a name, so that a company whose actual
// name contains one of these words is not damaged.
var corporateSuffixes = map[string]bool{
	"inc":          true,
	"incorporated": true,
	"corp":         true,
	"corporation":  true,
	"co":           true,
	"company":      true,
	"ltd":          true,
	"limited":      true,
	"llc":          true,
	"lp":           true,
	"llp":          true,
	"gmbh":         true,
	"mbh":          true,
	"ag":           true,
	"sa":           true,
	"se":           true,
	"bv":           true,
	"nv":           true,
	"oy":           true,
	"oyj":          true,
	"ab":           true,
	"as":           true,
	"asa":          true,
	"spa":          true,
	"srl":          true,
	"plc":          true,
	"kg":           true,
	"kgaa":         true,
	"pty":          true,
	"pte":          true,
	"holdings":     true,
	"holding":      true,
}

// asciiFold maps the accented letters that appear in vendor names onto ASCII.
//
// A great many ICS vendors are German or Nordic, and the same company reaches this
// function spelled both ways: an advisory says "Draegerwerk" where the device says
// "Dragerwerk" and the company itself writes "Draegerwerk". Without this the
// accented letter would be dropped to a space, splitting one name into two tokens
// and turning every such vendor into a separate unrecognised entry.
//
// The German pairs expand rather than strip, because that is how those companies
// spell themselves in ASCII. Elsewhere the accent is simply removed.
var asciiFold = map[rune]string{
	'\u00e4': "ae", '\u00f6': "oe", '\u00fc': "ue", '\u00df': "ss",
	'\u00e5': "a", '\u00e6': "ae", '\u00f8': "o",
	'\u00e0': "a", '\u00e1': "a", '\u00e2': "a", '\u00e3': "a",
	'\u00e8': "e", '\u00e9': "e", '\u00ea': "e", '\u00eb': "e",
	'\u00ec': "i", '\u00ed': "i", '\u00ee': "i", '\u00ef': "i",
	'\u00f1': "n",
	'\u00f2': "o", '\u00f3': "o", '\u00f4': "o", '\u00f5': "o",
	'\u00f9': "u", '\u00fa': "u", '\u00fb': "u",
	'\u00fd': "y", '\u00ff': "y",
	'\u00e7': "c", '\u0107': "c", '\u010d': "c",
	'\u015f': "s", '\u0161': "s", '\u017e': "z", '\u0142': "l",
}

// VendorKey normalizes a vendor string into an index key. Ampersand and plus are
// preserved because they are part of names such as B&R and Pepperl+Fuchs.
func VendorKey(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	var sb strings.Builder
	sb.Grow(len(lower))
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
		case r == '&' || r == '+':
			sb.WriteRune(r)
		case r == '-':
			// Hyphens are inconsistent across sources: "allen-bradley" and
			// "allen bradley" are the same company.
			sb.WriteRune(' ')
		default:
			if folded, ok := asciiFold[r]; ok {
				sb.WriteString(folded)
				continue
			}
			sb.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(sb.String()), " ")
}

// trimCorporateSuffixes removes trailing legal form tokens.
func trimCorporateSuffixes(key string) string {
	tokens := strings.Fields(key)
	for len(tokens) > 1 {
		last := tokens[len(tokens)-1]
		if !corporateSuffixes[last] {
			break
		}
		tokens = tokens[:len(tokens)-1]
	}
	// A trailing conjunction left behind by "gmbh & co kg" is noise too.
	for len(tokens) > 1 && (tokens[len(tokens)-1] == "&" || tokens[len(tokens)-1] == "and") {
		tokens = tokens[:len(tokens)-1]
	}
	return strings.Join(tokens, " ")
}

// LookupVendor resolves a vendor string against the table.
//
// The three stages run strongest first. Exact and suffix trimmed matches are
// authoritative. The token subset stage is a fallback for strings that carry a
// product name alongside the vendor, such as "Siemens SIMATIC S7-1200", and it
// requires the longest possible key so that a short alias cannot hijack a
// longer, more specific one.
func (t *VendorTable) LookupVendor(raw string) (VendorMatch, bool) {
	key := VendorKey(raw)
	if key == "" {
		return VendorMatch{Method: MatchNone}, false
	}

	if rec, ok := t.byKey[key]; ok {
		return VendorMatch{ID: rec.ID, Display: rec.Display, Matched: key, Method: MatchExact, Record: rec}, true
	}

	if trimmed := trimCorporateSuffixes(key); trimmed != key && trimmed != "" {
		if rec, ok := t.byKey[trimmed]; ok {
			return VendorMatch{ID: rec.ID, Display: rec.Display, Matched: trimmed, Method: MatchSuffixTrim, Record: rec}, true
		}
	}

	for _, candidate := range t.keysByLength {
		// Very short keys are too easy to hit by accident inside a longer
		// string, so the fallback ignores them.
		if len(candidate) < 4 {
			continue
		}
		if containsWholePhrase(key, candidate) {
			rec := t.byKey[candidate]
			return VendorMatch{ID: rec.ID, Display: rec.Display, Matched: candidate, Method: MatchTokenSubset, Record: rec}, true
		}
	}

	return VendorMatch{Method: MatchNone}, false
}

// containsWholePhrase reports whether phrase appears in key on token boundaries,
// so that "abb" does not match inside "rabbit".
func containsWholePhrase(key, phrase string) bool {
	keyTokens := strings.Fields(key)
	phraseTokens := strings.Fields(phrase)
	if len(phraseTokens) == 0 || len(phraseTokens) > len(keyTokens) {
		return false
	}
	for start := 0; start+len(phraseTokens) <= len(keyTokens); start++ {
		matched := true
		for offset, token := range phraseTokens {
			if keyTokens[start+offset] != token {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	return false
}

// VersionSchemeFor returns the comparator name configured for a vendor id, or an
// empty string when the vendor uses the generic comparator.
func (t *VendorTable) VersionSchemeFor(vendorID string) string {
	if rec, ok := t.byID[vendorID]; ok {
		return rec.VersionScheme
	}
	return ""
}

// CatalogParsersFor returns the catalog number parsers configured for a vendor.
func (t *VendorTable) CatalogParsersFor(vendorID string) []string {
	if rec, ok := t.byID[vendorID]; ok {
		return rec.CatalogParsers
	}
	return nil
}
