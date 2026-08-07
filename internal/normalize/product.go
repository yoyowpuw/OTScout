package normalize

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// FamilyRecord is one entry in the product family table.
type FamilyRecord struct {
	ID      string   `yaml:"id"`
	Vendor  string   `yaml:"vendor"`
	Display string   `yaml:"display"`
	Aliases []string `yaml:"aliases"`
	Models  []string `yaml:"models"`
}

type productFile struct {
	Version  int            `yaml:"version"`
	Families []FamilyRecord `yaml:"families"`
}

// ProductTable indexes product families by their aliases and models.
type ProductTable struct {
	records []FamilyRecord
	byID    map[string]*FamilyRecord
	// byKey maps a normalized alias to the family. Keys are scoped per vendor,
	// because "premium" means one thing to Schneider and nothing anywhere else,
	// and an unscoped index would let one vendor's alias capture another's
	// product.
	byKey map[string][]*FamilyRecord
	// modelKeys maps a normalized model designation to its family.
	modelKeys map[string][]*FamilyRecord
	// The compact indexes drop spaces entirely, so that "CPU 1516" and "CPU1516"
	// resolve to the same family without every spelling being listed by hand.
	// Vendors and operators are inconsistent about that space and always will be.
	byKeyCompact     map[string][]*FamilyRecord
	modelKeysCompact map[string][]*FamilyRecord
	// keysByLength supports longest-match lookup inside longer strings.
	keysByLength []string
}

var (
	productTableOnce sync.Once
	productTable     *ProductTable
	productTableErr  error
)

// DefaultProductTable returns the embedded family table, parsed once.
func DefaultProductTable() (*ProductTable, error) {
	productTableOnce.Do(func() {
		data, err := dataFS.ReadFile("data/products.yaml")
		if err != nil {
			productTableErr = fmt.Errorf("read embedded product table: %w", err)
			return
		}
		productTable, productTableErr = ParseProductTable(data)
	})
	return productTable, productTableErr
}

// ParseProductTable builds a family index from YAML.
func ParseProductTable(data []byte) (*ProductTable, error) {
	var file productFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parse product table: %w", err)
	}
	if len(file.Families) == 0 {
		return nil, fmt.Errorf("product table contains no families")
	}

	table := &ProductTable{
		records:          file.Families,
		byID:             make(map[string]*FamilyRecord, len(file.Families)),
		byKey:            make(map[string][]*FamilyRecord, len(file.Families)*4),
		modelKeys:        make(map[string][]*FamilyRecord, len(file.Families)*4),
		byKeyCompact:     make(map[string][]*FamilyRecord, len(file.Families)*4),
		modelKeysCompact: make(map[string][]*FamilyRecord, len(file.Families)*4),
	}

	keySet := make(map[string]struct{})
	for idx := range table.records {
		rec := &table.records[idx]
		if rec.ID == "" {
			return nil, fmt.Errorf("family entry %d has no id", idx)
		}
		if rec.Vendor == "" {
			return nil, fmt.Errorf("family %q has no vendor", rec.ID)
		}
		if rec.Display == "" {
			return nil, fmt.Errorf("family %q has no display name", rec.ID)
		}
		if _, exists := table.byID[rec.ID]; exists {
			return nil, fmt.Errorf("duplicate family id %q", rec.ID)
		}
		table.byID[rec.ID] = rec

		for _, alias := range append([]string{rec.Display, rec.ID}, rec.Aliases...) {
			key := ProductKey(alias)
			if key == "" {
				continue
			}
			table.byKey[key] = appendUnique(table.byKey[key], rec)
			compact := compactKey(key)
			table.byKeyCompact[compact] = appendUnique(table.byKeyCompact[compact], rec)
			keySet[key] = struct{}{}
		}
		for _, model := range rec.Models {
			key := ProductKey(model)
			if key == "" {
				continue
			}
			table.modelKeys[key] = appendUnique(table.modelKeys[key], rec)
			compact := compactKey(key)
			table.modelKeysCompact[compact] = appendUnique(table.modelKeysCompact[compact], rec)
			keySet[key] = struct{}{}
		}
	}

	table.keysByLength = make([]string, 0, len(keySet))
	for key := range keySet {
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

// Records returns every family, for the templates command and the docs.
func (t *ProductTable) Records() []FamilyRecord { return t.records }

// ProductKey normalizes a product name for comparison. Hyphens, underscores and
// runs of whitespace all collapse to a single space, so that S7-1200, S7_1200 and
// "S7 1200" reduce to the same key. Digits are kept attached to their letters so
// "cpu1214c" and "cpu 1214c" also converge.
func ProductKey(raw string) string {
	lower := strings.ToLower(strings.TrimSpace(raw))
	var sb strings.Builder
	sb.Grow(len(lower))
	for _, r := range lower {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
		case r == '+', r == '!':
			// Kept because they appear in real product names such as LOGO! and
			// Ewon Cosy+.
			sb.WriteRune(r)
		default:
			sb.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(sb.String()), " ")
}

// compactKey removes the spaces from a normalized key.
func compactKey(key string) string {
	return strings.ReplaceAll(key, " ", "")
}

func appendUnique(list []*FamilyRecord, rec *FamilyRecord) []*FamilyRecord {
	for _, existing := range list {
		if existing == rec {
			return list
		}
	}
	return append(list, rec)
}

// FamilyMatch is the result of resolving a product string to a family.
type FamilyMatch struct {
	Family  *FamilyRecord
	Matched string
	Method  MatchMethod
	// ViaModel is true when the string matched a specific model rather than the
	// family name, which is the common case for devices reporting themselves.
	ViaModel bool
}

// LookupProduct resolves a product string, optionally restricted to a vendor.
//
// Passing a vendor id matters. Several vendors use the same short product words,
// and an unscoped lookup would attach one company's advisory to another's device.
// When vendorID is empty the lookup still runs but only accepts an unambiguous
// answer.
func (t *ProductTable) LookupProduct(vendorID, raw string) (FamilyMatch, bool) {
	key := ProductKey(raw)
	if key == "" {
		return FamilyMatch{Method: MatchNone}, false
	}

	if match, ok := t.resolve(vendorID, key, key, MatchExact); ok {
		return match, true
	}

	// Fall back to finding the longest known alias or model inside the string,
	// which handles banners such as "SIMATIC S7-1200 CPU 1214C DC/DC/DC".
	for _, candidate := range t.keysByLength {
		if len(candidate) < 3 {
			continue
		}
		if !containsWholePhrase(key, candidate) {
			continue
		}
		if match, ok := t.resolve(vendorID, candidate, candidate, MatchTokenSubset); ok {
			return match, true
		}
	}

	return FamilyMatch{Method: MatchNone}, false
}

// resolve picks a family for a key, preferring an entry belonging to vendorID.
//
// Model designations are checked before family aliases because they are more
// specific, and the spaced indexes are checked before the compact ones so that an
// exactly written key is never resolved through a looser form.
func (t *ProductTable) resolve(vendorID, key, matched string, method MatchMethod) (FamilyMatch, bool) {
	compact := compactKey(key)
	lookups := []struct {
		index    map[string][]*FamilyRecord
		key      string
		viaModel bool
	}{
		{t.modelKeys, key, true},
		{t.byKey, key, false},
		{t.modelKeysCompact, compact, true},
		{t.byKeyCompact, compact, false},
	}

	for _, lookup := range lookups {
		candidates, ok := lookup.index[lookup.key]
		if !ok {
			continue
		}
		rec, ok := pickFamily(candidates, vendorID)
		if !ok {
			continue
		}
		return FamilyMatch{Family: rec, Matched: matched, Method: method, ViaModel: lookup.viaModel}, true
	}
	return FamilyMatch{}, false
}

// pickFamily selects among candidates sharing an alias. With a vendor in hand the
// choice is unambiguous. Without one, an alias claimed by several vendors is
// rejected rather than guessed.
func pickFamily(candidates []*FamilyRecord, vendorID string) (*FamilyRecord, bool) {
	if vendorID != "" {
		for _, rec := range candidates {
			if rec.Vendor == vendorID {
				return rec, true
			}
		}
		return nil, false
	}
	if len(candidates) == 1 {
		return candidates[0], true
	}
	return nil, false
}

// ByID looks a family up by canonical id.
func (t *ProductTable) ByID(id string) (*FamilyRecord, bool) {
	rec, ok := t.byID[id]
	return rec, ok
}
