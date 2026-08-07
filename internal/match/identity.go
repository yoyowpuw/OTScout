package match

import (
	"fmt"
	"strings"

	"github.com/yoyowpuw/OTScout/internal/advisory"
	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// strength is how precisely an asset was tied to an advisory product node.
//
// This is the axis the confidence tiers are built on, and it is deliberately
// coarse. The question an engineer is really asking is "do you know it is this
// exact device, or only that it is one of this kind", and a finer scale would
// imply a precision the underlying data does not have.
type strength int

const (
	// strengthNone means the product could not be tied to the asset at all. A
	// shared vendor is not a match: every Siemens advisory would otherwise land
	// on every Siemens device, which is the false positive flood that gets a
	// tool like this uninstalled.
	strengthNone strength = iota
	// strengthFamily means the two agree on a product family but not on which
	// member of it.
	strengthFamily
	// strengthProduct means a product name or model designation matched.
	strengthProduct
	// strengthCatalog means an order code or a CPE matched, which names one
	// orderable item and is the strongest identifier either side ever carries.
	strengthCatalog
)

// fieldRank is how specific one identity field is. A match is only as strong as
// the vaguer of the two fields that produced it, which is what stops a device
// that reports nothing but a family name from being credited with a product
// level match against an advisory that does name a model.
type fieldRank int

const (
	rankFamily  fieldRank = 1
	rankProduct fieldRank = 2
	rankCatalog fieldRank = 3
)

func strengthFor(rank fieldRank) strength {
	switch rank {
	case rankCatalog:
		return strengthCatalog
	case rankProduct:
		return strengthProduct
	default:
		return strengthFamily
	}
}

func rankFor(s strength) fieldRank {
	switch s {
	case strengthCatalog:
		return rankCatalog
	case strengthProduct:
		return rankProduct
	default:
		return rankFamily
	}
}

// advisoryOutranksMatch reports whether the advisory names a designation finer
// than the one that matched.
//
// product.name is skipped. It is the whole product name as the advisory printed
// it, a sentence rather than a designation, and it is routinely more specific in
// the trivial sense of also containing the vendor and the version. Treating that
// as a finer designation would make almost every match uncertain.
func advisoryOutranksMatch(fields []field, matchedKey string, level fieldRank) bool {
	return finerDesignation(fields, matchedKey, level) != ""
}

func finerDesignation(fields []field, matchedKey string, level fieldRank) string {
	for _, f := range fields {
		if f.Label == "product.name" || f.Key == matchedKey || f.Rank <= level {
			continue
		}
		if !informative(f.Key) {
			continue
		}
		return f.Value
	}
	return ""
}

// field is one comparable string together with where it came from.
type field struct {
	Label string
	Value string
	Key   string
	Rank  fieldRank
}

func newField(label, value string, rank fieldRank) (field, bool) {
	key := normalize.ProductKey(value)
	if key == "" {
		return field{}, false
	}
	return field{Label: label, Value: strings.TrimSpace(value), Key: key, Rank: rank}, true
}

// demoteFamilyNames lowers the rank of any field whose value is a family name.
//
// Which field a string sits in is a weak signal. The normalizer fills an empty
// product field with the family display name so that labels read well, and CSAF
// trees put family names in product branches routinely. Trusting the field name
// alone would then let "SIMATIC S7-1200" count as a product level match on both
// sides, and every S7-1200 advisory would land on every S7-1200 device as
// confirmed.
//
// The product table settles it: a string that resolves exactly to a family, other
// than through one of its model designations, is a family name wherever it is
// stored. Only demotion happens here. A model found in a family field is left
// alone rather than promoted, because being wrong in that direction costs an
// engineer a site visit.
func demoteFamilyNames(products *normalize.ProductTable, vendorID string, fields []field) {
	if products == nil {
		return
	}
	for idx := range fields {
		f := &fields[idx]
		if f.Rank <= rankFamily {
			continue
		}
		match, ok := products.LookupProduct(vendorID, f.Value)
		if !ok || match.ViaModel || match.Method != normalize.MatchExact {
			continue
		}
		f.Rank = rankFamily
	}
}

// assetFields lists what the device told us, ranked.
//
// CatalogNumber is not listed at catalog rank here even though it is one. Order
// codes are compared separately and exactly, because a partial or reformatted
// order code is a different device, and running one through the loose comparisons
// below would let 6ES7214-1AG40-0XB0 match 6ES7214-1AG40-0XB7.
func assetFields(id asset.Identity) []field {
	candidates := []struct {
		label string
		value string
		rank  fieldRank
	}{
		{"identity.model", id.Model, rankProduct},
		{"identity.product", id.Product, rankProduct},
		{"identity.product_raw", id.ProductRaw, rankProduct},
		{"identity.family", id.Family, rankFamily},
	}
	return collectFields(candidates)
}

// advisoryFields lists what the advisory product node says, ranked.
func advisoryFields(p advisory.Product) []field {
	candidates := []struct {
		label string
		value string
		rank  fieldRank
	}{
		{"product.model", p.Model, rankProduct},
		{"product.product", p.ProductNam, rankProduct},
		{"product.product_raw", p.ProductRaw, rankProduct},
		{"product.name", p.Name, rankProduct},
		{"product.family", p.Family, rankFamily},
		{"product.family_raw", p.FamilyRaw, rankFamily},
	}
	return collectFields(candidates)
}

func collectFields(candidates []struct {
	label string
	value string
	rank  fieldRank
}) []field {
	out := make([]field, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		f, ok := newField(c.label, c.value, c.rank)
		if !ok {
			continue
		}
		// The same string often sits in several fields. Keeping the first
		// occurrence keeps the strongest rank, since the list is ordered by it.
		if _, dup := seen[f.Key]; dup {
			continue
		}
		seen[f.Key] = struct{}{}
		out = append(out, f)
	}
	return out
}

// identityMatch is the outcome of comparing one asset against one advisory
// product node.
type identityMatch struct {
	Strength strength
	// AdvisoryMoreSpecific is true when the advisory names a finer designation
	// than the match established. That, rather than the match strength on its
	// own, is where real uncertainty lives: an advisory saying every S7-1200 is
	// affected settles the question for an S7-1200, while one naming CPU 1215C
	// leaves an S7-1200 of unknown model as a lead and nothing more.
	AdvisoryMoreSpecific bool
	Reasons              []finding.Reason
}

// genericWords are words that appear as whole product and family names in
// advisories while saying nothing about which device is meant.
//
// A corpus of a few thousand CISA advisories contains hundreds of product nodes
// named exactly "Firmware" or "Controller", and devices report the same words
// about themselves. Matching on one produces a finding that looks plausible and
// is pure coincidence, which is worse than producing nothing.
var genericWords = map[string]bool{
	"all": true, "control": true, "controller": true, "controllers": true,
	"cpu": true, "device": true, "devices": true, "family": true,
	"firmware": true, "gateway": true, "gateways": true, "hardware": true,
	"hmi": true, "module": true, "modules": true, "plc": true,
	"product": true, "products": true, "router": true, "routers": true,
	"series": true, "server": true, "servers": true, "software": true,
	"switch": true, "switches": true, "system": true, "systems": true,
	"unit": true, "units": true, "version": true, "versions": true,
}

// informative reports whether a normalized key says anything about which device
// is meant once the words shared by every advisory are set aside.
func informative(key string) bool {
	for _, word := range strings.Fields(key) {
		if !genericWords[word] {
			return true
		}
	}
	return false
}

// compareIdentity decides how strongly an asset and an advisory product node
// describe the same thing, assuming their vendors have already been found to
// agree.
//
// Both sides have been through the same normalizer, which is what makes this
// comparison meaningful: a vendor string spelled one way in an advisory and
// another way on the wire has already been reduced to one canonical value. Where
// normalization failed on both sides the raw strings are still compared, because
// an advisory and a device that spell an unknown product identically are still
// talking about the same product.
func compareIdentity(products *normalize.ProductTable, id asset.Identity, p advisory.Product) identityMatch {
	out := identityMatch{}

	// A CPE is an unambiguous identifier, so it settles the question outright.
	// ICS advisories almost never carry one, which is exactly why the rest of
	// this function exists.
	if p.CPE != "" && id.CatalogNumber != "" && cpeMatchesCatalog(p.CPE, id.CatalogNumber) {
		out.Strength = strengthCatalog
		out.Reasons = append(out.Reasons, finding.Reason{
			Kind:   finding.ReasonCPE,
			Detail: fmt.Sprintf("the advisory CPE %q names order code %q", p.CPE, id.CatalogNumber),
			Weight: 1,
			Passed: true,
		})
		return out
	}

	if p.CatalogNumber != "" && id.CatalogNumber != "" {
		// CatalogKey, not ProductKey. Order codes are written with the separators
		// in different places by everyone who writes them, and only the key that
		// strips separators entirely makes "6ES7 214-1AG40-0XB0" and
		// "6ES7214-1AG40-0XB0" the one code they actually are.
		assetCode := normalize.CatalogKey(id.CatalogNumber)
		advCode := normalize.CatalogKey(p.CatalogNumber)
		switch {
		case assetCode == "" || advCode == "":
		case assetCode == advCode:
			out.Strength = strengthCatalog
			out.Reasons = append(out.Reasons, finding.Reason{
				Kind:   finding.ReasonCatalogNumber,
				Detail: fmt.Sprintf("order code %q matches the advisory exactly", id.CatalogNumber),
				Weight: 1,
				Passed: true,
			})
			return out
		default:
			// Two order codes that disagree are two different orderable items, so
			// this node is not about this device and no amount of overlap in the
			// product names changes that. Without this the model names would keep
			// matching loosely, and an S7-1200 CPU would pick up an advisory
			// against a SIMATIC IOT2050 gateway on the strength of both being
			// called SIMATIC.
			out.Reasons = append(out.Reasons, finding.Reason{
				Kind: finding.ReasonCatalogNumber,
				Detail: fmt.Sprintf("order code %q is not the advisory's %q",
					id.CatalogNumber, p.CatalogNumber),
				Passed: false,
			})
			return out
		}
	}

	assetSide, advisorySide := assetFields(id), advisoryFields(p)
	demoteFamilyNames(products, id.Vendor, assetSide)
	demoteFamilyNames(products, p.Vendor, advisorySide)

	// Every pair is tried both ways and the strongest outcome wins.
	//
	// Precedence is by how precisely the pair identifies the device, not by which
	// technique found it. Checking all the exact matches first would look tidier
	// and be wrong: a device that reports a model and an advisory that spells out
	// a full product name agree exactly on their shared family name and only
	// approximately on the model, and preferring the exact agreement there would
	// throw away the more specific of the two answers.
	best := identityMatch{}
	matchedKey := ""
	consider := func(candidate identityMatch, ok bool, key string) {
		if !ok || candidate.Strength <= best.Strength {
			return
		}
		best, matchedKey = candidate, key
	}
	for _, a := range assetSide {
		for _, b := range advisorySide {
			if a.Key == b.Key {
				if !informative(a.Key) {
					continue
				}
				consider(exactMatch(a, b), true, a.Key)
				continue
			}
			candidate, ok, key := containmentMatch(a, b)
			consider(candidate, ok, key)
		}
	}
	if best.Strength > strengthNone {
		best.AdvisoryMoreSpecific = advisoryOutranksMatch(advisorySide, matchedKey, rankFor(best.Strength))
		if best.AdvisoryMoreSpecific {
			best.Reasons = append(best.Reasons, finding.Reason{
				Kind:   finding.ReasonProductExact,
				Detail: fmt.Sprintf("the advisory names %q, which this device did not report", finerDesignation(advisorySide, matchedKey, rankFor(best.Strength))),
				Passed: false,
			})
		}
		return best
	}

	out.Reasons = append(out.Reasons, finding.Reason{
		Kind:   finding.ReasonProductFamily,
		Detail: fmt.Sprintf("nothing in %q corresponds to %q", id.Label(), p.Label()),
		Passed: false,
	})
	return out
}

func exactMatch(a, b field) identityMatch {
	rank := a.Rank
	if b.Rank < rank {
		rank = b.Rank
	}
	level := strengthFor(rank)

	kind := finding.ReasonProductExact
	switch {
	case level == strengthFamily:
		kind = finding.ReasonProductFamily
	case a.Label == "identity.model" || b.Label == "product.model":
		kind = finding.ReasonProductModel
	case a.Value != b.Value:
		// The strings agreed only after normalization, which is worth saying so
		// that an operator reading the evidence is not confused by two spellings
		// that do not look alike.
		kind = finding.ReasonProductNormal
	}

	return identityMatch{
		Strength: level,
		Reasons: []finding.Reason{{
			Kind: kind,
			Detail: fmt.Sprintf("%s %q matches %s %q",
				a.Label, a.Value, b.Label, b.Value),
			Weight: float64(level),
			Passed: true,
		}},
	}
}

// containmentMatch handles the very common shape where one side carries a full
// banner and the other carries just the designation, as in an advisory naming
// "SIMATIC S7-1200 CPU 1214C DC/DC/DC" against a device reporting "CPU 1214C".
//
// Three guards keep this from becoming a substring search over the corpus, which
// is what it would otherwise be.
//
// The contained phrase has to be several characters long and has to say something
// once the words common to every advisory are set aside, or a device calling
// itself a "controller" would match everything ever published under that word.
//
// Then either the words the longer side adds have to be filler, or the contained
// phrase has to be a product level designation rather than a family name. This is
// the guard that carries the weight. "Modicon M340" inside "Modicon M340
// Controller" is the same product described at more length, and is kept. "SCALANCE"
// inside "SCALANCE XC-300/XR-300/XC-400 family" is a product line inside a list of
// specific models, and is not: a device that knows only that it is a SCALANCE has
// not been shown to be any of them.
func containmentMatch(a, b field) (identityMatch, bool, string) {
	var inner, outer field
	switch {
	case containsWholePhrase(b.Key, a.Key):
		inner, outer = a, b
	case containsWholePhrase(a.Key, b.Key):
		inner, outer = b, a
	default:
		return identityMatch{}, false, ""
	}

	if len(inner.Key) < 5 || !informative(inner.Key) {
		return identityMatch{}, false, ""
	}
	filler := addsOnlyFiller(outer.Key, inner.Key)
	if !filler && inner.Rank < rankProduct {
		return identityMatch{}, false, ""
	}

	rank := a.Rank
	if b.Rank < rank {
		rank = b.Rank
	}
	level := strengthFor(rank)

	detail := fmt.Sprintf("%s %q appears inside %s %q",
		inner.Label, inner.Value, outer.Label, outer.Value)
	if filler {
		detail = fmt.Sprintf("%s %q is %s %q with nothing added but filler",
			inner.Label, inner.Value, outer.Label, outer.Value)
	}

	return identityMatch{
		Strength: level,
		Reasons: []finding.Reason{{
			Kind:   finding.ReasonProductContained,
			Detail: detail,
			Weight: float64(level),
			Passed: true,
		}},
	}, true, inner.Key
}

// addsOnlyFiller reports whether the words the longer key adds beyond the shorter
// one say nothing about which device is meant, which makes the two names the same
// name written at different lengths.
func addsOnlyFiller(outerKey, innerKey string) bool {
	return !informative(strings.Replace(outerKey, innerKey, " ", 1))
}

// containsWholePhrase reports whether phrase appears in text on token
// boundaries, so that "s7 1200" is found in "simatic s7 1200 cpu" but "120" is
// not found in "1200".
func containsWholePhrase(text, phrase string) bool {
	if phrase == "" || text == "" || len(phrase) > len(text) {
		return false
	}
	from := 0
	for {
		idx := strings.Index(text[from:], phrase)
		if idx < 0 {
			return false
		}
		start := from + idx
		end := start + len(phrase)
		leftOK := start == 0 || text[start-1] == ' '
		rightOK := end == len(text) || text[end] == ' '
		if leftOK && rightOK {
			return true
		}
		from = start + 1
		if from >= len(text) {
			return false
		}
	}
}

// cpeMatchesCatalog checks an order code against the product component of a CPE.
//
// Only the product field is considered. A CPE version component describes the
// software version, which is the version range's business, and folding it in here
// would have an order code fail to match purely because the firmware differed.
func cpeMatchesCatalog(cpe, catalog string) bool {
	parts := strings.Split(cpe, ":")
	// cpe:2.3:part:vendor:product:version:...
	if len(parts) < 5 {
		return false
	}
	product := normalize.CatalogKey(parts[4])
	if product == "" {
		return false
	}
	return product == normalize.CatalogKey(catalog)
}
