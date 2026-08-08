// Package advisory holds the canonical advisory model and the readers that build
// it from the formats security advisories are actually published in.
//
// Every source is reduced to the same shape so that the matcher has one thing to
// compare against. That shape is deliberately close to CSAF, since CSAF is the
// only format among these that was designed to be machine readable, but it is not
// CSAF: the fields the matcher needs are lifted out of the product tree and
// flattened, because walking a tree per asset per advisory would be both slow and
// impossible to explain in an evidence trail.
package advisory

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// Severity is the qualitative rating attached to a score.
type Severity string

const (
	SeverityNone     Severity = "none"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
	SeverityUnknown  Severity = ""
)

// Rank orders severities for sorting, with unknown last so that a missing score
// never masquerades as a low one.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNone:
		return 1
	default:
		return 0
	}
}

// SeverityForScore maps a CVSS base score onto the qualitative bands the CVSS
// specification defines, for sources that publish a number and no rating.
func SeverityForScore(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	case score == 0:
		return SeverityNone
	default:
		return SeverityUnknown
	}
}

// Status is a CSAF product status. The matcher only ever treats known_affected as
// grounds for a finding, but the others are kept because an advisory that lists a
// product as fixed is the evidence that closes a finding out.
type Status string

const (
	StatusKnownAffected      Status = "known_affected"
	StatusKnownNotAffected   Status = "known_not_affected"
	StatusFixed              Status = "fixed"
	StatusFirstFixed         Status = "first_fixed"
	StatusFirstAffected      Status = "first_affected"
	StatusLastAffected       Status = "last_affected"
	StatusRecommended        Status = "recommended"
	StatusUnderInvestigation Status = "under_investigation"
)

// Advisory is one security advisory, from any source.
type Advisory struct {
	ID     string `json:"id"`
	Source string `json:"source"`

	Title     string    `json:"title,omitempty"`
	Summary   string    `json:"summary,omitempty"`
	Publisher string    `json:"publisher,omitempty"`
	TLP       string    `json:"tlp,omitempty"`
	URL       string    `json:"url,omitempty"`
	Published time.Time `json:"published,omitzero"`
	Updated   time.Time `json:"updated,omitzero"`

	Products        []Product       `json:"products,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	References      []Reference     `json:"references,omitempty"`
	Notes           []Note          `json:"notes,omitempty"`

	// Warnings records anything the reader could not make sense of. They travel
	// with the advisory so that a corpus can be audited for parse quality rather
	// than quietly losing products.
	Warnings []string `json:"warnings,omitempty"`
}

// Product is one leaf of an advisory product tree, flattened.
//
// CSAF nests vendor, family, name and version as branches, and a matcher that
// walked that tree for every asset would be both slow and impossible to explain.
// Flattening happens once, at read time, and every field keeps its raw form
// alongside the normalized one so the evidence view can show both.
type Product struct {
	// ID is the CSAF product_id, which vulnerabilities reference.
	ID string `json:"id"`
	// Name is the full product name as the advisory printed it.
	Name string `json:"name,omitempty"`

	VendorRaw string `json:"vendor_raw,omitempty"`
	Vendor    string `json:"vendor,omitempty"`

	FamilyRaw string `json:"family_raw,omitempty"`
	Family    string `json:"family,omitempty"`

	ProductRaw string `json:"product_raw,omitempty"`
	ProductNam string `json:"product,omitempty"`

	Model         string `json:"model,omitempty"`
	CatalogNumber string `json:"catalog_number,omitempty"`

	// VersionRaw is the branch text, which may be a single version or a range
	// phrase. Version is the parsed form.
	VersionRaw string               `json:"version_raw,omitempty"`
	Version    normalize.Constraint `json:"version"`

	// CPE is almost always empty for ICS advisories. It is kept because when it
	// is present it is the strongest identifier available.
	CPE string `json:"cpe,omitempty"`
}

// Label renders the product for a table row.
func (p Product) Label() string {
	name := firstNonEmpty(p.Name, p.ProductRaw, p.FamilyRaw)

	// A CSAF full product name is usually already "Vendor Thing Version", so
	// prepending the vendor and appending the version produces labels like
	// "ABB ABB 800xA Base 6.2.0-0 6.2.0-0". That string ends up quoted verbatim
	// in a report sent to an auditor, where it reads as a broken tool. The
	// checks are prefix and suffix rather than substring, so a vendor whose name
	// happens to appear inside a product designation is still shown.
	parts := make([]string, 0, 3)
	if vendor := firstNonEmpty(p.VendorRaw, p.Vendor); vendor != "" && !hasPrefixFold(name, vendor) {
		parts = append(parts, vendor)
	}
	if name != "" {
		parts = append(parts, name)
	}
	if p.VersionRaw != "" && !hasSuffixFold(name, p.VersionRaw) {
		parts = append(parts, p.VersionRaw)
	}
	if len(parts) == 0 {
		return p.ID
	}
	return strings.Join(parts, " ")
}

func hasPrefixFold(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func hasSuffixFold(value, suffix string) bool {
	return len(value) >= len(suffix) && strings.EqualFold(value[len(value)-len(suffix):], suffix)
}

// Vulnerability is one CVE within an advisory.
type Vulnerability struct {
	CVE   string `json:"cve,omitempty"`
	Title string `json:"title,omitempty"`
	CWE   string `json:"cwe,omitempty"`
	CWEID string `json:"cwe_id,omitempty"`

	Discovered time.Time `json:"discovered,omitzero"`
	Released   time.Time `json:"released,omitzero"`

	Scores       []Score             `json:"scores,omitempty"`
	Status       map[Status][]string `json:"status,omitempty"`
	Remediations []Remediation       `json:"remediations,omitempty"`
	References   []Reference         `json:"references,omitempty"`
	Notes        []Note              `json:"notes,omitempty"`

	// KEV and EPSS are filled by the enrichment sources rather than by the
	// advisory itself.
	KEV  *KEVEntry `json:"kev,omitempty"`
	EPSS *EPSS     `json:"epss,omitempty"`
}

// Affects reports whether a product id is listed as affected.
func (v Vulnerability) Affects(productID string) bool {
	for _, id := range v.Status[StatusKnownAffected] {
		if id == productID {
			return true
		}
	}
	return false
}

// AffectedProducts returns the product ids this vulnerability is known to affect.
// When the advisory lists no product status at all the caller is told so, because
// the two cases need different handling: an advisory that names no products at all
// applies to every product it lists, while one that names some is precise.
func (v Vulnerability) AffectedProducts() ([]string, bool) {
	ids, ok := v.Status[StatusKnownAffected]
	return ids, ok && len(ids) > 0
}

// BestScore returns the score the matcher should present, preferring the newest
// CVSS version. A single advisory routinely carries both a v3.1 and a v4.0 score,
// and showing whichever came first in the file would be arbitrary.
func (v Vulnerability) BestScore() (Score, bool) {
	best := Score{}
	found := false
	for _, score := range v.Scores {
		if !found || score.BetterThan(best) {
			best, found = score, true
		}
	}
	return best, found
}

// Severity is the qualitative rating of the best score.
func (v Vulnerability) Severity() Severity {
	if score, ok := v.BestScore(); ok {
		return score.Severity
	}
	return SeverityUnknown
}

// Score is one CVSS score attached to a vulnerability.
type Score struct {
	// Version is the CVSS specification version, such as "3.1" or "4.0".
	Version    string   `json:"version"`
	Vector     string   `json:"vector,omitempty"`
	BaseScore  float64  `json:"base_score"`
	Severity   Severity `json:"severity,omitempty"`
	Source     string   `json:"source,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// BetterThan orders scores by CVSS version and then by base score, so that the
// most recent scoring of the same flaw wins.
func (s Score) BetterThan(other Score) bool {
	mine, theirs := cvssRank(s.Version), cvssRank(other.Version)
	if mine != theirs {
		return mine > theirs
	}
	return s.BaseScore > other.BaseScore
}

func cvssRank(version string) int {
	switch {
	case strings.HasPrefix(version, "4"):
		return 4
	case strings.HasPrefix(version, "3"):
		return 3
	case strings.HasPrefix(version, "2"):
		return 2
	default:
		return 0
	}
}

// Remediation is what the advisory says to do about a vulnerability.
type Remediation struct {
	Category   string   `json:"category,omitempty"`
	Details    string   `json:"details,omitempty"`
	URL        string   `json:"url,omitempty"`
	ProductIDs []string `json:"product_ids,omitempty"`
}

// HasFix reports whether the remediation is an actual patch rather than advice to
// work around the problem. Operators triaging an OT site need that distinction:
// a firmware update needs an outage window and a workaround usually does not.
func (r Remediation) HasFix() bool {
	return r.Category == "vendor_fix"
}

// Reference is a link carried by an advisory.
type Reference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary,omitempty"`
	URL      string `json:"url"`
}

// Note is a block of advisory prose.
type Note struct {
	Category string `json:"category,omitempty"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

// KEVEntry records that a CVE is in the CISA Known Exploited Vulnerabilities
// catalogue, which for a plant operator outranks almost any score.
type KEVEntry struct {
	DateAdded         time.Time `json:"date_added,omitzero"`
	DueDate           time.Time `json:"due_date,omitzero"`
	RequiredAction    string    `json:"required_action,omitempty"`
	KnownRansomware   bool      `json:"known_ransomware,omitempty"`
	VulnerabilityName string    `json:"vulnerability_name,omitempty"`
}

// EPSS is the Exploit Prediction Scoring System estimate for a CVE.
type EPSS struct {
	Score      float64   `json:"score"`
	Percentile float64   `json:"percentile"`
	ModelDate  time.Time `json:"model_date,omitzero"`
}

// Normalize resolves vendor and product names against the normalization tables
// and parses every version range.
//
// This runs once when a corpus is built rather than at match time. An advisory
// corpus is read many times and written once, and doing the work at write time
// keeps a match run from re-parsing several thousand range strings.
func (a *Advisory) Normalize(n *normalize.Normalizer) {
	for idx := range a.Products {
		p := &a.Products[idx]

		if p.CatalogNumber == "" {
			if code, ok := orderCodeInName(p.Name, p.ProductRaw); ok {
				p.CatalogNumber = code
			}
		}

		report := n.Identity(p.identity())
		result := report.Result

		// Only a vendor the alias table recognised goes in the canonical field.
		// The normalizer guarantees that of its own result; assigning from the
		// vendor match as well states the requirement at the point that depends
		// on it, since the corpus statistics count an empty value here as a
		// missing alias to contribute.
		p.Vendor = report.Vendor.ID
		p.Family = firstNonEmpty(result.Family, p.Family)
		p.ProductNam = firstNonEmpty(result.Product, p.ProductNam)
		p.Model = firstNonEmpty(result.Model, p.Model)
		p.CatalogNumber = firstNonEmpty(result.CatalogNumber, p.CatalogNumber)

		p.Version = normalize.ParseConstraint(p.VersionRaw)
		if p.VersionRaw == "" {
			// An advisory that names a product and no version means every
			// version of it, which is the common shape for a hardware advisory.
			p.Version.Kind = normalize.ConstraintAll
		}
	}
}

// parentheticalToken finds a bracketed token long enough to be an order code.
var parentheticalToken = regexp.MustCompile(`\(([0-9A-Za-z][0-9A-Za-z .\-/]{5,})\)`)

// orderCodeInName recovers an order code that an advisory printed inside its
// product name rather than in a field of its own.
//
// Siemens does this throughout, publishing "SCALANCE M804PB (6GK5804-0AP00-2AA2)"
// as one string, and Siemens is by a wide margin the largest publisher of ICS
// advisories. A device asked for its identity reports that order code and often
// little else, so leaving the code buried in prose costs the exact matches that
// the strongest tier depends on.
//
// Only a token that a registered order code parser recognises is accepted. The
// same product names carry brackets around region codes and hardware revisions,
// and treating "(EU)" or "(A1)" as an order code would attach advisories to
// whatever else happened to be sold in Europe.
func orderCodeInName(names ...string) (string, bool) {
	for _, name := range names {
		for _, match := range parentheticalToken.FindAllStringSubmatch(name, -1) {
			candidate := strings.TrimSpace(match[1])
			if _, ok := normalize.ParseCatalog(candidate); ok {
				return candidate, true
			}
		}
	}
	return "", false
}

// identity presents the product as an asset identity so that one normalizer
// serves both sides of the match. That symmetry is the point: a vendor string
// spelled the same way in an advisory and on the wire has to reduce to the same
// canonical value, and the only way to guarantee that is to run the same code.
func (p Product) identity() asset.Identity {
	return asset.Identity{
		Vendor:        firstNonEmpty(p.VendorRaw, p.Vendor),
		VendorRaw:     p.VendorRaw,
		Product:       firstNonEmpty(p.ProductRaw, p.Name),
		ProductRaw:    firstNonEmpty(p.ProductRaw, p.Name),
		Family:        p.FamilyRaw,
		Model:         p.Model,
		CatalogNumber: p.CatalogNumber,
	}
}

// ProductByID looks a product up by its CSAF product id.
func (a *Advisory) ProductByID(id string) (*Product, bool) {
	for idx := range a.Products {
		if a.Products[idx].ID == id {
			return &a.Products[idx], true
		}
	}
	return nil, false
}

// CVEs lists the distinct CVE identifiers in the advisory, sorted.
func (a *Advisory) CVEs() []string {
	seen := make(map[string]struct{}, len(a.Vulnerabilities))
	for _, v := range a.Vulnerabilities {
		if v.CVE != "" {
			seen[v.CVE] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for cve := range seen {
		out = append(out, cve)
	}
	sort.Strings(out)
	return out
}

// Severity is the highest severity of any vulnerability in the advisory.
func (a *Advisory) Severity() Severity {
	worst := SeverityUnknown
	for _, v := range a.Vulnerabilities {
		if s := v.Severity(); s.Rank() > worst.Rank() {
			worst = s
		}
	}
	return worst
}

// HasKEV reports whether any CVE in the advisory is known to be exploited.
func (a *Advisory) HasKEV() bool {
	for _, v := range a.Vulnerabilities {
		if v.KEV != nil {
			return true
		}
	}
	return false
}

// MaxEPSS returns the highest exploit prediction score in the advisory.
func (a *Advisory) MaxEPSS() float64 {
	highest := 0.0
	for _, v := range a.Vulnerabilities {
		if v.EPSS != nil && v.EPSS.Score > highest {
			highest = v.EPSS.Score
		}
	}
	return highest
}

// Validate reports problems that would make an advisory useless to the matcher.
func (a *Advisory) Validate() error {
	if a.ID == "" {
		return fmt.Errorf("advisory has no id")
	}
	if a.Source == "" {
		return fmt.Errorf("advisory %s has no source", a.ID)
	}
	if len(a.Products) == 0 && len(a.Vulnerabilities) == 0 {
		return fmt.Errorf("advisory %s names neither a product nor a vulnerability", a.ID)
	}
	seen := make(map[string]struct{}, len(a.Products))
	for _, p := range a.Products {
		if p.ID == "" {
			return fmt.Errorf("advisory %s has a product with no id", a.ID)
		}
		if _, duplicate := seen[p.ID]; duplicate {
			return fmt.Errorf("advisory %s reuses product id %q", a.ID, p.ID)
		}
		seen[p.ID] = struct{}{}
	}
	return nil
}

// Sort orders the contents of an advisory so that writing it twice produces
// identical bytes. Corpora get committed and diffed, so stable output is what
// makes a change reviewable.
func (a *Advisory) Sort() {
	sort.SliceStable(a.Products, func(i, j int) bool { return a.Products[i].ID < a.Products[j].ID })
	sort.SliceStable(a.Vulnerabilities, func(i, j int) bool {
		if a.Vulnerabilities[i].CVE != a.Vulnerabilities[j].CVE {
			return a.Vulnerabilities[i].CVE < a.Vulnerabilities[j].CVE
		}
		return a.Vulnerabilities[i].Title < a.Vulnerabilities[j].Title
	})
	for idx := range a.Vulnerabilities {
		v := &a.Vulnerabilities[idx]
		for status := range v.Status {
			sort.Strings(v.Status[status])
		}
		sort.SliceStable(v.Scores, func(i, j int) bool { return v.Scores[i].BetterThan(v.Scores[j]) })
	}
	sort.SliceStable(a.References, func(i, j int) bool { return a.References[i].URL < a.References[j].URL })
	sort.Strings(a.Warnings)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
