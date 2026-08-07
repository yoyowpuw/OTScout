package advisory

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// CSAF 2.0 is the only advisory format among the sources otscout reads that was
// designed to be parsed. That does not make it easy. The product tree is a
// recursive branch structure with no schema constraint on depth or on which
// categories may nest inside which, and CISA in particular fills in no CPE and no
// product_identification_helper at all, so the only identifying information is the
// branch text itself. This file turns that tree into flat products, and it keeps
// the exact text of every branch it used, because the normalization that follows
// is guesswork and an operator has to be able to check it.

// maxCSAFBytes bounds a single advisory document. Advisories come from the
// network, so a reply that never ends must not be read into memory whole.
const maxCSAFBytes = 32 << 20

// maxBranchDepth stops a document whose branches point at each other, or which is
// simply nested absurdly deep, from exhausting the stack.
const maxBranchDepth = 64

type csafDocument struct {
	Document        csafMeta        `json:"document"`
	ProductTree     csafProductTree `json:"product_tree"`
	Vulnerabilities []csafVuln      `json:"vulnerabilities"`
}

type csafMeta struct {
	Category     string          `json:"category"`
	CSAFVersion  string          `json:"csaf_version"`
	Title        string          `json:"title"`
	Publisher    csafPublisher   `json:"publisher"`
	Tracking     csafTracking    `json:"tracking"`
	Notes        []csafNote      `json:"notes"`
	References   []csafReference `json:"references"`
	Distribution csafDistrib     `json:"distribution"`
	Lang         string          `json:"lang"`
}

type csafPublisher struct {
	Category  string `json:"category"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type csafDistrib struct {
	TLP struct {
		Label string `json:"label"`
	} `json:"tlp"`
}

type csafTracking struct {
	ID                 string    `json:"id"`
	Status             string    `json:"status"`
	Version            string    `json:"version"`
	InitialReleaseDate time.Time `json:"initial_release_date"`
	CurrentReleaseDate time.Time `json:"current_release_date"`
}

type csafNote struct {
	Category string `json:"category"`
	Title    string `json:"title"`
	Text     string `json:"text"`
}

type csafReference struct {
	Category string `json:"category"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

type csafProductTree struct {
	Branches         []csafBranch      `json:"branches"`
	FullProductNames []csafFullProduct `json:"full_product_names"`
	Relationships    []csafRelation    `json:"relationships"`
}

type csafBranch struct {
	Category string           `json:"category"`
	Name     string           `json:"name"`
	Branches []csafBranch     `json:"branches"`
	Product  *csafFullProduct `json:"product"`
}

type csafFullProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
	Helper    *struct {
		CPE    string   `json:"cpe"`
		SBOMs  []string `json:"sbom_urls"`
		Serial []string `json:"serial_numbers"`
		Model  []string `json:"model_numbers"`
		SKUs   []string `json:"skus"`
	} `json:"product_identification_helper"`
}

type csafRelation struct {
	Category                  string          `json:"category"`
	ProductReference          string          `json:"product_reference"`
	RelatesToProductReference string          `json:"relates_to_product_reference"`
	FullProductName           csafFullProduct `json:"full_product_name"`
}

type csafVuln struct {
	CVE           string              `json:"cve"`
	Title         string              `json:"title"`
	CWE           *csafCWE            `json:"cwe"`
	Notes         []csafNote          `json:"notes"`
	References    []csafReference     `json:"references"`
	DiscoveryDate time.Time           `json:"discovery_date"`
	ReleaseDate   time.Time           `json:"release_date"`
	ProductStatus map[string][]string `json:"product_status"`
	Scores        []csafScore         `json:"scores"`
	Remediations  []csafRemed         `json:"remediations"`
	IDs           []struct {
		SystemName string `json:"system_name"`
		Text       string `json:"text"`
	} `json:"ids"`
}

type csafCWE struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// csafScore holds the CVSS objects, which CSAF embeds verbatim from the CVSS JSON
// schema. Only the fields the matcher shows are read.
type csafScore struct {
	Products []string  `json:"products"`
	CVSSv2   *cvssBody `json:"cvss_v2"`
	CVSSv3   *cvssBody `json:"cvss_v3"`
	CVSSv4   *cvssBody `json:"cvss_v4"`
}

type cvssBody struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type csafRemed struct {
	Category string   `json:"category"`
	Details  string   `json:"details"`
	URL      string   `json:"url"`
	Products []string `json:"product_ids"`
}

// ParseCSAF reads one CSAF 2.0 advisory.
func ParseCSAF(r io.Reader, source string) (*Advisory, error) {
	var doc csafDocument
	decoder := json.NewDecoder(io.LimitReader(r, maxCSAFBytes))
	if err := decoder.Decode(&doc); err != nil {
		return nil, fmt.Errorf("parse CSAF document: %w", err)
	}
	return convertCSAF(&doc, source)
}

// ParseCSAFBytes reads one CSAF 2.0 advisory from memory.
func ParseCSAFBytes(data []byte, source string) (*Advisory, error) {
	return ParseCSAF(strings.NewReader(string(data)), source)
}

func convertCSAF(doc *csafDocument, source string) (*Advisory, error) {
	if doc.Document.Tracking.ID == "" {
		return nil, fmt.Errorf("CSAF document has no tracking id")
	}

	adv := &Advisory{
		ID:        doc.Document.Tracking.ID,
		Source:    source,
		Title:     strings.TrimSpace(doc.Document.Title),
		Publisher: strings.TrimSpace(doc.Document.Publisher.Name),
		TLP:       doc.Document.Distribution.TLP.Label,
		Published: doc.Document.Tracking.InitialReleaseDate,
		Updated:   doc.Document.Tracking.CurrentReleaseDate,
	}

	for _, note := range doc.Document.Notes {
		text := collapse(note.Text)
		if text == "" {
			continue
		}
		adv.Notes = append(adv.Notes, Note{Category: note.Category, Title: note.Title, Text: text})
		if adv.Summary == "" && (note.Category == "summary" || note.Category == "description") {
			adv.Summary = text
		}
	}

	for _, ref := range doc.Document.References {
		if ref.URL == "" {
			continue
		}
		adv.References = append(adv.References, Reference{Category: ref.Category, Summary: ref.Summary, URL: ref.URL})
		// The self reference is the canonical location of the advisory, which is
		// what an operator clicks through to.
		if adv.URL == "" && ref.Category == "self" {
			adv.URL = ref.URL
		}
	}
	if adv.URL == "" && len(adv.References) > 0 {
		adv.URL = adv.References[0].URL
	}

	products, warnings := flattenProductTree(&doc.ProductTree)
	adv.Products = products
	adv.Warnings = append(adv.Warnings, warnings...)

	for _, vuln := range doc.Vulnerabilities {
		adv.Vulnerabilities = append(adv.Vulnerabilities, convertVuln(vuln))
	}

	if len(adv.Products) == 0 {
		adv.Warnings = append(adv.Warnings,
			"the product tree yielded no products, so this advisory can never match an asset")
	}
	return adv, nil
}

func convertVuln(in csafVuln) Vulnerability {
	out := Vulnerability{
		CVE:        strings.TrimSpace(in.CVE),
		Title:      strings.TrimSpace(in.Title),
		Discovered: in.DiscoveryDate,
		Released:   in.ReleaseDate,
	}
	if in.CWE != nil {
		out.CWEID = in.CWE.ID
		out.CWE = in.CWE.Name
	}
	// Some publishers put the CVE in the ids list rather than in the cve field.
	if out.CVE == "" {
		for _, id := range in.IDs {
			if strings.HasPrefix(strings.ToUpper(id.Text), "CVE-") {
				out.CVE = strings.ToUpper(id.Text)
				break
			}
		}
	}

	for _, note := range in.Notes {
		if text := collapse(note.Text); text != "" {
			out.Notes = append(out.Notes, Note{Category: note.Category, Title: note.Title, Text: text})
		}
	}
	for _, ref := range in.References {
		if ref.URL != "" {
			out.References = append(out.References, Reference{Category: ref.Category, Summary: ref.Summary, URL: ref.URL})
		}
	}

	if len(in.ProductStatus) > 0 {
		out.Status = make(map[Status][]string, len(in.ProductStatus))
		for name, ids := range in.ProductStatus {
			if len(ids) == 0 {
				continue
			}
			out.Status[Status(name)] = append([]string(nil), ids...)
		}
	}

	for _, score := range in.Scores {
		for _, body := range []*cvssBody{score.CVSSv4, score.CVSSv3, score.CVSSv2} {
			if body == nil {
				continue
			}
			out.Scores = append(out.Scores, Score{
				Version:    firstNonEmpty(body.Version, cvssVersionFromVector(body.VectorString)),
				Vector:     body.VectorString,
				BaseScore:  body.BaseScore,
				Severity:   parseSeverity(body.BaseSeverity, body.BaseScore),
				ProductIDs: append([]string(nil), score.Products...),
			})
		}
	}

	for _, rem := range in.Remediations {
		out.Remediations = append(out.Remediations, Remediation{
			Category:   rem.Category,
			Details:    collapse(rem.Details),
			URL:        rem.URL,
			ProductIDs: append([]string(nil), rem.Products...),
		})
	}
	return out
}

func parseSeverity(label string, score float64) Severity {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "critical":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "none":
		return SeverityNone
	default:
		return SeverityForScore(score)
	}
}

// cvssVersionFromVector recovers the specification version from the vector when
// the version field is missing, which happens in hand assembled documents.
func cvssVersionFromVector(vector string) string {
	if !strings.HasPrefix(vector, "CVSS:") {
		return ""
	}
	rest := vector[len("CVSS:"):]
	if idx := strings.IndexByte(rest, '/'); idx > 0 {
		return rest[:idx]
	}
	return ""
}

// branchContext carries the identity accumulated on the way down the tree.
type branchContext struct {
	vendor  string
	family  string
	product string
	version string
	// versionIsRange records whether the version came from a
	// product_version_range branch, which changes nothing about how it is stored
	// but is worth knowing when a document is being audited.
	versionIsRange bool
	// path is the branch categories walked so far, used in warnings so that a
	// malformed document can actually be found and fixed.
	path []string
}

func (c branchContext) with(category, name string) branchContext {
	next := c
	next.path = append(append([]string(nil), c.path...), category+"="+name)
	switch category {
	case "vendor":
		next.vendor = name
	case "product_family":
		// Nested families are common: "SIMATIC" inside "SIMATIC S7-1500". The
		// deeper one is more specific, so it wins, and the outer one is not
		// discarded but folded in front of it.
		if c.family != "" && !strings.Contains(strings.ToLower(name), strings.ToLower(c.family)) {
			next.family = c.family + " " + name
		} else {
			next.family = name
		}
	case "product_name":
		next.product = name
	case "product_version":
		next.version = name
		next.versionIsRange = false
	case "product_version_range":
		next.version = name
		next.versionIsRange = true
	}
	return next
}

// flattenProductTree walks the branch structure and emits one product per leaf.
func flattenProductTree(tree *csafProductTree) ([]Product, []string) {
	products := make([]Product, 0, 16)
	warnings := make([]string, 0)
	seen := make(map[string]struct{}, 16)

	emit := func(full *csafFullProduct, ctx branchContext) {
		if full == nil || full.ProductID == "" {
			return
		}
		if _, duplicate := seen[full.ProductID]; duplicate {
			// A repeated product id is a document bug. Keeping the first is the
			// only safe choice, since the second may describe something else
			// entirely and vulnerabilities reference the id.
			warnings = append(warnings, fmt.Sprintf(
				"product id %q appears more than once, later definitions were ignored", full.ProductID))
			return
		}
		seen[full.ProductID] = struct{}{}
		products = append(products, buildProduct(full, ctx))
	}

	var walk func(branches []csafBranch, ctx branchContext, depth int)
	walk = func(branches []csafBranch, ctx branchContext, depth int) {
		if depth > maxBranchDepth {
			warnings = append(warnings, fmt.Sprintf(
				"product tree is nested deeper than %d levels at %s, the rest was not read",
				maxBranchDepth, strings.Join(ctx.path, " / ")))
			return
		}
		for _, branch := range branches {
			next := ctx.with(branch.Category, branch.Name)
			if branch.Product != nil {
				emit(branch.Product, next)
			}
			if len(branch.Branches) > 0 {
				walk(branch.Branches, next, depth+1)
			}
			// A branch that is neither a leaf nor a parent carries no product and
			// is silently ignored, which is correct: intermediate branches are
			// how the tree expresses shared context.
		}
	}
	walk(tree.Branches, branchContext{}, 0)

	// Products declared outside the tree have no branch context at all, so
	// whatever identity they carry has to come from the name itself.
	for idx := range tree.FullProductNames {
		emit(&tree.FullProductNames[idx], branchContext{})
	}

	// A relationship defines a new product in terms of two existing ones, as in
	// "software X installed on hardware Y". The new product inherits from the
	// component being described rather than from what it is installed on, since
	// that is the thing the advisory is about.
	byID := make(map[string]*Product, len(products))
	for idx := range products {
		byID[products[idx].ID] = &products[idx]
	}
	for idx := range tree.Relationships {
		rel := &tree.Relationships[idx]
		if rel.FullProductName.ProductID == "" {
			continue
		}
		ctx := branchContext{}
		if base, ok := byID[rel.ProductReference]; ok {
			ctx.vendor, ctx.family = base.VendorRaw, base.FamilyRaw
			ctx.product, ctx.version = base.ProductRaw, base.VersionRaw
		}
		emit(&rel.FullProductName, ctx)
	}

	return products, warnings
}

func buildProduct(full *csafFullProduct, ctx branchContext) Product {
	p := Product{
		ID:         full.ProductID,
		Name:       strings.TrimSpace(full.Name),
		VendorRaw:  strings.TrimSpace(ctx.vendor),
		FamilyRaw:  strings.TrimSpace(ctx.family),
		ProductRaw: strings.TrimSpace(ctx.product),
		VersionRaw: strings.TrimSpace(ctx.version),
	}
	if full.Helper != nil {
		p.CPE = full.Helper.CPE
		if len(full.Helper.Model) > 0 {
			p.Model = full.Helper.Model[0]
		}
		if len(full.Helper.SKUs) > 0 {
			p.CatalogNumber = full.Helper.SKUs[0]
		}
	}
	// The full name is the only identity a product declared outside the tree has,
	// so it stands in for the product branch when there was none.
	if p.ProductRaw == "" && p.FamilyRaw == "" {
		p.ProductRaw = p.Name
	}
	return p
}

// collapse trims a text block down to a single line of ordinary spaces. Advisory
// prose reaches HTML reports and terminal output, and the line breaks and runs of
// whitespace publishers leave in it serve no purpose in either.
func collapse(text string) string {
	return strings.Join(strings.Fields(text), " ")
}

// parseFloat reads a number that a CSV source wrote as text, returning zero for
// anything unreadable rather than failing the whole file.
func parseFloat(raw string) float64 {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0
	}
	return value
}
