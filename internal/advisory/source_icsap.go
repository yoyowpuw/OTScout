package advisory

import (
	"bytes"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// The ICS Advisory Project maintains a hand curated CSV of every CISA ICS
// advisory, with the vendor and product columns cleaned up by people who read the
// advisories. That cleanup is worth having even though the same advisories are
// available as CSAF: the CSAF product tree often carries a marketing product name
// where the CSV carries the name an operator would recognise, and the CSV names
// the affected version inline where CSAF sometimes leaves it out.
//
// It is published under the Open Database License, which is share-alike. A corpus
// built from it inherits that condition, which is why it is off by default and
// recorded as not redistributable: shipping it inside a combined release artefact
// would put the licence of the whole artefact in question.

// ICSAPSource reads the ICS Advisory Project CSV.
type ICSAPSource struct {
	Meta Info
	URL  string
}

func (s *ICSAPSource) Info() Info { return s.Meta }

// maxCSVRecords bounds the file, which holds a few thousand rows in practice.
const maxCSVRecords = 500_000

// icsapColumns maps each canonical field to the column names the file has used.
// The project has renamed columns between releases, so several spellings are
// accepted, and a missing required one is reported rather than silently producing
// empty advisories.
var icsapColumns = map[string][]string{
	"id":        {"ics-cert_number", "ics_cert_number", "advisory_number"},
	"title":     {"ics-cert_advisory_title", "advisory_title", "title"},
	"vendor":    {"vendor", "vendor_name"},
	"product":   {"product", "product_name"},
	"affected":  {"products_affected", "affected_products", "product_version"},
	"cves":      {"cve_number", "cve", "cves"},
	"cvss":      {"cumulative_cvss", "cvss_score", "cvss", "cvss_v3_score"},
	"severity":  {"cvss_severity", "severity"},
	"cwe":       {"cwe_number", "cwe"},
	"published": {"original_release_date", "release_date", "published"},
	"updated":   {"last_updated", "updated"},
	"sector":    {"critical_infrastructure_sector", "critical_infrastructure_sectors", "sectors"},
	"license":   {"license", "licence"},
}

func (s *ICSAPSource) Sync(ctx context.Context, env *Env) (*Result, error) {
	body, _, err := env.Fetcher.Get(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	return s.parse(ctx, bytes.NewReader(body), env)
}

func (s *ICSAPSource) parse(ctx context.Context, r io.Reader, env *Env) (*Result, error) {
	reader := csv.NewReader(r)
	// The file has a ragged history, so the column count is not enforced and a
	// short row is padded rather than failing the whole download.
	reader.FieldsPerRecord = -1
	reader.LazyQuotes = true

	header, err := reader.Read()
	if err != nil {
		return nil, fmt.Errorf("read CSV header: %w", err)
	}
	index := indexColumns(header, icsapColumns)
	for _, required := range []string{"id", "vendor"} {
		if _, ok := index[required]; !ok {
			return nil, fmt.Errorf("CSV at %s has no column for %s, its format has changed", s.URL, required)
		}
	}

	result := &Result{}
	byID := make(map[string]*Advisory, 4096)
	order := make([]string, 0, 4096)

	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		row, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			result.warn("skipping unreadable CSV row: %v", err)
			continue
		}
		result.Records++
		if result.Records > maxCSVRecords {
			result.warn("stopped after %d rows", maxCSVRecords)
			break
		}

		id := strings.TrimSpace(field(row, index, "id"))
		if id == "" {
			continue
		}

		adv, exists := byID[id]
		if !exists {
			adv = &Advisory{
				ID:        id,
				Source:    s.Meta.ID,
				Title:     collapse(field(row, index, "title")),
				Publisher: "ICS Advisory Project",
				URL:       cisaAdvisoryURL(id),
				Published: parseDay(field(row, index, "published")),
				Updated:   parseDay(field(row, index, "updated")),
			}
			byID[id] = adv
			order = append(order, id)
		}

		// Each row is one vendor's products within one advisory, so rows
		// accumulate into the advisory rather than replacing it. Forty of the
		// advisories in the file span several rows for exactly this reason.
		vendor := collapse(field(row, index, "vendor"))
		s.addProducts(adv, vendor, field(row, index, "affected"), field(row, index, "product"))
		s.addVulnerabilities(adv, row, index)

		if sector := collapse(field(row, index, "sector")); sector != "" && !hasNote(adv, sector) {
			adv.Notes = append(adv.Notes, Note{Category: "general", Title: "Sectors", Text: sector})
		}
	}

	// Every product of an advisory is affected by every CVE it lists, because the
	// CSV carries no per product status. Recording that explicitly rather than
	// leaving it implicit means the matcher does not have to guess and the
	// evidence trail can say where the assumption came from.
	for _, id := range order {
		adv := byID[id]
		ids := make([]string, 0, len(adv.Products))
		for _, product := range adv.Products {
			ids = append(ids, product.ID)
		}
		for idx := range adv.Vulnerabilities {
			adv.Vulnerabilities[idx].Status = map[Status][]string{StatusKnownAffected: ids}
		}
		if len(adv.Products) == 0 && len(adv.Vulnerabilities) == 0 {
			continue
		}
		if len(adv.Products) == 0 {
			adv.Warnings = append(adv.Warnings,
				"the row named no product, so this advisory can never match an asset")
		}
		result.Advisories = append(result.Advisories, *adv)
	}

	if len(result.Advisories) == 0 {
		return nil, fmt.Errorf("CSV at %s yielded no advisories", s.URL)
	}
	env.progressf("  %d advisories from %d rows\n", len(result.Advisories), result.Records)
	return result, nil
}

// productSeparator is what the affected products cell uses between entries.
//
// The spaces matter. A pipe with no spaces around it appears inside a single
// entry, as in "ControlLogix 5580 >=V36|<=V37", where it joins two halves of one
// version range. Splitting on a bare pipe would tear that entry in half and
// invent a product called "<=V37".
const productSeparator = " | "

// addProducts turns the affected products cell into one product per entry.
func (s *ICSAPSource) addProducts(adv *Advisory, vendor, affected, fallback string) {
	entries := strings.Split(affected, productSeparator)
	if strings.TrimSpace(affected) == "" {
		// Some rows name the product only in the summary column.
		entries = []string{fallback}
	}

	for _, entry := range entries {
		name, version := splitProductVersion(entry)
		if name == "" && version == "" {
			continue
		}
		if name == "" {
			// A version with no product attached cannot be matched against
			// anything, and guessing which product it belongs to would be
			// inventing data.
			adv.Warnings = append(adv.Warnings,
				fmt.Sprintf("affected entry %q named a version with no product", collapse(entry)))
			continue
		}
		adv.Products = append(adv.Products, Product{
			ID:         fmt.Sprintf("%s-%d", adv.ID, len(adv.Products)+1),
			Name:       strings.TrimSpace(vendor + " " + name),
			VendorRaw:  vendor,
			ProductRaw: name,
			VersionRaw: version,
		})
	}
}

// splitProductVersion separates a product name from the version constraint the
// file appends to it, as in "RadiAnt DICOM <=2025.2".
//
// The split happens only at an explicit comparison operator. A trailing token
// that merely looks like a version is left as part of the name, because ICS
// product names are full of them: "MXR300-16" and "1756-EN4TR" are model numbers,
// and reading either as a version would produce a product nobody can match and a
// range that is simply wrong.
func splitProductVersion(entry string) (name, version string) {
	trimmed := strings.TrimSpace(entry)
	if trimmed == "" {
		return "", ""
	}

	idx := strings.IndexAny(trimmed, "<>=")
	if idx < 0 {
		return trimmed, ""
	}
	return strings.TrimSpace(trimmed[:idx]), strings.TrimSpace(trimmed[idx:])
}

func (s *ICSAPSource) addVulnerabilities(adv *Advisory, row []string, index map[string]int) {
	score := parseFloat(field(row, index, "cvss"))
	severity := parseSeverity(field(row, index, "severity"), score)
	cwe := strings.TrimSpace(field(row, index, "cwe"))

	for _, cve := range splitList(field(row, index, "cves")) {
		cve = strings.ToUpper(strings.TrimSpace(cve))
		if !looksLikeCVE(cve) || hasCVE(adv, cve) {
			continue
		}
		vuln := Vulnerability{CVE: cve}
		if strings.HasPrefix(cwe, "CWE-") {
			vuln.CWEID = cwe
		}
		if score > 0 {
			// The file publishes one cumulative score per advisory rather than
			// one per CVE, so it is recorded as coming from this source and not
			// presented as the vendor's own scoring of that CVE.
			vuln.Scores = append(vuln.Scores, Score{
				Version:   "3.1",
				BaseScore: score,
				Severity:  severity,
				Source:    s.Meta.ID,
			})
		}
		adv.Vulnerabilities = append(adv.Vulnerabilities, vuln)
	}
}

// cisaAdvisoryURL builds the link to the human readable advisory. The file
// carries no link column, and an operator triaging a finding needs somewhere to
// click through to.
func cisaAdvisoryURL(id string) string {
	lower := strings.ToLower(strings.TrimSpace(id))
	switch {
	case strings.HasPrefix(lower, "icsma-"):
		return "https://www.cisa.gov/news-events/ics-medical-advisories/" + lower
	case strings.HasPrefix(lower, "icsa-"), strings.HasPrefix(lower, "icsv-"):
		return "https://www.cisa.gov/news-events/ics-advisories/" + lower
	default:
		return ""
	}
}

func hasCVE(adv *Advisory, cve string) bool {
	for _, v := range adv.Vulnerabilities {
		if v.CVE == cve {
			return true
		}
	}
	return false
}

func hasNote(adv *Advisory, text string) bool {
	for _, note := range adv.Notes {
		if note.Text == text {
			return true
		}
	}
	return false
}

// indexColumns resolves the canonical field names against a header row.
func indexColumns(header []string, wanted map[string][]string) map[string]int {
	positions := make(map[string]int, len(header))
	for idx, name := range header {
		positions[normaliseColumnName(name)] = idx
	}

	out := make(map[string]int, len(wanted))
	for field, candidates := range wanted {
		for _, candidate := range candidates {
			if idx, ok := positions[normaliseColumnName(candidate)]; ok {
				out[field] = idx
				break
			}
		}
	}
	return out
}

// normaliseColumnName reduces a header cell to a comparable key, since the file
// has used spaces, underscores, hyphens and mixed case for the same column.
func normaliseColumnName(raw string) string {
	var sb strings.Builder
	sb.Grow(len(raw))
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func field(row []string, index map[string]int, name string) string {
	idx, ok := index[name]
	if !ok || idx >= len(row) {
		return ""
	}
	return row[idx]
}

// splitList breaks a cell that holds several values, which this file does with
// commas, semicolons and newlines depending on the column.
func splitList(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == ' '
	})
}

func init() {
	register(&ICSAPSource{
		URL: "https://raw.githubusercontent.com/icsadvprj/ICS-Advisory-Project/main/ICS-CERT_ADV/CISA_ICS_ADV_Master.csv",
		Meta: Info{
			ID:       "ics-advisory-project",
			Name:     "ICS Advisory Project",
			Kind:     KindAdvisories,
			Homepage: "https://www.icsadvisoryproject.com/",
			License:  "Open Database License (ODbL) v1.0",
			// ODbL is share-alike. A combined release artefact containing this
			// would inherit that condition, so the answer here is no until
			// someone has decided that is acceptable.
			Redistributable: false,
			DefaultEnabled:  false,
			Summary:         "A curated CSV of CISA ICS advisories with the vendor, product and affected version cleaned up by hand.",
		},
	})
}
