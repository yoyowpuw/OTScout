package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// KEV is the single most useful piece of prioritisation data available for an OT
// site. A CVSS score says how bad a flaw could be in theory; the CISA Known
// Exploited Vulnerabilities catalogue says someone has actually been seen using
// it. When a plant can take one outage window this quarter, that is the
// distinction that decides what goes in it.

// KEVSource reads the CISA KEV catalogue.
type KEVSource struct {
	Meta Info
	URL  string
}

func (s *KEVSource) Info() Info { return s.Meta }

type kevCatalog struct {
	Title           string `json:"title"`
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Count           int    `json:"count"`
	Vulnerabilities []struct {
		CveID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		ShortDescription           string `json:"shortDescription"`
		RequiredAction             string `json:"requiredAction"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

func (s *KEVSource) Sync(ctx context.Context, env *Env) (*Result, error) {
	body, cached, err := env.Fetcher.Get(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	if cached {
		env.progressf("  catalogue unchanged\n")
	}

	var catalog kevCatalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil, fmt.Errorf("parse KEV catalogue: %w", err)
	}
	if len(catalog.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("KEV catalogue at %s contained no entries", s.URL)
	}

	result := &Result{KEV: make(map[string]KEVEntry, len(catalog.Vulnerabilities))}
	for _, entry := range catalog.Vulnerabilities {
		cve := strings.ToUpper(strings.TrimSpace(entry.CveID))
		if !looksLikeCVE(cve) {
			result.warn("skipping KEV entry with unreadable identifier %q", entry.CveID)
			continue
		}
		result.KEV[cve] = KEVEntry{
			DateAdded:         parseDay(entry.DateAdded),
			DueDate:           parseDay(entry.DueDate),
			RequiredAction:    collapse(entry.RequiredAction),
			KnownRansomware:   strings.EqualFold(strings.TrimSpace(entry.KnownRansomwareCampaignUse), "known"),
			VulnerabilityName: collapse(entry.VulnerabilityName),
		}
		result.Records++
	}
	env.progressf("  %d exploited vulnerabilities\n", result.Records)
	return result, nil
}

// parseDay reads the plain calendar dates these catalogues use.
func parseDay(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02", time.RFC3339, "2006/01/02", "01/02/2006"} {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.UTC()
		}
	}
	return time.Time{}
}

// looksLikeCVE checks the shape of an identifier before it is used as a map key,
// so that a malformed feed cannot fill the corpus with junk keys that silently
// never match anything.
func looksLikeCVE(id string) bool {
	if !strings.HasPrefix(id, "CVE-") {
		return false
	}
	parts := strings.Split(id, "-")
	if len(parts) != 3 || len(parts[1]) != 4 || len(parts[2]) < 4 {
		return false
	}
	for _, part := range parts[1:] {
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func init() {
	register(&KEVSource{
		URL: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
		Meta: Info{
			ID:              "cisa-kev",
			Name:            "CISA Known Exploited Vulnerabilities",
			Kind:            KindEnrichment,
			Homepage:        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
			License:         "public domain (US government work)",
			Redistributable: true,
			DefaultEnabled:  true,
			Summary:         "Marks the CVEs that have been observed in real attacks, which outranks any score when deciding what to patch first.",
		},
	})
}
