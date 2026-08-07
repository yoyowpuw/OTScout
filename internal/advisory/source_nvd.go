package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// NVD is used for one narrow purpose: filling in a CVSS score for a CVE that an
// ICS advisory named without scoring. It is deliberately not used as a source of
// products. NVD CPE data for industrial equipment is sparse and frequently wrong,
// and a wrong product match in an OT inventory costs an engineer a site visit.
//
// The API is rate limited hard for anonymous callers, so this source only asks
// about CVEs already in the corpus that carry no score, and it asks in batches.

// NVDSource enriches CVEs that have no score.
type NVDSource struct {
	Meta Info
	// BaseURL is the CVE API 2.0 endpoint.
	BaseURL string
	// APIKey raises the upstream rate limit when the operator has one.
	APIKey string
	// MaxLookups bounds a single run, since an unscored backlog of thousands
	// would otherwise take hours at the anonymous rate.
	MaxLookups int
}

func (s *NVDSource) Info() Info { return s.Meta }

// nvdResponse is the subset of the CVE API 2.0 shape that carries scores.
type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			LastModified string `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV40 []nvdMetric `json:"cvssMetricV40"`
				CVSSMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CVSSMetricV30 []nvdMetric `json:"cvssMetricV30"`
				CVSSMetricV2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`
			Weaknesses []struct {
				Description []struct {
					Lang  string `json:"lang"`
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
	BaseSeverity string `json:"baseSeverity"`
}

// NVDLookup is what this source contributes, keyed by CVE.
type NVDLookup struct {
	Scores      []Score `json:"scores,omitempty"`
	Description string  `json:"description,omitempty"`
	CWE         string  `json:"cwe,omitempty"`
}

// Sync is refused on its own, because this source has no feed to walk. It works
// from the corpus, which is what EnrichCorpus is given.
func (s *NVDSource) Sync(context.Context, *Env) (*Result, error) {
	return nil, fmt.Errorf("the NVD source enriches an existing corpus and has no feed of its own to sync")
}

// EnrichCorpus fills in scores for the CVEs the advisory sources left unscored.
func (s *NVDSource) EnrichCorpus(ctx context.Context, env *Env, corpus *Corpus) (*Result, error) {
	unscored := UnscoredCVEs(corpus)
	if len(unscored) == 0 {
		env.progressf("  every CVE in the corpus already carries a score\n")
		return &Result{}, nil
	}
	env.progressf("  %d CVEs in the corpus have no score\n", len(unscored))

	lookups, result, err := s.Enrich(ctx, env, unscored)
	if err != nil {
		return nil, err
	}
	filled := ApplyNVD(corpus, lookups)
	env.progressf("  filled in %d scores\n", filled)
	return result, nil
}

// Enrich looks up the given CVEs and returns what NVD knows about them.
func (s *NVDSource) Enrich(ctx context.Context, env *Env, cves []string) (map[string]NVDLookup, *Result, error) {
	result := &Result{}
	out := make(map[string]NVDLookup, len(cves))

	limit := s.MaxLookups
	if limit <= 0 {
		limit = 200
	}
	if len(cves) > limit {
		result.warn("looked up the first %d of %d unscored CVEs, run sync again to continue", limit, len(cves))
		cves = cves[:limit]
	}

	for _, cve := range cves {
		if err := ctx.Err(); err != nil {
			return out, result, err
		}
		if !looksLikeCVE(cve) {
			continue
		}
		lookup, err := s.fetchOne(ctx, env, cve)
		if err != nil {
			result.warn("look up %s: %v", cve, err)
			continue
		}
		result.Records++
		if lookup != nil {
			out[cve] = *lookup
		}
	}
	return out, result, nil
}

func (s *NVDSource) fetchOne(ctx context.Context, env *Env, cve string) (*NVDLookup, error) {
	endpoint := s.BaseURL
	if endpoint == "" {
		endpoint = defaultNVDEndpoint
	}
	query := url.Values{}
	query.Set("cveId", cve)

	var headers map[string]string
	if s.APIKey != "" {
		headers = map[string]string{"apiKey": s.APIKey}
	}
	body, _, err := env.Fetcher.GetWithHeaders(ctx, endpoint+"?"+query.Encode(), headers)
	if err != nil {
		return nil, err
	}

	var response nvdResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("parse NVD response: %w", err)
	}
	if len(response.Vulnerabilities) == 0 {
		return nil, nil
	}

	entry := response.Vulnerabilities[0].CVE
	lookup := &NVDLookup{}
	for _, description := range entry.Descriptions {
		if description.Lang == "en" {
			lookup.Description = collapse(description.Value)
			break
		}
	}
	for _, weakness := range entry.Weaknesses {
		for _, description := range weakness.Description {
			if strings.HasPrefix(description.Value, "CWE-") {
				lookup.CWE = description.Value
				break
			}
		}
		if lookup.CWE != "" {
			break
		}
	}

	metricSets := [][]nvdMetric{
		entry.Metrics.CVSSMetricV40,
		entry.Metrics.CVSSMetricV31,
		entry.Metrics.CVSSMetricV30,
		entry.Metrics.CVSSMetricV2,
	}
	for _, metrics := range metricSets {
		for _, metric := range metrics {
			// Only the primary scoring is taken. NVD carries secondary scorings
			// from vendors that frequently disagree, and presenting several
			// scores for one flaw helps nobody triage.
			if metric.Type != "" && !strings.EqualFold(metric.Type, "Primary") {
				continue
			}
			severity := firstNonEmpty(metric.CVSSData.BaseSeverity, metric.BaseSeverity)
			lookup.Scores = append(lookup.Scores, Score{
				Version:   metric.CVSSData.Version,
				Vector:    metric.CVSSData.VectorString,
				BaseScore: metric.CVSSData.BaseScore,
				Severity:  parseSeverity(severity, metric.CVSSData.BaseScore),
				Source:    "nvd",
			})
		}
	}
	return lookup, nil
}

const defaultNVDEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// ApplyNVD folds NVD lookups into a corpus, filling only what is missing.
//
// An advisory's own score always wins. The vendor who wrote the advisory knows
// their product, and NVD scores for ICS flaws are often assigned generically.
func ApplyNVD(corpus *Corpus, lookups map[string]NVDLookup) int {
	filled := 0
	for idx := range corpus.Advisories {
		for vIdx := range corpus.Advisories[idx].Vulnerabilities {
			vuln := &corpus.Advisories[idx].Vulnerabilities[vIdx]
			lookup, ok := lookups[vuln.CVE]
			if !ok {
				continue
			}
			if len(vuln.Scores) == 0 && len(lookup.Scores) > 0 {
				vuln.Scores = append(vuln.Scores, lookup.Scores...)
				filled++
			}
			if vuln.CWEID == "" {
				vuln.CWEID = lookup.CWE
			}
		}
	}
	return filled
}

// UnscoredCVEs lists the CVEs in a corpus that carry no score, which is what the
// NVD source is asked to fill in.
func UnscoredCVEs(corpus *Corpus) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0, 64)
	for idx := range corpus.Advisories {
		for _, vuln := range corpus.Advisories[idx].Vulnerabilities {
			if vuln.CVE == "" || len(vuln.Scores) > 0 {
				continue
			}
			if _, done := seen[vuln.CVE]; done {
				continue
			}
			seen[vuln.CVE] = struct{}{}
			out = append(out, vuln.CVE)
		}
	}
	return sortedStrings(out)
}

func init() {
	register(&NVDSource{
		BaseURL:    defaultNVDEndpoint,
		MaxLookups: 200,
		Meta: Info{
			ID:              "nvd",
			Name:            "NVD CVSS scores",
			Kind:            KindEnrichment,
			Homepage:        "https://nvd.nist.gov/",
			License:         "public domain (US government work)",
			Redistributable: true,
			// Off by default because the anonymous rate limit makes a first run
			// slow, and because most ICS advisories already carry their own score.
			DefaultEnabled: false,
			Summary:        "Fills in a CVSS score for CVEs that an advisory named without scoring.",
		},
	})
}
