package advisory

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// EPSS estimates the probability that a CVE will be exploited in the next thirty
// days. It complements KEV rather than duplicating it: KEV is a record of what has
// already happened, EPSS is a forecast, and an OT site with a narrow maintenance
// window needs both to order its work.
//
// The published file is a gzipped CSV of every scored CVE, which is a few
// megabytes. It is downloaded whole because there is no incremental form, and it
// is refreshed daily upstream.

// EPSSSource reads the daily EPSS scores.
type EPSSSource struct {
	Meta Info
	URL  string
}

func (s *EPSSSource) Info() Info { return s.Meta }

// maxEPSSRows bounds the CSV. The real file holds a few hundred thousand rows, so
// this leaves ample headroom while still refusing a file that never ends.
const maxEPSSRows = 5_000_000

func (s *EPSSSource) Sync(ctx context.Context, env *Env) (*Result, error) {
	body, cached, err := env.Fetcher.Get(ctx, s.URL)
	if err != nil {
		return nil, err
	}
	if cached {
		env.progressf("  scores unchanged\n")
	}

	reader, err := maybeGunzip(body)
	if err != nil {
		return nil, err
	}

	result := &Result{EPSS: make(map[string]EPSS, 1024)}
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1<<20)

	var (
		modelDate time.Time
		columns   map[string]int
		rows      int
	)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// The file opens with a comment line carrying the model version and the
		// date the scores were computed, which is worth keeping so a stale corpus
		// can be recognised.
		if strings.HasPrefix(line, "#") {
			if date := epssModelDate(line); !date.IsZero() {
				modelDate = date
			}
			continue
		}

		fields := strings.Split(line, ",")
		if columns == nil {
			columns = make(map[string]int, len(fields))
			for idx, name := range fields {
				columns[strings.ToLower(strings.TrimSpace(name))] = idx
			}
			if _, ok := columns["cve"]; !ok {
				return nil, fmt.Errorf("EPSS file at %s has no cve column", s.URL)
			}
			continue
		}

		rows++
		if rows > maxEPSSRows {
			result.warn("stopped after %d rows", maxEPSSRows)
			break
		}

		cve := strings.ToUpper(strings.TrimSpace(column(fields, columns, "cve")))
		if !looksLikeCVE(cve) {
			continue
		}
		result.EPSS[cve] = EPSS{
			Score:      parseFloat(column(fields, columns, "epss")),
			Percentile: parseFloat(column(fields, columns, "percentile")),
			ModelDate:  modelDate,
		}
		result.Records++
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read EPSS file: %w", err)
	}
	if result.Records == 0 {
		return nil, fmt.Errorf("EPSS file at %s yielded no scores", s.URL)
	}
	env.progressf("  %d scores\n", result.Records)
	return result, nil
}

func column(fields []string, columns map[string]int, name string) string {
	idx, ok := columns[name]
	if !ok || idx >= len(fields) {
		return ""
	}
	return fields[idx]
}

// epssModelDate reads the score date out of the header comment, which looks like
// "#model_version:v2023.03.01,score_date:2026-03-04T00:00:00+0000".
func epssModelDate(line string) time.Time {
	for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
		key, value, found := strings.Cut(part, ":")
		if !found || strings.TrimSpace(key) != "score_date" {
			continue
		}
		value = strings.TrimSpace(value)
		for _, layout := range []string{"2006-01-02T15:04:05-0700", time.RFC3339, "2006-01-02"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed.UTC()
			}
		}
	}
	return time.Time{}
}

// maybeGunzip transparently decompresses, since the same feed is served both ways
// depending on whether the transport already decoded it.
func maybeGunzip(body []byte) (io.Reader, error) {
	if len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		return bytes.NewReader(body), nil
	}
	gz, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("decompress: %w", err)
	}
	return gz, nil
}

func init() {
	register(&EPSSSource{
		URL: "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
		Meta: Info{
			ID:              "epss",
			Name:            "EPSS exploit prediction scores",
			Kind:            KindEnrichment,
			Homepage:        "https://www.first.org/epss/",
			License:         "free for public use, see the FIRST EPSS terms",
			Redistributable: true,
			DefaultEnabled:  true,
			Summary:         "Daily probability that each CVE will be exploited in the next thirty days.",
		},
	})
}
