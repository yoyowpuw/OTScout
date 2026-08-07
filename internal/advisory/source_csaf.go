package advisory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// A CSAF provider publishes a provider-metadata.json that points at one or more
// distributions. Each distribution offers a ROLIE feed, a directory listing, or
// both. One reader covers every provider, which is what makes adding a vendor
// feed a matter of adding a table entry rather than writing code.
//
// The discovery order below is deliberate. ROLIE carries a per entry update
// timestamp, so an incremental sync can skip documents that have not changed
// without downloading them. A plain index.txt carries no timestamps at all, so it
// is only used when there is no feed.

// CSAFSource reads any CSAF 2.0 provider.
type CSAFSource struct {
	Meta Info
	// ProviderMetadata is the provider-metadata.json URL.
	ProviderMetadata string
	// DocumentHosts names hosts other than the metadata host that this provider
	// is permitted to serve feeds and documents from. It exists because CISA
	// publishes its metadata on cisa.gov and its documents on GitHub, and it is
	// a fixed list rather than whatever the feed asks for, so that a tampered
	// feed cannot widen it.
	DocumentHosts []string
}

func (s *CSAFSource) Info() Info { return s.Meta }

type csafProviderMetadata struct {
	CanonicalURL string `json:"canonical_url"`
	Publisher    struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
	} `json:"publisher"`
	Distributions []struct {
		DirectoryURL string `json:"directory_url"`
		Rolie        *struct {
			Feeds []struct {
				Summary  string `json:"summary"`
				TLPLabel string `json:"tlp_label"`
				URL      string `json:"url"`
			} `json:"feeds"`
		} `json:"rolie"`
	} `json:"distributions"`
}

// rolieFeed is the subset of the ROLIE JSON feed format CSAF uses.
type rolieFeed struct {
	Feed struct {
		ID      string    `json:"id"`
		Title   string    `json:"title"`
		Updated time.Time `json:"updated"`
		Entry   []struct {
			ID      string    `json:"id"`
			Title   string    `json:"title"`
			Updated time.Time `json:"updated"`
			Link    []struct {
				Rel  string `json:"rel"`
				HRef string `json:"href"`
			} `json:"link"`
			Format struct {
				Schema  string `json:"schema"`
				Version string `json:"version"`
			} `json:"format"`
		} `json:"entry"`
	} `json:"feed"`
}

// Sync downloads every advisory the provider offers.
func (s *CSAFSource) Sync(ctx context.Context, env *Env) (*Result, error) {
	result := &Result{}

	metadata, _, err := env.Fetcher.Get(ctx, s.ProviderMetadata)
	if err != nil {
		return nil, fmt.Errorf("read provider metadata: %w", err)
	}
	var provider csafProviderMetadata
	if err := json.Unmarshal(metadata, &provider); err != nil {
		if looksLikeHTML(metadata) {
			// Several vendors answer a missing CSAF path with their ordinary web
			// page and an HTTP 200. Reporting a JSON syntax error for that sends
			// whoever reads it looking for a broken feed rather than a moved one.
			return nil, fmt.Errorf(
				"%s returned a web page rather than CSAF metadata, so the provider has moved it. "+
					"the current location is published in that vendor's security.txt", s.ProviderMetadata)
		}
		return nil, fmt.Errorf("parse provider metadata at %s: %w", s.ProviderMetadata, err)
	}

	documents, err := s.discover(ctx, env, &provider, result)
	if err != nil {
		return nil, err
	}
	if len(documents) == 0 {
		return nil, fmt.Errorf("provider %s listed no advisory documents", s.ProviderMetadata)
	}

	env.progressf("  %d advisory documents listed\n", len(documents))
	if env.MaxDocuments > 0 && len(documents) > env.MaxDocuments {
		result.warn("stopped at the %d document limit, %d were listed", env.MaxDocuments, len(documents))
		documents = documents[:env.MaxDocuments]
	}

	seen := make(map[string]struct{}, len(documents))
	for _, doc := range documents {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, _, err := env.Fetcher.Get(ctx, doc.url)
		if err != nil {
			// One bad document out of several thousand is normal and must not
			// cost the whole sync.
			result.warn("fetch %s: %v", doc.url, err)
			continue
		}
		result.Records++

		adv, err := ParseCSAFBytes(body, s.Meta.ID)
		if err != nil {
			result.warn("parse %s: %v", doc.url, err)
			continue
		}
		if err := adv.Validate(); err != nil {
			result.warn("%s: %v", doc.url, err)
			continue
		}
		if _, duplicate := seen[adv.ID]; duplicate {
			result.warn("advisory %s was listed more than once, the later copy was ignored", adv.ID)
			continue
		}
		seen[adv.ID] = struct{}{}

		if adv.URL == "" {
			adv.URL = doc.url
		}
		if adv.Publisher == "" {
			adv.Publisher = provider.Publisher.Name
		}
		result.Advisories = append(result.Advisories, *adv)
	}

	if len(result.Advisories) == 0 {
		return nil, fmt.Errorf("no advisory in %s could be read", s.ProviderMetadata)
	}
	return result, nil
}

// looksLikeHTML recognises a web page served where JSON was asked for.
func looksLikeHTML(body []byte) bool {
	head := strings.ToLower(strings.TrimSpace(string(body[:min(len(body), 512)])))
	return strings.HasPrefix(head, "<!doctype html") || strings.HasPrefix(head, "<html")
}

type csafDocumentRef struct {
	url     string
	updated time.Time
}

// discover builds the list of advisory URLs the provider offers.
func (s *CSAFSource) discover(ctx context.Context, env *Env, provider *csafProviderMetadata, result *Result) ([]csafDocumentRef, error) {
	seen := make(map[string]struct{})
	out := make([]csafDocumentRef, 0, 512)

	for _, dist := range provider.Distributions {
		if dist.Rolie == nil {
			continue
		}
		for _, feed := range dist.Rolie.Feeds {
			// Only the public feed is read. A provider can advertise amber and
			// red feeds that need credentials otscout does not have and should
			// not be asking for.
			if label := strings.ToUpper(feed.TLPLabel); label != "" && label != "WHITE" && label != "CLEAR" {
				continue
			}
			feedURL, err := resolveReference(s.ProviderMetadata, feed.URL, s.DocumentHosts...)
			if err != nil {
				result.warn("skipping feed %q: %v", feed.URL, err)
				continue
			}
			refs, err := s.readRolie(ctx, env, feedURL, result)
			if err != nil {
				result.warn("read feed %s: %v", feedURL, err)
				continue
			}
			for _, ref := range refs {
				if _, dup := seen[ref.url]; dup {
					continue
				}
				seen[ref.url] = struct{}{}
				out = append(out, ref)
			}
		}
	}
	if len(out) > 0 {
		return out, nil
	}

	// No usable feed, so fall back to the flat index a provider must also serve.
	for _, dist := range provider.Distributions {
		if dist.DirectoryURL == "" {
			continue
		}
		indexURL, err := resolveReference(s.ProviderMetadata, strings.TrimSuffix(dist.DirectoryURL, "/")+"/index.txt", s.DocumentHosts...)
		if err != nil {
			result.warn("skipping directory %q: %v", dist.DirectoryURL, err)
			continue
		}
		body, _, err := env.Fetcher.Get(ctx, indexURL)
		if err != nil {
			result.warn("read index %s: %v", indexURL, err)
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			docURL, err := resolveReference(indexURL, line, s.DocumentHosts...)
			if err != nil {
				result.warn("skipping index entry %q: %v", line, err)
				continue
			}
			if _, dup := seen[docURL]; dup {
				continue
			}
			seen[docURL] = struct{}{}
			out = append(out, csafDocumentRef{url: docURL})
		}
	}
	return out, nil
}

func (s *CSAFSource) readRolie(ctx context.Context, env *Env, feedURL string, result *Result) ([]csafDocumentRef, error) {
	body, _, err := env.Fetcher.Get(ctx, feedURL)
	if err != nil {
		return nil, err
	}
	var feed rolieFeed
	if err := json.Unmarshal(body, &feed); err != nil {
		return nil, fmt.Errorf("parse ROLIE feed: %w", err)
	}

	out := make([]csafDocumentRef, 0, len(feed.Feed.Entry))
	skipped := 0
	for _, entry := range feed.Feed.Entry {
		// The entry timestamp is what makes an incremental sync possible without
		// downloading the document to find out whether it changed.
		if !env.Since.IsZero() && !entry.Updated.IsZero() && entry.Updated.Before(env.Since) {
			skipped++
			continue
		}
		for _, link := range entry.Link {
			if link.Rel != "self" || !strings.HasSuffix(strings.ToLower(link.HRef), ".json") {
				continue
			}
			docURL, err := resolveReference(feedURL, link.HRef, s.DocumentHosts...)
			if err != nil {
				result.warn("skipping entry %q: %v", link.HRef, err)
				continue
			}
			out = append(out, csafDocumentRef{url: docURL, updated: entry.Updated})
			break
		}
	}
	if skipped > 0 {
		env.progressf("  %d entries unchanged since %s\n", skipped, env.Since.Format(time.RFC3339))
	}
	return out, nil
}

func init() {
	register(&CSAFSource{
		ProviderMetadata: "https://www.cisa.gov/sites/default/files/csaf/provider-metadata.json",
		DocumentHosts:    []string{"raw.githubusercontent.com"},
		Meta: Info{
			ID:              "cisa-csaf",
			Name:            "CISA ICS advisories (CSAF)",
			Kind:            KindAdvisories,
			Homepage:        "https://www.cisa.gov/news-events/cybersecurity-advisories",
			License:         "public domain (US government work)",
			Redistributable: true,
			DefaultEnabled:  true,
			Summary:         "The primary feed of ICS advisories, published as CSAF 2.0.",
		},
	})

	register(&CSAFSource{
		ProviderMetadata: "https://cert-portal.siemens.com/productcert/csaf/provider-metadata.json",
		Meta: Info{
			ID:       "siemens-csaf",
			Name:     "Siemens ProductCERT (CSAF)",
			Kind:     KindAdvisories,
			Homepage: "https://cert-portal.siemens.com/productcert/html/ssa-archive.html",
			License:  "see the Siemens terms of use",
			// Siemens publishes freely but sets terms on reuse, so a corpus built
			// from it is not shipped as a release artefact without checking.
			Redistributable: false,
			DefaultEnabled:  false,
			Summary:         "Siemens advisories, which cover far more product detail than the CISA summary of the same issue.",
		},
	})

	register(&CSAFSource{
		ProviderMetadata: "https://www.se.com/.well-known/csaf/provider-metadata.json",
		Meta: Info{
			ID:              "schneider-csaf",
			Name:            "Schneider Electric (CSAF)",
			Kind:            KindAdvisories,
			Homepage:        "https://www.se.com/ww/en/work/support/cybersecurity/security-notifications.jsp",
			License:         "see the Schneider Electric terms of use",
			Redistributable: false,
			DefaultEnabled:  false,
			Summary:         "Schneider Electric security notifications.",
		},
	})

	register(&CSAFSource{
		ProviderMetadata: "https://certvde.csaf-tp.certvde.com/.well-known/csaf/provider-metadata.json",
		Meta: Info{
			ID:       "cert-vde-csaf",
			Name:     "CERT@VDE (CSAF)",
			Kind:     KindAdvisories,
			Homepage: "https://certvde.com/",
			License:  "see the CERT@VDE terms of use",
			// CERT@VDE coordinates for much of the German automation industry,
			// including Phoenix Contact, Pilz, WAGO and Beckhoff, so it is the
			// single highest value vendor feed after Siemens.
			Redistributable: false,
			DefaultEnabled:  false,
			Summary:         "Coordinated advisories for German industrial automation vendors.",
		},
	})
}
