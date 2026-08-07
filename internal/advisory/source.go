package advisory

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// Kind separates sources that publish advisories from those that only add
// context to CVEs that came from somewhere else.
type Kind string

const (
	KindAdvisories Kind = "advisories"
	KindEnrichment Kind = "enrichment"
)

// Info describes a source, including the terms that decide whether the data it
// produces may be redistributed.
type Info struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Kind     Kind   `json:"kind"`
	Homepage string `json:"homepage,omitempty"`
	// License is the licence of the data, not of the code that reads it.
	License string `json:"license,omitempty"`
	// Redistributable says whether a corpus built from this source may be
	// published as a release artefact. Where the terms are unclear this is false,
	// because the cost of being wrong falls on whoever downloads the release.
	Redistributable bool   `json:"redistributable"`
	Summary         string `json:"summary,omitempty"`
	// DefaultEnabled keeps the out of the box sync to sources that are public
	// domain and known to be well behaved.
	DefaultEnabled bool `json:"default_enabled"`
}

// Source fetches and parses one upstream feed.
type Source interface {
	Info() Info
	Sync(ctx context.Context, env *Env) (*Result, error)
}

// CorpusEnricher is implemented by sources that have no feed of their own and
// instead answer questions about advisories already in the corpus. NVD is one:
// asking it for every CVE in existence would take hours at the anonymous rate
// limit, so it is only asked about the CVEs that turned up without a score.
type CorpusEnricher interface {
	Source
	EnrichCorpus(ctx context.Context, env *Env, corpus *Corpus) (*Result, error)
}

// Env is what a source is given to do its work.
type Env struct {
	Fetcher    *Fetcher
	Normalizer *normalize.Normalizer
	// Since limits a source to advisories changed after this time where the feed
	// supports it. Zero means fetch everything.
	Since time.Time
	// MaxDocuments caps how many advisory documents a single source downloads,
	// which keeps a first run against a large feed bounded and testable.
	MaxDocuments int
	// Progress receives human readable lines. It may be nil.
	Progress io.Writer
}

func (e *Env) progressf(format string, args ...any) {
	if e == nil || e.Progress == nil {
		return
	}
	fmt.Fprintf(e.Progress, format, args...)
}

// Result is what one source produced.
type Result struct {
	Advisories []Advisory
	KEV        map[string]KEVEntry
	EPSS       map[string]EPSS
	// Records counts the rows or documents read, which is not the same as the
	// advisory count for enrichment sources.
	Records  int
	Warnings []string
}

func (r *Result) warn(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// registry holds the built in sources.
var registry = map[string]Source{}

func register(s Source) {
	id := s.Info().ID
	if id == "" {
		panic("advisory source registered with no id")
	}
	if _, exists := registry[id]; exists {
		panic("advisory source " + id + " registered twice")
	}
	registry[id] = s
}

// Sources returns every registered source, ordered by id.
func Sources() []Source {
	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	out := make([]Source, 0, len(ids))
	for _, id := range ids {
		out = append(out, registry[id])
	}
	return out
}

// SourceByID looks up one source.
func SourceByID(id string) (Source, bool) {
	s, ok := registry[strings.TrimSpace(strings.ToLower(id))]
	return s, ok
}

// DefaultSourceIDs are the sources a plain sync uses.
func DefaultSourceIDs() []string {
	out := make([]string, 0, len(registry))
	for _, source := range Sources() {
		if source.Info().DefaultEnabled {
			out = append(out, source.Info().ID)
		}
	}
	return out
}

// SyncOptions configures a sync run.
type SyncOptions struct {
	Dir       string
	SourceIDs []string
	// CSAFProviders are extra providers named by URL or domain, resolved through
	// the CSAF discovery rules rather than being built in.
	CSAFProviders []string
	Since         time.Time
	Offline       bool
	MaxDocs       int
	Normalizer    *normalize.Normalizer
	Progress      io.Writer
	// Transport, Spacing and RetryBackoff are exposed so tests can serve fixtures
	// without a real network and without waiting out the pacing delays.
	Transport    http.RoundTripper
	Spacing      time.Duration
	RetryBackoff time.Duration
}

// SyncReport summarises a sync run.
type SyncReport struct {
	Corpus  *Corpus
	Fetch   FetchStats
	Sources []SourceState
	// Failed lists sources that could not be synced. A sync is not aborted by
	// one unreachable feed, because a corpus that is mostly current is far more
	// use than none at all, but the failure is reported and recorded.
	Failed []string
}

// Sync fetches the requested sources into the corpus at dir.
func Sync(ctx context.Context, opts SyncOptions) (*SyncReport, error) {
	if opts.Dir == "" {
		return nil, fmt.Errorf("no corpus directory given")
	}
	if len(opts.SourceIDs) == 0 && len(opts.CSAFProviders) == 0 {
		opts.SourceIDs = DefaultSourceIDs()
	}

	normalizer := opts.Normalizer
	if normalizer == nil {
		var err error
		normalizer, err = normalize.New()
		if err != nil {
			return nil, fmt.Errorf("load normalization tables: %w", err)
		}
	}

	corpus, err := LoadCorpus(opts.Dir)
	if err != nil {
		// A missing corpus is the normal first run, not a failure.
		corpus = NewCorpus(opts.Dir)
	}

	fetcher, err := NewFetcher(FetcherOptions{
		CacheDir:     corpus.CacheDir(),
		Offline:      opts.Offline,
		Transport:    opts.Transport,
		Spacing:      opts.Spacing,
		RetryBackoff: opts.RetryBackoff,
	})
	if err != nil {
		return nil, err
	}

	env := &Env{
		Fetcher:      fetcher,
		Normalizer:   normalizer,
		Since:        opts.Since,
		MaxDocuments: opts.MaxDocs,
		Progress:     opts.Progress,
	}

	sources := make([]Source, 0, len(opts.SourceIDs)+len(opts.CSAFProviders))
	for _, id := range opts.SourceIDs {
		source, ok := SourceByID(id)
		if !ok {
			return nil, fmt.Errorf("unknown advisory source %q, run 'otscout sync --list' to see the available ones", id)
		}
		sources = append(sources, source)
	}
	for _, target := range opts.CSAFProviders {
		// Discovery is done up front so that a mistyped provider fails before
		// anything has been downloaded, rather than halfway through a long sync.
		discovered, err := DiscoverCSAFSource(ctx, fetcher, target)
		if err != nil {
			return nil, err
		}
		sources = append(sources, discovered)
	}

	report := &SyncReport{Corpus: corpus}
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		state := runSource(ctx, source, env, corpus)
		corpus.SetSourceState(state)
		report.Sources = append(report.Sources, state)
		if state.Error != "" {
			report.Failed = append(report.Failed, state.ID)
		}
	}

	corpus.Normalize(normalizer)
	corpus.Reindex()
	corpus.PruneEnrichment()
	corpus.ApplyEnrichment()

	if err := corpus.Save(); err != nil {
		return nil, err
	}
	report.Fetch = fetcher.Stats()
	return report, nil
}

func runSource(ctx context.Context, source Source, env *Env, corpus *Corpus) SourceState {
	info := source.Info()
	state := SourceState{
		ID:              info.ID,
		Name:            info.Name,
		Kind:            string(info.Kind),
		Homepage:        info.Homepage,
		License:         info.License,
		Redistributable: info.Redistributable,
	}

	env.progressf("syncing %s\n", info.Name)

	var (
		result *Result
		err    error
	)
	if enricher, ok := source.(CorpusEnricher); ok {
		result, err = enricher.EnrichCorpus(ctx, env, corpus)
	} else {
		result, err = source.Sync(ctx, env)
	}
	if err != nil {
		// The previous state is kept so that a failed refresh does not make the
		// corpus look as though it never held this source.
		for _, existing := range corpus.Manifest.Sources {
			if existing.ID == info.ID {
				state = existing
			}
		}
		state.Error = err.Error()
		return state
	}

	state.LastSync = time.Now().UTC()
	state.Records = result.Records
	state.Warnings = sortedStrings(result.Warnings)
	state.Error = ""

	if info.Kind == KindAdvisories {
		corpus.ReplaceSource(info.ID, result.Advisories)
		state.Advisories = len(result.Advisories)
	}
	for cve, entry := range result.KEV {
		corpus.KEV[cve] = entry
	}
	for cve, score := range result.EPSS {
		corpus.EPSS[cve] = score
	}
	return state
}
