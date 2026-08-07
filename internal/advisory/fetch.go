package advisory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yoyowpuw/OTScout/internal/version"
)

// Fetching advisories is the one part of otscout that talks to the internet, and
// it is deliberately kept in a single file so that the boundary is obvious. It
// never runs on a plant network: sync is meant to be run on a connected machine
// and the resulting corpus carried in. Offline mode exists so that the same
// command works on the air-gapped side against an already downloaded corpus.

// ErrOffline is returned when a fetch is attempted with networking disabled.
var ErrOffline = errors.New("network access is disabled, run sync on a connected machine and copy the corpus across")

// ErrNotModified means the server confirmed the cached copy is current.
var ErrNotModified = errors.New("resource has not changed since the last sync")

const (
	defaultFetchTimeout   = 60 * time.Second
	defaultMaxBodyBytes   = 256 << 20
	defaultRetries        = 3
	defaultRetryBackoff   = 2 * time.Second
	defaultRequestSpacing = 100 * time.Millisecond
)

// Fetcher performs cached HTTP GETs.
//
// Every upstream here is a volunteer or a public agency, so the fetcher is
// conditional by default and paces itself. Hammering CISA to rebuild a corpus
// that changed by two advisories is both rude and the fastest way to get the
// project blocked.
type Fetcher struct {
	client   *http.Client
	cacheDir string
	offline  bool
	spacing  time.Duration
	retries  int
	backoff  time.Duration
	maxBytes int64

	mu       sync.Mutex
	lastCall time.Time
	stats    FetchStats
}

// FetchStats counts what a sync run did on the wire, which the CLI prints so an
// operator can see whether anything was actually downloaded.
type FetchStats struct {
	Requests    int   `json:"requests"`
	NotModified int   `json:"not_modified"`
	Bytes       int64 `json:"bytes"`
	Retries     int   `json:"retries"`
}

// FetcherOptions configures a Fetcher.
type FetcherOptions struct {
	CacheDir string
	Offline  bool
	Timeout  time.Duration
	// Spacing is the minimum gap between requests, applied across all sources.
	Spacing time.Duration
	Retries int
	// RetryBackoff is multiplied by the attempt number to space out retries.
	RetryBackoff time.Duration
	MaxBytes     int64
	// Transport is exposed so tests can serve fixtures without a real network.
	Transport http.RoundTripper
}

// NewFetcher builds a fetcher.
func NewFetcher(opts FetcherOptions) (*Fetcher, error) {
	if opts.Timeout <= 0 {
		opts.Timeout = defaultFetchTimeout
	}
	if opts.Spacing <= 0 {
		opts.Spacing = defaultRequestSpacing
	}
	if opts.Retries <= 0 {
		opts.Retries = defaultRetries
	}
	if opts.RetryBackoff <= 0 {
		opts.RetryBackoff = defaultRetryBackoff
	}
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxBodyBytes
	}
	if opts.CacheDir != "" {
		if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
			return nil, fmt.Errorf("create cache directory: %w", err)
		}
	}

	transport := opts.Transport
	if transport == nil {
		// The default transport is cloned rather than shared so that changing
		// these limits cannot affect anything else in the process.
		base := http.DefaultTransport.(*http.Transport).Clone()
		base.MaxIdleConnsPerHost = 4
		base.ForceAttemptHTTP2 = true
		transport = base
	}

	return &Fetcher{
		client: &http.Client{
			Timeout:   opts.Timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("stopped after 5 redirects")
				}
				return nil
			},
		},
		cacheDir: opts.CacheDir,
		offline:  opts.Offline,
		spacing:  opts.Spacing,
		retries:  opts.Retries,
		backoff:  opts.RetryBackoff,
		maxBytes: opts.MaxBytes,
	}, nil
}

// Stats returns a copy of the counters.
func (f *Fetcher) Stats() FetchStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stats
}

// Offline reports whether networking is disabled.
func (f *Fetcher) Offline() bool { return f.offline }

// cacheEntry is the metadata stored alongside a cached body.
type cacheEntry struct {
	URL          string    `json:"url"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	Fetched      time.Time `json:"fetched"`
	Digest       string    `json:"digest"`
	Bytes        int64     `json:"bytes"`
}

// Get fetches a URL, returning the body and whether it came from the cache.
//
// A conditional request is sent whenever a cached copy exists. When the server
// answers 304 the cached bytes are returned, which is what makes a daily sync
// cost a handful of requests rather than a full download.
func (f *Fetcher) Get(ctx context.Context, rawURL string) ([]byte, bool, error) {
	return f.GetWithHeaders(ctx, rawURL, nil)
}

// GetWithHeaders is Get with extra request headers, for the one upstream that
// raises its rate limit in exchange for an API key.
func (f *Fetcher) GetWithHeaders(ctx context.Context, rawURL string, headers map[string]string) ([]byte, bool, error) {
	if err := validateURL(rawURL); err != nil {
		return nil, false, err
	}

	entry, cached, _ := f.readCache(rawURL)
	if f.offline {
		if cached != nil {
			return cached, true, nil
		}
		return nil, false, fmt.Errorf("%w: %s is not in the local cache", ErrOffline, rawURL)
	}

	var lastErr error
	for attempt := 0; attempt <= f.retries; attempt++ {
		if attempt > 0 {
			f.mu.Lock()
			f.stats.Retries++
			f.mu.Unlock()
			// A linear backoff is enough here. These are bulk downloads with no
			// deadline, and an aggressive retry against a public agency is worse
			// than a slow sync.
			delay := time.Duration(attempt) * f.backoff
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case <-time.After(delay):
			}
		}

		body, notModified, err := f.doGet(ctx, rawURL, entry, headers)
		switch {
		case err == nil && notModified:
			return cached, true, nil
		case err == nil:
			return body, false, nil
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			return nil, false, err
		case !retryable(err):
			return nil, false, err
		}
		lastErr = err
	}

	// Falling back to a stale copy beats failing the whole sync over one
	// unreachable host, but the caller is told so it can warn.
	if cached != nil {
		return cached, true, fmt.Errorf("using the cached copy of %s: %w", rawURL, lastErr)
	}
	return nil, false, fmt.Errorf("fetch %s: %w", rawURL, lastErr)
}

func (f *Fetcher) doGet(ctx context.Context, rawURL string, entry *cacheEntry, headers map[string]string) ([]byte, bool, error) {
	f.pace(ctx)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, false, fmt.Errorf("build request: %w", err)
	}
	// Accept-Encoding is deliberately left unset. Setting it by hand switches off
	// the transport's transparent decompression, which would leave every caller
	// holding compressed bytes it did not ask for.
	req.Header.Set("User-Agent", version.UserAgent())
	if entry != nil {
		if entry.ETag != "" {
			req.Header.Set("If-None-Match", entry.ETag)
		}
		if entry.LastModified != "" {
			req.Header.Set("If-Modified-Since", entry.LastModified)
		}
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()

	f.mu.Lock()
	f.stats.Requests++
	f.mu.Unlock()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		f.mu.Lock()
		f.stats.NotModified++
		f.mu.Unlock()
		return nil, true, nil
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
		return nil, false, &httpError{status: resp.StatusCode, url: rawURL, temporary: true}
	case resp.StatusCode != http.StatusOK:
		return nil, false, &httpError{status: resp.StatusCode, url: rawURL}
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, f.maxBytes+1))
	if err != nil {
		return nil, false, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > f.maxBytes {
		return nil, false, fmt.Errorf("%s returned more than the %d byte limit", rawURL, f.maxBytes)
	}

	f.mu.Lock()
	f.stats.Bytes += int64(len(body))
	f.mu.Unlock()

	f.writeCache(rawURL, body, resp.Header.Get("ETag"), resp.Header.Get("Last-Modified"))
	return body, false, nil
}

// pace enforces the minimum gap between requests.
func (f *Fetcher) pace(ctx context.Context) {
	f.mu.Lock()
	wait := f.spacing - time.Since(f.lastCall)
	f.lastCall = time.Now().Add(max(wait, 0))
	f.mu.Unlock()

	if wait <= 0 {
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
}

type httpError struct {
	status    int
	url       string
	temporary bool
}

func (e *httpError) Error() string {
	return fmt.Sprintf("%s returned HTTP %d", e.url, e.status)
}

func retryable(err error) bool {
	var httpErr *httpError
	if errors.As(err, &httpErr) {
		return httpErr.temporary
	}
	// A transport level failure is almost always worth one more try.
	return true
}

// cachePath maps a URL to a file name. The hash keeps the name safe on every file
// system, and the host prefix keeps a cache directory readable to a human trying
// to work out where a stale file came from.
func (f *Fetcher) cachePath(rawURL string) (string, string) {
	sum := sha256.Sum256([]byte(rawURL))
	name := hex.EncodeToString(sum[:16])
	if parsed, err := url.Parse(rawURL); err == nil && parsed.Host != "" {
		name = sanitiseHost(parsed.Host) + "-" + name
	}
	return filepath.Join(f.cacheDir, name+".body"), filepath.Join(f.cacheDir, name+".json")
}

func sanitiseHost(host string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '-'
		}
	}, host)
}

func (f *Fetcher) readCache(rawURL string) (*cacheEntry, []byte, error) {
	if f.cacheDir == "" {
		return nil, nil, nil
	}
	bodyPath, metaPath := f.cachePath(rawURL)

	metaData, err := os.ReadFile(metaPath)
	if err != nil {
		return nil, nil, err
	}
	var entry cacheEntry
	if err := json.Unmarshal(metaData, &entry); err != nil {
		return nil, nil, err
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		return &entry, nil, err
	}
	// A cache whose body does not match its recorded digest was truncated or
	// tampered with, and using it would silently corrupt the corpus.
	if digest := digestOf(body); entry.Digest != "" && digest != entry.Digest {
		return nil, nil, fmt.Errorf("cached copy of %s failed its checksum", rawURL)
	}
	return &entry, body, nil
}

func (f *Fetcher) writeCache(rawURL string, body []byte, etag, lastModified string) {
	if f.cacheDir == "" {
		return
	}
	bodyPath, metaPath := f.cachePath(rawURL)
	entry := cacheEntry{
		URL:          rawURL,
		ETag:         etag,
		LastModified: lastModified,
		Fetched:      time.Now().UTC(),
		Digest:       digestOf(body),
		Bytes:        int64(len(body)),
	}
	metaData, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return
	}
	// The body is written first so that a crash between the two writes leaves a
	// body with no metadata, which is treated as a cache miss, rather than
	// metadata pointing at a body that was never written.
	if err := writeFileAtomic(bodyPath, body); err != nil {
		return
	}
	_ = writeFileAtomic(metaPath, metaData)
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// writeFileAtomic writes through a temporary file so that a reader never sees a
// half written corpus or cache entry.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create directory %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpName, err)
	}
	// Windows refuses a rename onto an existing file, so the target is removed
	// first. The window this opens is acceptable for a cache and for a corpus
	// that is rebuilt from scratch anyway.
	_ = os.Remove(path)
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replace %s: %w", path, err)
	}
	return nil
}

// validateURL refuses anything that is not a plain HTTPS or HTTP fetch.
//
// Source definitions can come from a configuration file, so this is a real
// boundary rather than a formality: a file or gopher URL in a config would
// otherwise turn the sync command into an arbitrary file reader.
func validateURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("bad URL %q: %w", rawURL, err)
	}
	switch parsed.Scheme {
	case "https":
	case "http":
		// Plain HTTP is allowed because some vendor CSAF mirrors still only
		// offer it, but the corpus records which sources used it.
	default:
		return fmt.Errorf("URL %q uses scheme %q, only http and https are allowed", rawURL, parsed.Scheme)
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL %q has no host", rawURL)
	}
	return nil
}

// resolveReference turns a link found inside a feed into an absolute URL.
//
// A feed is third party input, so by default it may only point within its own
// host: that is the cheapest way to stop a compromised vendor feed being used to
// probe arbitrary machines. Some providers legitimately split the two, and CISA
// is one, publishing its metadata on cisa.gov and its documents on GitHub. Those
// cases are handled by naming the extra host in the source definition, so the set
// of hosts a sync can reach is fixed in the binary rather than decided by whoever
// controls the feed.
func resolveReference(base, reference string, alsoAllow ...string) (string, error) {
	baseURL, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("bad base URL %q: %w", base, err)
	}
	refURL, err := url.Parse(strings.TrimSpace(reference))
	if err != nil {
		return "", fmt.Errorf("bad reference %q: %w", reference, err)
	}
	resolved := baseURL.ResolveReference(refURL)
	if err := validateURL(resolved.String()); err != nil {
		return "", err
	}

	if !strings.EqualFold(resolved.Host, baseURL.Host) && !hostAllowed(resolved.Host, alsoAllow) {
		return "", fmt.Errorf("feed at %s points at %s, which this source is not permitted to fetch from",
			baseURL.Host, resolved.Host)
	}
	return resolved.String(), nil
}

func hostAllowed(host string, allowed []string) bool {
	for _, candidate := range allowed {
		if strings.EqualFold(host, candidate) {
			return true
		}
	}
	return false
}

// sortedStrings returns a sorted copy, used for deterministic output.
func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
