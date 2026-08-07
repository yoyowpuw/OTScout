package advisory

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// CorpusSchemaVersion is bumped when the on-disk layout changes in a way an older
// build cannot read.
const CorpusSchemaVersion = "1"

// A corpus is a directory rather than a single file, because it is meant to be
// carried into an air-gapped site on removable media and rebuilt incrementally on
// the connected side. One file per source means a sync that only refreshes KEV
// rewrites one small file, and a reviewer looking at what changed can see it.
//
//	corpus/
//	  manifest.json
//	  advisories/<source>.jsonl
//	  enrichment/kev.json
//	  enrichment/epss.json
//	  cache/
const (
	manifestName    = "manifest.json"
	advisoriesDir   = "advisories"
	enrichmentDir   = "enrichment"
	cacheDirName    = "cache"
	kevFileName     = "kev.jsonl"
	epssFileName    = "epss.jsonl"
	maxManifestSize = 8 << 20
	// maxCorpusLineBytes bounds one JSON line. Some advisories are genuinely
	// large, so the limit is generous, but it is not unbounded.
	maxCorpusLineBytes = 16 << 20
)

// advisoryFilePath is where one source's advisories live.
//
// A source id is not always something this project chose. Discovery derives one
// from a hostname an operator typed, so it reaches the filesystem as untrusted
// input and gets sanitised rather than trusted. Anything outside the safe set
// becomes a dash, and a digest of the original id is appended whenever that
// substitution happens, so that two ids differing only in the replaced
// characters cannot end up sharing one file.
func advisoryFilePath(dir, id string) string {
	return filepath.Join(dir, advisoriesDir, sourceFileName(id)+".jsonl")
}

func sourceFileName(id string) string {
	var b strings.Builder
	b.Grow(len(id))
	changed := false
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			// Case folding on its own is not a substitution worth a digest, but
			// it does have to be recorded, or an id would name a different file
			// on Linux than on Windows.
			b.WriteRune(r + ('a' - 'A'))
			changed = true
		default:
			b.WriteByte('-')
			changed = true
		}
	}

	name := strings.Trim(b.String(), "-.")
	if name == "" {
		name = "source"
		changed = true
	}
	if !changed {
		return name
	}

	sum := sha256.Sum256([]byte(id))
	return name + "-" + hex.EncodeToString(sum[:4])
}

// Manifest describes what a corpus holds and where it came from.
type Manifest struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   time.Time     `json:"generated_at"`
	Generator     string        `json:"generator"`
	Sources       []SourceState `json:"sources"`
}

// SourceState records the outcome of the last sync of one source.
//
// Licence and redistribution are recorded per source on purpose. CISA advisories
// and NVD data are public domain, but the ICS Advisory Project and several vendor
// CSAF feeds carry terms that decide whether a built corpus may be published as a
// release artefact. Keeping the answer next to the data is the only way that
// question can be answered later without guessing.
type SourceState struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Kind            string    `json:"kind"`
	Homepage        string    `json:"homepage,omitempty"`
	License         string    `json:"license,omitempty"`
	Redistributable bool      `json:"redistributable"`
	LastSync        time.Time `json:"last_sync,omitzero"`
	Advisories      int       `json:"advisories"`
	Records         int       `json:"records,omitempty"`
	Digest          string    `json:"digest,omitempty"`
	Warnings        []string  `json:"warnings,omitempty"`
	Error           string    `json:"error,omitempty"`
}

// Corpus is an advisory corpus held in memory, backed by a directory.
type Corpus struct {
	Dir      string
	Manifest Manifest

	Advisories []Advisory

	// KEV and EPSS are kept separately from the advisories because they are
	// keyed by CVE and apply across every source. Folding them in at load time
	// means the matcher never has to know they came from somewhere else.
	KEV  map[string]KEVEntry
	EPSS map[string]EPSS

	byID  map[string]int
	byCVE map[string][]int
}

// NewCorpus returns an empty corpus rooted at a directory.
func NewCorpus(dir string) *Corpus {
	return &Corpus{
		Dir:  dir,
		KEV:  make(map[string]KEVEntry),
		EPSS: make(map[string]EPSS),
		Manifest: Manifest{
			SchemaVersion: CorpusSchemaVersion,
			Generator:     "otscout sync",
		},
	}
}

// CacheDir is where the fetcher keeps conditional request state.
func (c *Corpus) CacheDir() string { return filepath.Join(c.Dir, cacheDirName) }

// LoadCorpus reads a corpus from disk.
func LoadCorpus(dir string) (*Corpus, error) {
	corpus := NewCorpus(dir)

	manifestData, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no advisory corpus at %s, run 'otscout sync' first", dir)
		}
		return nil, fmt.Errorf("read corpus manifest: %w", err)
	}
	if len(manifestData) > maxManifestSize {
		return nil, fmt.Errorf("corpus manifest at %s is implausibly large", dir)
	}
	if err := json.Unmarshal(manifestData, &corpus.Manifest); err != nil {
		return nil, fmt.Errorf("parse corpus manifest: %w", err)
	}
	if corpus.Manifest.SchemaVersion != CorpusSchemaVersion {
		return nil, fmt.Errorf("corpus at %s uses schema version %q, this build understands %q",
			dir, corpus.Manifest.SchemaVersion, CorpusSchemaVersion)
	}

	for _, state := range corpus.Manifest.Sources {
		if state.Kind != string(KindAdvisories) {
			continue
		}
		loaded, err := readAdvisoryFile(advisoryFilePath(dir, state.ID))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		corpus.Advisories = append(corpus.Advisories, loaded...)
	}

	if err := readEnrichmentFile(filepath.Join(dir, enrichmentDir, kevFileName), corpus.KEV); err != nil {
		return nil, err
	}
	if err := readEnrichmentFile(filepath.Join(dir, enrichmentDir, epssFileName), corpus.EPSS); err != nil {
		return nil, err
	}

	corpus.Reindex()
	corpus.ApplyEnrichment()
	return corpus, nil
}

// enrichmentRecord is one line of an enrichment file. The CVE travels with the
// payload rather than being a JSON object key, which is what lets these files be
// read a line at a time and diffed a line at a time.
type enrichmentRecord[T any] struct {
	CVE   string `json:"cve"`
	Entry T      `json:"entry"`
}

func readEnrichmentFile[T any](path string, into map[string]T) error {
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %w", path, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxCorpusLineBytes)
	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var record enrichmentRecord[T]
		if err := json.Unmarshal(raw, &record); err != nil {
			return fmt.Errorf("parse %s line %d: %w", path, line, err)
		}
		if record.CVE == "" {
			continue
		}
		into[record.CVE] = record.Entry
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	return nil
}

func writeEnrichmentFile[T any](path string, entries map[string]T) error {
	keys := make([]string, 0, len(entries))
	for key := range entries {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var buf strings.Builder
	for _, key := range keys {
		encoded, err := json.Marshal(enrichmentRecord[T]{CVE: key, Entry: entries[key]})
		if err != nil {
			return fmt.Errorf("encode %s for %s: %w", key, path, err)
		}
		buf.Write(encoded)
		buf.WriteByte('\n')
	}
	return writeFileAtomic(path, []byte(buf.String()))
}

func readAdvisoryFile(path string) ([]Advisory, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	out := make([]Advisory, 0, 256)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxCorpusLineBytes)

	line := 0
	for scanner.Scan() {
		line++
		raw := scanner.Bytes()
		if len(raw) == 0 {
			continue
		}
		var adv Advisory
		if err := json.Unmarshal(raw, &adv); err != nil {
			return nil, fmt.Errorf("parse %s line %d: %w", path, line, err)
		}
		out = append(out, adv)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return out, nil
}

// Save writes the corpus back to its directory.
func (c *Corpus) Save() error {
	c.Manifest.SchemaVersion = CorpusSchemaVersion
	c.Manifest.GeneratedAt = time.Now().UTC()
	if c.Manifest.Generator == "" {
		c.Manifest.Generator = "otscout sync"
	}

	bySource := make(map[string][]Advisory, len(c.Manifest.Sources))
	for _, adv := range c.Advisories {
		bySource[adv.Source] = append(bySource[adv.Source], adv)
	}

	for idx := range c.Manifest.Sources {
		state := &c.Manifest.Sources[idx]
		if state.Kind != string(KindAdvisories) {
			continue
		}
		list := bySource[state.ID]
		digest, err := writeAdvisoryFile(advisoryFilePath(c.Dir, state.ID), list)
		if err != nil {
			return err
		}
		state.Advisories = len(list)
		state.Digest = digest
	}

	if err := writeEnrichmentFile(filepath.Join(c.Dir, enrichmentDir, kevFileName), c.KEV); err != nil {
		return err
	}
	if err := writeEnrichmentFile(filepath.Join(c.Dir, enrichmentDir, epssFileName), c.EPSS); err != nil {
		return err
	}

	sort.SliceStable(c.Manifest.Sources, func(i, j int) bool {
		return c.Manifest.Sources[i].ID < c.Manifest.Sources[j].ID
	})
	manifestData, err := json.MarshalIndent(c.Manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("encode corpus manifest: %w", err)
	}
	return writeFileAtomic(filepath.Join(c.Dir, manifestName), append(manifestData, '\n'))
}

// writeAdvisoryFile writes one source as JSON lines and returns its digest.
//
// Advisories are sorted by id and their contents sorted internally, so that a
// sync which changed nothing produces a byte identical file. That is what lets a
// corpus be committed to version control and reviewed as a diff.
func writeAdvisoryFile(path string, list []Advisory) (string, error) {
	sorted := append([]Advisory(nil), list...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].ID < sorted[j].ID })

	var buf strings.Builder
	for idx := range sorted {
		sorted[idx].Sort()
		// Enrichment is derived data held elsewhere in the corpus, so it is
		// stripped before writing. Keeping it here too would mean a KEV refresh
		// rewrote every advisory file.
		stripped := sorted[idx]
		stripped.Vulnerabilities = stripEnrichment(stripped.Vulnerabilities)

		encoded, err := json.Marshal(stripped)
		if err != nil {
			return "", fmt.Errorf("encode advisory %s: %w", stripped.ID, err)
		}
		buf.Write(encoded)
		buf.WriteByte('\n')
	}

	data := []byte(buf.String())
	if err := writeFileAtomic(path, data); err != nil {
		return "", err
	}
	return digestOf(data), nil
}

func stripEnrichment(vulns []Vulnerability) []Vulnerability {
	if len(vulns) == 0 {
		return nil
	}
	out := make([]Vulnerability, len(vulns))
	copy(out, vulns)
	for idx := range out {
		out[idx].KEV = nil
		out[idx].EPSS = nil
	}
	return out
}

// PruneEnrichment drops enrichment for CVEs the corpus does not mention.
//
// EPSS publishes a score for every CVE in existence, which is a few hundred
// thousand rows, while an ICS corpus references a few thousand. Storing the rest
// would put forty megabytes of unusable data on the removable media that carries
// this corpus into a plant. Enrichment for a CVE no advisory mentions cannot be
// reached by anything, so nothing is lost by dropping it, and a later sync that
// adds new advisories refetches enrichment in one cheap conditional request.
//
// This is skipped while the corpus holds no advisories, so that syncing the
// enrichment sources first does not throw the data away before the advisories
// it belongs to have arrived.
func (c *Corpus) PruneEnrichment() (removed int) {
	if len(c.Advisories) == 0 {
		return 0
	}

	wanted := make(map[string]struct{}, len(c.Advisories)*2)
	for idx := range c.Advisories {
		for _, cve := range c.Advisories[idx].CVEs() {
			wanted[cve] = struct{}{}
		}
	}

	for cve := range c.KEV {
		if _, keep := wanted[cve]; !keep {
			delete(c.KEV, cve)
			removed++
		}
	}
	for cve := range c.EPSS {
		if _, keep := wanted[cve]; !keep {
			delete(c.EPSS, cve)
			removed++
		}
	}
	return removed
}

// Reindex rebuilds the lookup maps.
func (c *Corpus) Reindex() {
	c.byID = make(map[string]int, len(c.Advisories))
	c.byCVE = make(map[string][]int, len(c.Advisories))
	for idx := range c.Advisories {
		adv := &c.Advisories[idx]
		c.byID[adv.ID] = idx
		for _, cve := range adv.CVEs() {
			c.byCVE[cve] = append(c.byCVE[cve], idx)
		}
	}
}

// ApplyEnrichment attaches KEV and EPSS records to matching vulnerabilities.
func (c *Corpus) ApplyEnrichment() {
	for idx := range c.Advisories {
		for vIdx := range c.Advisories[idx].Vulnerabilities {
			vuln := &c.Advisories[idx].Vulnerabilities[vIdx]
			if vuln.CVE == "" {
				continue
			}
			if entry, ok := c.KEV[vuln.CVE]; ok {
				copied := entry
				vuln.KEV = &copied
			}
			if score, ok := c.EPSS[vuln.CVE]; ok {
				copied := score
				vuln.EPSS = &copied
			}
		}
	}
}

// ReplaceSource swaps in the advisories from one source, leaving the others
// alone. A sync that refreshes only KEV must not drop the CISA corpus.
func (c *Corpus) ReplaceSource(sourceID string, list []Advisory) {
	kept := make([]Advisory, 0, len(c.Advisories))
	for _, adv := range c.Advisories {
		if adv.Source != sourceID {
			kept = append(kept, adv)
		}
	}
	c.Advisories = append(kept, list...)
	c.Reindex()
}

// SetSourceState records the outcome of syncing one source.
func (c *Corpus) SetSourceState(state SourceState) {
	for idx := range c.Manifest.Sources {
		if c.Manifest.Sources[idx].ID == state.ID {
			c.Manifest.Sources[idx] = state
			return
		}
	}
	c.Manifest.Sources = append(c.Manifest.Sources, state)
}

// Get returns an advisory by id.
func (c *Corpus) Get(id string) (*Advisory, bool) {
	idx, ok := c.byID[id]
	if !ok {
		return nil, false
	}
	return &c.Advisories[idx], true
}

// ByCVE returns every advisory that mentions a CVE.
func (c *Corpus) ByCVE(cve string) []*Advisory {
	indexes := c.byCVE[strings.ToUpper(strings.TrimSpace(cve))]
	out := make([]*Advisory, 0, len(indexes))
	for _, idx := range indexes {
		out = append(out, &c.Advisories[idx])
	}
	return out
}

// Normalize runs the normalization tables over every advisory. It is called after
// a sync so that the stored corpus already holds resolved vendor ids and parsed
// version ranges, keeping that cost out of every later match run.
func (c *Corpus) Normalize(n *normalize.Normalizer) {
	for idx := range c.Advisories {
		c.Advisories[idx].Normalize(n)
	}
}

// CorpusStats summarises a corpus for the CLI and the dashboard header.
type CorpusStats struct {
	Advisories        int              `json:"advisories"`
	Products          int              `json:"products"`
	CVEs              int              `json:"cves"`
	KEV               int              `json:"kev"`
	EPSS              int              `json:"epss"`
	BySource          map[string]int   `json:"by_source"`
	BySeverity        map[Severity]int `json:"by_severity"`
	ByVendor          map[string]int   `json:"by_vendor"`
	UnresolvedVendors int              `json:"unresolved_vendors"`
	UnparsedRanges    int              `json:"unparsed_ranges"`
	Oldest            time.Time        `json:"oldest,omitzero"`
	Newest            time.Time        `json:"newest,omitzero"`
}

// Stats computes the summary counts.
//
// The two quality counters matter more than the totals. An advisory whose vendor
// did not resolve or whose version range did not parse is one the matcher can only
// treat as a weak guess, so tracking them is how the normalization tables get
// improved with evidence rather than by hunch.
func (c *Corpus) Stats() CorpusStats {
	stats := CorpusStats{
		BySource:   make(map[string]int),
		BySeverity: make(map[Severity]int),
		ByVendor:   make(map[string]int),
		KEV:        len(c.KEV),
		EPSS:       len(c.EPSS),
	}
	cves := make(map[string]struct{})

	for idx := range c.Advisories {
		adv := &c.Advisories[idx]
		stats.Advisories++
		stats.BySource[adv.Source]++
		stats.BySeverity[adv.Severity()]++
		stats.Products += len(adv.Products)

		for _, cve := range adv.CVEs() {
			cves[cve] = struct{}{}
		}
		for _, product := range adv.Products {
			if product.Vendor != "" {
				stats.ByVendor[product.Vendor]++
			} else if product.VendorRaw != "" {
				stats.UnresolvedVendors++
			}
			if product.Version.Kind == normalize.ConstraintUnknown {
				stats.UnparsedRanges++
			}
		}

		if !adv.Published.IsZero() {
			if stats.Oldest.IsZero() || adv.Published.Before(stats.Oldest) {
				stats.Oldest = adv.Published
			}
			if adv.Published.After(stats.Newest) {
				stats.Newest = adv.Published
			}
		}
	}
	stats.CVEs = len(cves)
	return stats
}

// WriteJSON serialises the whole corpus as one JSON document, for the single file
// report and for the embedded server.
func (c *Corpus) WriteJSON(w io.Writer) error {
	payload := struct {
		Manifest   Manifest            `json:"manifest"`
		Advisories []Advisory          `json:"advisories"`
		KEV        map[string]KEVEntry `json:"kev,omitempty"`
		EPSS       map[string]EPSS     `json:"epss,omitempty"`
	}{
		Manifest:   c.Manifest,
		Advisories: c.Advisories,
		KEV:        c.KEV,
		EPSS:       c.EPSS,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode corpus: %w", err)
	}
	return nil
}
