// Package finding defines the output of the matcher: a link between an asset in
// the local inventory and an advisory in the corpus, together with the full
// reasoning that produced the link.
//
// Every finding carries its evidence. In OT a false positive costs an engineer a
// site visit, so a match that cannot explain itself is worse than no match at
// all.
package finding

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// SchemaVersion is bumped when the on-disk findings format changes
// incompatibly.
const SchemaVersion = "1"

// Tier is the confidence bucket a finding lands in. The tiers exist so an
// operator can work the list top down and stop when the evidence gets too thin
// to act on.
type Tier string

const (
	// TierConfirmed means the vendor, product and version all matched, and the
	// version fell inside an affected range. Act on these.
	TierConfirmed Tier = "confirmed"
	// TierLikely means vendor and product matched but the version was absent or
	// could not be compared. Verify the firmware version, then act.
	TierLikely Tier = "likely"
	// TierPossible means only the vendor and a product family matched. Treat as
	// a lead, not a conclusion.
	TierPossible Tier = "possible"
)

// Rank orders tiers from strongest to weakest.
func (t Tier) Rank() int {
	switch t {
	case TierConfirmed:
		return 3
	case TierLikely:
		return 2
	case TierPossible:
		return 1
	default:
		return 0
	}
}

// Description explains the tier in the words the UI shows on hover.
func (t Tier) Description() string {
	switch t {
	case TierConfirmed:
		return "Vendor, product and version matched, and the version is inside an affected range"
	case TierLikely:
		return "Vendor and product matched, but the version could not be compared"
	case TierPossible:
		return "Only the vendor and a product family matched"
	default:
		return "Unclassified"
	}
}

// ReasonKind labels one step in the matching chain.
type ReasonKind string

const (
	ReasonVendorExact      ReasonKind = "vendor_exact"
	ReasonVendorAlias      ReasonKind = "vendor_alias"
	ReasonProductExact     ReasonKind = "product_exact"
	ReasonProductNormal    ReasonKind = "product_normalized"
	ReasonProductModel     ReasonKind = "product_model"
	ReasonProductContained ReasonKind = "product_contained"
	ReasonProductFamily    ReasonKind = "product_family"
	ReasonCatalogNumber    ReasonKind = "catalog_number"
	ReasonCPE              ReasonKind = "cpe"
	ReasonVersionInRange   ReasonKind = "version_in_range"
	ReasonVersionAllAffect ReasonKind = "version_all_affected"
	ReasonVersionExact     ReasonKind = "version_exact"
	ReasonVersionUnknown   ReasonKind = "version_unknown"
	ReasonVersionOutOfRang ReasonKind = "version_out_of_range"
)

// Reason is one link in the evidence chain, recorded whether it passed or
// failed. Failed reasons are kept deliberately: knowing that a version check
// ran and came back negative is what stops an operator re-doing the analysis by
// hand.
type Reason struct {
	Kind   ReasonKind `json:"kind"`
	Detail string     `json:"detail"`
	Weight float64    `json:"weight"`
	Passed bool       `json:"passed"`
}

// VersionCheck records how a firmware version was compared against an advisory
// constraint, including which comparator handled it.
type VersionCheck struct {
	AssetVersion string `json:"asset_version"`
	Constraint   string `json:"constraint"`
	Comparator   string `json:"comparator"`
	Result       string `json:"result"`
	Explanation  string `json:"explanation"`
}

// Finding links one asset to one advisory.
type Finding struct {
	ID string `json:"id"`

	AssetID      string `json:"asset_id"`
	AssetAddress string `json:"asset_address"`
	AssetLabel   string `json:"asset_label"`
	AssetPurdue  string `json:"asset_purdue,omitempty"`
	AssetRole    string `json:"asset_role,omitempty"`

	AdvisoryID     string    `json:"advisory_id"`
	AdvisorySource string    `json:"advisory_source"`
	Title          string    `json:"title"`
	Published      time.Time `json:"published,omitzero"`

	CVEs []string `json:"cves,omitempty"`

	Tier  Tier    `json:"tier"`
	Score float64 `json:"score"`

	CVSS       float64 `json:"cvss,omitempty"`
	CVSSVector string  `json:"cvss_vector,omitempty"`
	Severity   string  `json:"severity,omitempty"`
	KEV        bool    `json:"kev"`
	EPSS       float64 `json:"epss,omitempty"`

	// MatchedVendor and the fields below record the advisory product_tree node
	// that matched, so the evidence view can show the advisory side of the
	// comparison verbatim.
	MatchedVendor    string `json:"matched_vendor,omitempty"`
	MatchedProduct   string `json:"matched_product,omitempty"`
	MatchedVersion   string `json:"matched_version,omitempty"`
	MatchedProductID string `json:"matched_product_id,omitempty"`

	// AlsoMatched names the other product_tree nodes in the same advisory that
	// this asset matched. One finding is emitted per advisory rather than per
	// node, because a CSAF tree listing fourteen variants of one device would
	// otherwise become fourteen findings that an engineer has to dismiss one at
	// a time. The nodes are kept so the evidence view can still show them.
	AlsoMatched []string `json:"also_matched,omitempty"`

	// AssetIdentity is the normalized identity the match was made against, and
	// EvidenceIDs point at the observations it came from. Together they let the
	// evidence view show the wire, the normalized identity and the advisory node
	// side by side without re-running the match.
	AssetIdentity asset.Identity `json:"asset_identity,omitzero"`
	EvidenceIDs   []string       `json:"evidence_ids,omitempty"`

	VersionCheck *VersionCheck `json:"version_check,omitempty"`
	Reasons      []Reason      `json:"reasons,omitempty"`

	// FixAvailable is true when the advisory offers a vendor fix rather than only
	// a workaround. In a plant that is the difference between needing an outage
	// window and not, so it is worth a column of its own.
	FixAvailable bool `json:"fix_available,omitempty"`

	Remediations []string `json:"remediations,omitempty"`
	References   []string `json:"references,omitempty"`
}

// Priority produces a single sortable number for the findings table. KEV
// membership dominates because a vulnerability known to be exploited in the
// wild outranks a theoretically worse one that nobody is using.
func (f Finding) Priority() float64 {
	score := f.Score * 10
	if f.KEV {
		score += 1000
	}
	score += f.EPSS * 100
	score += f.CVSS
	score += float64(f.Tier.Rank()) * 50
	return score
}

// Set is the on-disk findings document.
type Set struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Generator     string    `json:"generator"`
	InventoryPath string    `json:"inventory_path,omitempty"`
	CorpusPath    string    `json:"corpus_path,omitempty"`
	Findings      []Finding `json:"findings"`
	Summary       Summary   `json:"summary"`
}

// Summary holds the counts the dashboard header and CLI output display.
type Summary struct {
	Total          int          `json:"total"`
	ByTier         map[Tier]int `json:"by_tier"`
	AssetsAffected int          `json:"assets_affected"`
	KEVCount       int          `json:"kev_count"`
	FixAvailable   int          `json:"fix_available"`
	UniqueCVEs     int          `json:"unique_cves"`

	// AssetsConsidered and the fields below describe the run rather than its
	// output. A findings document with an empty list means something quite
	// different depending on whether nothing matched or nothing was identifiable
	// in the first place, and an operator has to be able to tell which.
	AssetsConsidered   int `json:"assets_considered"`
	AssetsUnidentified int `json:"assets_unidentified"`
	AssetsUnknownVendo int `json:"assets_unknown_vendor"`
	RuledOutByVersion  int `json:"ruled_out_by_version"`
}

// NewSet returns an empty findings document.
func NewSet(generator string) *Set {
	return &Set{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Generator:     generator,
		Findings:      make([]Finding, 0),
	}
}

// Finalize sorts findings by priority and recomputes the summary.
func (s *Set) Finalize() {
	sort.SliceStable(s.Findings, func(i, j int) bool {
		if s.Findings[i].Priority() != s.Findings[j].Priority() {
			return s.Findings[i].Priority() > s.Findings[j].Priority()
		}
		if s.Findings[i].AdvisoryID != s.Findings[j].AdvisoryID {
			return s.Findings[i].AdvisoryID < s.Findings[j].AdvisoryID
		}
		return s.Findings[i].AssetID < s.Findings[j].AssetID
	})

	// The run counters are preserved: the matcher sets them and they describe the
	// inputs, which recounting the output cannot recover.
	summary := Summary{
		ByTier:             make(map[Tier]int),
		AssetsConsidered:   s.Summary.AssetsConsidered,
		AssetsUnidentified: s.Summary.AssetsUnidentified,
		AssetsUnknownVendo: s.Summary.AssetsUnknownVendo,
		RuledOutByVersion:  s.Summary.RuledOutByVersion,
	}
	assets := make(map[string]struct{})
	cves := make(map[string]struct{})
	for _, f := range s.Findings {
		summary.Total++
		summary.ByTier[f.Tier]++
		assets[f.AssetID] = struct{}{}
		if f.KEV {
			summary.KEVCount++
		}
		if f.FixAvailable {
			summary.FixAvailable++
		}
		for _, cve := range f.CVEs {
			cves[cve] = struct{}{}
		}
	}
	summary.AssetsAffected = len(assets)
	summary.UniqueCVEs = len(cves)
	s.Summary = summary
}

// Save writes the findings document to disk.
func (s *Set) Save(path string) error {
	s.Finalize()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode findings: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write findings: %w", err)
	}
	return nil
}

// Load reads a findings document from disk.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read findings: %w", err)
	}
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("parse findings %s: %w", path, err)
	}
	if set.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("findings %s uses schema version %q, this build understands %q",
			path, set.SchemaVersion, SchemaVersion)
	}
	return &set, nil
}

// NewID builds a deterministic finding id from the asset and advisory pair so
// that two runs over unchanged inputs produce identical output.
func NewID(assetID, advisoryID, product string) string {
	return fmt.Sprintf("%s:%s:%s", assetID, advisoryID, product)
}
