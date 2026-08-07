package asset

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Inventory is the on-disk asset document, written by ingest and probe and read
// by match, report and serve.
type Inventory struct {
	SchemaVersion string    `json:"schema_version"`
	GeneratedAt   time.Time `json:"generated_at"`
	Generator     string    `json:"generator"`
	Assets        []Asset   `json:"assets"`
	Flows         []Flow    `json:"flows,omitempty"`

	// index maps asset id to position in Assets. It is rebuilt on load and
	// never serialised.
	index map[string]int `json:"-"`
}

// NewInventory returns an empty inventory stamped with the current time.
func NewInventory(generator string) *Inventory {
	return &Inventory{
		SchemaVersion: SchemaVersion,
		GeneratedAt:   time.Now().UTC(),
		Generator:     generator,
		Assets:        make([]Asset, 0),
		index:         make(map[string]int),
	}
}

func (inv *Inventory) ensureIndex() {
	if inv.index != nil {
		return
	}
	inv.index = make(map[string]int, len(inv.Assets))
	for idx := range inv.Assets {
		inv.index[inv.Assets[idx].ID] = idx
	}
}

// Upsert adds an asset or merges it into the existing entry with the same id,
// returning a pointer to the stored asset.
func (inv *Inventory) Upsert(a Asset) *Asset {
	inv.ensureIndex()
	if a.ID == "" {
		a.ID = NewID(a.Addresses)
	}
	if idx, ok := inv.index[a.ID]; ok {
		inv.Assets[idx].Merge(&a)
		return &inv.Assets[idx]
	}
	inv.Assets = append(inv.Assets, a)
	inv.index[a.ID] = len(inv.Assets) - 1
	return &inv.Assets[len(inv.Assets)-1]
}

// ByAddress finds an asset by any of its addresses, creating one when absent.
// Ingest uses this to attach observations to the right device without caring
// which address a given log format happened to record.
func (inv *Inventory) ByAddress(addr Addresses) *Asset {
	inv.ensureIndex()
	id := NewID(addr)
	if idx, ok := inv.index[id]; ok {
		return &inv.Assets[idx]
	}
	// Fall back to matching on any single address, since one source may know
	// only the IP while another knows only the MAC.
	for idx := range inv.Assets {
		existing := &inv.Assets[idx]
		if addr.IPv4 != "" && existing.Addresses.IPv4 == addr.IPv4 {
			return existing
		}
		if addr.MAC != "" && existing.Addresses.MAC == addr.MAC {
			return existing
		}
	}
	return inv.Upsert(Asset{ID: id, Addresses: addr})
}

// Get returns the asset with the given id.
func (inv *Inventory) Get(id string) (*Asset, bool) {
	inv.ensureIndex()
	idx, ok := inv.index[id]
	if !ok {
		return nil, false
	}
	return &inv.Assets[idx], true
}

// Classify runs role and Purdue inference over every asset.
func (inv *Inventory) Classify() {
	for idx := range inv.Assets {
		Classify(&inv.Assets[idx]).Apply(&inv.Assets[idx])
	}
}

// Finalize normalises ordering and derived data before writing. Deterministic
// output matters because inventories get committed to version control and
// diffed between scans.
func (inv *Inventory) Finalize() {
	inv.Classify()
	inv.Flows = MergeFlows(inv.Flows)

	sort.SliceStable(inv.Assets, func(i, j int) bool {
		return compareAssets(inv.Assets[i], inv.Assets[j])
	})
	for idx := range inv.Assets {
		a := &inv.Assets[idx]
		sort.SliceStable(a.Services, func(i, j int) bool {
			if a.Services[i].Port != a.Services[j].Port {
				return a.Services[i].Port < a.Services[j].Port
			}
			return a.Services[i].Transport < a.Services[j].Transport
		})
	}
	sort.SliceStable(inv.Flows, func(i, j int) bool {
		return inv.Flows[i].Key() < inv.Flows[j].Key()
	})
	inv.index = nil
	inv.ensureIndex()
}

func compareAssets(a, b Asset) bool {
	ai, aok := ipSortKey(a.Addresses.IPv4)
	bi, bok := ipSortKey(b.Addresses.IPv4)
	if aok && bok && ai != bi {
		return ai < bi
	}
	if aok != bok {
		return aok
	}
	if a.Addresses.Primary() != b.Addresses.Primary() {
		return a.Addresses.Primary() < b.Addresses.Primary()
	}
	return a.ID < b.ID
}

// ipSortKey converts a dotted quad into a sortable integer so that 10.0.0.9
// sorts before 10.0.0.10 instead of after it.
func ipSortKey(ip string) (uint32, bool) {
	if ip == "" {
		return 0, false
	}
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return 0, false
	}
	var key uint32
	for _, part := range parts {
		var octet int
		if _, err := fmt.Sscanf(part, "%d", &octet); err != nil || octet < 0 || octet > 255 {
			return 0, false
		}
		key = key<<8 | uint32(octet)
	}
	return key, true
}

// SegmentationIssues grades the flows recorded in the inventory.
func (inv *Inventory) SegmentationIssues() []SegmentationIssue {
	return AnalyzeSegmentation(inv.Assets, inv.Flows)
}

// Merge folds another inventory into this one.
func (inv *Inventory) Merge(other *Inventory) {
	for _, a := range other.Assets {
		inv.Upsert(a)
	}
	inv.Flows = append(inv.Flows, other.Flows...)
}

// Save writes the inventory as indented JSON, creating parent directories.
func (inv *Inventory) Save(path string) error {
	inv.Finalize()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create output directory: %w", err)
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create inventory file: %w", err)
	}
	defer file.Close()

	if err := inv.Write(file); err != nil {
		return err
	}
	return file.Close()
}

// Write serialises the inventory to w.
func (inv *Inventory) Write(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(inv); err != nil {
		return fmt.Errorf("encode inventory: %w", err)
	}
	return nil
}

// LoadInventory reads an inventory document from disk.
func LoadInventory(path string) (*Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read inventory: %w", err)
	}
	var inv Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parse inventory %s: %w", path, err)
	}
	if inv.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("inventory %s uses schema version %q, this build understands %q",
			path, inv.SchemaVersion, SchemaVersion)
	}
	inv.ensureIndex()
	return &inv, nil
}

// Stats summarises an inventory for the CLI and for the dashboard header.
type Stats struct {
	Assets       int                 `json:"assets"`
	Identified   int                 `json:"identified"`
	Flows        int                 `json:"flows"`
	ByPurdue     map[PurdueLevel]int `json:"by_purdue"`
	ByRole       map[Role]int        `json:"by_role"`
	ByProtocol   map[string]int      `json:"by_protocol"`
	Segmentation int                 `json:"segmentation_issues"`
}

// Stats computes the summary counts.
func (inv *Inventory) Stats() Stats {
	st := Stats{
		Assets:     len(inv.Assets),
		Flows:      len(inv.Flows),
		ByPurdue:   make(map[PurdueLevel]int),
		ByRole:     make(map[Role]int),
		ByProtocol: make(map[string]int),
	}
	for idx := range inv.Assets {
		a := &inv.Assets[idx]
		if !a.Identity.Empty() {
			st.Identified++
		}
		st.ByPurdue[a.Purdue]++
		st.ByRole[a.Role]++
		for _, proto := range a.Protocols() {
			st.ByProtocol[proto]++
		}
	}
	st.Segmentation = len(inv.SegmentationIssues())
	return st
}
