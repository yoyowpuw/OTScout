// Package ingest builds an asset inventory from data that already exists: packet
// captures, Zeek logs and Nmap output.
//
// Nothing in this package opens a network socket. That is the whole point of it.
// A site can get a complete inventory and a correlated advisory list without a
// single packet being sent at its equipment, which is the only way many plants
// will allow a tool anywhere near their network. The absence of any network code
// here is asserted by a test rather than left as a promise.
package ingest

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// Options configures an ingest run.
type Options struct {
	// PcapFiles are packet captures in pcap or pcapng format.
	PcapFiles []string
	// ZeekPaths are Zeek log files or directories containing them.
	ZeekPaths []string
	// NmapFiles are Nmap XML output files.
	NmapFiles []string

	// Normalizer resolves vendor and product identities. When nil, the embedded
	// tables are loaded.
	Normalizer *normalize.Normalizer

	// MaxFlowBufferBytes caps how much payload is held per direction of a TCP
	// conversation while waiting for a response to become complete. A capture is
	// untrusted input, so this bound is what stops a crafted file from exhausting
	// memory.
	MaxFlowBufferBytes int

	// MaxPacketsPerFile stops reading a capture after this many packets. Zero
	// means no limit.
	MaxPacketsPerFile int

	// Progress receives human readable progress lines. It may be nil.
	Progress io.Writer
}

const (
	defaultMaxFlowBufferBytes = 64 * 1024
	// A protocol identification response that does not fit in this much data is
	// not one this build understands.
	maxDecodeAttemptBytes = 16 * 1024
)

// Stats summarises what an ingest run read.
type Stats struct {
	FilesRead       int            `json:"files_read"`
	PacketsRead     int            `json:"packets_read"`
	PayloadsTried   int            `json:"payloads_tried"`
	IdentitiesFound int            `json:"identities_found"`
	RecordsRead     map[string]int `json:"records_read,omitempty"`
	Warnings        []string       `json:"warnings,omitempty"`
}

func newStats() *Stats {
	return &Stats{RecordsRead: make(map[string]int)}
}

func (s *Stats) warn(format string, args ...any) {
	s.Warnings = append(s.Warnings, fmt.Sprintf(format, args...))
}

// Result is the outcome of an ingest run.
type Result struct {
	Inventory *asset.Inventory
	Stats     *Stats
	// Reports holds the normalization reasoning per asset id, which the evidence
	// view renders.
	Reports map[string]normalize.IdentityReport
}

// Run reads every configured source and returns an inventory.
//
// Sources are processed from most to least authoritative: packet captures carry
// actual protocol responses, Nmap script output carries responses Nmap itself
// collected, and Zeek logs and Nmap banners are weaker inferences. Identity fields
// are filled only when still empty, so a stronger source is never overwritten by a
// weaker one that happened to be read later.
func Run(ctx context.Context, opts Options) (*Result, error) {
	if len(opts.PcapFiles) == 0 && len(opts.ZeekPaths) == 0 && len(opts.NmapFiles) == 0 {
		return nil, errors.New("no input given: pass at least one of --pcap, --zeek or --nmap")
	}
	if opts.MaxFlowBufferBytes <= 0 {
		opts.MaxFlowBufferBytes = defaultMaxFlowBufferBytes
	}

	normalizer := opts.Normalizer
	if normalizer == nil {
		var err error
		normalizer, err = normalize.New()
		if err != nil {
			return nil, fmt.Errorf("load normalization tables: %w", err)
		}
	}

	s := newSink(normalizer)

	for _, path := range opts.PcapFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.progressf(opts.Progress, "reading capture %s\n", path)
		if err := readPcapFile(ctx, path, s, opts); err != nil {
			// One unreadable file must not lose the work already done on the
			// others, so this is a warning and the run continues.
			s.stats.warn("capture %s: %v", path, err)
			continue
		}
		s.stats.FilesRead++
	}

	for _, path := range opts.NmapFiles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.progressf(opts.Progress, "reading nmap output %s\n", path)
		if err := readNmapXML(path, s); err != nil {
			s.stats.warn("nmap %s: %v", path, err)
			continue
		}
		s.stats.FilesRead++
	}

	for _, path := range opts.ZeekPaths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		s.progressf(opts.Progress, "reading zeek logs at %s\n", path)
		count, err := readZeekPath(ctx, path, s)
		if err != nil {
			s.stats.warn("zeek %s: %v", path, err)
			continue
		}
		s.stats.FilesRead += count
	}

	inv := s.finish()
	reports := normalizer.Inventory(inv)
	inv.Finalize()

	for idx := range inv.Assets {
		if !inv.Assets[idx].Identity.Empty() {
			s.stats.IdentitiesFound++
		}
	}

	return &Result{Inventory: inv, Stats: s.stats, Reports: reports}, nil
}

// sink accumulates assets and flows across every source.
type sink struct {
	inv        *asset.Inventory
	normalizer *normalize.Normalizer
	stats      *Stats
	devices    map[string]*deviceBuilder
	flows      []asset.Flow
}

func newSink(normalizer *normalize.Normalizer) *sink {
	return &sink{
		inv:        asset.NewInventory("otscout ingest"),
		normalizer: normalizer,
		stats:      newStats(),
		devices:    make(map[string]*deviceBuilder),
	}
}

func (s *sink) progressf(w io.Writer, format string, args ...any) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, format, args...)
}

// device returns the builder for an address, creating it on first sight.
func (s *sink) device(addr asset.Addresses) *deviceBuilder {
	stored := s.inv.ByAddress(addr)
	// Fill in address fields a later source knows and an earlier one did not.
	if stored.Addresses.IPv4 == "" {
		stored.Addresses.IPv4 = addr.IPv4
	}
	if stored.Addresses.IPv6 == "" {
		stored.Addresses.IPv6 = addr.IPv6
	}
	if stored.Addresses.MAC == "" {
		stored.Addresses.MAC = addr.MAC
	}
	if stored.Addresses.Hostname == "" {
		stored.Addresses.Hostname = addr.Hostname
	}

	builder, ok := s.devices[stored.ID]
	if !ok {
		builder = &deviceBuilder{asset: stored, fields: make(map[string]string)}
		s.devices[stored.ID] = builder
	}
	// The inventory slice can be reallocated by an append, so the pointer is
	// refreshed rather than cached across calls.
	builder.asset = stored
	return builder
}

// addFlow records an observed conversation.
func (s *sink) addFlow(flow asset.Flow) {
	s.flows = append(s.flows, flow)
}

// minUncorroboratedCatalogConfidence is the bar an order code has to clear when it
// was found in free text that names no vendor. With a vendor to check it against a
// weaker parse is still trustworthy; without one, only a strong parse is.
const minUncorroboratedCatalogConfidence = 0.8

// sniffText recovers a vendor and an order code from a free text device
// description, of the kind LLDP and Nmap service output carry.
//
// The vendor is resolved first and then used to restrict which order code schemes
// apply. That ordering is what stops a fragment of one vendor's code from being
// read as another vendor's: "6GK5 208-0BA10-2AA3" contains "208-0BA10-2AA3", which
// on its own parses as a Rockwell Micro800 catalog number, and the only thing that
// rules it out is that the same sentence says Siemens.
func (s *sink) sniffText(text string) (vendorDisplay, catalog string) {
	if strings.TrimSpace(text) == "" {
		return "", ""
	}

	vendorID := ""
	if match, ok := s.normalizer.Vendors.LookupVendor(text); ok {
		vendorID, vendorDisplay = match.ID, match.Display
	}

	bestConfidence := 0.0
	for _, candidate := range catalogCandidates(text) {
		result, ok := s.parseCatalogCandidate(candidate, vendorID)
		if !ok {
			continue
		}
		// A stronger parse always wins. At equal strength the shorter candidate
		// wins, because the longer one has picked up a neighbouring word: both
		// "1756-L71/B" and "1756-L71/B LOGIX5571" parse as a ControlLogix 5570,
		// and only the first is the order code.
		switch {
		case result.Confidence > bestConfidence,
			result.Confidence == bestConfidence && catalog != "" && len(candidate) < len(catalog):
			catalog, bestConfidence = candidate, result.Confidence
		}
	}
	return vendorDisplay, catalog
}

// applyTextIdentity folds whatever sniffText recovers into a device, filling only
// fields that are still empty and recording how it was reached.
func (s *sink) applyTextIdentity(device *deviceBuilder, text string) {
	vendor, catalog := s.sniffText(text)
	if vendor != "" && device.asset.Identity.Vendor == "" && device.asset.Identity.VendorRaw == "" {
		device.setVendor(vendor)
		device.addNote(fmt.Sprintf("vendor %s named in %q", vendor, collapseWhitespace(text)))
	}
	if catalog != "" && device.asset.Identity.CatalogNumber == "" {
		device.setCatalogNumber(catalog)
		device.addNote(fmt.Sprintf("order code %s recognised in %q", catalog, collapseWhitespace(text)))
	}
}

func (s *sink) parseCatalogCandidate(candidate, vendorID string) (normalize.CatalogResult, bool) {
	if vendorID == "" {
		result, ok := normalize.ParseCatalog(candidate)
		if !ok || result.Confidence < minUncorroboratedCatalogConfidence {
			return normalize.CatalogResult{}, false
		}
		return result, true
	}
	result, ok := s.normalizer.Vendors.ParseCatalogForVendor(vendorID, candidate)
	// A vendor that declares no parsers falls back to trying all of them, so the
	// result still has to be checked against the vendor the text named.
	if !ok || (result.VendorID != "" && result.VendorID != vendorID) {
		return normalize.CatalogResult{}, false
	}
	return result, true
}

// catalogCandidates breaks free text into the token sequences worth trying as an
// order code: every token, and every adjacent pair within one clause. Pairs are
// needed because Siemens prints its MLFB with a space in the middle. Pairs never
// cross a comma, since two words either side of one are not part of one code.
func catalogCandidates(text string) []string {
	clauses := strings.FieldsFunc(text, func(r rune) bool {
		return r == ',' || r == ';' || r == '\n' || r == '\r' || r == '(' || r == ')'
	})

	out := make([]string, 0, 16)
	for _, clause := range clauses {
		tokens := strings.Fields(clause)
		for idx := range tokens {
			token := strings.Trim(tokens[idx], ".:\"'")
			if token == "" {
				continue
			}
			if len(token) >= 6 {
				out = append(out, token)
			}
			if idx+1 < len(tokens) {
				next := strings.Trim(tokens[idx+1], ".:\"'")
				if next != "" {
					out = append(out, token+" "+next)
				}
			}
		}
	}
	return out
}

// finish resolves flow endpoints to asset ids and returns the inventory.
func (s *sink) finish() *asset.Inventory {
	byAddress := make(map[string]string, len(s.inv.Assets))
	for idx := range s.inv.Assets {
		a := &s.inv.Assets[idx]
		for _, addr := range []string{a.Addresses.IPv4, a.Addresses.IPv6, a.Addresses.MAC} {
			if addr != "" {
				byAddress[addr] = a.ID
			}
		}
	}

	for idx := range s.flows {
		flow := &s.flows[idx]
		if id, ok := byAddress[flow.SrcAddr]; ok {
			flow.SrcAssetID = id
		}
		if id, ok := byAddress[flow.DstAddr]; ok {
			flow.DstAssetID = id
		}
	}
	s.inv.Flows = append(s.inv.Flows, s.flows...)
	return s.inv
}

// deviceBuilder collects observations about one device before they are written to
// the asset.
type deviceBuilder struct {
	asset  *asset.Asset
	fields map[string]string
	notes  []string
}

func (d *deviceBuilder) setField(key, value string) {
	if key == "" || value == "" {
		return
	}
	d.fields[key] = value
}

// pendingFields returns the fields gathered since the last call and clears them,
// so that each evidence record carries only what that observation contributed.
func (d *deviceBuilder) pendingFields() map[string]string {
	if len(d.fields) == 0 {
		return nil
	}
	out := make(map[string]string, len(d.fields))
	for key, value := range d.fields {
		out[key] = value
	}
	d.fields = make(map[string]string)
	return out
}

func (d *deviceBuilder) pendingNotes() []string {
	if len(d.notes) == 0 {
		return nil
	}
	out := append([]string(nil), d.notes...)
	d.notes = nil
	return out
}

func (d *deviceBuilder) addNote(note string) {
	for _, existing := range d.notes {
		if existing == note {
			return
		}
	}
	d.notes = append(d.notes, note)
}

// The setters below fill a field only when it is still empty. Ingest reads several
// sources of differing quality, and a weaker source arriving later must not
// displace what a stronger one already established.
func (d *deviceBuilder) setVendor(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if d.asset.Identity.VendorRaw == "" {
		d.asset.Identity.VendorRaw = value
	}
	if d.asset.Identity.Vendor == "" {
		d.asset.Identity.Vendor = value
	}
}

func (d *deviceBuilder) setProduct(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if d.asset.Identity.ProductRaw == "" {
		d.asset.Identity.ProductRaw = value
	}
	if d.asset.Identity.Product == "" {
		d.asset.Identity.Product = value
	}
}

func (d *deviceBuilder) setFirmware(value string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	if d.asset.Identity.FirmwareRaw == "" {
		d.asset.Identity.FirmwareRaw = value
	}
	if d.asset.Identity.Firmware == "" {
		d.asset.Identity.Firmware = value
	}
}

func (d *deviceBuilder) setSerial(value string) {
	if value = strings.TrimSpace(value); value != "" && d.asset.Identity.Serial == "" {
		d.asset.Identity.Serial = value
	}
}

func (d *deviceBuilder) setCatalogNumber(value string) {
	if value = strings.TrimSpace(value); value != "" && d.asset.Identity.CatalogNumber == "" {
		d.asset.Identity.CatalogNumber = value
	}
}

func (d *deviceBuilder) setHardwareRev(value string) {
	if value = strings.TrimSpace(value); value != "" && d.asset.Identity.HardwareRev == "" {
		d.asset.Identity.HardwareRev = value
	}
}

func (d *deviceBuilder) setRole(role asset.Role) {
	if role != asset.RoleUnknown && d.asset.Role == asset.RoleUnknown {
		d.asset.Role = role
	}
}

func (d *deviceBuilder) mergeIdentity(id asset.Identity) {
	d.setVendor(firstNonEmpty(id.VendorRaw, id.Vendor))
	d.setProduct(firstNonEmpty(id.ProductRaw, id.Product))
	d.setFirmware(firstNonEmpty(id.FirmwareRaw, id.Firmware))
	d.setSerial(id.Serial)
	d.setCatalogNumber(id.CatalogNumber)
	d.setHardwareRev(id.HardwareRev)
	if d.asset.Identity.Model == "" {
		d.asset.Identity.Model = id.Model
	}
	if d.asset.Identity.Family == "" {
		d.asset.Identity.Family = id.Family
	}
}

func (d *deviceBuilder) addService(svc asset.Service) {
	d.asset.AddService(svc)
}

func (d *deviceBuilder) addEvidence(ev asset.Evidence) {
	if len(ev.Fields) == 0 && len(ev.Notes) == 0 && len(ev.Response) == 0 {
		return
	}
	d.asset.AddEvidence(ev)
}

func (d *deviceBuilder) touchSeen(ts time.Time) {
	if ts.IsZero() {
		return
	}
	if d.asset.FirstSeen.IsZero() || ts.Before(d.asset.FirstSeen) {
		d.asset.FirstSeen = ts
	}
	if ts.After(d.asset.LastSeen) {
		d.asset.LastSeen = ts
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// sortedKeys is used when building deterministic output from a map.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
