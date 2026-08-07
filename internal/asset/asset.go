// Package asset defines the canonical asset model that every part of otscout
// reads and writes. Both the passive ingest path and the active probe path
// converge on these types, which is what allows a single normalization layer
// and a single matcher to serve both.
package asset

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// SchemaVersion is bumped whenever the on-disk inventory format changes in a
// way that older readers cannot handle.
const SchemaVersion = "1"

// SourceKind records how a piece of information reached us. Keeping this on
// every observation is what lets the UI tell an operator whether a finding
// came from a packet we sent or from traffic we merely watched.
type SourceKind string

const (
	SourceProbe  SourceKind = "probe"
	SourcePcap   SourceKind = "pcap"
	SourceZeek   SourceKind = "zeek"
	SourceNmap   SourceKind = "nmap"
	SourceManual SourceKind = "manual"
)

// Passive reports whether the source kind sent any packets to the device.
func (s SourceKind) Passive() bool { return s != SourceProbe }

// Identity holds both the raw strings seen on the wire and their normalized
// forms. The raw values are never discarded: the evidence trail in the UI
// shows operators exactly what was observed before normalization guessed at
// its meaning, and that transparency is what makes the matcher trustworthy.
type Identity struct {
	Vendor    string `json:"vendor,omitempty"`
	VendorRaw string `json:"vendor_raw,omitempty"`

	Product    string `json:"product,omitempty"`
	ProductRaw string `json:"product_raw,omitempty"`

	Family string `json:"family,omitempty"`
	Model  string `json:"model,omitempty"`

	// CatalogNumber is the vendor order code, for example the Siemens MLFB
	// 6ES7 214-1AG40-0XB0 or the Rockwell catalog number 1756-L71. These
	// encode the model and are often the only reliable identifier a device
	// reports.
	CatalogNumber string `json:"catalog_number,omitempty"`

	Firmware    string `json:"firmware,omitempty"`
	FirmwareRaw string `json:"firmware_raw,omitempty"`

	HardwareRev string `json:"hardware_rev,omitempty"`
	Serial      string `json:"serial,omitempty"`
}

// Empty reports whether nothing at all is known about the device identity.
func (i Identity) Empty() bool {
	return i.Vendor == "" && i.VendorRaw == "" &&
		i.Product == "" && i.ProductRaw == "" &&
		i.Family == "" && i.Model == "" &&
		i.CatalogNumber == "" && i.Firmware == "" && i.FirmwareRaw == ""
}

// Label renders a short human readable identity for tables and logs.
func (i Identity) Label() string {
	parts := make([]string, 0, 3)
	switch {
	case i.Vendor != "":
		parts = append(parts, i.Vendor)
	case i.VendorRaw != "":
		parts = append(parts, i.VendorRaw)
	}
	switch {
	case i.Product != "":
		parts = append(parts, i.Product)
	case i.ProductRaw != "":
		parts = append(parts, i.ProductRaw)
	case i.Family != "":
		parts = append(parts, i.Family)
	}
	if i.Firmware != "" {
		parts = append(parts, i.Firmware)
	}
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, " ")
}

// Merge folds other into i, preferring values already present. Normalization
// runs before merging, so a later observation never downgrades a field that an
// earlier, better observation already filled in.
func (i *Identity) Merge(other Identity) {
	mergeString(&i.Vendor, other.Vendor)
	mergeString(&i.VendorRaw, other.VendorRaw)
	mergeString(&i.Product, other.Product)
	mergeString(&i.ProductRaw, other.ProductRaw)
	mergeString(&i.Family, other.Family)
	mergeString(&i.Model, other.Model)
	mergeString(&i.CatalogNumber, other.CatalogNumber)
	mergeString(&i.Firmware, other.Firmware)
	mergeString(&i.FirmwareRaw, other.FirmwareRaw)
	mergeString(&i.HardwareRev, other.HardwareRev)
	mergeString(&i.Serial, other.Serial)
}

func mergeString(dst *string, src string) {
	if *dst == "" {
		*dst = src
	}
}

// Service is a network service observed on an asset.
type Service struct {
	Port      int        `json:"port"`
	Transport string     `json:"transport"`
	Protocol  string     `json:"protocol,omitempty"`
	Banner    string     `json:"banner,omitempty"`
	FirstSeen time.Time  `json:"first_seen,omitzero"`
	LastSeen  time.Time  `json:"last_seen,omitzero"`
	Source    SourceKind `json:"source,omitempty"`
}

// Endpoint renders the service as host:port for display.
func (s Service) Endpoint(host string) string {
	return fmt.Sprintf("%s:%d", host, s.Port)
}

// Evidence is one observation that contributed to an asset. Request is nil for
// anything the passive path produced, which gives the UI an unambiguous way to
// show that no packets were sent.
type Evidence struct {
	ID         string            `json:"id"`
	Source     SourceKind        `json:"source"`
	Protocol   string            `json:"protocol,omitempty"`
	TemplateID string            `json:"template_id,omitempty"`
	Endpoint   string            `json:"endpoint,omitempty"`
	Timestamp  time.Time         `json:"timestamp,omitzero"`
	Request    HexBytes          `json:"request,omitempty"`
	Response   HexBytes          `json:"response,omitempty"`
	Fields     map[string]string `json:"fields,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}

// Asset is a single device in the inventory.
type Asset struct {
	ID        string      `json:"id"`
	Addresses Addresses   `json:"addresses"`
	Identity  Identity    `json:"identity"`
	Purdue    PurdueLevel `json:"purdue"`
	Role      Role        `json:"role"`
	Services  []Service   `json:"services,omitempty"`
	Evidence  []Evidence  `json:"evidence,omitempty"`
	Tags      []string    `json:"tags,omitempty"`
	FirstSeen time.Time   `json:"first_seen,omitzero"`
	LastSeen  time.Time   `json:"last_seen,omitzero"`
	Sources   []string    `json:"sources,omitempty"`
}

// Addresses holds the network identifiers for an asset.
type Addresses struct {
	IPv4     string `json:"ipv4,omitempty"`
	IPv6     string `json:"ipv6,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// Primary returns the most useful address for display and for asset identity.
func (a Addresses) Primary() string {
	switch {
	case a.IPv4 != "":
		return a.IPv4
	case a.IPv6 != "":
		return a.IPv6
	case a.MAC != "":
		return a.MAC
	case a.Hostname != "":
		return a.Hostname
	default:
		return ""
	}
}

// NewID derives a stable asset identifier from the addresses. Stability across
// runs matters because the baseline diff view compares two separate scans and
// needs to recognise the same device in both.
func NewID(addr Addresses) string {
	key := strings.ToLower(strings.Join([]string{addr.IPv4, addr.IPv6, addr.MAC}, "|"))
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}

// AddService records a service, merging into an existing entry when the port
// and transport already appear.
func (a *Asset) AddService(svc Service) {
	for idx := range a.Services {
		existing := &a.Services[idx]
		if existing.Port != svc.Port || existing.Transport != svc.Transport {
			continue
		}
		mergeString(&existing.Protocol, svc.Protocol)
		mergeString(&existing.Banner, svc.Banner)
		if existing.FirstSeen.IsZero() || (!svc.FirstSeen.IsZero() && svc.FirstSeen.Before(existing.FirstSeen)) {
			existing.FirstSeen = svc.FirstSeen
		}
		if svc.LastSeen.After(existing.LastSeen) {
			existing.LastSeen = svc.LastSeen
		}
		return
	}
	a.Services = append(a.Services, svc)
}

// AddEvidence appends an observation and widens the asset time window.
func (a *Asset) AddEvidence(ev Evidence) {
	if ev.ID == "" {
		ev.ID = evidenceID(a.ID, len(a.Evidence), ev)
	}
	a.Evidence = append(a.Evidence, ev)
	a.touch(ev.Timestamp)
	a.addSource(string(ev.Source))
}

func evidenceID(assetID string, index int, ev Evidence) string {
	key := fmt.Sprintf("%s|%d|%s|%s|%s", assetID, index, ev.Source, ev.Protocol, ev.TemplateID)
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:6])
}

func (a *Asset) touch(ts time.Time) {
	if ts.IsZero() {
		return
	}
	if a.FirstSeen.IsZero() || ts.Before(a.FirstSeen) {
		a.FirstSeen = ts
	}
	if ts.After(a.LastSeen) {
		a.LastSeen = ts
	}
}

func (a *Asset) addSource(src string) {
	if src == "" {
		return
	}
	for _, existing := range a.Sources {
		if existing == src {
			return
		}
	}
	a.Sources = append(a.Sources, src)
	sort.Strings(a.Sources)
}

// AddTag records a tag once.
func (a *Asset) AddTag(tag string) {
	if tag == "" {
		return
	}
	for _, existing := range a.Tags {
		if existing == tag {
			return
		}
	}
	a.Tags = append(a.Tags, tag)
	sort.Strings(a.Tags)
}

// Ports returns the sorted list of observed ports, used by role inference and
// by the topology view.
func (a *Asset) Ports() []int {
	ports := make([]int, 0, len(a.Services))
	for _, svc := range a.Services {
		ports = append(ports, svc.Port)
	}
	sort.Ints(ports)
	return ports
}

// Protocols returns the distinct sorted protocol names observed on the asset.
func (a *Asset) Protocols() []string {
	seen := make(map[string]struct{}, len(a.Services))
	for _, svc := range a.Services {
		if svc.Protocol != "" {
			seen[svc.Protocol] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Merge folds another observation of the same device into a.
func (a *Asset) Merge(other *Asset) {
	mergeString(&a.Addresses.IPv4, other.Addresses.IPv4)
	mergeString(&a.Addresses.IPv6, other.Addresses.IPv6)
	mergeString(&a.Addresses.MAC, other.Addresses.MAC)
	mergeString(&a.Addresses.Hostname, other.Addresses.Hostname)
	a.Identity.Merge(other.Identity)
	if a.Purdue == PurdueUnknown {
		a.Purdue = other.Purdue
	}
	if a.Role == RoleUnknown {
		a.Role = other.Role
	}
	for _, svc := range other.Services {
		a.AddService(svc)
	}
	for _, ev := range other.Evidence {
		a.AddEvidence(ev)
	}
	for _, tag := range other.Tags {
		a.AddTag(tag)
	}
	for _, src := range other.Sources {
		a.addSource(src)
	}
	a.touch(other.FirstSeen)
	a.touch(other.LastSeen)
}
