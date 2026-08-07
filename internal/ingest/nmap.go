package ingest

import (
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// nmapRun is the subset of the Nmap XML schema otscout reads.
//
// Nmap output is a common starting point because many sites already have a scan
// on file from an IT audit, which means an inventory can be built without sending
// anything new at the equipment.
type nmapRun struct {
	Scanner string     `xml:"scanner,attr"`
	Args    string     `xml:"args,attr"`
	Start   int64      `xml:"start,attr"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	StartTime int64         `xml:"starttime,attr"`
	EndTime   int64         `xml:"endtime,attr"`
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames []nmapHost2   `xml:"hostnames>hostname"`
	Ports     []nmapPort    `xml:"ports>port"`
	OSMatches []nmapOSMatch `xml:"os>osmatch"`
	Scripts   []nmapScript  `xml:"hostscript>script"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr   string `xml:"addr,attr"`
	Type   string `xml:"addrtype,attr"`
	Vendor string `xml:"vendor,attr"`
}

type nmapHost2 struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	DeviceType string `xml:"devicetype,attr"`
}

type nmapOSMatch struct {
	Name string `xml:"name,attr"`
}

// nmapScript holds a script result. Nmap emits structured output as nested tables
// of key and value elements, which is far more reliable to read than the flat
// text rendering.
type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// flatten collects every key and value pair in a script result, including nested
// tables, so that callers do not have to know how deep a particular script nests
// its output.
func (s nmapScript) flatten() map[string]string {
	out := make(map[string]string)
	for _, elem := range s.Elems {
		if elem.Key != "" {
			out[elem.Key] = strings.TrimSpace(elem.Value)
		}
	}
	var walk func(tables []nmapTable)
	walk = func(tables []nmapTable) {
		for _, table := range tables {
			for _, elem := range table.Elems {
				if elem.Key != "" {
					out[elem.Key] = strings.TrimSpace(elem.Value)
				}
			}
			walk(table.Tables)
		}
	}
	walk(s.Tables)
	return out
}

// nmapScriptIdentity maps the identity fields of the ICS scripts Nmap ships.
//
// The key names come from the scripts themselves. A script whose keys are not
// listed here contributes nothing rather than being guessed at, which keeps a
// future Nmap release from silently producing wrong identities.
//
// The mapping is an ordered list rather than a map because two keys can feed the
// same canonical field, as the BACnet firmware keys do. Iterating in a fixed order
// is what makes ingesting the same file twice give the same answer.
var nmapScriptIdentity = map[string][]nmapScriptField{
	"s7-info": {
		{"Module", "catalog_number"},
		{"Module Type", "product"},
		{"Version", "firmware"},
		{"Serial Number", "serial"},
		// The basic hardware key holds a second order code rather than a
		// revision, so it stays an evidence field and never reaches the identity.
		{"Basic Hardware", "basic_hardware"},
		{"System Name", "system_name"},
		{"Plant Identification", "plant_identification"},
	},
	"enip-info": {
		{"Vendor", "vendor"},
		{"Product Name", "product"},
		{"Revision", "firmware"},
		{"Serial Number", "serial"},
		{"Device Type", "device_type"},
		{"Product Code", "product_code"},
	},
	"modbus-discover": {
		{"Vendor", "vendor"},
	},
	"bacnet-info": {
		{"Vendor Name", "vendor"},
		{"Model Name", "product"},
		{"Firmware", "firmware"},
		{"Application Software", "firmware"},
		{"Serial Number", "serial"},
		{"Object Name", "system_name"},
		{"Instance Number", "device_instance"},
	},
}

// nmapScriptField ties one script output key to a canonical identity field.
type nmapScriptField struct {
	Key   string
	Field string
}

// readNmapXML parses an Nmap XML file into the inventory.
func readNmapXML(path string, sink *sink) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open nmap file: %w", err)
	}
	defer file.Close()

	return parseNmapXML(file, path, sink)
}

func parseNmapXML(r io.Reader, source string, sink *sink) error {
	var run nmapRun
	decoder := xml.NewDecoder(r)
	// Nmap output is well formed XML, but files handed over by other people are
	// untrusted input. Entity expansion is refused so that a crafted file cannot
	// make the parser allocate without bound.
	decoder.Strict = false
	decoder.Entity = xml.HTMLEntity

	if err := decoder.Decode(&run); err != nil {
		return fmt.Errorf("parse nmap XML %s: %w", source, err)
	}

	up, down := 0, 0
	for _, host := range run.Hosts {
		if host.Status.State != "" && host.Status.State != "up" {
			down++
			continue
		}
		ingestNmapHost(host, run.Start, sink)
		up++
	}
	sink.stats.RecordsRead["nmap.hosts"] += up
	sink.stats.RecordsRead["nmap.hosts_down"] += down
	return nil
}

func ingestNmapHost(host nmapHost, runStart int64, sink *sink) {
	addr := asset.Addresses{}
	macVendor := ""
	for _, a := range host.Addresses {
		switch a.Type {
		case "ipv4":
			addr.IPv4 = a.Addr
		case "ipv6":
			addr.IPv6 = a.Addr
		case "mac":
			addr.MAC = normalizeMAC(a.Addr)
			macVendor = a.Vendor
		}
	}
	for _, name := range host.Hostnames {
		if name.Name != "" {
			addr.Hostname = name.Name
			break
		}
	}
	if addr.Primary() == "" {
		return
	}

	seen := nmapTimestamp(host.StartTime, host.EndTime, runStart)
	device := sink.device(addr)
	device.touchSeen(seen)

	// The OUI vendor from a MAC address is a weak signal: it names whoever made
	// the network interface, which for an industrial PC is often not the vendor
	// of the control software. It is recorded but never used as the vendor.
	if macVendor != "" {
		device.setField("mac_oui_vendor", macVendor)
	}

	for _, osMatch := range host.OSMatches {
		if osMatch.Name != "" {
			device.setField("nmap_os_match", osMatch.Name)
			break
		}
	}

	for _, script := range host.Scripts {
		applyNmapScript(script, device)
	}

	banners := make([]string, 0, len(host.Ports))
	for _, port := range host.Ports {
		if port.State.State != "open" {
			continue
		}
		transport := port.Protocol
		if transport == "" {
			transport = "tcp"
		}
		banner := nmapBanner(port.Service)
		if banner != "" {
			banners = append(banners, banner)
		}
		device.addService(asset.Service{
			Port:      port.PortID,
			Transport: transport,
			Protocol:  nmapProtocolName(port),
			Banner:    banner,
			FirstSeen: seen,
			LastSeen:  seen,
			Source:    asset.SourceNmap,
		})

		for _, script := range port.Scripts {
			applyNmapScript(script, device)
		}
	}

	// A script reports a product name rather than an order code, and the order
	// code is what an advisory can be matched against, so one is looked for inside
	// the other. An ENIP product name of "1756-L71/B LOGIX5571" carries the
	// catalog number 1756-L71/B, which resolves to a ControlLogix 5570.
	sink.applyTextIdentity(device, device.asset.Identity.ProductRaw)
	// Failing that, the service fingerprint Nmap produced is the last thing left
	// to read, and it names the vendor often enough to be worth reading.
	sink.applyTextIdentity(device, strings.Join(banners, ", "))

	device.addEvidence(asset.Evidence{
		Source:    asset.SourceNmap,
		Endpoint:  addr.Primary(),
		Timestamp: seen,
		Fields:    device.pendingFields(),
		Notes: append(device.pendingNotes(),
			"read from Nmap output supplied by the operator, otscout sent nothing itself"),
	})
}

// applyNmapScript folds a script result into the device identity.
func applyNmapScript(script nmapScript, device *deviceBuilder) {
	mapping, known := nmapScriptIdentity[script.ID]
	if !known {
		return
	}
	values := script.flatten()
	if len(values) == 0 {
		return
	}

	applied := false
	for _, entry := range mapping {
		value := strings.TrimSpace(values[entry.Key])
		if value == "" || value == "-" {
			continue
		}
		device.setField(script.ID+"."+entry.Key, value)
		applied = true

		switch entry.Field {
		case "vendor":
			device.setVendor(value)
		case "product":
			device.setProduct(value)
		case "firmware":
			device.setFirmware(value)
		case "serial":
			device.setSerial(value)
		case "catalog_number":
			device.setCatalogNumber(value)
		case "hardware":
			device.setHardwareRev(value)
		}
	}
	if applied {
		device.addNote(fmt.Sprintf("Nmap script %s supplied identity fields", script.ID))
	}
}

// nmapProtocolName prefers the port based protocol name otscout uses elsewhere so
// that filters behave consistently, and falls back to what Nmap called it.
func nmapProtocolName(port nmapPort) string {
	if name := asset.ProtocolForPort(port.PortID); name != "" {
		return name
	}
	return port.Service.Name
}

func nmapBanner(svc nmapService) string {
	parts := make([]string, 0, 3)
	for _, part := range []string{svc.Product, svc.Version, svc.ExtraInfo} {
		if strings.TrimSpace(part) != "" {
			parts = append(parts, strings.TrimSpace(part))
		}
	}
	return strings.Join(parts, " ")
}

func nmapTimestamp(hostStart, hostEnd, runStart int64) time.Time {
	for _, candidate := range []int64{hostEnd, hostStart, runStart} {
		if candidate > 0 {
			return time.Unix(candidate, 0).UTC()
		}
	}
	return time.Time{}
}

// normalizeMAC lowercases a hardware address and settles on colon separators, so
// that the same interface seen by two sources produces one asset.
func normalizeMAC(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			return r
		case r >= 'A' && r <= 'F':
			return r + ('a' - 'A')
		default:
			return -1
		}
	}, raw)
	if len(cleaned) != 12 {
		return strings.ToLower(strings.TrimSpace(raw))
	}
	parts := make([]string, 0, 6)
	for idx := 0; idx < 12; idx += 2 {
		parts = append(parts, cleaned[idx:idx+2])
	}
	return strings.Join(parts, ":")
}

func parsePort(raw string) (int, bool) {
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value <= 0 || value > 65535 {
		return 0, false
	}
	return value, true
}
