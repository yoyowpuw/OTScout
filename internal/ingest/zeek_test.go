package ingest

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// zeekTSV renders a log in the tab separated format Zeek writes by default.
//
// Building the header from code rather than pasting a fixture keeps the tabs
// unambiguous, which matters because a fixture with spaces where tabs belong
// fails in a way that looks like a parser bug.
func zeekTSV(path string, fields []string, rows ...[]string) string {
	var sb strings.Builder
	sb.WriteString("#separator \\x09\n")
	sb.WriteString("#set_separator\t,\n")
	sb.WriteString("#empty_field\t(empty)\n")
	sb.WriteString("#unset_field\t-\n")
	// An empty path stands for a rotated log that lost its directive, where the
	// kind has to come from the file name instead.
	if path != "" {
		sb.WriteString("#path\t" + path + "\n")
	}
	sb.WriteString("#open\t2026-03-04-09-30-00\n")
	sb.WriteString("#fields\t" + strings.Join(fields, "\t") + "\n")
	for _, row := range rows {
		sb.WriteString(strings.Join(row, "\t") + "\n")
	}
	sb.WriteString("#close\t2026-03-04-10-30-00\n")
	return sb.String()
}

var connFields = []string{
	"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
	"service", "duration", "orig_bytes", "resp_bytes", "conn_state",
	"orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
}

// sampleConnLog holds one completed Modbus conversation.
var sampleConnLog = zeekTSV("conn", connFields,
	[]string{
		"1772000000.100000", "CJ1", "10.20.0.40", "51234", "10.20.0.5", "502", "tcp",
		"modbus", "1.250000", "24", "36", "SF", "6", "344", "5", "276",
	},
)

func writeZeek(t *testing.T, name, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	writeFile(t, path, contents)
	return path
}

func TestIngestZeekConnLog(t *testing.T) {
	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "conn.log", sampleConnLog)}}).Inventory

	// Zeek names the initiator and the responder outright, so the listening end is
	// known rather than guessed at from port numbers.
	server := findAsset(t, inv, "10.20.0.5")
	svc := serviceOn(server, 502, "tcp")
	if svc == nil {
		t.Fatalf("no Modbus service on the responder, services = %+v", server.Services)
	}
	if svc.Protocol != "modbus" {
		t.Errorf("service protocol = %q, want modbus from the Zeek service field", svc.Protocol)
	}
	if svc.Source != asset.SourceZeek {
		t.Errorf("service source = %q, want zeek", svc.Source)
	}

	client := findAsset(t, inv, "10.20.0.40")
	if serviceOn(client, 502, "tcp") != nil {
		t.Error("the initiator must not be credited with the service")
	}

	if len(inv.Flows) != 1 {
		t.Fatalf("recorded %d flows, want 1: %+v", len(inv.Flows), inv.Flows)
	}
	flow := inv.Flows[0]
	if flow.SrcAddr != "10.20.0.40" || flow.DstAddr != "10.20.0.5" || flow.DstPort != 502 {
		t.Errorf("flow = %s -> %s:%d, want the initiator to responder direction", flow.SrcAddr, flow.DstAddr, flow.DstPort)
	}
	if flow.Packets != 11 {
		t.Errorf("flow packets = %d, want 11 from both directions", flow.Packets)
	}
	if flow.Bytes != 620 {
		t.Errorf("flow bytes = %d, want 620", flow.Bytes)
	}
	if flow.FirstSeen.IsZero() {
		t.Error("the Zeek timestamp should have been parsed")
	}
	if !flow.LastSeen.After(flow.FirstSeen) {
		t.Error("the connection duration should extend the last seen time")
	}
}

func TestIngestZeekIgnoresConnectionsTheResponderRefused(t *testing.T) {
	// Zeek logs refused and unanswered attempts. Treating those as open ports
	// would fill the inventory with services that do not exist, and every later
	// step trusts the service list.
	cases := map[string]string{
		"rejected": "REJ",
		"no reply": "S0",
		"syn only": "SH",
	}
	for name, state := range cases {
		t.Run(name, func(t *testing.T) {
			log := zeekTSV("conn", connFields, []string{
				"1772000000.100000", "CJ2", "10.20.0.40", "51235", "10.20.0.8", "502", "tcp",
				"-", "0.000100", "0", "0", state, "1", "60", "0", "0",
			})
			inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "conn.log", log)}}).Inventory
			device := findAsset(t, inv, "10.20.0.8")
			if svc := serviceOn(device, 502, "tcp"); svc != nil {
				t.Errorf("conn_state %s was recorded as an open service: %+v", state, svc)
			}
			if len(inv.Flows) != 1 {
				t.Errorf("the attempt should still be a flow, got %d", len(inv.Flows))
			}
		})
	}
}

func TestIngestZeekJSONLines(t *testing.T) {
	// Sites that ship logs to a collector switch Zeek to JSON, so both forms have
	// to produce the same inventory.
	log := strings.Join([]string{
		`{"ts":"2026-03-04T09:30:00.100000Z","uid":"CJ3","id.orig_h":"10.20.0.40","id.orig_p":51234,` +
			`"id.resp_h":"10.20.0.5","id.resp_p":502,"proto":"tcp","service":"modbus","duration":1.25,` +
			`"conn_state":"SF","orig_pkts":6,"orig_ip_bytes":344,"resp_pkts":5,"resp_ip_bytes":276}`,
		`{"ts":"2026-03-04T09:30:02.000000Z","uid":"CJ4","id.orig_h":"10.20.0.40","id.orig_p":51236,` +
			`"id.resp_h":"10.20.0.9","id.resp_p":44818,"proto":"tcp","service":"enip","conn_state":"REJ",` +
			`"orig_pkts":1,"orig_ip_bytes":60,"resp_pkts":0,"resp_ip_bytes":0}`,
	}, "\n")

	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "conn.log", log)}}).Inventory

	server := findAsset(t, inv, "10.20.0.5")
	if svc := serviceOn(server, 502, "tcp"); svc == nil {
		t.Errorf("no Modbus service from the JSON log, services = %+v", server.Services)
	} else if svc.FirstSeen.IsZero() {
		t.Error("the ISO 8601 timestamp should have been parsed")
	}

	refused := findAsset(t, inv, "10.20.0.9")
	if svc := serviceOn(refused, 44818, "tcp"); svc != nil {
		t.Errorf("the refused connection was recorded as a service: %+v", svc)
	}
	if len(inv.Flows) != 2 {
		t.Errorf("recorded %d flows, want 2", len(inv.Flows))
	}
}

func TestIngestZeekNestedJSONKeysMatchTheTSVNames(t *testing.T) {
	// Some pipelines emit the connection identifier as a nested object rather than
	// as dotted keys. Flattening it means one set of field names serves both.
	log := `{"ts":1772000000.1,"id":{"orig_h":"10.20.0.40","orig_p":51234,"resp_h":"10.20.0.5","resp_p":502},` +
		`"proto":"tcp","service":"modbus","conn_state":"SF","resp_pkts":5}`

	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "conn.log", log)}}).Inventory
	device := findAsset(t, inv, "10.20.0.5")
	if svc := serviceOn(device, 502, "tcp"); svc == nil {
		t.Errorf("nested keys were not flattened, services = %+v", device.Services)
	}
}

func TestIngestZeekIndustrialLogSuppliesIdentity(t *testing.T) {
	// The industrial analyzers are a separate Zeek package, and each protocol
	// names its fields differently. Rather than encode every schema, the known
	// identity field names are looked for in any industrial log.
	log := zeekTSV("cip_identity",
		[]string{"ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "vendor_id", "vendor", "product_name", "revision", "serial_number", "device_type"},
		[]string{
			"1772000000.100000", "CJ5", "10.20.0.40", "51234", "10.20.0.21", "44818",
			"1", "Rockwell Automation/Allen-Bradley", "1756-L71/B LOGIX5571", "20.11", "0x12345678",
			"Programmable Logic Controller",
		},
	)

	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "cip_identity.log", log)}}).Inventory
	device := findAsset(t, inv, "10.20.0.21")

	if device.Identity.Vendor != "rockwell-automation" {
		t.Errorf("Vendor = %q, want rockwell-automation", device.Identity.Vendor)
	}
	if device.Identity.Firmware != "20.11" {
		t.Errorf("Firmware = %q, want 20.11", device.Identity.Firmware)
	}
	if device.Identity.Serial != "0x12345678" {
		t.Errorf("Serial = %q", device.Identity.Serial)
	}
	if len(device.Evidence) == 0 {
		t.Error("the identity should be backed by an evidence record naming the log it came from")
	}
}

func TestIngestZeekIndustrialLogAttributesIdentityToTheSender(t *testing.T) {
	// is_orig says which end sent the message. Getting it wrong would put a PLC
	// identity on the engineering workstation that queried it.
	fields := []string{"ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "is_orig", "vendor_name", "firmware_revision"}

	respLog := zeekTSV("bacnet_property", fields, []string{
		"1772000000.100000", "10.30.0.40", "47808", "10.30.0.33", "47808", "F", "Reliable Controls Corporation", "2.7",
	})
	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "bacnet_property.log", respLog)}}).Inventory
	if device := findAsset(t, inv, "10.30.0.33"); device.Identity.VendorRaw != "Reliable Controls Corporation" {
		t.Errorf("responder identity = %+v, want the vendor on the responder", device.Identity)
	}
	if device := findAsset(t, inv, "10.30.0.40"); !device.Identity.Empty() {
		t.Errorf("the querying host was given an identity: %+v", device.Identity)
	}

	origLog := zeekTSV("bacnet_property", fields, []string{
		"1772000000.100000", "10.30.0.33", "47808", "10.30.0.40", "47808", "T", "Reliable Controls Corporation", "2.7",
	})
	inv = runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "bacnet_property.log", origLog)}}).Inventory
	if device := findAsset(t, inv, "10.30.0.33"); device.Identity.VendorRaw != "Reliable Controls Corporation" {
		t.Errorf("with is_orig set the identity belongs to the initiator, got %+v", device.Identity)
	}
}

func TestIngestZeekLeavesIdentityAloneForNonIndustrialLogs(t *testing.T) {
	// http.log has a "version" field that means the HTTP version. Reading identity
	// fields out of every log would turn that into a firmware revision.
	log := zeekTSV("http",
		[]string{"ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "version", "host", "user_agent"},
		[]string{"1772000000.100000", "10.20.0.40", "51234", "10.20.0.11", "80", "1.1", "plc.example", "Mozilla/5.0"},
	)

	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "http.log", log)}}).Inventory
	for idx := range inv.Assets {
		if !inv.Assets[idx].Identity.Empty() {
			t.Errorf("http.log produced an identity for %s: %+v",
				inv.Assets[idx].Addresses.Primary(), inv.Assets[idx].Identity)
		}
	}
}

func TestIngestZeekDHCPBindsNameAddressAndHardware(t *testing.T) {
	log := zeekTSV("dhcp",
		[]string{"ts", "uids", "client_addr", "server_addr", "mac", "host_name", "domain", "lease_time"},
		[]string{"1772000000.100000", "CJ6", "10.20.0.55", "10.20.0.1", "00:1b:1b:11:22:33", "ews-line2", "plant.local", "3600.000000"},
	)

	device := findAsset(t, runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "dhcp.log", log)}}).Inventory, "10.20.0.55")
	if device.Addresses.Hostname != "ews-line2" {
		t.Errorf("Hostname = %q, want ews-line2", device.Addresses.Hostname)
	}
	if device.Addresses.MAC != "00:1b:1b:11:22:33" {
		t.Errorf("MAC = %q", device.Addresses.MAC)
	}
}

func TestIngestZeekDNSNamesTheAnsweredAddress(t *testing.T) {
	log := zeekTSV("dns",
		[]string{"ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "query", "qtype_name", "answers"},
		[]string{"1772000000.100000", "10.20.0.40", "53311", "10.20.0.1", "53", "historian.plant.local", "A", "10.20.0.80"},
		[]string{"1772000001.100000", "10.20.0.40", "53312", "10.20.0.1", "53", "80.0.20.10.in-addr.arpa", "PTR", "historian.plant.local"},
	)

	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "dns.log", log)}}).Inventory
	device := findAsset(t, inv, "10.20.0.80")
	if device.Addresses.Hostname != "historian.plant.local" {
		t.Errorf("Hostname = %q, want the name from the A record", device.Addresses.Hostname)
	}
	// The reverse lookup answer is a name, not an address, and must not have been
	// turned into an asset.
	for idx := range inv.Assets {
		if inv.Assets[idx].Addresses.Primary() == "historian.plant.local" {
			t.Error("a hostname from a PTR answer was treated as an address")
		}
	}
}

func TestIngestZeekSoftwareBannerStaysOutOfTheIdentity(t *testing.T) {
	log := zeekTSV("software",
		[]string{"ts", "host", "host_p", "software_type", "name", "unparsed_version"},
		[]string{"1772000000.100000", "10.20.0.11", "80", "HTTP::SERVER", "SIMATIC-HTTP", "SIMATIC-HTTP/2.0"},
	)

	device := findAsset(t, runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "software.log", log)}}).Inventory, "10.20.0.11")
	if !device.Identity.Empty() {
		t.Errorf("a software banner became an identity: %+v", device.Identity)
	}
	found := false
	for _, ev := range device.Evidence {
		if ev.Fields["zeek_software.HTTP::SERVER"] == "SIMATIC-HTTP/2.0" {
			found = true
		}
	}
	if !found {
		t.Errorf("the banner should be kept as evidence, evidence = %+v", device.Evidence)
	}
}

func TestIngestZeekKnownServices(t *testing.T) {
	log := zeekTSV("known_services",
		[]string{"ts", "host", "port_num", "port_proto", "service"},
		[]string{"1772000000.100000", "10.20.0.5", "502", "tcp", "modbus"},
		[]string{"1772000000.100000", "10.30.0.33", "47808", "udp", "-"},
	)

	inv := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "known_services.log", log)}}).Inventory
	if svc := serviceOn(findAsset(t, inv, "10.20.0.5"), 502, "tcp"); svc == nil || svc.Protocol != "modbus" {
		t.Errorf("Modbus service = %+v", svc)
	}
	// With no service name from Zeek, the port itself names the protocol.
	if svc := serviceOn(findAsset(t, inv, "10.30.0.33"), 47808, "udp"); svc == nil || svc.Protocol != "bacnet" {
		t.Errorf("BACnet service = %+v, want the protocol inferred from the port", svc)
	}
}

func TestIngestZeekDirectoryReadsEveryLogAndRotatedNames(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "conn.log"), sampleConnLog)
	writeFile(t, filepath.Join(dir, "not-a-log.txt"), "ignore me")

	// A rotated log keeps its kind in the first part of the name, which is how the
	// kind is recovered when the file has no path directive.
	rotated := zeekTSV("", []string{"ts", "host", "port_num", "port_proto", "service"},
		[]string{"1772000000.100000", "10.20.0.7", "102", "tcp", "s7comm"})
	writeGzipFile(t, filepath.Join(dir, "known_services.09-00-00-10-00-00.log.gz"), rotated)

	result := runIngest(t, Options{ZeekPaths: []string{dir}})
	if result.Stats.FilesRead != 2 {
		t.Errorf("FilesRead = %d, want 2", result.Stats.FilesRead)
	}
	if lookupAsset(result.Inventory, "10.20.0.5") == nil {
		t.Error("conn.log was not read")
	}
	device := findAsset(t, result.Inventory, "10.20.0.7")
	if svc := serviceOn(device, 102, "tcp"); svc == nil {
		t.Errorf("the rotated gzipped log was not read, services = %+v", device.Services)
	}
}

func TestIngestZeekRejectsDataWithoutAFieldsHeader(t *testing.T) {
	// Without the header the columns have no names. Guessing the schema would
	// invent data, so the file is skipped and the operator told.
	log := "1772000000.100000\tCJ7\t10.20.0.40\t51234\t10.20.0.5\t502\ttcp\n"
	result := runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "conn.log", log)}})
	if len(result.Inventory.Assets) != 0 {
		t.Errorf("assets were created from a headerless log: %+v", result.Inventory.Assets)
	}
	if len(result.Stats.Warnings) == 0 {
		t.Error("skipping the file should be reported")
	}
}

func TestIngestZeekHonoursANonDefaultSeparator(t *testing.T) {
	log := strings.Join([]string{
		"#separator \\x7c",
		"#set_separator|,",
		"#empty_field|(empty)",
		"#unset_field|-",
		"#path|known_services",
		"#fields|ts|host|port_num|port_proto|service",
		"1772000000.100000|10.20.0.5|502|tcp|modbus",
	}, "\n")

	device := findAsset(t, runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "known_services.log", log)}}).Inventory, "10.20.0.5")
	if svc := serviceOn(device, 502, "tcp"); svc == nil {
		t.Errorf("the declared separator was not honoured, services = %+v", device.Services)
	}
}

func TestIngestZeekTreatsUnsetFieldsAsAbsent(t *testing.T) {
	// A literal "-" in the log means the field was not set. Storing it as a value
	// would put a dash in the inventory where a vendor name belongs.
	log := zeekTSV("cip_identity",
		[]string{"ts", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "vendor", "product_name", "revision"},
		[]string{"1772000000.100000", "10.20.0.40", "51234", "10.20.0.21", "44818", "-", "1756-L71/B LOGIX5571", "-"},
	)

	device := findAsset(t, runIngest(t, Options{ZeekPaths: []string{writeZeek(t, "cip_identity.log", log)}}).Inventory, "10.20.0.21")
	if strings.Contains(device.Identity.VendorRaw, "-") && device.Identity.VendorRaw == "-" {
		t.Errorf("an unset field became a value: %+v", device.Identity)
	}
	if device.Identity.Firmware == "-" {
		t.Errorf("Firmware = %q, want it left empty", device.Identity.Firmware)
	}
	if device.Identity.ProductRaw != "1756-L71/B LOGIX5571" {
		t.Errorf("ProductRaw = %q", device.Identity.ProductRaw)
	}
}

func TestIngestZeekMissingPathIsAnError(t *testing.T) {
	if _, err := Run(t.Context(), Options{ZeekPaths: []string{filepath.Join(t.TempDir(), "absent")}}); err != nil {
		t.Fatalf("a missing path should be warned about, not returned as an error: %v", err)
	}
}

func TestParseZeekTimeAcceptsBothForms(t *testing.T) {
	epoch := parseZeekTime("1772000000.100000")
	if epoch.IsZero() || epoch.Nanosecond() == 0 {
		t.Errorf("epoch form parsed as %v", epoch)
	}
	iso := parseZeekTime("2026-03-04T09:30:00.1Z")
	if iso.IsZero() {
		t.Error("the ISO 8601 form should parse")
	}
	for _, raw := range []string{"", "-", "not a time"} {
		if got := parseZeekTime(raw); !got.IsZero() {
			t.Errorf("parseZeekTime(%q) = %v, want the zero time", raw, got)
		}
	}
}

func TestZeekKindFromName(t *testing.T) {
	cases := map[string]string{
		"conn.log":                                  "conn",
		"conn.00:00:00-01:00:00.log.gz":             "conn",
		"cip_identity.log":                          "cip_identity",
		filepath.Join("logs", "current", "dns.log"): "dns",
	}
	for name, want := range cases {
		if got := zeekKindFromName(name); got != want {
			t.Errorf("zeekKindFromName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestIsICSLogKind(t *testing.T) {
	for _, kind := range []string{"modbus", "modbus_detailed", "cip_identity", "bacnet_property", "s7comm_read_szl", "enip"} {
		if !isICSLogKind(kind) {
			t.Errorf("isICSLogKind(%q) = false, want true", kind)
		}
	}
	for _, kind := range []string{"conn", "http", "ssl", "dns", "software", "modbusters"} {
		if isICSLogKind(kind) {
			t.Errorf("isICSLogKind(%q) = true, want false", kind)
		}
	}
}

func writeGzipFile(t *testing.T, path, contents string) {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write([]byte(contents)); err != nil {
		t.Fatalf("compress: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
