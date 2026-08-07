package ingest

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// Zeek is the most valuable passive source a site can already have, because it is
// commonly deployed on a SPAN port and its logs cover weeks rather than the
// minutes a capture holds. This file reads both the tab separated format Zeek
// writes by default and the JSON lines format sites switch to when shipping logs
// to a collector.

// maxZeekLineBytes bounds a single log line. Logs are untrusted input and a line
// with no newline in it would otherwise be read into memory whole.
const maxZeekLineBytes = 1 << 20

// zeekRecord is one log line with its fields resolved by name.
type zeekRecord struct {
	// path is the Zeek log kind, for example "conn" or "cip_identity".
	path   string
	fields map[string]string
	line   int
}

func (r zeekRecord) get(name string) string { return r.fields[name] }

// has reports whether a field is present and set.
func (r zeekRecord) has(name string) bool {
	value, ok := r.fields[name]
	return ok && value != ""
}

func (r zeekRecord) getInt(name string) (int, bool) {
	raw := strings.TrimSpace(r.fields[name])
	if raw == "" {
		return 0, false
	}
	if value, err := strconv.Atoi(raw); err == nil {
		return value, true
	}
	// JSON output can render a count as a float.
	if value, err := strconv.ParseFloat(raw, 64); err == nil && !math.IsNaN(value) {
		return int(value), true
	}
	return 0, false
}

func (r zeekRecord) getUint(name string) uint64 {
	value, ok := r.getInt(name)
	if !ok || value < 0 {
		return 0
	}
	return uint64(value)
}

// getBool reads a Zeek boolean, which is "T" or "F" in the tab separated format
// and a real boolean in JSON.
func (r zeekRecord) getBool(name string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(r.fields[name])) {
	case "t", "true":
		return true, true
	case "f", "false":
		return false, true
	default:
		return false, false
	}
}

func (r zeekRecord) timestamp() time.Time { return parseZeekTime(r.fields["ts"]) }

// parseZeekTime accepts both the epoch seconds Zeek writes by default and the
// ISO 8601 form it writes when configured for a log collector.
func parseZeekTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "-" {
		return time.Time{}
	}
	if seconds, err := strconv.ParseFloat(raw, 64); err == nil && seconds > 0 {
		whole, frac := math.Modf(seconds)
		return time.Unix(int64(whole), int64(frac*float64(time.Second))).UTC()
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999Z0700", "2006-01-02-15-04-05"} {
		if ts, err := time.Parse(layout, raw); err == nil {
			return ts.UTC()
		}
	}
	return time.Time{}
}

// readZeekPath reads a Zeek log file, or every log in a directory, and returns how
// many files were read.
func readZeekPath(ctx context.Context, path string, s *sink) (int, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat zeek path: %w", err)
	}
	if !info.IsDir() {
		if err := readZeekFile(ctx, path, s); err != nil {
			return 0, err
		}
		return 1, nil
	}

	count := 0
	walkErr := filepath.WalkDir(path, func(entry string, d fs.DirEntry, err error) error {
		if err != nil {
			s.stats.warn("zeek walk %s: %v", entry, err)
			return nil
		}
		if d.IsDir() || !looksLikeZeekLog(d.Name()) {
			return nil
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := readZeekFile(ctx, entry, s); err != nil {
			// A directory of logs usually contains kinds otscout does not read,
			// so one failure never stops the rest.
			s.stats.warn("zeek %s: %v", entry, err)
			return nil
		}
		count++
		return nil
	})
	if walkErr != nil {
		return count, walkErr
	}
	if count == 0 {
		return 0, fmt.Errorf("no zeek logs found under %s", path)
	}
	return count, nil
}

func looksLikeZeekLog(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".log") || strings.HasSuffix(lower, ".log.gz")
}

// zeekKindFromName derives the log kind from a file name, handling both plain
// names and the rotated form "conn.00:00:00-01:00:00.log.gz".
func zeekKindFromName(name string) string {
	base := filepath.Base(name)
	if idx := strings.IndexByte(base, '.'); idx > 0 {
		return base[:idx]
	}
	return base
}

func readZeekFile(ctx context.Context, path string, s *sink) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open zeek log: %w", err)
	}
	defer file.Close()

	var reader io.Reader = file
	if strings.HasSuffix(strings.ToLower(path), ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return fmt.Errorf("open gzip zeek log: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	return parseZeekStream(ctx, reader, zeekKindFromName(path), path, s)
}

// parseZeekStream reads either format and dispatches each record.
func parseZeekStream(ctx context.Context, r io.Reader, defaultKind, source string, s *sink) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), maxZeekLineBytes)

	separator := "\t"
	setSeparator := ","
	unsetField := "-"
	emptyField := "(empty)"
	kind := defaultKind
	var fields []string

	lineNo := 0
	records := 0
	for scanner.Scan() {
		lineNo++
		if lineNo%4096 == 0 {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "#") {
			directive, value := splitZeekDirective(line, separator)
			switch directive {
			case "separator":
				if decoded := unescapeZeekLiteral(value); decoded != "" {
					separator = decoded
				}
			case "set_separator":
				setSeparator = value
			case "unset_field":
				unsetField = value
			case "empty_field":
				emptyField = value
			case "path":
				if value != "" {
					kind = value
				}
			case "fields":
				fields = strings.Split(value, separator)
			}
			continue
		}

		var record zeekRecord
		switch {
		case line[0] == '{':
			values, err := parseZeekJSONLine(line)
			if err != nil {
				s.stats.warn("zeek %s line %d: %v", source, lineNo, err)
				continue
			}
			record = zeekRecord{path: kind, fields: values, line: lineNo}
		case len(fields) > 0:
			record = zeekRecord{
				path:   kind,
				fields: parseZeekTSVLine(line, fields, separator, setSeparator, unsetField, emptyField),
				line:   lineNo,
			}
		default:
			// Without a #fields header the columns have no names, so the line
			// cannot be read. Guessing at the schema would invent data.
			s.stats.warn("zeek %s: data before a #fields header, file skipped", source)
			return nil
		}

		applyZeekRecord(record, s)
		records++
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read zeek log %s: %w", source, err)
	}
	s.stats.RecordsRead["zeek."+kind] += records
	return nil
}

// splitZeekDirective reads a header line. The separator directive is special: it
// declares the separator, so it cannot itself be split by one and uses a space.
func splitZeekDirective(line, separator string) (string, string) {
	body := line[1:]
	if strings.HasPrefix(body, "separator") {
		_, value, _ := strings.Cut(body, " ")
		return "separator", strings.TrimSpace(value)
	}
	name, value, found := strings.Cut(body, separator)
	if !found {
		return strings.TrimSpace(name), ""
	}
	return strings.TrimSpace(name), value
}

// unescapeZeekLiteral decodes the escaped byte Zeek uses to declare a separator,
// written as "\x09" for a tab.
func unescapeZeekLiteral(raw string) string {
	if !strings.HasPrefix(raw, "\\x") || len(raw) < 4 {
		return raw
	}
	value, err := strconv.ParseUint(raw[2:4], 16, 8)
	if err != nil {
		return raw
	}
	return string([]byte{byte(value)})
}

func parseZeekTSVLine(line string, fields []string, separator, setSeparator, unsetField, emptyField string) map[string]string {
	columns := strings.Split(line, separator)
	out := make(map[string]string, len(fields))
	for idx, name := range fields {
		if idx >= len(columns) {
			break
		}
		value := columns[idx]
		switch value {
		case unsetField:
			continue
		case emptyField:
			value = ""
		}
		if setSeparator != "," && strings.Contains(value, setSeparator) {
			value = strings.ReplaceAll(value, setSeparator, ",")
		}
		out[name] = value
	}
	return out
}

// parseZeekJSONLine flattens a JSON log line to string values. Nested objects get
// dotted keys so that both output styles produce the same field names.
func parseZeekJSONLine(line string) (map[string]string, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return nil, fmt.Errorf("parse json log line: %w", err)
	}
	out := make(map[string]string, len(raw))
	flattenJSON("", raw, out)
	return out, nil
}

func flattenJSON(prefix string, node map[string]any, out map[string]string) {
	for key, value := range node {
		name := key
		if prefix != "" {
			name = prefix + "." + key
		}
		switch typed := value.(type) {
		case nil:
			continue
		case map[string]any:
			flattenJSON(name, typed, out)
		case []any:
			parts := make([]string, 0, len(typed))
			for _, item := range typed {
				parts = append(parts, scalarToString(item))
			}
			out[name] = strings.Join(parts, ",")
		default:
			out[name] = scalarToString(typed)
		}
	}
}

func scalarToString(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case bool:
		if typed {
			return "T"
		}
		return "F"
	case float64:
		if typed == math.Trunc(typed) && math.Abs(typed) < 1e15 {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return fmt.Sprint(typed)
	}
}

// applyZeekRecord routes a record to the handler for its log kind.
func applyZeekRecord(record zeekRecord, s *sink) {
	switch record.path {
	case "conn":
		applyZeekConn(record, s)
	case "known_hosts":
		applyZeekKnownHost(record, s)
	case "known_services":
		applyZeekKnownService(record, s)
	case "dhcp":
		applyZeekDHCP(record, s)
	case "dns":
		applyZeekDNS(record, s)
	case "software":
		applyZeekSoftware(record, s)
	}

	// Industrial protocol logs come from the ICSNPP analyzer set rather than from
	// Zeek itself, and their field names differ per protocol. Rather than encode
	// every schema, the known identity field names are looked for in any log whose
	// kind belongs to an industrial analyzer, so a newly released analyzer that
	// uses the same names works with no change here.
	if isICSLogKind(record.path) {
		applyZeekICSIdentity(record, s)
	}
}

func applyZeekConn(record zeekRecord, s *sink) {
	// Zeek names the connection initiator "orig" and the listener "resp", which
	// removes the guesswork the capture reader has to do about which end is the
	// server.
	client := record.get("id.orig_h")
	server := record.get("id.resp_h")
	serverPort, portOK := record.getInt("id.resp_p")
	if !usableIP(client) || !usableIP(server) || !portOK {
		return
	}
	transport := record.get("proto")
	if transport == "" {
		transport = "tcp"
	}
	ts := record.timestamp()

	protocolName := zeekServiceName(record.get("service"))
	if protocolName == "" {
		protocolName = asset.ProtocolForPort(serverPort)
	}

	s.addFlow(asset.Flow{
		SrcAddr:   client,
		DstAddr:   server,
		DstPort:   serverPort,
		Transport: transport,
		Protocol:  protocolName,
		Packets:   record.getUint("orig_pkts") + record.getUint("resp_pkts"),
		Bytes:     record.getUint("orig_ip_bytes") + record.getUint("resp_ip_bytes"),
		FirstSeen: ts,
		LastSeen:  connEnd(record, ts),
		Source:    asset.SourceZeek,
	})

	// Both ends become assets whether or not the connection succeeded, because
	// segmentation analysis grades a flow by the Purdue level of each end and
	// cannot grade one whose far end is missing from the inventory.
	s.device(addressesFor(client)).touchSeen(ts)
	serverDevice := s.device(addressesFor(server))
	serverDevice.touchSeen(ts)

	// The service, on the other hand, is only recorded when the listener actually
	// answered. Zeek logs refused and unanswered attempts too, and treating those
	// as open ports would fill the inventory with services that do not exist.
	if !zeekResponderAnswered(record) {
		return
	}
	serverDevice.addService(asset.Service{
		Port:      serverPort,
		Transport: transport,
		Protocol:  protocolName,
		FirstSeen: ts,
		LastSeen:  connEnd(record, ts),
		Source:    asset.SourceZeek,
	})
}

func connEnd(record zeekRecord, start time.Time) time.Time {
	raw := strings.TrimSpace(record.get("duration"))
	if raw == "" || start.IsZero() {
		return start
	}
	seconds, err := strconv.ParseFloat(raw, 64)
	if err != nil || seconds < 0 {
		return start
	}
	return start.Add(time.Duration(seconds * float64(time.Second)))
}

// zeekResponderAnswered reports whether the listening end sent anything back.
func zeekResponderAnswered(record zeekRecord) bool {
	if state := record.get("conn_state"); state == "S0" || state == "REJ" || state == "SH" {
		return false
	}
	if pkts, ok := record.getInt("resp_pkts"); ok {
		return pkts > 0
	}
	if bytesSeen, ok := record.getInt("resp_ip_bytes"); ok {
		return bytesSeen > 0
	}
	// Without counters, a state that Zeek only assigns after a reply is the
	// remaining evidence.
	switch record.get("conn_state") {
	case "SF", "S1", "S2", "S3", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SHR", "OTH":
		return true
	default:
		return false
	}
}

// zeekServiceName takes the first entry of Zeek's service field, which can list
// several when a connection was analysed by more than one analyzer.
func zeekServiceName(raw string) string {
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" && part != "-" {
			return part
		}
	}
	return ""
}

func applyZeekKnownHost(record zeekRecord, s *sink) {
	host := record.get("host")
	if !usableIP(host) {
		return
	}
	device := s.device(addressesFor(host))
	device.touchSeen(record.timestamp())
}

func applyZeekKnownService(record zeekRecord, s *sink) {
	host := record.get("host")
	port, ok := record.getInt("port_num")
	if !usableIP(host) || !ok {
		return
	}
	transport := record.get("port_proto")
	if transport == "" {
		transport = "tcp"
	}
	protocolName := zeekServiceName(record.get("service"))
	if protocolName == "" {
		protocolName = asset.ProtocolForPort(port)
	}
	ts := record.timestamp()

	device := s.device(addressesFor(host))
	device.touchSeen(ts)
	device.addService(asset.Service{
		Port:      port,
		Transport: transport,
		Protocol:  protocolName,
		FirstSeen: ts,
		LastSeen:  ts,
		Source:    asset.SourceZeek,
	})
}

func applyZeekDHCP(record zeekRecord, s *sink) {
	// DHCP is the one core log that ties a hardware address to both an IP and a
	// name, all three straight from the device.
	ip := firstNonEmpty(record.get("client_addr"), record.get("requested_addr"))
	mac := normalizeMAC(record.get("mac"))
	if !usableIP(ip) {
		return
	}
	addr := asset.Addresses{IPv4: ip, Hostname: record.get("host_name")}
	if usableMAC(mac) {
		addr.MAC = mac
	}
	device := s.device(addr)
	device.touchSeen(record.timestamp())
	device.setField("dhcp_host_name", record.get("host_name"))
	device.setField("dhcp_domain", record.get("domain"))
	device.addEvidence(asset.Evidence{
		Source:    asset.SourceZeek,
		Protocol:  "dhcp",
		Endpoint:  ip,
		Timestamp: record.timestamp(),
		Fields:    device.pendingFields(),
		Notes:     []string{"name and address binding reported by the device in its own DHCP request"},
	})
}

func applyZeekDNS(record zeekRecord, s *sink) {
	// Only forward address lookups are used, because they name the address in the
	// answer. Reverse lookups and other record types would need the query itself
	// decoded and are not worth the ambiguity.
	if qtype := strings.ToUpper(record.get("qtype_name")); qtype != "A" && qtype != "AAAA" {
		return
	}
	name := strings.TrimSuffix(strings.TrimSpace(record.get("query")), ".")
	if name == "" {
		return
	}
	for _, answer := range strings.Split(record.get("answers"), ",") {
		answer = strings.TrimSpace(answer)
		if !usableIP(answer) {
			continue
		}
		device := s.device(addressesFor(answer))
		if device.asset.Addresses.Hostname == "" {
			device.asset.Addresses.Hostname = name
		}
		device.touchSeen(record.timestamp())
	}
}

func applyZeekSoftware(record zeekRecord, s *sink) {
	host := record.get("host")
	if !usableIP(host) {
		return
	}
	banner := firstNonEmpty(record.get("unparsed_version"), record.get("name"))
	if banner == "" {
		return
	}
	device := s.device(addressesFor(host))
	device.touchSeen(record.timestamp())
	// A software banner names the server program, not the control device, so it
	// is recorded as evidence and never promoted to the asset identity.
	device.setField("zeek_software."+firstNonEmpty(record.get("software_type"), "unknown"), banner)
	device.addEvidence(asset.Evidence{
		Source:    asset.SourceZeek,
		Protocol:  "software",
		Endpoint:  host,
		Timestamp: record.timestamp(),
		Fields:    device.pendingFields(),
		Notes:     []string{"software banner observed by Zeek, recorded as context rather than as the device identity"},
	})
}

// icsLogPrefixes are the industrial analyzer log families otscout reads identity
// fields from.
var icsLogPrefixes = []string{
	"modbus", "bacnet", "enip", "cip", "s7comm", "dnp3", "opcua", "profinet",
	"ethercat", "iec104", "genisys", "synchrophasor", "hart", "omron", "fins",
	"ge_srtp", "bsap", "tds", "ecat",
}

func isICSLogKind(kind string) bool {
	for _, prefix := range icsLogPrefixes {
		if kind == prefix || strings.HasPrefix(kind, prefix+"_") {
			return true
		}
	}
	return false
}

// zeekICSIdentityFields maps the field names industrial analyzers use to the
// canonical identity fields. Only names that are unambiguous in an industrial log
// are listed: "version" is deliberately absent because it appears in logs where it
// means something else entirely.
var zeekICSIdentityFields = map[string]string{
	"vendor":                       "vendor",
	"vendor_name":                  "vendor",
	"vendor_id":                    "vendor_id",
	"product_name":                 "product",
	"model_name":                   "product",
	"device_model":                 "product",
	"module_type":                  "product",
	"cpu_type":                     "product",
	"firmware_revision":            "firmware",
	"firmware_version":             "firmware",
	"application_software_version": "firmware",
	"revision":                     "firmware",
	"serial_number":                "serial",
	"module":                       "catalog_number",
	"order_code":                   "catalog_number",
	"basic_hardware":               "hardware",
	"hardware_revision":            "hardware",
	"device_type":                  "device_type",
	"object_name":                  "system_name",
	"plant_identification":         "plant",
}

// applyZeekICSIdentity lifts identity fields out of an industrial protocol log.
func applyZeekICSIdentity(record zeekRecord, s *sink) {
	// The identity describes whoever sent the message. Zeek marks that with
	// is_orig, and where the field is absent the responder is assumed, since a
	// device reports its identity in a reply.
	sender, peer := record.get("id.resp_h"), record.get("id.orig_h")
	if isOrig, present := record.getBool("is_orig"); present && isOrig {
		sender, peer = peer, sender
	}
	if !usableIP(sender) {
		return
	}
	// The other end is a real host too, and the topology view needs it present
	// even when no conn.log was supplied alongside the protocol log.
	if usableIP(peer) {
		s.device(addressesFor(peer)).touchSeen(record.timestamp())
	}

	found := make(map[string]string)
	for name, field := range zeekICSIdentityFields {
		value := strings.TrimSpace(record.get(name))
		if value == "" || value == "-" {
			continue
		}
		found[field] = value
	}
	if len(found) == 0 {
		return
	}

	device := s.device(addressesFor(sender))
	device.touchSeen(record.timestamp())
	for _, field := range sortedKeys(found) {
		value := found[field]
		device.setField(record.path+"."+field, value)
		switch field {
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
	device.addEvidence(asset.Evidence{
		Source:    asset.SourceZeek,
		Protocol:  record.path,
		Endpoint:  sender,
		Timestamp: record.timestamp(),
		Fields:    device.pendingFields(),
		Notes: []string{
			fmt.Sprintf("identity read from the %s log at line %d, produced by traffic Zeek watched", record.path, record.line),
		},
	})
}

// addressesFor builds an address set from a single IP string.
func addressesFor(ip string) asset.Addresses {
	if strings.Contains(ip, ":") {
		return asset.Addresses{IPv6: ip}
	}
	return asset.Addresses{IPv4: ip}
}
