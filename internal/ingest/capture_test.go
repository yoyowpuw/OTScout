package ingest

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// captureBuilder assembles a synthetic capture in memory.
//
// Building captures rather than committing binary files keeps the test readable:
// the bytes that matter are visible in the test that depends on them, and a
// reviewer can see what a case is actually asserting about.
type captureBuilder struct {
	t     *testing.T
	buf   bytes.Buffer
	w     *pcapgo.Writer
	clock time.Time
}

func newCaptureBuilder(t *testing.T) *captureBuilder {
	t.Helper()
	b := &captureBuilder{
		t:     t,
		clock: time.Date(2026, 3, 4, 9, 30, 0, 0, time.UTC),
	}
	b.w = pcapgo.NewWriter(&b.buf)
	if err := b.w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	return b
}

func (b *captureBuilder) tick() time.Time {
	b.clock = b.clock.Add(10 * time.Millisecond)
	return b.clock
}

func (b *captureBuilder) write(frame []byte) {
	b.t.Helper()
	ci := gopacket.CaptureInfo{
		Timestamp:     b.tick(),
		CaptureLength: len(frame),
		Length:        len(frame),
	}
	if err := b.w.WritePacket(ci, frame); err != nil {
		b.t.Fatalf("write packet: %v", err)
	}
}

func mustMAC(t *testing.T, raw string) net.HardwareAddr {
	t.Helper()
	hw, err := net.ParseMAC(raw)
	if err != nil {
		t.Fatalf("bad mac in fixture %q: %v", raw, err)
	}
	return hw
}

func serializeFrame(t *testing.T, parts ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, parts...); err != nil {
		t.Fatalf("serialize frame: %v", err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

type tcpFlags struct {
	syn bool
	ack bool
	rst bool
	psh bool
}

func (b *captureBuilder) tcp(srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort int, flags tcpFlags, payload []byte) *captureBuilder {
	b.t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       mustMAC(b.t, srcMAC),
		DstMAC:       mustMAC(b.t, dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		Seq:     1,
		Window:  8192,
		SYN:     flags.syn,
		ACK:     flags.ack,
		RST:     flags.rst,
		PSH:     flags.psh,
	}
	if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
		b.t.Fatalf("set checksum layer: %v", err)
	}
	b.write(serializeFrame(b.t, eth, ip, tcp, gopacket.Payload(payload)))
	return b
}

func (b *captureBuilder) udp(srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort int, payload []byte) *captureBuilder {
	b.t.Helper()
	eth := &layers.Ethernet{
		SrcMAC:       mustMAC(b.t, srcMAC),
		DstMAC:       mustMAC(b.t, dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(dstPort),
	}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		b.t.Fatalf("set checksum layer: %v", err)
	}
	b.write(serializeFrame(b.t, eth, ip, udp, gopacket.Payload(payload)))
	return b
}

func (b *captureBuilder) arp(mac, ip string) *captureBuilder {
	b.t.Helper()
	hw := mustMAC(b.t, mac)
	eth := &layers.Ethernet{
		SrcMAC:       hw,
		DstMAC:       mustMAC(b.t, "ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeARP,
	}
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   hw,
		SourceProtAddress: net.ParseIP(ip).To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    net.ParseIP("10.20.0.1").To4(),
	}
	b.write(serializeFrame(b.t, eth, arp))
	return b
}

// lldpTLV encodes one LLDP type length value field. The type occupies the top
// seven bits of the first two octets and the length the remaining nine.
func lldpTLV(typ int, body []byte) []byte {
	header := uint16(typ)<<9 | uint16(len(body))
	out := []byte{byte(header >> 8), byte(header)}
	return append(out, body...)
}

func (b *captureBuilder) lldp(mac, sysName, sysDescr, portDescr string) *captureBuilder {
	b.t.Helper()
	hw := mustMAC(b.t, mac)

	frame := make([]byte, 0, 256)
	frame = append(frame, lldpTLV(1, append([]byte{4}, hw...))...) // chassis id, MAC subtype
	frame = append(frame, lldpTLV(2, append([]byte{5}, "port1"...))...)
	frame = append(frame, lldpTLV(3, []byte{0x00, 0x78})...) // time to live 120s
	frame = append(frame, lldpTLV(4, []byte(portDescr))...)
	frame = append(frame, lldpTLV(5, []byte(sysName))...)
	frame = append(frame, lldpTLV(6, []byte(sysDescr))...)
	// Capabilities: bridge bit set in both the supported and enabled masks.
	frame = append(frame, lldpTLV(7, []byte{0x00, 0x04, 0x00, 0x04})...)
	frame = append(frame, lldpTLV(0, nil)...)

	eth := &layers.Ethernet{
		SrcMAC:       hw,
		DstMAC:       mustMAC(b.t, "01:80:c2:00:00:0e"),
		EthernetType: layers.EthernetTypeLinkLayerDiscovery,
	}
	b.write(serializeFrame(b.t, eth, gopacket.Payload(frame)))
	return b
}

// save writes the capture to a temporary file and returns its path.
func (b *captureBuilder) save(name string) string {
	b.t.Helper()
	path := filepath.Join(b.t.TempDir(), name)
	if err := os.WriteFile(path, b.buf.Bytes(), 0o600); err != nil {
		b.t.Fatalf("write capture: %v", err)
	}
	return path
}

func (b *captureBuilder) saveGzip(name string) string {
	b.t.Helper()
	path := filepath.Join(b.t.TempDir(), name)
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	if _, err := gz.Write(b.buf.Bytes()); err != nil {
		b.t.Fatalf("compress capture: %v", err)
	}
	if err := gz.Close(); err != nil {
		b.t.Fatalf("close gzip: %v", err)
	}
	if err := os.WriteFile(path, out.Bytes(), 0o600); err != nil {
		b.t.Fatalf("write capture: %v", err)
	}
	return path
}

func mustHexBytes(t *testing.T, s string) []byte {
	t.Helper()
	cleaned := strings.NewReplacer(" ", "", "\n", "", "\t", "").Replace(s)
	out, err := hex.DecodeString(cleaned)
	if err != nil {
		t.Fatalf("bad hex in fixture: %v", err)
	}
	return out
}

// wagoModbusIdentity is the same Read Device Identification response the protocol
// tests use, so that a change in the decoder shows up in both places.
func wagoModbusIdentity(t *testing.T) []byte {
	return mustHexBytes(t, ""+
		"0001 0000 0022 01"+
		"2b 0e 01 02 00 00 03"+
		"00 04 57 41 47 4f"+
		"01 08 37 35 30 2d 38 32 30 32"+
		"02 08 30 31 2e 30 32 2e 30 33")
}

func runIngest(t *testing.T, opts Options) *Result {
	t.Helper()
	result, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return result
}

// findAsset locates an asset by IP and fails the test when it is missing, which
// produces a far more useful failure than a nil dereference.
func findAsset(t *testing.T, inv *asset.Inventory, ip string) *asset.Asset {
	t.Helper()
	for idx := range inv.Assets {
		a := &inv.Assets[idx]
		if a.Addresses.IPv4 == ip || a.Addresses.IPv6 == ip {
			return a
		}
	}
	addrs := make([]string, 0, len(inv.Assets))
	for idx := range inv.Assets {
		addrs = append(addrs, inv.Assets[idx].Addresses.Primary())
	}
	t.Fatalf("no asset for %s, inventory holds %v", ip, addrs)
	return nil
}

func lookupAsset(inv *asset.Inventory, ip string) *asset.Asset {
	for idx := range inv.Assets {
		if inv.Assets[idx].Addresses.IPv4 == ip {
			return &inv.Assets[idx]
		}
	}
	return nil
}

func serviceOn(a *asset.Asset, port int, transport string) *asset.Service {
	for idx := range a.Services {
		if a.Services[idx].Port == port && a.Services[idx].Transport == transport {
			return &a.Services[idx]
		}
	}
	return nil
}

func TestIngestPcapRecoversModbusIdentity(t *testing.T) {
	const (
		hmi = "10.20.0.40"
		plc = "10.20.0.5"
	)
	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:40", "aa:bb:cc:00:00:05", hmi, plc, 51234, 502, tcpFlags{syn: true}, nil).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", plc, hmi, 502, 51234, tcpFlags{syn: true, ack: true}, nil).
		tcp("aa:bb:cc:00:00:40", "aa:bb:cc:00:00:05", hmi, plc, 51234, 502, tcpFlags{ack: true, psh: true},
			mustHexBytes(t, "0001 0000 0005 01 2b 0e 01 00")).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", plc, hmi, 502, 51234, tcpFlags{ack: true, psh: true},
			wagoModbusIdentity(t)).
		save("plant.pcap")

	result := runIngest(t, Options{PcapFiles: []string{path}})
	device := findAsset(t, result.Inventory, plc)

	if device.Identity.VendorRaw != "WAGO" {
		t.Errorf("VendorRaw = %q, want WAGO", device.Identity.VendorRaw)
	}
	// The normalizer should have resolved the raw string to the canonical vendor
	// and used the product code as an order code.
	if device.Identity.Vendor != "wago" {
		t.Errorf("Vendor = %q, want wago", device.Identity.Vendor)
	}
	if device.Identity.CatalogNumber == "" {
		t.Error("the Modbus product code should have been kept as the catalog number")
	}
	if device.Role != asset.RolePLC || device.Purdue != asset.PurdueL1 {
		t.Errorf("Role = %q, Purdue = %q, want plc at L1", device.Role, device.Purdue)
	}

	svc := serviceOn(device, 502, "tcp")
	if svc == nil {
		t.Fatalf("no Modbus service recorded, services = %+v", device.Services)
	}
	if svc.Source != asset.SourcePcap {
		t.Errorf("service source = %q, want pcap", svc.Source)
	}

	// The client end must appear too, otherwise the topology view has a flow with
	// only one end placed.
	if lookupAsset(result.Inventory, hmi) == nil {
		t.Error("the client side of the conversation should also be an asset")
	}
}

// TestIngestPcapDecodesAServiceOnAnUnregisteredPort covers a device reachable
// somewhere other than its registered port.
//
// Gateways remap ports, honeypots bind high ones to avoid needing root, and
// plenty of products simply ship listening elsewhere. Deciding what to decode
// purely from the port number would leave every one of those uninventoried, and
// they are not the rare case.
func TestIngestPcapDecodesAServiceOnAnUnregisteredPort(t *testing.T) {
	const plc = "10.20.0.6"
	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:40", "aa:bb:cc:00:00:06", "10.20.0.40", plc, 51234, 5020, tcpFlags{syn: true}, nil).
		tcp("aa:bb:cc:00:00:06", "aa:bb:cc:00:00:40", plc, "10.20.0.40", 5020, 51234, tcpFlags{syn: true, ack: true}, nil).
		tcp("aa:bb:cc:00:00:06", "aa:bb:cc:00:00:40", plc, "10.20.0.40", 5020, 51234, tcpFlags{ack: true, psh: true},
			wagoModbusIdentity(t)).
		save("gateway.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, plc)
	if device.Identity.VendorRaw != "WAGO" {
		t.Errorf("VendorRaw = %q, want WAGO: the response was Modbus wherever it was heard", device.Identity.VendorRaw)
	}

	// Reaching an identity by content is a weaker claim than reaching it on the
	// registered port, so the evidence has to say which one happened.
	found := false
	for _, ev := range device.Evidence {
		for _, note := range ev.Notes {
			if strings.Contains(note, "not the registered port") {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the evidence does not record that the port was unexpected: %+v", device.Evidence)
	}
}

// TestIngestPcapKeepsWhatALaterAnswerAdds guards against stopping at the first
// thing a device says.
//
// Identity arrives in pieces. A BACnet controller announces itself and only
// names its model when asked, and a Siemens CPU splits its identity across
// separate SZL reads. Treating a service as finished once anything decoded would
// keep whichever piece happened to arrive first.
func TestIngestPcapKeepsWhatALaterAnswerAdds(t *testing.T) {
	const controller = "10.20.0.7"

	// An I-Am, which gives a device instance and a vendor number but no text,
	// followed by the model name that a ReadProperty returns.
	iAm := mustHexBytes(t, "810b0014 0100 1000 c402008d11 220400 9100 210f")
	modelName := mustHexBytes(t, "810a0026 0100 30 01 0c 0c02008d11 1946 3e 751200 5641562d444420436f6e74726f6c6c6572 3f")

	path := newCaptureBuilder(t).
		udp("aa:bb:cc:00:00:07", "ff:ff:ff:ff:ff:ff", controller, "10.20.0.255", 47808, 47808, iAm).
		udp("aa:bb:cc:00:00:07", "aa:bb:cc:00:00:40", controller, "10.20.0.40", 47808, 55000, modelName).
		save("building.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, controller)
	if device.Identity.ProductRaw != "VAV-DD Controller" {
		t.Errorf("ProductRaw = %q, want the model name from the second answer", device.Identity.ProductRaw)
	}
	if device.Role != asset.RoleBuildingAC {
		t.Errorf("Role = %q, want %q from the first answer", device.Role, asset.RoleBuildingAC)
	}
}

// TestIngestPcapDoesNotRecordAnEvidenceEntryPerPoll is the other half of the
// test above.
//
// An HMI polls a PLC for as long as the plant runs, and a capture of that is
// thousands of near identical frames. Continuing to decode them must not mean
// continuing to record them, or one asset ends up carrying an evidence trail
// nobody can read and a file nobody can open.
func TestIngestPcapDoesNotRecordAnEvidenceEntryPerPoll(t *testing.T) {
	const plc = "10.20.0.8"

	builder := newCaptureBuilder(t)
	for transaction := 1; transaction <= 25; transaction++ {
		// Only the transaction id differs between polls, which is exactly what
		// varies on a real one.
		response := []byte{
			byte(transaction >> 8), byte(transaction), 0x00, 0x00, 0x00, 0x07, 0x01,
			0x03, 0x04, 0x00, 0x64, 0x00, 0xc8,
		}
		builder.tcp("aa:bb:cc:00:00:08", "aa:bb:cc:00:00:40", plc, "10.20.0.40", 502, 51234,
			tcpFlags{ack: true, psh: true}, response)
	}

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{builder.save("poll.pcap")}}).Inventory, plc)
	if len(device.Evidence) != 1 {
		t.Errorf("25 polls produced %d evidence entries, want 1: they all say the same thing", len(device.Evidence))
	}
}

func TestIngestPcapEvidenceKeepsTheResponseBytesAndNoRequest(t *testing.T) {
	const plc = "10.20.0.5"
	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", plc, "10.20.0.40", 502, 51234,
			tcpFlags{ack: true, psh: true}, wagoModbusIdentity(t)).
		save("plant.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, plc)

	var found *asset.Evidence
	for idx := range device.Evidence {
		if device.Evidence[idx].Protocol == "modbus" {
			found = &device.Evidence[idx]
		}
	}
	if found == nil {
		t.Fatalf("no Modbus evidence recorded, evidence = %+v", device.Evidence)
	}
	if !bytes.Equal(found.Response, wagoModbusIdentity(t)) {
		t.Errorf("evidence response = %x, want the bytes from the capture", found.Response)
	}
	// This is the assertion that makes the passive path auditable. A request
	// recorded on a passive observation would tell an operator otscout sent
	// something when it did not.
	if found.Request != nil {
		t.Errorf("passive evidence carries a request of %x, it must be absent", found.Request)
	}
	if found.Source != asset.SourcePcap {
		t.Errorf("evidence source = %q, want pcap", found.Source)
	}
}

func TestIngestPassiveEvidenceNeverCarriesARequest(t *testing.T) {
	// The same invariant, checked across every passive source at once, so that a
	// new source added later cannot quietly break it.
	const plc = "10.20.0.5"
	pcapPath := newCaptureBuilder(t).
		arp("aa:bb:cc:00:00:05", plc).
		lldp("aa:bb:cc:00:00:09", "sw-line3", "Siemens, SIMATIC NET, SCALANCE X208, 6GK5 208-0BA10-2AA3", "port1").
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", plc, "10.20.0.40", 502, 51234,
			tcpFlags{ack: true, psh: true}, wagoModbusIdentity(t)).
		save("mixed.pcap")

	dir := t.TempDir()
	zeekPath := filepath.Join(dir, "conn.log")
	writeFile(t, zeekPath, sampleConnLog)
	nmapPath := filepath.Join(dir, "audit.xml")
	writeFile(t, nmapPath, sampleNmapXML)

	result := runIngest(t, Options{
		PcapFiles: []string{pcapPath},
		ZeekPaths: []string{zeekPath},
		NmapFiles: []string{nmapPath},
	})

	total := 0
	for idx := range result.Inventory.Assets {
		for _, ev := range result.Inventory.Assets[idx].Evidence {
			total++
			if !ev.Source.Passive() {
				t.Errorf("asset %s holds evidence from source %q on the passive path",
					result.Inventory.Assets[idx].Addresses.Primary(), ev.Source)
			}
			if ev.Request != nil {
				t.Errorf("asset %s evidence %s carries a request",
					result.Inventory.Assets[idx].Addresses.Primary(), ev.ID)
			}
		}
	}
	if total == 0 {
		t.Fatal("no evidence was recorded at all, so the assertion proved nothing")
	}
}

func TestIngestPcapDoesNotAttachARoutedMACToAnyAsset(t *testing.T) {
	// Two hosts arriving through one gateway share a source MAC. Binding it would
	// merge them into a single asset, which is the worst kind of inventory error
	// because the merged entry looks plausible.
	const gateway = "aa:bb:cc:00:00:01"
	path := newCaptureBuilder(t).
		tcp(gateway, "aa:bb:cc:00:00:05", "192.168.9.10", "10.20.0.5", 40001, 502, tcpFlags{syn: true}, nil).
		tcp(gateway, "aa:bb:cc:00:00:05", "192.168.9.11", "10.20.0.5", 40002, 502, tcpFlags{syn: true}, nil).
		tcp("aa:bb:cc:00:00:05", gateway, "10.20.0.5", "192.168.9.10", 502, 40001, tcpFlags{syn: true, ack: true}, nil).
		save("routed.pcap")

	inv := runIngest(t, Options{PcapFiles: []string{path}}).Inventory

	for _, ip := range []string{"192.168.9.10", "192.168.9.11"} {
		device := findAsset(t, inv, ip)
		if device.Addresses.MAC != "" {
			t.Errorf("%s was given hardware address %q even though it is shared with another host",
				ip, device.Addresses.MAC)
		}
	}
	// The device with a MAC of its own still gets it.
	plc := findAsset(t, inv, "10.20.0.5")
	if plc.Addresses.MAC != "aa:bb:cc:00:00:05" {
		t.Errorf("PLC hardware address = %q, want aa:bb:cc:00:00:05", plc.Addresses.MAC)
	}
	if len(inv.Assets) != 3 {
		t.Errorf("inventory holds %d assets, want 3 distinct devices", len(inv.Assets))
	}
}

func TestIngestPcapAssemblesAResponseSplitAcrossSegments(t *testing.T) {
	// Real captures split responses. A decoder run on the first segment alone sees
	// a truncated message, so the reader has to hold it and try again.
	full := wagoModbusIdentity(t)
	first, second := full[:12], full[12:]

	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", "10.20.0.5", "10.20.0.40", 502, 51234,
			tcpFlags{ack: true, psh: true}, first).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", "10.20.0.5", "10.20.0.40", 502, 51234,
			tcpFlags{ack: true, psh: true}, second).
		save("split.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, "10.20.0.5")
	if device.Identity.VendorRaw != "WAGO" {
		t.Errorf("VendorRaw = %q, want WAGO recovered from the reassembled response", device.Identity.VendorRaw)
	}
}

func TestIngestPcapDoesNotRecordServicesForRefusedConnections(t *testing.T) {
	// Zeek and Nmap both distinguish a refused port from an open one, and so must
	// the capture reader. An inventory listing ports that are shut is worse than
	// useless because every later step trusts it.
	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:40", "aa:bb:cc:00:00:07", "10.20.0.40", "10.20.0.7", 51234, 502, tcpFlags{syn: true}, nil).
		tcp("aa:bb:cc:00:00:07", "aa:bb:cc:00:00:40", "10.20.0.7", "10.20.0.40", 502, 51234, tcpFlags{rst: true, ack: true}, nil).
		save("refused.pcap")

	inv := runIngest(t, Options{PcapFiles: []string{path}}).Inventory
	device := findAsset(t, inv, "10.20.0.7")
	if svc := serviceOn(device, 502, "tcp"); svc != nil {
		t.Errorf("a refused port was recorded as a service: %+v", svc)
	}
	// The attempt is still a flow, which is what the segmentation view needs.
	if len(inv.Flows) == 0 {
		t.Error("the connection attempt should still appear as a flow")
	}
}

func TestIngestPcapRecordsFlowsFromClientToServer(t *testing.T) {
	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:40", "aa:bb:cc:00:00:05", "10.20.0.40", "10.20.0.5", 51234, 502, tcpFlags{syn: true}, nil).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", "10.20.0.5", "10.20.0.40", 502, 51234, tcpFlags{syn: true, ack: true}, nil).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", "10.20.0.5", "10.20.0.40", 502, 51234, tcpFlags{ack: true, psh: true}, []byte{0}).
		save("flow.pcap")

	inv := runIngest(t, Options{PcapFiles: []string{path}}).Inventory
	if len(inv.Flows) != 1 {
		t.Fatalf("recorded %d flows, want a single one in the client to server direction: %+v", len(inv.Flows), inv.Flows)
	}
	flow := inv.Flows[0]
	if flow.SrcAddr != "10.20.0.40" || flow.DstAddr != "10.20.0.5" || flow.DstPort != 502 {
		t.Errorf("flow = %s -> %s:%d, want 10.20.0.40 -> 10.20.0.5:502", flow.SrcAddr, flow.DstAddr, flow.DstPort)
	}
	if flow.Protocol != "modbus" {
		t.Errorf("flow protocol = %q, want modbus", flow.Protocol)
	}
	if flow.Packets != 3 {
		t.Errorf("flow packets = %d, want all 3 packets of the conversation", flow.Packets)
	}
	if flow.SrcAssetID == "" || flow.DstAssetID == "" {
		t.Error("both flow endpoints should resolve to asset ids")
	}
}

func TestIngestPcapReadsARPBindings(t *testing.T) {
	path := newCaptureBuilder(t).
		arp("aa:bb:cc:00:00:05", "10.20.0.5").
		save("arp.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, "10.20.0.5")
	if device.Addresses.MAC != "aa:bb:cc:00:00:05" {
		t.Errorf("MAC = %q, want the address announced in the ARP frame", device.Addresses.MAC)
	}
	if len(device.Evidence) == 0 {
		t.Error("the ARP observation should be recorded as evidence")
	}
}

func TestIngestPcapReadsLLDPAndRecognisesTheOrderCode(t *testing.T) {
	// A managed switch answers no control protocol, so LLDP is often the only way
	// it gets identified at all.
	path := newCaptureBuilder(t).
		lldp("aa:bb:cc:00:00:09", "sw-line3",
			"Siemens, SIMATIC NET, SCALANCE X208, 6GK5 208-0BA10-2AA3, HW: 4, FW: V5.2.3", "Port 1").
		save("lldp.pcap")

	inv := runIngest(t, Options{PcapFiles: []string{path}}).Inventory
	if len(inv.Assets) != 1 {
		t.Fatalf("recorded %d assets, want 1", len(inv.Assets))
	}
	device := &inv.Assets[0]

	if device.Addresses.Hostname != "sw-line3" {
		t.Errorf("Hostname = %q, want sw-line3", device.Addresses.Hostname)
	}
	if device.Addresses.MAC != "aa:bb:cc:00:00:09" {
		t.Errorf("MAC = %q, want aa:bb:cc:00:00:09", device.Addresses.MAC)
	}
	// The order code is what turns the free text description into something the
	// matcher can use, so the vendor should now be resolved from it.
	if device.Identity.CatalogNumber == "" {
		t.Fatalf("no catalog number recognised, identity = %+v", device.Identity)
	}
	if device.Identity.Vendor != "siemens" {
		t.Errorf("Vendor = %q, want siemens resolved from the MLFB", device.Identity.Vendor)
	}
	if device.Role != asset.RoleNetwork {
		t.Errorf("Role = %q, want network-device from the LLDP bridge capability", device.Role)
	}
}

func TestSniffTextIgnoresDescriptionsWithoutAnOrderCode(t *testing.T) {
	s := newTestSink(t)
	cases := []string{
		"",
		"Generic Ethernet Switch, 8 ports, revision 3",
		"Linux 4.19.0 armv7l build 20240115",
		"Contact support on 555 123 4567 for assistance",
		"Managed switch firmware 2.4.1, serial 1234567890",
	}
	for _, text := range cases {
		vendor, catalog := s.sniffText(text)
		if vendor != "" || catalog != "" {
			t.Errorf("sniffText(%q) = (%q, %q), want no match", text, vendor, catalog)
		}
	}
}

func TestSniffTextUsesTheNamedVendorToRuleOutForeignOrderCodes(t *testing.T) {
	// This is the case that motivates resolving the vendor first. The fragment
	// "208-0BA10-2AA3" parses on its own as a Rockwell Micro800 catalog number,
	// and the only thing that rules it out is that the description says Siemens.
	s := newTestSink(t)
	vendor, catalog := s.sniffText("Siemens, SIMATIC NET, SCALANCE X208, 6GK5 208-0BA10-2AA3, HW: 4, FW: V5.2.3")
	if vendor != "Siemens" {
		t.Errorf("vendor = %q, want Siemens", vendor)
	}
	if catalog != "6GK5 208-0BA10-2AA3" {
		t.Errorf("catalog = %q, want the whole MLFB", catalog)
	}
}

func TestSniffTextPrefersTheOrderCodeOverTheWordsBesideIt(t *testing.T) {
	// "1756-L71/B LOGIX5571" parses as a ControlLogix 5570 whether or not the
	// trailing word is included, so the shorter reading has to win.
	s := newTestSink(t)
	_, catalog := s.sniffText("1756-L71/B LOGIX5571")
	if catalog != "1756-L71/B" {
		t.Errorf("catalog = %q, want 1756-L71/B", catalog)
	}
}

func newTestSink(t *testing.T) *sink {
	t.Helper()
	normalizer, err := normalize.New()
	if err != nil {
		t.Fatalf("load normalization tables: %v", err)
	}
	return newSink(normalizer)
}

func TestIngestReadsPcapngAndGzippedCaptures(t *testing.T) {
	// The format is detected from the file contents, not the extension, because
	// captures arrive named whatever the person who exported them chose.
	gzPath := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:05", "aa:bb:cc:00:00:40", "10.20.0.5", "10.20.0.40", 502, 51234,
			tcpFlags{ack: true, psh: true}, wagoModbusIdentity(t)).
		saveGzip("plant.pcap.gz")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{gzPath}}).Inventory, "10.20.0.5")
	if device.Identity.VendorRaw != "WAGO" {
		t.Errorf("gzip capture: VendorRaw = %q, want WAGO", device.Identity.VendorRaw)
	}

	ngPath := writePcapng(t, "plant.pcapng", func(w *pcapgo.NgWriter) {
		b := newCaptureBuilder(t)
		eth := &layers.Ethernet{
			SrcMAC:       mustMAC(t, "aa:bb:cc:00:00:05"),
			DstMAC:       mustMAC(t, "aa:bb:cc:00:00:40"),
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP,
			SrcIP: net.ParseIP("10.20.0.5").To4(),
			DstIP: net.ParseIP("10.20.0.40").To4(),
		}
		tcp := &layers.TCP{SrcPort: 502, DstPort: 51234, Seq: 1, Window: 8192, ACK: true, PSH: true}
		if err := tcp.SetNetworkLayerForChecksum(ip); err != nil {
			t.Fatalf("set checksum layer: %v", err)
		}
		frame := serializeFrame(t, eth, ip, tcp, gopacket.Payload(wagoModbusIdentity(t)))
		ci := gopacket.CaptureInfo{Timestamp: b.tick(), CaptureLength: len(frame), Length: len(frame)}
		if err := w.WritePacket(ci, frame); err != nil {
			t.Fatalf("write pcapng packet: %v", err)
		}
	})

	device = findAsset(t, runIngest(t, Options{PcapFiles: []string{ngPath}}).Inventory, "10.20.0.5")
	if device.Identity.VendorRaw != "WAGO" {
		t.Errorf("pcapng capture: VendorRaw = %q, want WAGO", device.Identity.VendorRaw)
	}
}

func writePcapng(t *testing.T, name string, fill func(*pcapgo.NgWriter)) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pcapng: %v", err)
	}
	defer file.Close()

	w, err := pcapgo.NewNgWriter(file, layers.LinkTypeEthernet)
	if err != nil {
		t.Fatalf("open pcapng writer: %v", err)
	}
	fill(w)
	if err := w.Flush(); err != nil {
		t.Fatalf("flush pcapng: %v", err)
	}
	return path
}

func TestIngestPcapDecodesBACnetOverUDP(t *testing.T) {
	// BACnet identification arrives over UDP, so the reader must treat a datagram
	// from the device port as a response without a handshake to lean on.
	iAm := mustHexBytes(t, ""+
		"81 0b 0019"+
		"01 20 ffff 00 ff"+
		"10 00"+
		"c4 02000064"+
		"22 01e0"+
		"91 00"+
		"22 0005")

	path := newCaptureBuilder(t).
		udp("aa:bb:cc:00:00:21", "aa:bb:cc:00:00:40", "10.30.0.33", "10.30.0.40", 47808, 47808, iAm).
		save("bacnet.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, "10.30.0.33")
	if device.Role != asset.RoleBuildingAC {
		t.Errorf("Role = %q, want building-controller", device.Role)
	}
	if svc := serviceOn(device, 47808, "udp"); svc == nil {
		t.Errorf("no BACnet service recorded, services = %+v", device.Services)
	}
}

func TestIngestPcapCollectsAnHTTPServerBannerWithoutClaimingAnIdentity(t *testing.T) {
	// A Server header names the web server, not the controller. It belongs in the
	// service banner so an engineer can read it, and nowhere near the identity the
	// matcher trusts.
	response := []byte("HTTP/1.1 200 OK\r\nServer: SIMATIC-HTTP/2.0\r\nContent-Length: 0\r\n\r\n")
	path := newCaptureBuilder(t).
		tcp("aa:bb:cc:00:00:11", "aa:bb:cc:00:00:40", "10.20.0.11", "10.20.0.40", 80, 51000,
			tcpFlags{ack: true, psh: true}, response).
		save("http.pcap")

	device := findAsset(t, runIngest(t, Options{PcapFiles: []string{path}}).Inventory, "10.20.0.11")
	svc := serviceOn(device, 80, "tcp")
	if svc == nil {
		t.Fatalf("no HTTP service recorded, services = %+v", device.Services)
	}
	if svc.Banner != "SIMATIC-HTTP/2.0" {
		t.Errorf("banner = %q, want SIMATIC-HTTP/2.0", svc.Banner)
	}
	if !device.Identity.Empty() {
		t.Errorf("a Server header must not become an identity, got %+v", device.Identity)
	}
}

func TestIngestRejectsAnEmptyInvocation(t *testing.T) {
	if _, err := Run(context.Background(), Options{}); err == nil {
		t.Fatal("running with no inputs should be an error rather than an empty inventory")
	}
}

func TestIngestReportsAnUnreadableCaptureWithoutLosingOtherWork(t *testing.T) {
	good := newCaptureBuilder(t).
		arp("aa:bb:cc:00:00:05", "10.20.0.5").
		save("good.pcap")
	bad := filepath.Join(t.TempDir(), "truncated.pcap")
	writeFile(t, bad, "this is not a capture")

	result := runIngest(t, Options{PcapFiles: []string{bad, good}})
	if len(result.Stats.Warnings) == 0 {
		t.Error("the unreadable file should produce a warning")
	}
	if lookupAsset(result.Inventory, "10.20.0.5") == nil {
		t.Error("the readable file should still have been ingested")
	}
	if result.Stats.FilesRead != 1 {
		t.Errorf("FilesRead = %d, want 1", result.Stats.FilesRead)
	}
}

func TestIngestHonoursContextCancellation(t *testing.T) {
	path := newCaptureBuilder(t).
		arp("aa:bb:cc:00:00:05", "10.20.0.5").
		save("arp.pcap")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Run(ctx, Options{PcapFiles: []string{path}}); err == nil {
		t.Fatal("a cancelled context should stop the run")
	}
}

func TestUsableAddressFilters(t *testing.T) {
	badMACs := []string{
		"ff:ff:ff:ff:ff:ff", // broadcast
		"01:80:c2:00:00:0e", // LLDP multicast group
		"01:00:5e:00:00:01", // IPv4 multicast
		"33:33:00:00:00:01", // IPv6 multicast
		"00:00:00:00:00:00",
		"not a mac",
	}
	for _, mac := range badMACs {
		if usableMAC(mac) {
			t.Errorf("usableMAC(%q) = true, want false", mac)
		}
	}
	if !usableMAC("aa:bb:cc:00:00:05") {
		t.Error("a normal unicast address should be usable")
	}

	badIPs := []string{"", "0.0.0.0", "255.255.255.255", "224.0.0.1", "ff02::1", "not an ip"}
	for _, ip := range badIPs {
		if usableIP(ip) {
			t.Errorf("usableIP(%q) = true, want false", ip)
		}
	}
	for _, ip := range []string{"10.20.0.5", "fd00::5"} {
		if !usableIP(ip) {
			t.Errorf("usableIP(%q) = false, want true", ip)
		}
	}
}

func TestNormalizeMACSettlesOnOneForm(t *testing.T) {
	for _, raw := range []string{"AA-BB-CC-00-00-05", "AABBCC000005", "aa:bb:cc:00:00:05", "AA:BB:CC:00:00:05"} {
		if got := normalizeMAC(raw); got != "aa:bb:cc:00:00:05" {
			t.Errorf("normalizeMAC(%q) = %q, want aa:bb:cc:00:00:05", raw, got)
		}
	}
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
