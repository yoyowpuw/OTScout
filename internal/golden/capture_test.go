package golden

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/ingest"
	"github.com/yoyowpuw/OTScout/internal/protocol"
)

// This file replays the corpus as a packet capture and runs the whole passive
// path over it.
//
// Decoding a frame correctly is not the same as producing a correct inventory.
// Between the two sit the parts most likely to be wrong in a way no unit test
// notices: working out which end of a conversation is the device, binding
// hardware addresses to hosts, merging what several protocols said about one
// host, and resolving the vendor and product strings into canonical ones. A
// fixture that decodes perfectly and then lands on the wrong asset is worth
// nothing, so the corpus is checked at both levels.
//
// The addresses come from the network GRFICSv3 documents, because a realistic
// layout is what makes the segmentation question meaningful: an HMI in the DMZ
// polling a PLC in the ICS network is the finding, and it only exists if the two
// are on the subnets they would really be on. GRFICS puts its OpenPLC at
// 192.168.95.2 and its HMI at 192.168.90.107, with a firewall between the two
// networks at .200 on each.
//
// The devices answering are the ones the corpus records, so this is a composite
// rather than a reproduction: GRFICS runs OpenPLC, and the Siemens, Rockwell and
// Johnson Controls hosts here stand in for the equipment a real plant of this
// shape would have on those subnets.

const (
	hmiIP  = "192.168.90.107" // the GRFICS HMI, in the DMZ
	hmiMAC = "08:00:27:90:01:07"

	workstationIP  = "192.168.95.5" // engineering workstation, in the ICS network
	workstationMAC = "08:00:27:95:00:05"

	plcIP  = "192.168.95.2" // OpenPLC
	plcMAC = "08:00:27:95:00:02"

	siemensIP  = "192.168.95.11"
	siemensMAC = "08:00:27:95:00:0b"

	conpotModbusIP  = "192.168.95.10"
	conpotModbusMAC = "08:00:27:95:00:0a"

	rockwellIP  = "192.168.95.12"
	rockwellMAC = "08:00:27:95:00:0c"

	alertonIP  = "192.168.95.13"
	alertonMAC = "08:00:27:95:00:0d"

	webIP  = "192.168.95.20"
	webMAC = "08:00:27:95:00:14"

	// The two hosts below answer with bytes recorded from real equipment rather
	// than from an emulator, which is what makes the normalization assertions
	// about them worth making: an emulator's identity strings are as tidy as
	// whoever wrote the template, and a plant's are not.
	s7300IP  = "192.168.95.14"
	s7300MAC = "08:00:27:95:00:0e"

	metasysIP  = "192.168.95.15"
	metasysMAC = "08:00:27:95:00:0f"
)

func TestCorpusReplayedAsACaptureBuildsTheInventory(t *testing.T) {
	fixtures := byID(t)
	cap := newCapture(t)

	for _, host := range []struct{ ip, mac string }{
		{hmiIP, hmiMAC},
		{workstationIP, workstationMAC},
		{plcIP, plcMAC},
		{siemensIP, siemensMAC},
		{conpotModbusIP, conpotModbusMAC},
		{rockwellIP, rockwellMAC},
		{alertonIP, alertonMAC},
		{webIP, webMAC},
		{s7300IP, s7300MAC},
		{metasysIP, metasysMAC},
	} {
		cap.arp(host.mac, host.ip)
	}

	// The workstation asks the OpenPLC what it is and is told the function does
	// not exist.
	cap.exchange(workstationMAC, workstationIP, plcMAC, plcIP, 49152, 502,
		fixtures["openplc-v3-modbus-identification-refused"])

	// The HMI polls the PLC for process values from the other side of the
	// firewall, which is the conversation the topology view has to flag.
	cap.exchange(hmiMAC, hmiIP, plcMAC, plcIP, 49153, 502,
		fixtures["openplc-v3-modbus-read-holding-registers"])

	cap.exchange(workstationMAC, workstationIP, siemensMAC, siemensIP, 49154, 102,
		fixtures["conpot-default-s7comm-component-identification"])

	cap.exchange(workstationMAC, workstationIP, conpotModbusMAC, conpotModbusIP, 49155, 502,
		fixtures["conpot-default-modbus-read-device-identification"])

	cap.exchange(workstationMAC, workstationIP, rockwellMAC, rockwellIP, 49156, 44818,
		fixtures["conpot-default-enip-list-identity"])

	cap.exchange(workstationMAC, workstationIP, webMAC, webIP, 49157, 502,
		fixtures["http-server-on-the-modbus-port"])

	// BACnet announcements are broadcast from the registered port to itself,
	// while a tool reading a property answers back to whatever port asked.
	cap.udp(alertonMAC, alertonIP, "ff:ff:ff:ff:ff:ff", "192.168.95.255", 47808, 47808,
		fixtures["conpot-default-bacnet-i-am"].Response)
	cap.udp(workstationMAC, workstationIP, alertonMAC, alertonIP, 55000, 47808,
		fixtures["conpot-default-bacnet-model-name"].Request.Bytes)
	cap.udp(alertonMAC, alertonIP, workstationMAC, workstationIP, 47808, 55000,
		fixtures["conpot-default-bacnet-model-name"].Response)

	// The real S7-300 splits its identity across two SZL reads and the real
	// Metasys controller across two property reads, so between them they are the
	// case the passive path is most likely to get wrong: an asset whose identity
	// is only complete if nothing stopped listening after the first answer.
	cap.exchange(workstationMAC, workstationIP, s7300MAC, s7300IP, 49158, 102,
		fixtures["iti-siemens-s7-300-order-number"])
	cap.exchange(workstationMAC, workstationIP, s7300MAC, s7300IP, 49159, 102,
		fixtures["iti-siemens-s7-300-module-identification"])

	cap.udp(metasysMAC, metasysIP, workstationMAC, workstationIP, 47808, 55001,
		fixtures["iti-johnson-controls-bacnet-model-name"].Response)
	cap.udp(metasysMAC, metasysIP, workstationMAC, workstationIP, 47808, 55001,
		fixtures["iti-johnson-controls-bacnet-firmware-revision"].Response)

	inv := cap.ingest(t)

	t.Run("the Siemens CPU is identified and resolved", func(t *testing.T) {
		a := assetAt(t, inv, siemensIP)
		want := asset.Identity{
			Vendor:     "siemens",
			VendorRaw:  "Siemens",
			Product:    "IM151-8 PN/DP CPU",
			ProductRaw: "IM151-8 PN/DP CPU",
			Family:     "SIMATIC ET 200",
			Serial:     "88111222",
		}
		if a.Identity != want {
			t.Errorf("identity = %+v\nwant %+v", a.Identity, want)
		}
		if a.Role != asset.RolePLC {
			t.Errorf("role = %q, want %q", a.Role, asset.RolePLC)
		}
		if !hasService(a, 102, "tcp") {
			t.Error("the ISO-on-TCP service is missing from the asset")
		}
	})

	t.Run("the Rockwell controller keeps its order code", func(t *testing.T) {
		a := assetAt(t, inv, rockwellIP)
		if a.Identity.Vendor != "rockwell-automation" {
			t.Errorf("vendor = %q, want the canonical rockwell id", a.Identity.Vendor)
		}
		if a.Identity.CatalogNumber != "1756-L61" {
			t.Errorf("catalog number = %q, want 1756-L61", a.Identity.CatalogNumber)
		}
		if a.Identity.Firmware != "2.10" {
			t.Errorf("firmware = %q, want 2.10", a.Identity.Firmware)
		}
		if a.Role != asset.RolePLC {
			t.Errorf("role = %q, want %q", a.Role, asset.RolePLC)
		}
	})

	t.Run("the BACnet controller is placed without a product name from the I-Am", func(t *testing.T) {
		a := assetAt(t, inv, alertonIP)
		if a.Identity.Product != "VAV-DD Controller" {
			t.Errorf("product = %q, want the model name the ReadProperty returned", a.Identity.Product)
		}
		if a.Role != asset.RoleBuildingAC {
			t.Errorf("role = %q, want %q", a.Role, asset.RoleBuildingAC)
		}
	})

	t.Run("the PLC that refused identification is still an asset", func(t *testing.T) {
		a := assetAt(t, inv, plcIP)
		if !a.Identity.Empty() {
			t.Errorf("identity = %+v, want nothing: the device reported nothing about itself", a.Identity)
		}
		if !hasService(a, 502, "tcp") {
			t.Error("the Modbus service is missing, though the device answered twice")
		}
		if len(a.Evidence) == 0 {
			t.Error("refusing to answer is an observation and belongs in the evidence trail")
		}
	})

	t.Run("the web server on the Modbus port gets no industrial identity", func(t *testing.T) {
		a := assetAt(t, inv, webIP)
		if !a.Identity.Empty() {
			t.Errorf("identity = %+v, want nothing at all", a.Identity)
		}
		if a.Role == asset.RolePLC {
			t.Error("a web server on port 502 must not be filed as a PLC")
		}
	})

	t.Run("the workstation is not given the identity of what it asked", func(t *testing.T) {
		a := assetAt(t, inv, workstationIP)
		if !a.Identity.Empty() {
			t.Errorf("identity = %+v, want nothing: every response here travelled the other way", a.Identity)
		}
	})

	t.Run("the real S7-300 resolves from its order number", func(t *testing.T) {
		a := assetAt(t, inv, s7300IP)
		want := asset.Identity{
			Vendor:        "siemens",
			VendorRaw:     "Siemens",
			Product:       "CPU 315-2 PN/DP",
			ProductRaw:    "CPU 315-2 PN/DP",
			Family:        "SIMATIC S7-300",
			Model:         "CPU 315",
			CatalogNumber: "6ES7 315-2EH14-0AB0",
			Firmware:      "V3.0.1",
			FirmwareRaw:   "V3.0.1",
			Serial:        "S C-B1U393142011",
		}
		if a.Identity != want {
			t.Errorf("identity = %+v\nwant %+v", a.Identity, want)
		}
	})

	t.Run("the real Metasys controller keeps both properties it reported", func(t *testing.T) {
		a := assetAt(t, inv, metasysIP)
		if a.Identity.ProductRaw != "MS-NAE4510-2" {
			t.Errorf("product = %q, want MS-NAE4510-2", a.Identity.ProductRaw)
		}
		if a.Identity.Firmware != "5.1.0.4400" {
			t.Errorf("firmware = %q, want 5.1.0.4400 from the second property read", a.Identity.Firmware)
		}
		if a.Role != asset.RoleBuildingAC {
			t.Errorf("role = %q, want %q", a.Role, asset.RoleBuildingAC)
		}
	})

	t.Run("the poll that crossed the DMZ boundary is recorded as a flow", func(t *testing.T) {
		if !hasFlow(inv, hmiIP, plcIP, 502) {
			t.Fatalf("no flow from the DMZ HMI to the ICS PLC, so the segmentation view has nothing to work from")
		}
	})
}

// TestEveryFixtureThatCarriesAnIdentityReachesTheInventory guards the join
// between the two halves of this package.
//
// A fixture can decode correctly and still never reach an asset, because the
// capture path decides separately whether the frame came from a device at all.
// This walks the corpus rather than a hand written list, so a fixture added
// later is covered without anybody remembering to add it here.
func TestEveryFixtureThatCarriesAnIdentityReachesTheInventory(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	for _, f := range fixtures {
		if f.Expect.Identity.Empty() {
			continue
		}
		t.Run(f.ID, func(t *testing.T) {
			const deviceIP, deviceMAC = "10.20.30.40", "08:00:27:de:ad:01"
			const clientIP, clientMAC = "10.20.30.41", "08:00:27:de:ad:02"

			cap := newCapture(t)
			cap.arp(deviceMAC, deviceIP)
			cap.arp(clientMAC, clientIP)
			if f.Transport == "udp" {
				cap.udp(deviceMAC, deviceIP, clientMAC, clientIP, f.Port, 55000, f.Response)
			} else {
				cap.exchange(clientMAC, clientIP, deviceMAC, deviceIP, 49152, f.Port, f)
			}

			a := assetAt(t, cap.ingest(t), deviceIP)
			// The inventory holds normalized identities, so the raw fields are
			// what compare directly against the fixture.
			if a.Identity.ProductRaw != f.Expect.Identity.ProductRaw {
				t.Errorf("product = %q, want %q", a.Identity.ProductRaw, f.Expect.Identity.ProductRaw)
			}
			if a.Identity.VendorRaw != f.Expect.Identity.VendorRaw {
				t.Errorf("vendor = %q, want %q", a.Identity.VendorRaw, f.Expect.Identity.VendorRaw)
			}
			if a.Identity.Serial != f.Expect.Identity.Serial {
				t.Errorf("serial = %q, want %q", a.Identity.Serial, f.Expect.Identity.Serial)
			}
		})
	}
}

// TestDeclinedFixturesProduceNoIndustrialAssetEither carries the negative
// fixtures through the whole passive path rather than only past the decoders.
//
// A decoder refusing a payload is one guarantee and the inventory not inventing
// something anyway is another. What these assets are allowed to end up with is a
// service and a name for it drawn from the port convention, which is a claim about
// what usually listens there and is fair. What they must not end up with is an
// identity, or an evidence entry attributing bytes to one of the protocols this
// package decodes, because that is the claim an engineer would act on.
func TestDeclinedFixturesProduceNoIndustrialAssetEither(t *testing.T) {
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}

	decoded := map[string]bool{
		protocol.NameModbus: true,
		protocol.NameENIP:   true,
		protocol.NameS7comm: true,
		protocol.NameBACnet: true,
	}

	for _, f := range fixtures {
		if f.Expect.Verdict != VerdictNotThisProtocol {
			continue
		}
		t.Run(f.ID, func(t *testing.T) {
			const deviceIP, deviceMAC = "10.20.30.50", "08:00:27:de:ad:03"
			const clientIP, clientMAC = "10.20.30.51", "08:00:27:de:ad:04"

			cap := newCapture(t)
			cap.arp(deviceMAC, deviceIP)
			cap.arp(clientMAC, clientIP)
			if f.Transport == "udp" {
				cap.udp(deviceMAC, deviceIP, clientMAC, clientIP, f.Port, 55000, f.Response)
			} else {
				cap.exchange(clientMAC, clientIP, deviceMAC, deviceIP, 49152, f.Port, f)
			}

			a := assetAt(t, cap.ingest(t), deviceIP)
			if !a.Identity.Empty() {
				t.Errorf("identity = %+v, want nothing", a.Identity)
			}
			for _, ev := range a.Evidence {
				if decoded[ev.Protocol] {
					t.Errorf("the evidence trail attributes these bytes to %s", ev.Protocol)
				}
			}
			for _, svc := range a.Services {
				if svc.Port == f.Port && decoded[svc.Protocol] {
					t.Errorf("the service on port %d was labelled %s", svc.Port, svc.Protocol)
				}
			}
		})
	}
}

func byID(t *testing.T) map[string]Fixture {
	t.Helper()
	fixtures, err := Load()
	if err != nil {
		t.Fatalf("load corpus: %v", err)
	}
	out := make(map[string]Fixture, len(fixtures))
	for _, f := range fixtures {
		out[f.ID] = f
	}
	return out
}

// capture assembles a pcap in memory.
type capture struct {
	t     *testing.T
	buf   bytes.Buffer
	w     *pcapgo.Writer
	clock time.Time
}

func newCapture(t *testing.T) *capture {
	t.Helper()
	c := &capture{t: t, clock: time.Date(2026, 5, 12, 8, 15, 0, 0, time.UTC)}
	c.w = pcapgo.NewWriter(&c.buf)
	if err := c.w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("write pcap header: %v", err)
	}
	return c
}

// exchange writes a complete TCP conversation: a handshake, the request, the
// reply and a close. The handshake matters because it is what tells the reader
// which end is listening without having to guess from port numbers.
func (c *capture) exchange(clientMAC, clientIP, serverMAC, serverIP string, clientPort, serverPort int, f Fixture) {
	c.t.Helper()
	c.tcp(clientMAC, clientIP, serverMAC, serverIP, clientPort, serverPort, tcpFlags{syn: true}, nil)
	c.tcp(serverMAC, serverIP, clientMAC, clientIP, serverPort, clientPort, tcpFlags{syn: true, ack: true}, nil)
	c.tcp(clientMAC, clientIP, serverMAC, serverIP, clientPort, serverPort, tcpFlags{ack: true}, nil)

	if f.Request != nil {
		c.tcp(clientMAC, clientIP, serverMAC, serverIP, clientPort, serverPort, tcpFlags{psh: true, ack: true}, f.Request.Bytes)
	}
	c.tcp(serverMAC, serverIP, clientMAC, clientIP, serverPort, clientPort, tcpFlags{psh: true, ack: true}, f.Response)
	c.tcp(clientMAC, clientIP, serverMAC, serverIP, clientPort, serverPort, tcpFlags{rst: true}, nil)
}

type tcpFlags struct{ syn, ack, rst, psh bool }

func (c *capture) tcp(srcMAC, srcIP, dstMAC, dstIP string, srcPort, dstPort int, flags tcpFlags, payload []byte) {
	c.t.Helper()
	ip := c.ipv4(srcIP, dstIP, layers.IPProtocolTCP)
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
		c.t.Fatalf("set checksum layer: %v", err)
	}
	c.write(c.ethernet(srcMAC, dstMAC), ip, tcp, gopacket.Payload(payload))
}

func (c *capture) udp(srcMAC, srcIP, dstMAC, dstIP string, srcPort, dstPort int, payload []byte) {
	c.t.Helper()
	ip := c.ipv4(srcIP, dstIP, layers.IPProtocolUDP)
	udp := &layers.UDP{SrcPort: layers.UDPPort(srcPort), DstPort: layers.UDPPort(dstPort)}
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		c.t.Fatalf("set checksum layer: %v", err)
	}
	c.write(c.ethernet(srcMAC, dstMAC), ip, udp, gopacket.Payload(payload))
}

func (c *capture) arp(mac, ip string) {
	c.t.Helper()
	hw := c.mac(mac)
	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   hw,
		SourceProtAddress: net.ParseIP(ip).To4(),
		DstHwAddress:      make([]byte, 6),
		DstProtAddress:    make([]byte, 4),
	}
	eth := &layers.Ethernet{
		SrcMAC:       hw,
		DstMAC:       c.mac("ff:ff:ff:ff:ff:ff"),
		EthernetType: layers.EthernetTypeARP,
	}
	c.write(eth, arp)
}

func (c *capture) ethernet(srcMAC, dstMAC string) *layers.Ethernet {
	return &layers.Ethernet{
		SrcMAC:       c.mac(srcMAC),
		DstMAC:       c.mac(dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
}

func (c *capture) ipv4(srcIP, dstIP string, proto layers.IPProtocol) *layers.IPv4 {
	return &layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: proto,
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
	}
}

func (c *capture) mac(raw string) net.HardwareAddr {
	c.t.Helper()
	hw, err := net.ParseMAC(raw)
	if err != nil {
		c.t.Fatalf("bad mac %q: %v", raw, err)
	}
	return hw
}

func (c *capture) write(parts ...gopacket.SerializableLayer) {
	c.t.Helper()
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, parts...); err != nil {
		c.t.Fatalf("serialize frame: %v", err)
	}
	frame := buf.Bytes()

	c.clock = c.clock.Add(5 * time.Millisecond)
	info := gopacket.CaptureInfo{Timestamp: c.clock, CaptureLength: len(frame), Length: len(frame)}
	if err := c.w.WritePacket(info, frame); err != nil {
		c.t.Fatalf("write packet: %v", err)
	}
}

func (c *capture) ingest(t *testing.T) *asset.Inventory {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corpus.pcap")
	if err := os.WriteFile(path, c.buf.Bytes(), 0o600); err != nil {
		t.Fatalf("write capture: %v", err)
	}

	result, err := ingest.Run(context.Background(), ingest.Options{PcapFiles: []string{path}})
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	for _, warning := range result.Stats.Warnings {
		t.Errorf("ingest warned: %s", warning)
	}
	return result.Inventory
}

func assetAt(t *testing.T, inv *asset.Inventory, ip string) *asset.Asset {
	t.Helper()
	for idx := range inv.Assets {
		if inv.Assets[idx].Addresses.IPv4 == ip {
			return &inv.Assets[idx]
		}
	}
	t.Fatalf("no asset at %s; the inventory holds %v", ip, addressesIn(inv))
	return nil
}

func addressesIn(inv *asset.Inventory) []string {
	out := make([]string, 0, len(inv.Assets))
	for idx := range inv.Assets {
		out = append(out, inv.Assets[idx].Addresses.Primary())
	}
	return out
}

func hasService(a *asset.Asset, port int, transport string) bool {
	for _, svc := range a.Services {
		if svc.Port == port && svc.Transport == transport {
			return true
		}
	}
	return false
}

func hasFlow(inv *asset.Inventory, src, dst string, port int) bool {
	for _, flow := range inv.Flows {
		if flow.SrcAddr == src && flow.DstAddr == dst && flow.DstPort == port {
			return true
		}
	}
	return false
}
