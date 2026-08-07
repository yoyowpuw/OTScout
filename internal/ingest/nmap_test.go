package ingest

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// sampleNmapXML is a scan of one Siemens PLC, with a host that did not answer and
// a port that was closed, so the reader has to distinguish all three.
const sampleNmapXML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --script s7-info -oX audit.xml 10.20.0.0/24" start="1772000000">
  <host starttime="1772000010" endtime="1772000020">
    <status state="up" reason="arp-response"/>
    <address addr="10.20.0.12" addrtype="ipv4"/>
    <address addr="00:1B:1B:AA:BB:CC" addrtype="mac" vendor="Siemens Numerical Control Ltd."/>
    <hostnames><hostname name="plc-line2" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="102">
        <state state="open" reason="syn-ack"/>
        <service name="iso-tsap" product="Siemens S7 PLC" method="probed" conf="10"/>
        <script id="s7-info" output="Module: 6ES7 315-2EH14-0AB0">
          <elem key="Module">6ES7 315-2EH14-0AB0</elem>
          <elem key="Basic Hardware">6ES7 315-2EH14-0AB0</elem>
          <elem key="Version">3.2.6</elem>
          <elem key="System Name">SIMATIC 300(1)</elem>
          <elem key="Module Type">CPU 315-2 PN/DP</elem>
          <elem key="Serial Number">S C-C2UR28922014</elem>
        </script>
      </port>
      <port protocol="tcp" portid="80">
        <state state="closed" reason="reset"/>
        <service name="http"/>
      </port>
    </ports>
    <os><osmatch name="Siemens Simatic 300 PLC" accuracy="95"/></os>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.20.0.99" addrtype="ipv4"/>
  </host>
</nmaprun>
`

func writeNmap(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.xml")
	writeFile(t, path, contents)
	return path
}

func TestIngestNmapS7InfoScript(t *testing.T) {
	inv := runIngest(t, Options{NmapFiles: []string{writeNmap(t, sampleNmapXML)}}).Inventory
	device := findAsset(t, inv, "10.20.0.12")

	if device.Addresses.Hostname != "plc-line2" {
		t.Errorf("Hostname = %q, want plc-line2", device.Addresses.Hostname)
	}
	if device.Addresses.MAC != "00:1b:1b:aa:bb:cc" {
		t.Errorf("MAC = %q, want the address lowercased with colons", device.Addresses.MAC)
	}

	// The order code is the part that makes the asset matchable, and the
	// normalizer should have resolved the vendor and family from it.
	if !strings.HasPrefix(device.Identity.CatalogNumber, "6ES7") {
		t.Errorf("CatalogNumber = %q, want the MLFB from the Module key", device.Identity.CatalogNumber)
	}
	if device.Identity.Vendor != "siemens" {
		t.Errorf("Vendor = %q, want siemens", device.Identity.Vendor)
	}
	if device.Identity.Firmware != "3.2.6" {
		t.Errorf("Firmware = %q, want 3.2.6", device.Identity.Firmware)
	}
	if device.Identity.Serial != "S C-C2UR28922014" {
		t.Errorf("Serial = %q", device.Identity.Serial)
	}
	// The basic hardware key is a second order code, not a revision, so it must
	// not have been written to the hardware revision field.
	if device.Identity.HardwareRev != "" {
		t.Errorf("HardwareRev = %q, want it left empty", device.Identity.HardwareRev)
	}

	if svc := serviceOn(device, 102, "tcp"); svc == nil {
		t.Errorf("no S7 service recorded, services = %+v", device.Services)
	} else if svc.Banner != "Siemens S7 PLC" {
		t.Errorf("banner = %q, want the Nmap service product", svc.Banner)
	}
}

func TestIngestNmapSkipsHostsThatDidNotAnswer(t *testing.T) {
	inv := runIngest(t, Options{NmapFiles: []string{writeNmap(t, sampleNmapXML)}}).Inventory
	if lookupAsset(inv, "10.20.0.99") != nil {
		t.Error("a host Nmap reported as down must not become an asset")
	}
	if len(inv.Assets) != 1 {
		t.Errorf("inventory holds %d assets, want 1", len(inv.Assets))
	}
}

func TestIngestNmapSkipsClosedPorts(t *testing.T) {
	device := findAsset(t, runIngest(t, Options{NmapFiles: []string{writeNmap(t, sampleNmapXML)}}).Inventory, "10.20.0.12")
	if svc := serviceOn(device, 80, "tcp"); svc != nil {
		t.Errorf("a closed port was recorded as a service: %+v", svc)
	}
}

func TestIngestNmapKeepsTheOUIVendorOutOfTheIdentity(t *testing.T) {
	// The vendor behind a hardware address is whoever made the network interface.
	// On an industrial PC that is frequently not the vendor of the control
	// software, so it is recorded as context and never as the asset vendor.
	xml := `<?xml version="1.0"?>
<nmaprun start="1772000000">
  <host><status state="up"/>
    <address addr="10.20.0.60" addrtype="ipv4"/>
    <address addr="00:0C:29:11:22:33" addrtype="mac" vendor="VMware, Inc."/>
    <ports><port protocol="tcp" portid="102"><state state="open"/><service name="iso-tsap"/></port></ports>
  </host>
</nmaprun>`

	device := findAsset(t, runIngest(t, Options{NmapFiles: []string{writeNmap(t, xml)}}).Inventory, "10.20.0.60")
	if device.Identity.Vendor != "" || device.Identity.VendorRaw != "" {
		t.Errorf("identity vendor was taken from the OUI: %+v", device.Identity)
	}

	found := false
	for _, ev := range device.Evidence {
		if ev.Fields["mac_oui_vendor"] == "VMware, Inc." {
			found = true
		}
	}
	if !found {
		t.Errorf("the OUI vendor should be kept as evidence, evidence = %+v", device.Evidence)
	}
}

func TestIngestNmapEtherNetIPScript(t *testing.T) {
	xml := `<?xml version="1.0"?>
<nmaprun start="1772000000">
  <host><status state="up"/>
    <address addr="10.20.0.21" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="44818"><state state="open"/>
      <service name="EtherNetIP-2"/>
      <script id="enip-info" output="Vendor: Rockwell Automation">
        <elem key="Vendor">Rockwell Automation/Allen-Bradley</elem>
        <elem key="Product Name">1756-L71/B LOGIX5571</elem>
        <elem key="Revision">20.11</elem>
        <elem key="Serial Number">0x12345678</elem>
        <elem key="Device Type">Programmable Logic Controller</elem>
      </script>
    </port></ports>
  </host>
</nmaprun>`

	device := findAsset(t, runIngest(t, Options{NmapFiles: []string{writeNmap(t, xml)}}).Inventory, "10.20.0.21")
	if device.Identity.Vendor != "rockwell-automation" {
		t.Errorf("Vendor = %q, want rockwell-automation", device.Identity.Vendor)
	}
	if device.Identity.Firmware != "20.11" {
		t.Errorf("Firmware = %q, want 20.11", device.Identity.Firmware)
	}
	// The product name carries the order code, and the order code is what narrows
	// the device to a family an advisory is written against.
	if device.Identity.CatalogNumber == "" {
		t.Errorf("no order code was recovered from the product name, identity = %+v", device.Identity)
	}
	if device.Identity.Family == "" {
		t.Errorf("the order code should have resolved a family, identity = %+v", device.Identity)
	}
	if device.Role != asset.RolePLC {
		t.Errorf("Role = %q, want plc from port 44818", device.Role)
	}
}

func TestIngestNmapReadsNestedScriptTables(t *testing.T) {
	// Some scripts nest their output one or two tables deep. The reader collects
	// keys at any depth so that a schema change in a script does not silently drop
	// every field.
	xml := `<?xml version="1.0"?>
<nmaprun start="1772000000">
  <host><status state="up"/>
    <address addr="10.30.0.33" addrtype="ipv4"/>
    <ports><port protocol="udp" portid="47808"><state state="open"/>
      <script id="bacnet-info" output="...">
        <table key="Device">
          <elem key="Vendor Name">Reliable Controls Corporation</elem>
          <table key="Software">
            <elem key="Firmware">2.7</elem>
            <elem key="Model Name">MACH-ProWebSys</elem>
          </table>
        </table>
      </script>
    </port></ports>
  </host>
</nmaprun>`

	device := findAsset(t, runIngest(t, Options{NmapFiles: []string{writeNmap(t, xml)}}).Inventory, "10.30.0.33")
	if device.Identity.VendorRaw != "Reliable Controls Corporation" {
		t.Errorf("VendorRaw = %q, want the value from the outer table", device.Identity.VendorRaw)
	}
	if device.Identity.Firmware != "2.7" {
		t.Errorf("Firmware = %q, want 2.7 from the nested table", device.Identity.Firmware)
	}
	if device.Identity.ProductRaw != "MACH-ProWebSys" {
		t.Errorf("ProductRaw = %q, want MACH-ProWebSys", device.Identity.ProductRaw)
	}
}

func TestIngestNmapIgnoresScriptsItDoesNotKnow(t *testing.T) {
	// An unrecognised script contributes nothing rather than having its keys
	// guessed at, because a wrong identity is worse than a missing one.
	xml := `<?xml version="1.0"?>
<nmaprun start="1772000000">
  <host><status state="up"/>
    <address addr="10.20.0.70" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="502"><state state="open"/>
      <script id="some-future-script" output="...">
        <elem key="Vendor">Definitely Not This Vendor</elem>
        <elem key="Version">9.9.9</elem>
      </script>
    </port></ports>
  </host>
</nmaprun>`

	device := findAsset(t, runIngest(t, Options{NmapFiles: []string{writeNmap(t, xml)}}).Inventory, "10.20.0.70")
	if !device.Identity.Empty() {
		t.Errorf("an unknown script produced an identity: %+v", device.Identity)
	}
}

func TestIngestNmapReportsAMalformedFileWithoutFailingTheRun(t *testing.T) {
	path := writeNmap(t, "<nmaprun><host><status state=\"up\"")
	result, err := Run(t.Context(), Options{NmapFiles: []string{path}})
	if err != nil {
		t.Fatalf("a malformed file should be a warning, not a failure: %v", err)
	}
	if len(result.Stats.Warnings) == 0 {
		t.Error("the malformed file should have produced a warning")
	}
}

func TestIngestNmapIsIdempotent(t *testing.T) {
	// Reading the same file twice must not double the services or produce a
	// different identity, because operators re-run ingest as scans are refreshed.
	path := writeNmap(t, sampleNmapXML)
	first := runIngest(t, Options{NmapFiles: []string{path}}).Inventory
	second := runIngest(t, Options{NmapFiles: []string{path, path}}).Inventory

	if len(first.Assets) != len(second.Assets) {
		t.Fatalf("asset count changed from %d to %d", len(first.Assets), len(second.Assets))
	}
	a, b := findAsset(t, first, "10.20.0.12"), findAsset(t, second, "10.20.0.12")
	if len(a.Services) != len(b.Services) {
		t.Errorf("service count changed from %d to %d", len(a.Services), len(b.Services))
	}
	if a.Identity != b.Identity {
		t.Errorf("identity changed:\n first = %+v\nsecond = %+v", a.Identity, b.Identity)
	}
}
