package asset

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNewIDIsStableAndAddressSensitive(t *testing.T) {
	a := Addresses{IPv4: "10.0.0.5", MAC: "00:1b:1b:aa:bb:cc"}
	if NewID(a) != NewID(a) {
		t.Fatal("NewID must be deterministic across calls")
	}
	b := Addresses{IPv4: "10.0.0.6", MAC: "00:1b:1b:aa:bb:cc"}
	if NewID(a) == NewID(b) {
		t.Fatal("different addresses must not collide")
	}
	// Case should not create a second identity for the same device.
	upper := Addresses{IPv4: "10.0.0.5", MAC: "00:1B:1B:AA:BB:CC"}
	if NewID(a) != NewID(upper) {
		t.Fatal("MAC case must not change the asset id")
	}
}

func TestIdentityMergePrefersExistingValues(t *testing.T) {
	base := Identity{Vendor: "siemens", Firmware: "V4.5.1"}
	base.Merge(Identity{Vendor: "rockwell", Product: "S7-1200", Serial: "S-123"})

	if base.Vendor != "siemens" {
		t.Errorf("merge overwrote an existing vendor: got %q", base.Vendor)
	}
	if base.Product != "S7-1200" {
		t.Errorf("merge did not fill an empty product: got %q", base.Product)
	}
	if base.Serial != "S-123" {
		t.Errorf("merge did not fill an empty serial: got %q", base.Serial)
	}
}

func TestIdentityLabelFallsBackThroughRawValues(t *testing.T) {
	cases := []struct {
		name string
		id   Identity
		want string
	}{
		{"empty", Identity{}, "unknown"},
		{"raw only", Identity{VendorRaw: "Siemens AG"}, "Siemens AG"},
		{"normalized wins", Identity{Vendor: "siemens", VendorRaw: "Siemens AG"}, "siemens"},
		{"with firmware", Identity{Vendor: "siemens", Product: "S7-1200", Firmware: "4.5.1"}, "siemens S7-1200 4.5.1"},
		{"family fallback", Identity{Vendor: "abb", Family: "foxman-un"}, "abb foxman-un"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.Label(); got != tc.want {
				t.Errorf("Label() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClassifyPrefersStrongestPortSignal(t *testing.T) {
	// A PLC that also exposes a web server must be classified from the control
	// protocol, not from the far weaker HTTP signal.
	a := &Asset{ID: "x"}
	a.AddService(Service{Port: 80, Transport: "tcp"})
	a.AddService(Service{Port: 502, Transport: "tcp"})

	inf := Classify(a)
	if inf.Role != RolePLC {
		t.Errorf("Role = %q, want %q", inf.Role, RolePLC)
	}
	if inf.Purdue != PurdueL1 {
		t.Errorf("Purdue = %q, want %q", inf.Purdue, PurdueL1)
	}
	if !strings.Contains(inf.Reason, "502") {
		t.Errorf("Reason should name the deciding port, got %q", inf.Reason)
	}
}

func TestClassifyDoesNotOverwriteExplicitValues(t *testing.T) {
	a := &Asset{ID: "x", Role: RoleHistorian, Purdue: PurdueL3}
	a.AddService(Service{Port: 502, Transport: "tcp"})

	Classify(a).Apply(a)
	if a.Role != RoleHistorian {
		t.Errorf("inference overwrote an explicit role: %q", a.Role)
	}
	if a.Purdue != PurdueL3 {
		t.Errorf("inference overwrote an explicit level: %q", a.Purdue)
	}
}

// TestClassifyLetsTheObservedProtocolBeatThePortNumber covers the case where the
// two sources of evidence disagree.
//
// Port 502 is a convention and a decoded HTTP banner is a fact. Filing this
// device as a PLC would place it in the inventory at Purdue L1, put it on the
// topology beside the controllers, and hand it to the matcher as equipment whose
// firmware advisories are worth checking. All three would be wrong, and the
// operator would have no way to see why from the record.
func TestClassifyLetsTheObservedProtocolBeatThePortNumber(t *testing.T) {
	a := &Asset{ID: "x"}
	a.AddService(Service{Port: 502, Transport: "tcp", Protocol: "http"})

	inf := Classify(a)
	if inf.Role == RolePLC {
		t.Error("an HTTP server on the Modbus port was classified as a PLC")
	}
	if inf.Purdue == PurdueL1 {
		t.Errorf("Purdue = %q: an HTTP server does not belong at the control level", inf.Purdue)
	}
}

// TestClassifyStillUsesThePortWhenNothingWasDecoded keeps the rule above from
// being read as distrust of port numbers.
//
// Most of a passive inventory is ports and nothing else: a device that answered
// nobody during the capture is still a device, and the port it listens on is the
// only evidence there is about it.
func TestClassifyStillUsesThePortWhenNothingWasDecoded(t *testing.T) {
	a := &Asset{ID: "x"}
	a.AddService(Service{Port: 502, Transport: "tcp"})

	if inf := Classify(a); inf.Role != RolePLC {
		t.Errorf("Role = %q, want %q from the port alone", inf.Role, RolePLC)
	}
}

func TestClassifyWithNoKnownPorts(t *testing.T) {
	a := &Asset{ID: "x"}
	a.AddService(Service{Port: 12345, Transport: "tcp"})

	inf := Classify(a)
	if inf.Role != RoleUnknown || inf.Purdue != PurdueUnknown {
		t.Errorf("unrecognised ports must not produce a classification, got %q/%q", inf.Role, inf.Purdue)
	}
}

func TestPurdueRankOrdersDMZBetweenThreeAndFour(t *testing.T) {
	if !(PurdueL3.Rank() < PurdueDMZ.Rank() && PurdueDMZ.Rank() < PurdueL4.Rank()) {
		t.Fatal("L3.5 must sort between L3 and L4")
	}
	if PurdueUnknown.Known() {
		t.Fatal("the empty level must not report as known")
	}
}

func TestAddServiceMergesSamePort(t *testing.T) {
	early := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	late := early.Add(time.Hour)

	a := &Asset{ID: "x"}
	a.AddService(Service{Port: 502, Transport: "tcp", FirstSeen: late, LastSeen: late})
	a.AddService(Service{Port: 502, Transport: "tcp", Protocol: "modbus", FirstSeen: early, LastSeen: early})

	if len(a.Services) != 1 {
		t.Fatalf("expected the services to merge, got %d entries", len(a.Services))
	}
	svc := a.Services[0]
	if svc.Protocol != "modbus" {
		t.Errorf("merge lost the protocol name: %q", svc.Protocol)
	}
	if !svc.FirstSeen.Equal(early) {
		t.Errorf("FirstSeen = %v, want the earlier time %v", svc.FirstSeen, early)
	}
	if !svc.LastSeen.Equal(late) {
		t.Errorf("LastSeen = %v, want the later time %v", svc.LastSeen, late)
	}
}

func TestAddServiceKeepsDifferentTransportsApart(t *testing.T) {
	a := &Asset{ID: "x"}
	a.AddService(Service{Port: 47808, Transport: "udp"})
	a.AddService(Service{Port: 47808, Transport: "tcp"})
	if len(a.Services) != 2 {
		t.Fatalf("tcp and udp on the same port are distinct services, got %d", len(a.Services))
	}
}

func TestSourceKindPassive(t *testing.T) {
	if SourceProbe.Passive() {
		t.Error("the probe source is the only active one and must report not passive")
	}
	for _, src := range []SourceKind{SourcePcap, SourceZeek, SourceNmap, SourceManual} {
		if !src.Passive() {
			t.Errorf("%q must report as passive", src)
		}
	}
}

func TestHexBytesRoundTripsAsHexNotBase64(t *testing.T) {
	original := HexBytes{0x00, 0x01, 0x2b, 0xff}
	encoded, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(encoded) != `"00012bff"` {
		t.Fatalf("encoded = %s, want lowercase hex", encoded)
	}

	var decoded HexBytes
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatalf("round trip changed the bytes: %x", decoded)
	}
}

func TestHexBytesUnmarshalRejectsBadInput(t *testing.T) {
	var h HexBytes
	if err := json.Unmarshal([]byte(`"zz"`), &h); err == nil {
		t.Fatal("expected an error for non hex input")
	}
	if err := json.Unmarshal([]byte(`123`), &h); err == nil {
		t.Fatal("expected an error for a non string value")
	}
}

func TestHexDumpShowsOffsetsAndPrintableColumn(t *testing.T) {
	dump := HexBytes("otscout probe").HexDump()
	if !strings.Contains(dump, "0000") {
		t.Error("hex dump must start with an offset")
	}
	if !strings.Contains(dump, "|otscout probe|") {
		t.Errorf("hex dump must include the printable column, got:\n%s", dump)
	}
}

func TestInventoryUpsertMergesByID(t *testing.T) {
	inv := NewInventory("test")
	addr := Addresses{IPv4: "10.0.0.5"}

	first := Asset{ID: NewID(addr), Addresses: addr, Identity: Identity{Vendor: "siemens"}}
	first.AddService(Service{Port: 102, Transport: "tcp"})
	inv.Upsert(first)

	second := Asset{ID: NewID(addr), Addresses: addr, Identity: Identity{Firmware: "V4.5.1"}}
	second.AddService(Service{Port: 80, Transport: "tcp"})
	inv.Upsert(second)

	if len(inv.Assets) != 1 {
		t.Fatalf("expected one asset after upsert, got %d", len(inv.Assets))
	}
	got := inv.Assets[0]
	if got.Identity.Vendor != "siemens" || got.Identity.Firmware != "V4.5.1" {
		t.Errorf("identity did not merge: %+v", got.Identity)
	}
	if len(got.Services) != 2 {
		t.Errorf("expected both services, got %d", len(got.Services))
	}
}

func TestInventoryByAddressMatchesOnPartialAddress(t *testing.T) {
	inv := NewInventory("test")
	inv.Upsert(Asset{Addresses: Addresses{IPv4: "10.0.0.5", MAC: "00:11:22:33:44:55"}})

	// A second source knows only the MAC. It must land on the same asset rather
	// than creating a duplicate.
	got := inv.ByAddress(Addresses{MAC: "00:11:22:33:44:55"})
	if got.Addresses.IPv4 != "10.0.0.5" {
		t.Fatalf("expected to match the existing asset, got %+v", got.Addresses)
	}
	if len(inv.Assets) != 1 {
		t.Fatalf("expected no duplicate asset, got %d", len(inv.Assets))
	}
}

func TestInventoryFinalizeSortsAddressesNumerically(t *testing.T) {
	inv := NewInventory("test")
	for _, ip := range []string{"10.0.0.10", "10.0.0.2", "10.0.0.9"} {
		inv.Upsert(Asset{Addresses: Addresses{IPv4: ip}})
	}
	inv.Finalize()

	want := []string{"10.0.0.2", "10.0.0.9", "10.0.0.10"}
	for idx, expected := range want {
		if got := inv.Assets[idx].Addresses.IPv4; got != expected {
			t.Errorf("position %d = %s, want %s", idx, got, expected)
		}
	}
}

func TestInventoryStats(t *testing.T) {
	inv := NewInventory("test")
	plc := Asset{Addresses: Addresses{IPv4: "10.0.0.5"}, Identity: Identity{Vendor: "siemens"}}
	plc.AddService(Service{Port: 102, Transport: "tcp", Protocol: "s7comm"})
	inv.Upsert(plc)
	inv.Upsert(Asset{Addresses: Addresses{IPv4: "10.0.0.6"}})
	inv.Finalize()

	st := inv.Stats()
	if st.Assets != 2 {
		t.Errorf("Assets = %d, want 2", st.Assets)
	}
	if st.Identified != 1 {
		t.Errorf("Identified = %d, want 1", st.Identified)
	}
	if st.ByProtocol["s7comm"] != 1 {
		t.Errorf("ByProtocol[s7comm] = %d, want 1", st.ByProtocol["s7comm"])
	}
}
