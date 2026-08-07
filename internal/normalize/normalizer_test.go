package normalize

import (
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

func testNormalizer(t *testing.T) *Normalizer {
	t.Helper()
	n, err := New()
	if err != nil {
		t.Fatalf("build normalizer: %v", err)
	}
	return n
}

func TestNormalizeSiemensDeviceFromCatalogNumber(t *testing.T) {
	n := testNormalizer(t)
	// This is what an S7-1200 reports over S7comm: a vendor string, an order
	// number and a firmware string, all unstructured.
	in := asset.Identity{
		VendorRaw:     "Siemens AG",
		ProductRaw:    "CPU 1214C DC/DC/DC",
		CatalogNumber: "6ES7 214-1AG40-0XB0",
		Firmware:      "V4.5.1",
	}

	report := n.Identity(in)
	got := report.Result

	if got.Vendor != "siemens" {
		t.Errorf("Vendor = %q, want siemens", got.Vendor)
	}
	if got.Family != "SIMATIC S7-1200" {
		t.Errorf("Family = %q, want SIMATIC S7-1200", got.Family)
	}
	if got.Model != "CPU 1214C" {
		t.Errorf("Model = %q, want CPU 1214C", got.Model)
	}
	if got.Firmware != "V4.5.1" {
		t.Errorf("Firmware = %q, want V4.5.1 preserved", got.Firmware)
	}
	// The raw observations must survive, because the evidence view shows the
	// operator what was actually seen before normalization interpreted it.
	if got.VendorRaw != "Siemens AG" {
		t.Errorf("VendorRaw = %q, want the original string", got.VendorRaw)
	}
	if got.ProductRaw != "CPU 1214C DC/DC/DC" {
		t.Errorf("ProductRaw = %q, want the original string", got.ProductRaw)
	}
	if report.Catalog == nil {
		t.Fatal("expected the catalog number to be parsed")
	}
	if len(report.Steps) == 0 {
		t.Error("normalization must record the steps it took")
	}
}

func TestNormalizeUsesSiemensComparator(t *testing.T) {
	n := testNormalizer(t)
	report := n.Identity(asset.Identity{VendorRaw: "Siemens", Firmware: "V4.5 SP2"})
	if got := n.Comparator(report.Result).Name(); got != "siemens" {
		t.Errorf("comparator = %q, want siemens", got)
	}
}

func TestNormalizeHitachiEnergyUsesABBComparator(t *testing.T) {
	n := testNormalizer(t)
	report := n.Identity(asset.Identity{
		VendorRaw:  "Hitachi Energy",
		ProductRaw: "FOXMAN-UN",
		Firmware:   "R16B_PC4",
	})
	if report.Result.Vendor != "hitachi-energy" {
		t.Fatalf("Vendor = %q", report.Result.Vendor)
	}
	if report.Result.Family != "FOXMAN-UN" {
		t.Errorf("Family = %q, want FOXMAN-UN", report.Result.Family)
	}
	cmp := n.Comparator(report.Result)
	if cmp.Name() != "abb" {
		t.Fatalf("comparator = %q, want abb", cmp.Name())
	}
	// End to end: the advisory range from the CISA document must now evaluate.
	eval := ParseConstraint("<R15A").Evaluate(report.Result.Firmware, cmp)
	if eval.Result != EvalNotAffected {
		t.Errorf("R16B_PC4 against <R15A = %q, want not_affected", eval.Result)
	}
}

func TestNormalizeInfersVendorFromCatalogNumberAlone(t *testing.T) {
	n := testNormalizer(t)
	// Some devices report an order code and nothing else identifying.
	report := n.Identity(asset.Identity{CatalogNumber: "1756-L71"})
	if report.Result.Vendor != "rockwell-automation" {
		t.Errorf("Vendor = %q, want rockwell-automation", report.Result.Vendor)
	}
	if report.Result.Family != "ControlLogix" {
		t.Errorf("Family = %q, want ControlLogix", report.Result.Family)
	}
}

func TestNormalizeInfersVendorFromProductAlone(t *testing.T) {
	n := testNormalizer(t)
	report := n.Identity(asset.Identity{ProductRaw: "MicroLogix 1400"})
	if report.Result.Vendor != "rockwell-automation" {
		t.Errorf("Vendor = %q, want rockwell-automation", report.Result.Vendor)
	}
}

func TestNormalizeNotesUnknownVendor(t *testing.T) {
	n := testNormalizer(t)
	report := n.Identity(asset.Identity{VendorRaw: "Acme Controls"})
	if report.Result.Vendor != "" {
		t.Errorf("Vendor = %q, want empty for an unknown vendor", report.Result.Vendor)
	}
	if len(report.Notes) == 0 {
		t.Error("an unknown vendor should be noted so the operator knows why matching is limited")
	}
	if !strings.Contains(strings.Join(report.Notes, " "), "Acme Controls") {
		t.Errorf("the note should name the unresolved vendor, got %v", report.Notes)
	}
}

func TestCleanVersionStripsLabelsOnly(t *testing.T) {
	cases := map[string]string{
		"V4.5.1":                "V4.5.1",
		"Firmware V4.5.1":       "V4.5.1",
		"firmware version 2.30": "2.30",
		"FW 1.2.3":              "1.2.3",
		"Rev. 20.011":           "20.011",
		"  V4.5 SP2  ":          "V4.5 SP2",
		"version: 3.1":          "3.1",
		"R16B_PC4":              "R16B_PC4",
		"":                      "",
	}
	for input, want := range cases {
		if got := CleanVersion(input); got != want {
			t.Errorf("CleanVersion(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizeInventoryUpdatesAssetsInPlace(t *testing.T) {
	n := testNormalizer(t)
	inv := asset.NewInventory("test")
	inv.Upsert(asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.0.0.5"},
		Identity: asset.Identity{
			VendorRaw:  "Siemens AG",
			ProductRaw: "CPU 1214C",
			Firmware:   "Firmware V4.5.1",
		},
	})
	// An asset with no identity at all must be left alone rather than given one.
	inv.Upsert(asset.Asset{Addresses: asset.Addresses{IPv4: "10.0.0.6"}})

	reports := n.Inventory(inv)
	if len(reports) != 1 {
		t.Fatalf("expected one report, got %d", len(reports))
	}

	first, _ := inv.Get(asset.NewID(asset.Addresses{IPv4: "10.0.0.5"}))
	if first.Identity.Vendor != "siemens" {
		t.Errorf("Vendor = %q, want siemens", first.Identity.Vendor)
	}
	if first.Identity.Firmware != "V4.5.1" {
		t.Errorf("Firmware = %q, want the label stripped", first.Identity.Firmware)
	}

	second, _ := inv.Get(asset.NewID(asset.Addresses{IPv4: "10.0.0.6"}))
	if !second.Identity.Empty() {
		t.Error("an asset with no identity must not be given one")
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	n := testNormalizer(t)
	in := asset.Identity{
		VendorRaw:     "Siemens AG",
		ProductRaw:    "CPU 1214C",
		CatalogNumber: "6ES7 214-1AG40-0XB0",
		Firmware:      "Firmware V4.5.1",
	}
	once := n.Identity(in).Result
	twice := n.Identity(once).Result
	if once != twice {
		t.Errorf("normalizing twice changed the result:\nfirst:  %+v\nsecond: %+v", once, twice)
	}
}
