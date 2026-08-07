package normalize

import "testing"

func testProductTable(t *testing.T) *ProductTable {
	t.Helper()
	table, err := DefaultProductTable()
	if err != nil {
		t.Fatalf("load embedded product table: %v", err)
	}
	return table
}

func TestEmbeddedProductTableIsValid(t *testing.T) {
	table := testProductTable(t)
	if len(table.Records()) < 40 {
		t.Errorf("expected a substantial family table, got %d entries", len(table.Records()))
	}

	// Every family must name a vendor that exists in the vendor table, otherwise
	// the vendor scoped lookup can never succeed for it.
	vendors := testVendorTable(t)
	for _, family := range table.Records() {
		if _, ok := vendors.ByID(family.Vendor); !ok {
			t.Errorf("family %q names vendor %q, which is not in vendors.yaml", family.ID, family.Vendor)
		}
	}
}

func TestLookupProductExactFamilyNames(t *testing.T) {
	table := testProductTable(t)
	cases := []struct {
		vendor string
		input  string
		want   string
	}{
		{"siemens", "SIMATIC S7-1200", "SIMATIC S7-1200"},
		{"siemens", "s7-1200", "SIMATIC S7-1200"},
		{"siemens", "S7 1200", "SIMATIC S7-1200"},
		{"siemens", "s71200", "SIMATIC S7-1200"},
		{"schneider-electric", "Modicon M580", "Modicon M580"},
		{"schneider-electric", "m580", "Modicon M580"},
		{"hitachi-energy", "FOXMAN-UN", "FOXMAN-UN"},
		{"rockwell-automation", "ControlLogix 5580", "ControlLogix 5580"},
		{"mitsubishi-electric", "MELSEC iQ-R", "MELSEC iQ-R"},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			match, ok := table.LookupProduct(tc.vendor, tc.input)
			if !ok {
				t.Fatalf("LookupProduct(%q, %q) found nothing", tc.vendor, tc.input)
			}
			if match.Family.Display != tc.want {
				t.Errorf("Family = %q, want %q", match.Family.Display, tc.want)
			}
		})
	}
}

func TestLookupProductResolvesModelToFamily(t *testing.T) {
	table := testProductTable(t)
	// A PLC reports its model, while the advisory names the family. This is the
	// join that makes the two comparable.
	cases := []struct {
		vendor string
		model  string
		family string
	}{
		{"siemens", "CPU 1214C", "SIMATIC S7-1200"},
		{"siemens", "cpu1516", "SIMATIC S7-1500"},
		{"siemens", "CPU 315", "SIMATIC S7-300"},
		{"mitsubishi-electric", "R08CPU", "MELSEC iQ-R"},
		{"mitsubishi-electric", "FX5U", "MELSEC iQ-F"},
		{"ruggedcom", "RSG2100", "RUGGEDCOM ROS"},
	}
	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			match, ok := table.LookupProduct(tc.vendor, tc.model)
			if !ok {
				t.Fatalf("LookupProduct(%q, %q) found nothing", tc.vendor, tc.model)
			}
			if match.Family.Display != tc.family {
				t.Errorf("Family = %q, want %q", match.Family.Display, tc.family)
			}
			if !match.ViaModel {
				t.Error("ViaModel should be true when a model designation matched")
			}
		})
	}
}

func TestLookupProductFindsFamilyInsideBanner(t *testing.T) {
	table := testProductTable(t)
	match, ok := table.LookupProduct("siemens", "SIMATIC S7-1200 CPU 1214C DC/DC/DC")
	if !ok {
		t.Fatal("expected to find the family inside a full banner")
	}
	if match.Family.Display != "SIMATIC S7-1200" {
		t.Errorf("Family = %q, want SIMATIC S7-1200", match.Family.Display)
	}
	if match.Method != MatchTokenSubset {
		t.Errorf("Method = %q, want %q", match.Method, MatchTokenSubset)
	}
}

func TestLookupProductIsVendorScoped(t *testing.T) {
	table := testProductTable(t)
	// "premium" is a Schneider product line. Asking for it under another vendor
	// must not return Schneider's family, because that would attach Schneider
	// advisories to a different company's device.
	if match, ok := table.LookupProduct("siemens", "Premium"); ok {
		t.Errorf("Premium resolved under siemens to %q", match.Family.Display)
	}
	if _, ok := table.LookupProduct("schneider-electric", "Premium"); !ok {
		t.Error("Premium should resolve under schneider-electric")
	}
}

func TestLookupProductWithoutVendorRejectsAmbiguity(t *testing.T) {
	// Two vendors sharing an alias must not be resolved by guessing when the
	// caller has no vendor to scope by.
	data := []byte(`
version: 1
families:
  - id: alpha-controller
    vendor: siemens
    display: Alpha Controller
    aliases: [shared line]
  - id: beta-controller
    vendor: abb
    display: Beta Controller
    aliases: [shared line]
`)
	table, err := ParseProductTable(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if match, ok := table.LookupProduct("", "shared line"); ok {
		t.Errorf("an ambiguous alias resolved to %q", match.Family.Display)
	}
	if match, ok := table.LookupProduct("abb", "shared line"); !ok || match.Family.ID != "beta-controller" {
		t.Error("scoping by vendor should disambiguate")
	}
}

func TestLookupProductUnknownInput(t *testing.T) {
	table := testProductTable(t)
	for _, input := range []string{"", "   ", "a product nobody makes"} {
		if match, ok := table.LookupProduct("siemens", input); ok {
			t.Errorf("LookupProduct(%q) unexpectedly matched %q", input, match.Family.Display)
		}
	}
}

func TestProductKeyNormalization(t *testing.T) {
	cases := map[string]string{
		"SIMATIC S7-1200":  "simatic s7 1200",
		"S7_1200":          "s7 1200",
		"CPU 1214C":        "cpu 1214c",
		"LOGO!":            "logo!",
		"Ewon Cosy+":       "ewon cosy+",
		"  MELSEC   iQ-R ": "melsec iq r",
	}
	for input, want := range cases {
		if got := ProductKey(input); got != want {
			t.Errorf("ProductKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseProductTableRejectsDuplicateID(t *testing.T) {
	data := []byte(`
version: 1
families:
  - id: dup
    vendor: siemens
    display: One
  - id: dup
    vendor: siemens
    display: Two
`)
	if _, err := ParseProductTable(data); err == nil {
		t.Fatal("expected an error for a duplicate family id")
	}
}

func TestParseProductTableRequiresVendorAndDisplay(t *testing.T) {
	missingVendor := []byte("version: 1\nfamilies:\n  - id: x\n    display: X\n")
	if _, err := ParseProductTable(missingVendor); err == nil {
		t.Error("expected an error when a family has no vendor")
	}
	missingDisplay := []byte("version: 1\nfamilies:\n  - id: x\n    vendor: siemens\n")
	if _, err := ParseProductTable(missingDisplay); err == nil {
		t.Error("expected an error when a family has no display name")
	}
}
