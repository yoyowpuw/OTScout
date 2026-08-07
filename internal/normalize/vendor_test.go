package normalize

import "testing"

func testVendorTable(t *testing.T) *VendorTable {
	t.Helper()
	table, err := DefaultVendorTable()
	if err != nil {
		t.Fatalf("load embedded vendor table: %v", err)
	}
	return table
}

func TestEmbeddedVendorTableIsValid(t *testing.T) {
	// ParseVendorTable rejects duplicate ids and ambiguous aliases, so simply
	// loading the shipped table is a meaningful check on the data file.
	table := testVendorTable(t)
	if len(table.Records()) < 50 {
		t.Errorf("expected a substantial vendor table, got %d entries", len(table.Records()))
	}
}

func TestLookupVendorExactAndAlias(t *testing.T) {
	table := testVendorTable(t)
	cases := []struct {
		input  string
		wantID string
		method MatchMethod
	}{
		{"Siemens", "siemens", MatchExact},
		{"siemens", "siemens", MatchExact},
		{"SIEMENS AG", "siemens", MatchExact},
		{"Allen-Bradley", "rockwell-automation", MatchExact},
		{"Allen Bradley", "rockwell-automation", MatchExact},
		{"Rockwell Automation", "rockwell-automation", MatchExact},
		{"Hitachi Energy", "hitachi-energy", MatchExact},
		{"Hitachi ABB Power Grids", "hitachi-energy", MatchExact},
		{"Schneider Electric", "schneider-electric", MatchExact},
		{"Modicon", "schneider-electric", MatchExact},
		{"Pepperl+Fuchs", "pepperl-fuchs", MatchExact},
		{"B&R", "b-and-r", MatchExact},
		{"Wonderware", "aveva", MatchExact},
		{"KEPServerEX", "ptc", MatchExact},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			match, ok := table.LookupVendor(tc.input)
			if !ok {
				t.Fatalf("LookupVendor(%q) found nothing", tc.input)
			}
			if match.ID != tc.wantID {
				t.Errorf("ID = %q, want %q", match.ID, tc.wantID)
			}
			if match.Method != tc.method {
				t.Errorf("Method = %q, want %q", match.Method, tc.method)
			}
		})
	}
}

func TestLookupVendorTrimsCorporateSuffixes(t *testing.T) {
	table := testVendorTable(t)
	cases := []string{
		"Moxa Inc.",
		"Advantech Co., Ltd.",
		"Phoenix Contact GmbH & Co. KG",
		"Beckhoff Automation GmbH",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			match, ok := table.LookupVendor(input)
			if !ok {
				t.Fatalf("LookupVendor(%q) found nothing", input)
			}
			if match.ID == "" {
				t.Error("expected a canonical id")
			}
			if !match.Exact() {
				t.Errorf("suffix trimming should count as an exact resolution, got %q", match.Method)
			}
		})
	}
}

func TestLookupVendorFindsVendorInsideBanner(t *testing.T) {
	table := testVendorTable(t)
	// Device banners carry the vendor alongside a product name.
	match, ok := table.LookupVendor("SIMATIC S7-1200 by Siemens")
	if !ok {
		t.Fatal("expected to find the vendor inside the banner")
	}
	if match.ID != "siemens" {
		t.Errorf("ID = %q, want siemens", match.ID)
	}
	if match.Method != MatchTokenSubset {
		t.Errorf("Method = %q, want %q", match.Method, MatchTokenSubset)
	}
	if match.Exact() {
		t.Error("a token subset match must not be reported as exact")
	}
}

func TestLookupVendorPrefersLongestAlias(t *testing.T) {
	table := testVendorTable(t)
	// "Delta" alone belongs to Delta Electronics, but "Delta Controls" is a
	// different company. The longer alias has to win or findings land on the
	// wrong vendor.
	match, ok := table.LookupVendor("Delta Controls Inc.")
	if !ok {
		t.Fatal("expected a match")
	}
	if match.ID != "delta-controls" {
		t.Errorf("ID = %q, want delta-controls", match.ID)
	}

	other, ok := table.LookupVendor("Delta Electronics")
	if !ok {
		t.Fatal("expected a match")
	}
	if other.ID != "delta-electronics" {
		t.Errorf("ID = %q, want delta-electronics", other.ID)
	}
}

func TestLookupVendorKeepsSiemensAndSiemensEnergyApart(t *testing.T) {
	table := testVendorTable(t)
	// These are separate companies publishing separate advisories. Collapsing
	// them would attach one company's advisories to the other's devices.
	first, _ := table.LookupVendor("Siemens")
	second, _ := table.LookupVendor("Siemens Energy")
	if first.ID == second.ID {
		t.Fatalf("Siemens and Siemens Energy both resolved to %q", first.ID)
	}
}

func TestLookupVendorRejectsUnknownAndShortNoise(t *testing.T) {
	table := testVendorTable(t)
	for _, input := range []string{"", "   ", "Acme Widgets", "xyz"} {
		if match, ok := table.LookupVendor(input); ok {
			t.Errorf("LookupVendor(%q) unexpectedly matched %q", input, match.ID)
		}
	}
}

func TestLookupVendorDoesNotMatchInsideWords(t *testing.T) {
	table := testVendorTable(t)
	// "abb" must not be found inside an unrelated word.
	if match, ok := table.LookupVendor("Rabbit Semiconductor"); ok {
		t.Errorf("matched %q inside an unrelated word", match.ID)
	}
}

func TestVendorKeyNormalization(t *testing.T) {
	cases := map[string]string{
		"Siemens AG":               "siemens ag",
		"Allen-Bradley":            "allen bradley",
		"Pepperl+Fuchs":            "pepperl+fuchs",
		"B&R":                      "b&r",
		"  Schneider   Electric  ": "schneider electric",
		"Advantech Co., Ltd.":      "advantech co ltd",
	}
	for input, want := range cases {
		if got := VendorKey(input); got != want {
			t.Errorf("VendorKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVendorKeyFoldsAccentsTheWayTheCompaniesSpellThemselves(t *testing.T) {
	// Dropping the accented letter instead would split one name into two tokens
	// and leave every German vendor looking like a different company depending on
	// which source named it.
	cases := map[string]string{
		"\u00c4hnliche":               "aehnliche",
		"Dr\u00e4gerwerk AG":          "draegerwerk ag",
		"B\u00fcrkert":                "buerkert",
		"Sch\u00f6ller":               "schoeller",
		"Weidm\u00fcller Interface":   "weidmueller interface",
		"Sch\u00fctze GmbH":           "schuetze gmbh",
		"V\u00e6rl\u00f8se":           "vaerlose",
		"Sch\u00e4fer & S\u00f6hne":   "schaefer & soehne",
		"Gr\u00fcnbeck Wasseraufb.":   "gruenbeck wasseraufb",
		"Telefon\u00e1ktiebolaget LM": "telefonaktiebolaget lm",
	}
	for input, want := range cases {
		if got := VendorKey(input); got != want {
			t.Errorf("VendorKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestVendorTableResolvesAnUmlautSpellingWithoutAnAliasForIt(t *testing.T) {
	table := testVendorTable(t)
	match, ok := table.LookupVendor("Dr\u00e4gerwerk AG & Co. KGaA")
	if !ok {
		t.Fatal("the umlaut spelling did not resolve")
	}
	if match.ID != "draeger" {
		t.Errorf("vendor id = %q, want draeger", match.ID)
	}
}

func TestParseVendorTableRejectsAmbiguousAlias(t *testing.T) {
	// An alias claimed by two vendors is a data error that would silently
	// misattribute findings, so it must fail the build rather than warn.
	data := []byte(`
version: 1
vendors:
  - id: alpha
    display: Alpha
    aliases: [shared name]
  - id: beta
    display: Beta
    aliases: [shared name]
`)
	if _, err := ParseVendorTable(data); err == nil {
		t.Fatal("expected an error for an alias claimed by two vendors")
	}
}

func TestParseVendorTableRejectsDuplicateID(t *testing.T) {
	data := []byte(`
version: 1
vendors:
  - id: alpha
    display: Alpha
  - id: alpha
    display: Alpha Again
`)
	if _, err := ParseVendorTable(data); err == nil {
		t.Fatal("expected an error for a duplicate vendor id")
	}
}

func TestVersionSchemeAndCatalogParsersAreWired(t *testing.T) {
	table := testVendorTable(t)
	if got := table.VersionSchemeFor("hitachi-energy"); got != "abb" {
		t.Errorf("hitachi-energy version scheme = %q, want abb", got)
	}
	if got := table.VersionSchemeFor("siemens"); got != "siemens" {
		t.Errorf("siemens version scheme = %q, want siemens", got)
	}
	if parsers := table.CatalogParsersFor("siemens"); len(parsers) == 0 || parsers[0] != "siemens-mlfb" {
		t.Errorf("siemens catalog parsers = %v, want siemens-mlfb first", parsers)
	}
	// A vendor with no declared scheme falls back to the generic comparator.
	if got := table.ComparatorForVendor("moxa").Name(); got != "generic" {
		t.Errorf("moxa comparator = %q, want generic", got)
	}
}
