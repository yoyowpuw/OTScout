package normalize

import "testing"

func TestSiemensMLFBRecoversFamilyAndModel(t *testing.T) {
	cases := []struct {
		raw    string
		family string
		model  string
	}{
		{"6ES7 214-1AG40-0XB0", "SIMATIC S7-1200", "CPU 1214C"},
		{"6ES7214-1AG40-0XB0", "SIMATIC S7-1200", "CPU 1214C"},
		{"6es7 211-1ae40-0xb0", "SIMATIC S7-1200", "CPU 1211C"},
		{"6ES7 516-3AN02-0AB0", "SIMATIC S7-1500", "CPU 1516"},
		{"6ES7 315-2EH14-0AB0", "SIMATIC S7-300", "CPU 315"},
		{"6ES7 414-3EM07-0AB0", "SIMATIC S7-400", "CPU 414"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			result, ok := ParseCatalog(tc.raw)
			if !ok {
				t.Fatalf("ParseCatalog(%q) found nothing", tc.raw)
			}
			if result.Parser != "siemens-mlfb" {
				t.Errorf("Parser = %q, want siemens-mlfb", result.Parser)
			}
			if result.VendorID != "siemens" {
				t.Errorf("VendorID = %q, want siemens", result.VendorID)
			}
			if result.Family != tc.family {
				t.Errorf("Family = %q, want %q", result.Family, tc.family)
			}
			if result.Model != tc.model {
				t.Errorf("Model = %q, want %q", result.Model, tc.model)
			}
			if result.Explanation == "" {
				t.Error("a catalog parse must explain how it read the code")
			}
		})
	}
}

func TestSiemensMLFBRestoresConventionalFormatting(t *testing.T) {
	result, ok := ParseCatalog("6ES72141AG400XB0")
	if !ok {
		t.Fatal("expected a match")
	}
	if result.Normalized != "6ES7 214-1AG40-0XB0" {
		t.Errorf("Normalized = %q, want the grouped form printed on the device", result.Normalized)
	}
}

func TestSiemensMLFBRecognisesNonControllerGroups(t *testing.T) {
	// A SCALANCE switch order code should still resolve the product line even
	// though it is not in the controller type table.
	result, ok := ParseCatalog("6GK5 208-0BA00-2AB2")
	if !ok {
		t.Fatal("expected a match")
	}
	if result.Series != "SCALANCE" {
		t.Errorf("Series = %q, want SCALANCE", result.Series)
	}
	// Confidence must be lower than a full model match, because only the line
	// was identified.
	if result.Confidence >= 0.9 {
		t.Errorf("Confidence = %v, expected a reduced score for a line only match", result.Confidence)
	}
}

func TestSiemensMLFBAttributesRuggedcomSeparately(t *testing.T) {
	result, ok := ParseCatalog("6GK6 000-8AS00-0AA0")
	if !ok {
		t.Fatal("expected a match")
	}
	if result.VendorID != "ruggedcom" {
		t.Errorf("VendorID = %q, want ruggedcom", result.VendorID)
	}
}

func TestSiemensMLFBRejectsNonSiemensCodes(t *testing.T) {
	for _, raw := range []string{"1756-L71", "R08CPU", "hello world", "6XX9 999"} {
		if result, ok := (siemensMLFB{}).Parse(raw); ok {
			t.Errorf("Parse(%q) should have been rejected, got %+v", raw, result)
		}
	}
}

func TestRockwellCatalogControllerSeries(t *testing.T) {
	cases := []struct {
		raw    string
		family string
		series string
		model  string
	}{
		{"1756-L71", "ControlLogix", "ControlLogix 5570", "L71"},
		{"1756-L61", "ControlLogix", "ControlLogix 5560", "L61"},
		{"1756-L81E", "ControlLogix", "ControlLogix 5580", "L81E"},
		{"1756L83E", "ControlLogix", "ControlLogix 5580", "L83E"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			result, ok := ParseCatalog(tc.raw)
			if !ok {
				t.Fatalf("ParseCatalog(%q) found nothing", tc.raw)
			}
			if result.VendorID != "rockwell-automation" {
				t.Errorf("VendorID = %q", result.VendorID)
			}
			if result.Family != tc.family {
				t.Errorf("Family = %q, want %q", result.Family, tc.family)
			}
			if result.Series != tc.series {
				t.Errorf("Series = %q, want %q", result.Series, tc.series)
			}
			if result.Model != tc.model {
				t.Errorf("Model = %q, want %q", result.Model, tc.model)
			}
		})
	}
}

func TestRockwellCatalogPanelViewPlus(t *testing.T) {
	result, ok := ParseCatalog("2711P-T10C4D8")
	if !ok {
		t.Fatal("expected a match")
	}
	if result.Family != "PanelView Plus" {
		t.Errorf("Family = %q, want PanelView Plus", result.Family)
	}
	if result.Normalized != "2711P-T10C4D8" {
		t.Errorf("Normalized = %q", result.Normalized)
	}
}

func TestRockwellCatalogDoesNotGuessAcrossPlatforms(t *testing.T) {
	// An L3 suffix means CompactLogix 5380 on a 5069 but something else on a
	// 1769. The parser must not carry one platform's series onto another.
	compact5380, ok := ParseCatalog("5069-L340ERM")
	if !ok {
		t.Fatal("expected a match for 5069-L340ERM")
	}
	if compact5380.Series != "CompactLogix 5380" {
		t.Errorf("5069 Series = %q, want CompactLogix 5380", compact5380.Series)
	}

	older, ok := ParseCatalog("1769-L35E")
	if !ok {
		t.Fatal("expected a match for 1769-L35E")
	}
	if older.Series != "CompactLogix" {
		t.Errorf("1769 Series = %q, want the plain family rather than a guessed series", older.Series)
	}
	if older.Model != "L35E" {
		t.Errorf("1769 Model = %q, want L35E", older.Model)
	}
}

func TestRockwellCatalogRejectsForeignCodes(t *testing.T) {
	for _, raw := range []string{"6ES7 214-1AG40-0XB0", "R08CPU", "abc"} {
		if _, ok := (rockwellCatalog{}).Parse(raw); ok {
			t.Errorf("Parse(%q) should have been rejected", raw)
		}
	}
}

func TestMitsubishiCatalog(t *testing.T) {
	cases := []struct {
		raw    string
		family string
		model  string
	}{
		{"R08CPU", "MELSEC iQ-R", "R08CPU"},
		{"Q03UDVCPU", "MELSEC-Q", "Q03UDVCPU"},
		{"L02CPU", "MELSEC-L", "L02CPU"},
		{"FX5U-32MT/ES", "MELSEC iQ-F", "FX5U"},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			result, ok := ParseCatalog(tc.raw)
			if !ok {
				t.Fatalf("ParseCatalog(%q) found nothing", tc.raw)
			}
			if result.VendorID != "mitsubishi-electric" {
				t.Errorf("VendorID = %q", result.VendorID)
			}
			if result.Family != tc.family {
				t.Errorf("Family = %q, want %q", result.Family, tc.family)
			}
			if result.Model != tc.model {
				t.Errorf("Model = %q, want %q", result.Model, tc.model)
			}
		})
	}
}

func TestCatalogKeyStripsSeparators(t *testing.T) {
	cases := map[string]string{
		"6ES7 214-1AG40-0XB0": "6ES72141AG400XB0",
		"1756-L71":            "1756L71",
		"fx5u-32mt/es":        "FX5U32MTES",
	}
	for input, want := range cases {
		if got := CatalogKey(input); got != want {
			t.Errorf("CatalogKey(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseCatalogWithRestrictsToNamedParsers(t *testing.T) {
	// Scoping to the vendor's own parsers stops another vendor's scheme from
	// claiming a code that happens to fit its pattern.
	if _, ok := ParseCatalogWith("1756-L71", []string{"siemens-mlfb"}); ok {
		t.Error("a Rockwell code must not be parsed by the Siemens parser")
	}
	if _, ok := ParseCatalogWith("1756-L71", []string{"rockwell-catalog"}); !ok {
		t.Error("expected the Rockwell parser to accept a Rockwell code")
	}
}

func TestParseCatalogForVendorUsesConfiguredParsers(t *testing.T) {
	table := testVendorTable(t)
	result, ok := table.ParseCatalogForVendor("siemens", "6ES7 214-1AG40-0XB0")
	if !ok {
		t.Fatal("expected a match")
	}
	if result.Parser != "siemens-mlfb" {
		t.Errorf("Parser = %q", result.Parser)
	}
}

func TestCatalogParserNamesAreRegistered(t *testing.T) {
	names := CatalogParserNames()
	want := map[string]bool{"siemens-mlfb": false, "rockwell-catalog": false, "mitsubishi-catalog": false}
	for _, name := range names {
		if _, ok := want[name]; ok {
			want[name] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("parser %q is not registered", name)
		}
	}
}
