package advisory

import (
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// The Siemens shape below is the one that matters most. Siemens publishes an
// advisory covering a dozen CPU variants as a product_family branch holding one
// product_name branch per variant, each holding a version range. Getting this
// wrong means either missing every Siemens finding or reporting every Siemens
// device as vulnerable to everything.
const siemensCSAF = `{
  "document": {
    "category": "csaf_security_advisory",
    "csaf_version": "2.0",
    "title": "SSA-123456: Denial of Service in SIMATIC S7-1500 CPUs",
    "publisher": {"category": "vendor", "name": "Siemens ProductCERT"},
    "distribution": {"tlp": {"label": "WHITE"}},
    "notes": [
      {"category": "summary", "title": "Summary", "text": "Affected devices\ncontain a flaw\n  that allows a reboot."}
    ],
    "references": [
      {"category": "self", "summary": "Advisory", "url": "https://cert-portal.siemens.com/productcert/html/ssa-123456.html"}
    ],
    "tracking": {
      "id": "SSA-123456",
      "status": "final",
      "version": "1.0",
      "initial_release_date": "2026-01-13T00:00:00Z",
      "current_release_date": "2026-02-10T00:00:00Z"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "vendor",
        "name": "Siemens",
        "branches": [
          {
            "category": "product_family",
            "name": "SIMATIC S7-1500 CPU family",
            "branches": [
              {
                "category": "product_name",
                "name": "SIMATIC S7-1500 CPU 1516-3 PN/DP",
                "branches": [
                  {
                    "category": "product_version_range",
                    "name": "<V2.9.2",
                    "product": {
                      "product_id": "1",
                      "name": "SIMATIC S7-1500 CPU 1516-3 PN/DP",
                      "product_identification_helper": {"skus": ["6ES7516-3AN02-0AB0"]}
                    }
                  }
                ]
              },
              {
                "category": "product_name",
                "name": "SIMATIC S7-1500 CPU 1518-4 PN/DP",
                "branches": [
                  {
                    "category": "product_version",
                    "name": "V2.8.1",
                    "product": {"product_id": "2", "name": "SIMATIC S7-1500 CPU 1518-4 PN/DP V2.8.1"}
                  }
                ]
              }
            ]
          }
        ]
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2026-11111",
      "title": "Improper input validation",
      "cwe": {"id": "CWE-20", "name": "Improper Input Validation"},
      "product_status": {"known_affected": ["1"], "fixed": ["2"]},
      "scores": [
        {
          "products": ["1"],
          "cvss_v3": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "baseScore": 7.5, "baseSeverity": "HIGH"}
        },
        {
          "products": ["1"],
          "cvss_v4": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", "baseScore": 8.7, "baseSeverity": "HIGH"}
        }
      ],
      "remediations": [
        {"category": "vendor_fix", "details": "Update to V2.9.2 or later", "product_ids": ["1"]},
        {"category": "mitigation", "details": "Block port 102", "product_ids": ["1"]}
      ]
    }
  ]
}`

func TestParseCSAFFlattensTheProductTreeIntoOneProductPerLeaf(t *testing.T) {
	adv, err := ParseCSAFBytes([]byte(siemensCSAF), "siemens-csaf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if adv.ID != "SSA-123456" {
		t.Errorf("id = %q, want SSA-123456", adv.ID)
	}
	if adv.Publisher != "Siemens ProductCERT" {
		t.Errorf("publisher = %q", adv.Publisher)
	}
	if adv.URL != "https://cert-portal.siemens.com/productcert/html/ssa-123456.html" {
		t.Errorf("url = %q, want the self reference", adv.URL)
	}
	// The summary reaches a terminal and an HTML report, so the line breaks the
	// publisher left in it are collapsed.
	if want := "Affected devices contain a flaw that allows a reboot."; adv.Summary != want {
		t.Errorf("summary = %q, want %q", adv.Summary, want)
	}

	if len(adv.Products) != 2 {
		t.Fatalf("got %d products, want 2: %+v", len(adv.Products), adv.Products)
	}

	first := adv.Products[0]
	if first.ID != "1" {
		t.Errorf("first product id = %q", first.ID)
	}
	if first.VendorRaw != "Siemens" {
		t.Errorf("vendor came from the wrong branch: %q", first.VendorRaw)
	}
	if first.FamilyRaw != "SIMATIC S7-1500 CPU family" {
		t.Errorf("family = %q", first.FamilyRaw)
	}
	if first.ProductRaw != "SIMATIC S7-1500 CPU 1516-3 PN/DP" {
		t.Errorf("product = %q", first.ProductRaw)
	}
	// The range phrase is kept exactly as printed. Parsing it is a separate step,
	// and the evidence view has to be able to show what the advisory actually said.
	if first.VersionRaw != "<V2.9.2" {
		t.Errorf("version = %q, want the range text kept verbatim", first.VersionRaw)
	}
	if first.CatalogNumber != "6ES7516-3AN02-0AB0" {
		t.Errorf("catalog number from the identification helper = %q", first.CatalogNumber)
	}

	if adv.Products[1].VersionRaw != "V2.8.1" {
		t.Errorf("second product version = %q", adv.Products[1].VersionRaw)
	}
}

func TestParseCSAFKeepsProductStatusSoAFixedProductIsNotReportedAsAffected(t *testing.T) {
	adv, err := ParseCSAFBytes([]byte(siemensCSAF), "siemens-csaf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(adv.Vulnerabilities) != 1 {
		t.Fatalf("got %d vulnerabilities", len(adv.Vulnerabilities))
	}
	vuln := adv.Vulnerabilities[0]

	if !vuln.Affects("1") {
		t.Error("product 1 is listed as known_affected and should report as affected")
	}
	if vuln.Affects("2") {
		t.Error("product 2 is listed as fixed and must not report as affected")
	}
	ids, explicit := vuln.AffectedProducts()
	if !explicit {
		t.Error("the advisory named its affected products, so the caller must be told the list is explicit")
	}
	if len(ids) != 1 || ids[0] != "1" {
		t.Errorf("affected ids = %v", ids)
	}
	if vuln.CWEID != "CWE-20" {
		t.Errorf("cwe id = %q", vuln.CWEID)
	}
}

func TestBestScorePrefersTheNewerCVSSVersionOverTheHigherNumber(t *testing.T) {
	adv, err := ParseCSAFBytes([]byte(siemensCSAF), "siemens-csaf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	best, ok := adv.Vulnerabilities[0].BestScore()
	if !ok {
		t.Fatal("no score was read")
	}
	// Both scorings describe the same flaw. Showing whichever came first in the
	// file would be arbitrary, so the newer specification wins.
	if best.Version != "4.0" {
		t.Errorf("best score version = %q, want 4.0", best.Version)
	}
	if best.BaseScore != 8.7 {
		t.Errorf("best base score = %v, want 8.7", best.BaseScore)
	}
	if best.Severity != SeverityHigh {
		t.Errorf("severity = %q", best.Severity)
	}
}

func TestRemediationSeparatesAVendorFixFromAWorkaround(t *testing.T) {
	adv, err := ParseCSAFBytes([]byte(siemensCSAF), "siemens-csaf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	remediations := adv.Vulnerabilities[0].Remediations
	if len(remediations) != 2 {
		t.Fatalf("got %d remediations", len(remediations))
	}
	// A firmware update needs an outage window and a workaround usually does not,
	// so the two cannot be presented as the same thing.
	if !remediations[0].HasFix() {
		t.Error("the vendor_fix entry should report as a fix")
	}
	if remediations[1].HasFix() {
		t.Error("a mitigation is not a fix")
	}
}

func TestParseCSAFRefusesADocumentWithNoTrackingID(t *testing.T) {
	_, err := ParseCSAFBytes([]byte(`{"document":{"title":"no id"}}`), "test")
	if err == nil {
		t.Fatal("a document with no tracking id has no usable identity and must be refused")
	}
}

func TestParseCSAFWarnsWhenTheProductTreeIsEmpty(t *testing.T) {
	doc := `{"document":{"tracking":{"id":"ICSA-26-001-01"}},"vulnerabilities":[{"cve":"CVE-2026-1"}]}`
	adv, err := ParseCSAFBytes([]byte(doc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// An advisory with no products can never match an asset. That is not an error
	// in the document, but it is worth recording so a corpus can be audited.
	if len(adv.Warnings) == 0 {
		t.Fatal("an advisory with no products should carry a warning")
	}
	if !strings.Contains(adv.Warnings[0], "never match") {
		t.Errorf("warning = %q", adv.Warnings[0])
	}
}

func TestParseCSAFKeepsTheFirstDefinitionWhenAProductIDIsReused(t *testing.T) {
	doc := `{
      "document": {"tracking": {"id": "ICSA-26-002-01"}},
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Acme", "branches": [
            {"category": "product_name", "name": "First", "product": {"product_id": "dup", "name": "First"}},
            {"category": "product_name", "name": "Second", "product": {"product_id": "dup", "name": "Second"}}
          ]}
        ]
      }
    }`
	adv, err := ParseCSAFBytes([]byte(doc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(adv.Products) != 1 {
		t.Fatalf("got %d products, want the duplicate dropped", len(adv.Products))
	}
	// Vulnerabilities reference products by id, so the second definition cannot
	// simply overwrite the first: it might describe something else entirely.
	if adv.Products[0].Name != "First" {
		t.Errorf("kept %q, want the first definition", adv.Products[0].Name)
	}
	if len(adv.Warnings) == 0 {
		t.Error("a reused product id is a document bug and should be recorded")
	}
}

func TestParseCSAFStopsWalkingATreeNestedAbsurdlyDeep(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"document":{"tracking":{"id":"ICSA-26-003-01"}},"product_tree":{"branches":`)
	depth := maxBranchDepth + 10
	for i := 0; i < depth; i++ {
		sb.WriteString(`[{"category":"product_family","name":"deep","branches":`)
	}
	sb.WriteString(`[]`)
	for i := 0; i < depth; i++ {
		sb.WriteString(`}]`)
	}
	sb.WriteString(`}}`)

	adv, err := ParseCSAFBytes([]byte(sb.String()), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	found := false
	for _, warning := range adv.Warnings {
		if strings.Contains(warning, "nested deeper") {
			found = true
		}
	}
	if !found {
		t.Errorf("a tree deeper than the limit should be reported, got %v", adv.Warnings)
	}
}

func TestParseCSAFReadsProductsDeclaredOutsideTheTree(t *testing.T) {
	doc := `{
      "document": {"tracking": {"id": "ICSA-26-004-01"}},
      "product_tree": {
        "full_product_names": [
          {"product_id": "flat", "name": "Allen-Bradley ControlLogix 1756-L71"}
        ]
      }
    }`
	adv, err := ParseCSAFBytes([]byte(doc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(adv.Products) != 1 {
		t.Fatalf("got %d products", len(adv.Products))
	}
	// With no branch context the full name is the only identity there is, so it
	// has to stand in for the product branch that was never there.
	if adv.Products[0].ProductRaw != "Allen-Bradley ControlLogix 1756-L71" {
		t.Errorf("product = %q", adv.Products[0].ProductRaw)
	}
}

func TestParseCSAFInheritsIdentityAcrossARelationship(t *testing.T) {
	doc := `{
      "document": {"tracking": {"id": "ICSA-26-005-01"}},
      "product_tree": {
        "branches": [
          {"category": "vendor", "name": "Siemens", "branches": [
            {"category": "product_name", "name": "SIMATIC WinCC", "branches": [
              {"category": "product_version", "name": "V7.5", "product": {"product_id": "sw", "name": "SIMATIC WinCC V7.5"}}
            ]}
          ]}
        ],
        "relationships": [
          {
            "category": "installed_on",
            "product_reference": "sw",
            "relates_to_product_reference": "host",
            "full_product_name": {"product_id": "sw-on-host", "name": "SIMATIC WinCC V7.5 on Windows Server"}
          }
        ]
      }
    }`
	adv, err := ParseCSAFBytes([]byte(doc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	related, ok := adv.ProductByID("sw-on-host")
	if !ok {
		t.Fatal("the relationship product was not created")
	}
	// The advisory is about the software, not about what it happens to run on,
	// so the identity comes from the component being described.
	if related.VendorRaw != "Siemens" || related.VersionRaw != "V7.5" {
		t.Errorf("relationship product inherited %q %q", related.VendorRaw, related.VersionRaw)
	}
}

func TestNormalizeResolvesTheVendorAndParsesTheRange(t *testing.T) {
	adv, err := ParseCSAFBytes([]byte(siemensCSAF), "siemens-csaf")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n, err := normalize.New()
	if err != nil {
		t.Fatalf("load normalization tables: %v", err)
	}
	adv.Normalize(n)

	if adv.Products[0].Vendor != "siemens" {
		t.Errorf("vendor resolved to %q, want siemens", adv.Products[0].Vendor)
	}
	// "<V2.9.2" is the shape the matcher has to evaluate against a firmware
	// string read off the wire, so it has to come out of the corpus already parsed.
	if adv.Products[0].Version.Kind == normalize.ConstraintUnknown {
		t.Errorf("version range %q was not parsed", adv.Products[0].VersionRaw)
	}
}

func TestNormalizeLeavesTheCanonicalVendorEmptyWhenTheAliasTableDoesNotKnowIt(t *testing.T) {
	doc := `{
      "document": {"tracking": {"id": "ICSA-26-007-01"}},
      "product_tree": {"branches": [
        {"category": "vendor", "name": "o6 Automation GmbH", "branches": [
          {"category": "product_name", "name": "Widget", "product": {"product_id": "p1", "name": "Widget"}}
        ]}
      ]}
    }`
	adv, err := ParseCSAFBytes([]byte(doc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n, err := normalize.New()
	if err != nil {
		t.Fatalf("load normalization tables: %v", err)
	}
	adv.Normalize(n)

	// Storing the unrecognised name in the canonical field would have the matcher
	// compare a display name against a canonical id. That never matches, and the
	// failure is invisible. An empty field is a fact the statistics can report.
	if adv.Products[0].Vendor != "" {
		t.Errorf("canonical vendor = %q, want it left empty", adv.Products[0].Vendor)
	}
	if adv.Products[0].VendorRaw != "o6 Automation GmbH" {
		t.Errorf("the raw name must survive for the evidence view, got %q", adv.Products[0].VendorRaw)
	}
}

func TestNormalizeTreatsAProductWithNoVersionAsEveryVersion(t *testing.T) {
	doc := `{
      "document": {"tracking": {"id": "ICSA-26-006-01"}},
      "product_tree": {"branches": [
        {"category": "vendor", "name": "Moxa", "branches": [
          {"category": "product_name", "name": "EDS-405A", "product": {"product_id": "p1", "name": "EDS-405A"}}
        ]}
      ]}
    }`
	adv, err := ParseCSAFBytes([]byte(doc), "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	n, err := normalize.New()
	if err != nil {
		t.Fatalf("load normalization tables: %v", err)
	}
	adv.Normalize(n)

	// A hardware advisory that names no version means every version of that
	// device. Leaving it unknown would silently drop the finding.
	if adv.Products[0].Version.Kind != normalize.ConstraintAll {
		t.Errorf("version kind = %v, want every version", adv.Products[0].Version.Kind)
	}
}

func TestValidateRejectsAnAdvisoryTheMatcherCouldNotUse(t *testing.T) {
	cases := []struct {
		name string
		adv  Advisory
	}{
		{"no id", Advisory{Source: "test", Products: []Product{{ID: "1"}}}},
		{"no source", Advisory{ID: "A", Products: []Product{{ID: "1"}}}},
		{"nothing in it", Advisory{ID: "A", Source: "test"}},
		{"product with no id", Advisory{ID: "A", Source: "test", Products: []Product{{Name: "x"}}}},
		{"reused product id", Advisory{ID: "A", Source: "test", Products: []Product{{ID: "1"}, {ID: "1"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.adv.Validate(); err == nil {
				t.Error("expected the advisory to be refused")
			}
		})
	}
}

func TestSeverityForScoreFollowsTheCVSSBands(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{0, SeverityNone},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10.0, SeverityCritical},
	}
	for _, tc := range cases {
		if got := SeverityForScore(tc.score); got != tc.want {
			t.Errorf("score %v gave %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestSeverityRankPutsUnknownBelowNone(t *testing.T) {
	// A missing score must never sort as though it were a low one, or an
	// unscored critical flaw disappears off the bottom of a triage table.
	if SeverityUnknown.Rank() >= SeverityNone.Rank() {
		t.Error("unknown severity should rank below none")
	}
	if SeverityCritical.Rank() <= SeverityHigh.Rank() {
		t.Error("critical should outrank high")
	}
}
