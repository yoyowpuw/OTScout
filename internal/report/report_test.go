package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/finding"
)

// fixedTime keeps every generated document byte for byte reproducible, which is
// what lets two assessments of an unchanged plant be diffed against each other.
var fixedTime = time.Date(2026, 3, 14, 9, 30, 0, 0, time.UTC)

func vexOptions() VEXOptions {
	return VEXOptions{
		PublisherName:      "Example Water Authority",
		PublisherNamespace: "https://water.example",
		Now:                fixedTime,
	}
}

// sampleSet is a small but awkward inventory: two devices of the same product,
// one confirmed and one not, plus a device matched only by family and an
// advisory with no CVE at all.
func sampleSet() *finding.Set {
	set := finding.NewSet("otscout match")
	set.GeneratedAt = fixedTime
	set.InventoryPath = "assets.json"
	set.CorpusPath = "corpus"

	set.Findings = []finding.Finding{
		{
			ID:           "asset-1:ICSA-24-100-01:cpu",
			AssetID:      "asset-1",
			AssetAddress: "10.10.1.5",
			AssetLabel:   "Line 2 PLC",
			AssetPurdue:  "L1",
			AssetRole:    "controller",
			AdvisoryID:   "ICSA-24-100-01",
			AdvisorySource: "cisa",
			Title:        "Siemens SIMATIC S7-300 improper access control",
			Published:    fixedTime.AddDate(0, -2, 0),
			CVEs:         []string{"CVE-2024-1111"},
			Tier:         finding.TierConfirmed,
			Score:        0.95,
			CVSS:         9.8,
			CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity:     "critical",
			KEV:          true,
			EPSS:         0.4213,
			MatchedVendor:  "Siemens",
			MatchedProduct: "SIMATIC S7-300 CPU 315-2 PN/DP",
			MatchedVersion: "< 3.2.12",
			AssetIdentity: asset.Identity{
				Vendor: "Siemens", Product: "CPU 315-2 PN/DP", Firmware: "3.2.6",
			},
			VersionCheck: &finding.VersionCheck{
				AssetVersion: "3.2.6", Constraint: "< 3.2.12", Comparator: "siemens",
				Result: "affected", Explanation: "3.2.6 is below 3.2.12",
			},
			Reasons: []finding.Reason{
				{Kind: finding.ReasonVendorExact, Detail: "vendor Siemens matched exactly", Passed: true},
				{Kind: finding.ReasonVersionInRange, Detail: "3.2.6 is below 3.2.12", Passed: true},
			},
			FixAvailable: true,
			Remediations: []finding.Remediation{
				{Category: "vendor_fix", Details: "Update to firmware 3.2.12 or later."},
				{Category: "workaround", Details: "Restrict port 102 to the engineering VLAN."},
			},
			References: []string{"https://cisa.example/ICSA-24-100-01"},
		},
		{
			// Same product as above, but this one could not be version checked.
			// The product must not end up in both statuses.
			ID:           "asset-2:ICSA-24-100-01:cpu",
			AssetID:      "asset-2",
			AssetAddress: "10.10.1.6",
			AssetLabel:   "Line 3 PLC",
			AdvisoryID:   "ICSA-24-100-01",
			AdvisorySource: "cisa",
			Title:        "Siemens SIMATIC S7-300 improper access control",
			CVEs:         []string{"CVE-2024-1111"},
			Tier:         finding.TierLikely,
			Score:        0.6,
			CVSS:         9.8,
			CVSSVector:   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Severity:     "critical",
			KEV:          true,
			MatchedVendor:  "Siemens",
			MatchedProduct: "SIMATIC S7-300 CPU 315-2 PN/DP",
			AssetIdentity: asset.Identity{
				Vendor: "Siemens", Product: "CPU 315-2 PN/DP", Firmware: "3.2.6",
			},
			FixAvailable: true,
			Remediations: []finding.Remediation{
				{Category: "vendor_fix", Details: "Update to firmware 3.2.12 or later."},
			},
			References: []string{"https://cisa.example/ICSA-24-100-01"},
		},
		{
			// No CVE assigned, and a weaker tier. Both have to survive the trip.
			ID:           "asset-3:ICSA-24-200-02:drive",
			AssetID:      "asset-3",
			AssetAddress: "10.10.2.9",
			AssetLabel:   "Feed pump drive",
			AdvisoryID:   "ICSA-24-200-02",
			AdvisorySource: "cisa",
			Title:        "Example Drives firmware weakness",
			Tier:         finding.TierPossible,
			Score:        0.3,
			AssetIdentity: asset.Identity{Vendor: "Example Drives", Family: "ACS"},
			MatchedVendor:  "Example Drives",
			MatchedProduct: "ACS580",
		},
	}

	set.Summary.AssetsConsidered = 12
	set.Summary.AssetsUnidentified = 4
	set.Summary.AssetsUnknownVendo = 1
	set.Summary.RuledOutByVersion = 2
	set.Finalize()
	return set
}

func buildVEX(t *testing.T, set *finding.Set, opts VEXOptions) map[string]any {
	t.Helper()
	doc, err := BuildVEX(set, opts)
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteVEX(&buf, doc); err != nil {
		t.Fatalf("WriteVEX: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(buf.Bytes(), &generic); err != nil {
		t.Fatalf("the VEX document is not valid JSON: %v", err)
	}
	return generic
}

// TestTheVEXSatisfiesTheBaseProfile checks the fields CSAF 2.0 section 4.1 makes
// mandatory. A consumer validates before it reads, so a document missing one of
// these is not a weaker report, it is a file that gets rejected at the door.
func TestTheVEXSatisfiesTheBaseProfile(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	document, ok := doc["document"].(map[string]any)
	if !ok {
		t.Fatal("no /document")
	}
	if document["category"] != "csaf_vex" {
		t.Errorf("category is %v, want csaf_vex", document["category"])
	}
	if document["csaf_version"] != "2.0" {
		t.Errorf("csaf_version is %v, want 2.0", document["csaf_version"])
	}
	for _, field := range []string{"title", "publisher", "tracking"} {
		if _, present := document[field]; !present {
			t.Errorf("/document/%s is missing", field)
		}
	}

	publisher := document["publisher"].(map[string]any)
	for _, field := range []string{"category", "name", "namespace"} {
		if publisher[field] == nil || publisher[field] == "" {
			t.Errorf("/document/publisher/%s is missing", field)
		}
	}

	tracking := document["tracking"].(map[string]any)
	for _, field := range []string{
		"current_release_date", "id", "initial_release_date", "revision_history", "status", "version",
	} {
		if tracking[field] == nil {
			t.Errorf("/document/tracking/%s is missing", field)
		}
	}

	history := tracking["revision_history"].([]any)
	if len(history) == 0 {
		t.Fatal("revision_history is empty")
	}
	revision := history[0].(map[string]any)
	for _, field := range []string{"date", "number", "summary"} {
		if revision[field] == nil || revision[field] == "" {
			t.Errorf("/document/tracking/revision_history[0]/%s is missing", field)
		}
	}
}

// TestEveryAffectedProductCarriesAnActionStatement is the requirement most
// easily missed, and the one that matters most: CSAF section 4.5 says a product
// listed as known_affected must have a remediation. Telling somebody they are
// exposed without telling them what to do is not a valid VEX.
//
// Recommended test 6.2.2 extends the same rule to under_investigation, so this
// checks both.
func TestEveryAffectedProductCarriesAnActionStatement(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	for _, raw := range doc["vulnerabilities"].([]any) {
		vuln := raw.(map[string]any)
		name := vulnerabilityName(vuln)

		status, ok := vuln["product_status"].(map[string]any)
		if !ok {
			t.Errorf("%s has no product_status", name)
			continue
		}

		needing := make(map[string]bool)
		for _, key := range []string{"known_affected", "under_investigation"} {
			for _, id := range stringsOf(status[key]) {
				needing[id] = true
			}
		}
		if len(needing) == 0 {
			t.Errorf("%s lists no product in any status, which no profile allows", name)
			continue
		}

		covered := make(map[string]bool)
		remediations, _ := vuln["remediations"].([]any)
		if len(remediations) == 0 {
			t.Errorf("%s has no remediations at all", name)
		}
		for _, rawRem := range remediations {
			remediation := rawRem.(map[string]any)
			if remediation["category"] == nil || remediation["details"] == "" {
				t.Errorf("%s has a remediation with no category or no details", name)
			}
			for _, id := range stringsOf(remediation["product_ids"]) {
				covered[id] = true
			}
		}

		for id := range needing {
			if !covered[id] {
				t.Errorf("%s lists product %s without an action statement", name, id)
			}
		}
	}
}

// TestARemediationKeepsTheCategoryTheAdvisoryGaveIt. Folding a workaround and a
// vendor fix into one entry meant the workaround's text arrived labelled
// vendor_fix, which tells a machine the vulnerability is resolved when nobody
// said that. CSAF gives the five categories distinct meanings and a consumer
// acts on them.
func TestARemediationKeepsTheCategoryTheAdvisoryGaveIt(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	found := make(map[string]string)
	for _, raw := range doc["vulnerabilities"].([]any) {
		vuln := raw.(map[string]any)
		if vulnerabilityName(vuln) != "CVE-2024-1111" {
			continue
		}
		for _, rawRem := range vuln["remediations"].([]any) {
			remediation := rawRem.(map[string]any)
			category := remediation["category"].(string)
			if !csafRemediationCategories[category] {
				t.Errorf("category %q is not one CSAF allows", category)
			}
			found[category] = remediation["details"].(string)
		}
	}

	if !strings.Contains(found["vendor_fix"], "3.2.12") {
		t.Errorf("the vendor fix lost its text: %q", found["vendor_fix"])
	}
	if strings.Contains(found["vendor_fix"], "engineering VLAN") {
		t.Errorf("the workaround was folded into the vendor fix: %q", found["vendor_fix"])
	}
	if !strings.Contains(found["workaround"], "engineering VLAN") {
		t.Errorf("the workaround was lost: %q", found["workaround"])
	}
}

// TestAFixAndNoFixAreNeverStatedTogether. CSAF section 3.2.3.12.1 says
// vendor_fix contradicts none_available and no_fix_planned for the same
// product. A document that says both leaves a consumer to pick one.
func TestAFixAndNoFixAreNeverStatedTogether(t *testing.T) {
	set := sampleSet()
	set.Findings[0].Remediations = []finding.Remediation{
		{Category: "vendor_fix", Details: "Update to firmware 3.2.12 or later."},
		{Category: "none_available", Details: "No fix is available for the 2.x line."},
		{Category: "no_fix_planned", Details: "The 1.x line is end of life."},
	}

	doc, err := BuildVEX(set, vexOptions())
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}

	for _, vuln := range doc.Vulnerabilities {
		byProduct := make(map[string]map[string]bool)
		for _, remediation := range vuln.Remediations {
			for _, id := range remediation.ProductIDs {
				if byProduct[id] == nil {
					byProduct[id] = make(map[string]bool)
				}
				byProduct[id][remediation.Category] = true
			}
		}
		for id, categories := range byProduct {
			if categories["vendor_fix"] && (categories["none_available"] || categories["no_fix_planned"]) {
				t.Errorf("%s says product %s both has a fix and has none", vuln.CVE, id)
			}
		}
	}
}

// TestTheBibliographyIsCapped. An ICS advisory cites dozens of sources and
// covers dozens of CVEs. Copying the whole list onto each of them produced a
// document where the references outweighed the findings seven to one.
func TestTheBibliographyIsCapped(t *testing.T) {
	set := sampleSet()
	many := []string{"https://cisa.example/ICSA-24-100-01"}
	for i := 0; i < 40; i++ {
		many = append(many, "https://vendor.example/note-"+string(rune('a'+i%26))+string(rune('0'+i/26)))
	}
	set.Findings[0].References = many

	doc, err := BuildVEX(set, vexOptions())
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}

	for _, vuln := range doc.Vulnerabilities {
		if len(vuln.References) > maxReferences {
			t.Errorf("%s carries %d references, more than the cap of %d",
				vuln.CVE, len(vuln.References), maxReferences)
		}
	}

	// The advisory's own URL is the one link a reader needs, so it survives.
	for _, vuln := range doc.Vulnerabilities {
		if vuln.CVE != "CVE-2024-1111" {
			continue
		}
		if len(vuln.References) == 0 || vuln.References[0].URL != "https://cisa.example/ICSA-24-100-01" {
			t.Error("the advisory URL was not kept at the head of the references")
		}
	}
}

// TestEveryVulnerabilityIsIdentifiedAndDescribed covers the other two VEX
// profile requirements: a cve or an ids entry, and a note.
func TestEveryVulnerabilityIsIdentifiedAndDescribed(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	vulnerabilities := doc["vulnerabilities"].([]any)
	if len(vulnerabilities) == 0 {
		t.Fatal("the document lists no vulnerabilities")
	}

	for _, raw := range vulnerabilities {
		vuln := raw.(map[string]any)
		name := vulnerabilityName(vuln)

		_, hasCVE := vuln["cve"]
		ids, _ := vuln["ids"].([]any)
		if !hasCVE && len(ids) == 0 {
			t.Errorf("%s has neither a cve nor an ids entry", name)
		}

		notes, _ := vuln["notes"].([]any)
		if len(notes) == 0 {
			t.Errorf("%s has no notes", name)
		}
		for _, rawNote := range notes {
			note := rawNote.(map[string]any)
			if note["category"] == nil || note["text"] == "" {
				t.Errorf("%s has a note with no category or no text", name)
			}
		}
	}
}

// TestEveryReferencedProductIsInTheProductTree guards the requirement that
// /product_tree lists everything referenced later. A product id that appears in
// a status but not in the tree is a dangling reference, and a validator rejects
// the whole document for it.
func TestEveryReferencedProductIsInTheProductTree(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	declared := make(map[string]bool)
	tree := doc["product_tree"].(map[string]any)
	names, _ := tree["full_product_names"].([]any)
	if len(names) == 0 {
		t.Fatal("the product tree is empty")
	}
	for _, raw := range names {
		product := raw.(map[string]any)
		id := product["product_id"].(string)
		if product["name"] == "" {
			t.Errorf("product %s has no name", id)
		}
		if declared[id] {
			t.Errorf("product id %s is declared twice", id)
		}
		declared[id] = true
	}

	for _, raw := range doc["vulnerabilities"].([]any) {
		vuln := raw.(map[string]any)
		name := vulnerabilityName(vuln)
		for _, id := range referencedProducts(vuln) {
			if !declared[id] {
				t.Errorf("%s references product %s, which the product tree does not declare", name, id)
			}
		}
	}
}

// TestOnlyConfirmedFindingsAreStatedAsAffected is the honesty guarantee. A VEX
// gets consumed by tooling and quoted by people, so a tier that means "we could
// not check the version" must not arrive looking like a conclusion.
func TestOnlyConfirmedFindingsAreStatedAsAffected(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	tree := doc["product_tree"].(map[string]any)
	nameByID := make(map[string]string)
	for _, raw := range tree["full_product_names"].([]any) {
		product := raw.(map[string]any)
		nameByID[product["product_id"].(string)] = product["name"].(string)
	}

	var affected []string
	for _, raw := range doc["vulnerabilities"].([]any) {
		vuln := raw.(map[string]any)
		status := vuln["product_status"].(map[string]any)
		for _, id := range stringsOf(status["known_affected"]) {
			affected = append(affected, nameByID[id])
		}
	}

	// Only the Siemens CPU was confirmed. The drive matched on family alone and
	// must not be asserted anywhere.
	for _, name := range affected {
		if strings.Contains(name, "Example Drives") {
			t.Errorf("a possible tier finding was stated as known_affected: %s", name)
		}
	}
	if len(affected) != 1 {
		t.Errorf("got %d affected products, want 1: %v", len(affected), affected)
	}
}

// TestAProductIsNeverBothAffectedAndUnderInvestigation covers the case that
// produced the rule: two identical devices, one version checked and one not.
// The product is one product, and a contradictory status is a document a
// consumer cannot act on.
func TestAProductIsNeverBothAffectedAndUnderInvestigation(t *testing.T) {
	doc := buildVEX(t, sampleSet(), vexOptions())

	for _, raw := range doc["vulnerabilities"].([]any) {
		vuln := raw.(map[string]any)
		status := vuln["product_status"].(map[string]any)

		affected := make(map[string]bool)
		for _, id := range stringsOf(status["known_affected"]) {
			affected[id] = true
		}
		for _, id := range stringsOf(status["under_investigation"]) {
			if affected[id] {
				t.Errorf("%s lists product %s as both affected and under investigation",
					vulnerabilityName(vuln), id)
			}
		}
	}
}

// TestAddressesStayOutOfTheDocumentByDefault. A VEX is made to be handed to
// somebody outside the plant, and the addresses of exploitable equipment are
// the last thing that should leave with it by accident.
func TestAddressesStayOutOfTheDocumentByDefault(t *testing.T) {
	var buf bytes.Buffer
	doc, err := BuildVEX(sampleSet(), vexOptions())
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	if err := WriteVEX(&buf, doc); err != nil {
		t.Fatalf("WriteVEX: %v", err)
	}

	for _, address := range []string{"10.10.1.5", "10.10.1.6", "10.10.2.9"} {
		if strings.Contains(buf.String(), address) {
			t.Errorf("device address %s leaked into the default VEX output", address)
		}
	}

	// It still has to say how many devices are behind a product, or the reader
	// cannot size the problem.
	if !strings.Contains(buf.String(), "2 devices") {
		t.Error("the document does not say how many devices run the shared product")
	}

	opts := vexOptions()
	opts.IncludeAddresses = true
	withAddresses, err := BuildVEX(sampleSet(), opts)
	if err != nil {
		t.Fatalf("BuildVEX: %v", err)
	}
	buf.Reset()
	if err := WriteVEX(&buf, withAddresses); err != nil {
		t.Fatalf("WriteVEX: %v", err)
	}
	if !strings.Contains(buf.String(), "10.10.1.5") {
		t.Error("--include-addresses did not put addresses in the document")
	}
}

// TestAVEXWithoutAPublisherIsRefused. The document is a statement by somebody,
// and this tool is not the somebody. Guessing a publisher would put words in an
// organisation's mouth.
func TestAVEXWithoutAPublisherIsRefused(t *testing.T) {
	for _, missing := range []VEXOptions{
		{PublisherNamespace: "https://water.example"},
		{PublisherName: "Example Water Authority"},
	} {
		if _, err := BuildVEX(sampleSet(), missing); err == nil {
			t.Errorf("a VEX was built with %+v, which names no issuer", missing)
		}
	}
}

func TestAnInvalidTLPLabelIsRefused(t *testing.T) {
	opts := vexOptions()
	opts.TLP = "PURPLE"
	if _, err := BuildVEX(sampleSet(), opts); err == nil {
		t.Error("TLP:PURPLE was accepted")
	}
}

// TestTheSameFindingsProduceTheSameDocument. Two assessments of an unchanged
// plant have to be diffable, or nobody can tell what moved between them.
func TestTheSameFindingsProduceTheSameDocument(t *testing.T) {
	render := func() string {
		var buf bytes.Buffer
		doc, err := BuildVEX(sampleSet(), vexOptions())
		if err != nil {
			t.Fatalf("BuildVEX: %v", err)
		}
		if err := WriteVEX(&buf, doc); err != nil {
			t.Fatalf("WriteVEX: %v", err)
		}
		return buf.String()
	}

	if first, second := render(), render(); first != second {
		t.Error("two runs over identical findings produced different documents")
	}
}

func TestCSVHasARowPerFindingAndAHeader(t *testing.T) {
	set := sampleSet()
	var buf bytes.Buffer
	if err := WriteCSV(&buf, set); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	body := strings.TrimPrefix(buf.String(), "\ufeff")
	if body == buf.String() {
		t.Error("the CSV has no byte order mark, so Excel will misread accented vendor names")
	}

	records, err := csv.NewReader(strings.NewReader(body)).ReadAll()
	if err != nil {
		t.Fatalf("the CSV does not parse: %v", err)
	}
	if len(records) != len(set.Findings)+1 {
		t.Fatalf("got %d rows including the header, want %d", len(records), len(set.Findings)+1)
	}
	if len(records[0]) != len(csvColumns) {
		t.Errorf("the header has %d columns, the column list has %d", len(records[0]), len(csvColumns))
	}
	for idx, row := range records {
		if len(row) != len(csvColumns) {
			t.Errorf("row %d has %d fields, want %d", idx, len(row), len(csvColumns))
		}
	}
}

// TestCSVLeavesAnAbsentScoreBlank. A CVSS of 0.0 and an advisory with no score
// are different facts, and a column showing 0.0 for both invites somebody to
// sort by it and conclude the unscored rows are harmless.
func TestCSVLeavesAnAbsentScoreBlank(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCSV(&buf, sampleSet()); err != nil {
		t.Fatalf("WriteCSV: %v", err)
	}

	records, err := csv.NewReader(strings.NewReader(strings.TrimPrefix(buf.String(), "\ufeff"))).ReadAll()
	if err != nil {
		t.Fatalf("the CSV does not parse: %v", err)
	}

	column := indexOf(records[0], "cvss")
	if column < 0 {
		t.Fatal("no cvss column")
	}
	unscored := records[len(records)-1]
	if unscored[column] != "" {
		t.Errorf("an advisory with no CVSS rendered as %q, want an empty cell", unscored[column])
	}
}

func TestTheHTMLReportIsSelfContained(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleSet(), HTMLOptions{Now: fixedTime}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := buf.String()

	// Anything that would make the browser reach out. This file gets opened on
	// a machine that may never have had a route off the plant, and a report that
	// renders as unstyled text because it wanted a font is a report nobody
	// trusts.
	for _, external := range []string{
		"http://", "src=\"//", "href=\"//", "@import", "cdn.", "fonts.googleapis",
	} {
		if strings.Contains(body, external) {
			t.Errorf("the HTML report contains %q, so it is not self contained", external)
		}
	}

	// Advisory URLs are the exception, and they are text rather than something
	// the browser fetches.
	if strings.Count(body, "https://") != strings.Count(body, "https://cisa.example/ICSA-24-100-01") {
		t.Error("the report links to an https resource other than the advisory references it prints")
	}
}

// TestTheHTMLReportEscapesWhatCameOffTheWire. Every product string in this
// report was supplied by a device under no obligation to be honest about its
// own name, and a product name is exactly where somebody would put a script tag.
func TestTheHTMLReportEscapesWhatCameOffTheWire(t *testing.T) {
	set := sampleSet()
	set.Findings[0].AssetLabel = `<script>alert("xss")</script>`
	set.Findings[0].MatchedProduct = `"><img src=x onerror=alert(1)>`
	set.Findings[0].AssetIdentity.Product = `</title><script>bad()</script>`

	var buf bytes.Buffer
	if err := WriteHTML(&buf, set, HTMLOptions{Now: fixedTime}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := buf.String()

	for _, injected := range []string{
		`<script>alert("xss")</script>`,
		`<img src=x onerror=alert(1)>`,
		`<script>bad()</script>`,
	} {
		if strings.Contains(body, injected) {
			t.Errorf("device supplied markup reached the page unescaped: %s", injected)
		}
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("the markup was not escaped, it was dropped, which hides what the device claimed")
	}
}

// TestTheHTMLReportSaysWhatItCouldNotSee. A report listing three findings and
// nothing else invites the reading that there are three problems. If a third of
// the inventory was never identifiable, that is the more important number.
func TestTheHTMLReportSaysWhatItCouldNotSee(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, sampleSet(), HTMLOptions{Now: fixedTime}); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	body := buf.String()

	for _, expected := range []string{"4 devices", "12", "Coverage is partial"} {
		if !strings.Contains(body, expected) {
			t.Errorf("the coverage note does not mention %q", expected)
		}
	}
}

// TestAnEmptyFindingsSetStillRenders. Zero findings is the most likely result of
// a first run, and it is exactly when a broken report would be least noticed.
func TestAnEmptyFindingsSetStillRenders(t *testing.T) {
	empty := finding.NewSet("otscout match")
	empty.GeneratedAt = fixedTime
	empty.Summary.AssetsConsidered = 5
	empty.Finalize()

	var html bytes.Buffer
	if err := WriteHTML(&html, empty, HTMLOptions{Now: fixedTime}); err != nil {
		t.Fatalf("WriteHTML on an empty set: %v", err)
	}
	if !strings.Contains(html.String(), "No advisory matched") {
		t.Error("the empty state does not explain that nothing matched")
	}
	if !strings.Contains(html.String(), "not a clean bill of health") {
		t.Error("the empty state reads as an all clear, which it is not")
	}

	var csvOut bytes.Buffer
	if err := WriteCSV(&csvOut, empty); err != nil {
		t.Fatalf("WriteCSV on an empty set: %v", err)
	}

	doc, err := BuildVEX(empty, vexOptions())
	if err != nil {
		t.Fatalf("BuildVEX on an empty set: %v", err)
	}
	if err := WriteVEX(io.Discard, doc); err != nil {
		t.Fatalf("WriteVEX on an empty set: %v", err)
	}
}

func vulnerabilityName(vuln map[string]any) string {
	if cve, ok := vuln["cve"].(string); ok && cve != "" {
		return cve
	}
	if ids, ok := vuln["ids"].([]any); ok && len(ids) > 0 {
		if text, ok := ids[0].(map[string]any)["text"].(string); ok {
			return text
		}
	}
	return "an unnamed vulnerability"
}

func referencedProducts(vuln map[string]any) []string {
	var out []string
	if status, ok := vuln["product_status"].(map[string]any); ok {
		for _, key := range []string{"known_affected", "under_investigation"} {
			out = append(out, stringsOf(status[key])...)
		}
	}
	for _, key := range []string{"remediations", "threats"} {
		items, _ := vuln[key].([]any)
		for _, raw := range items {
			out = append(out, stringsOf(raw.(map[string]any)["product_ids"])...)
		}
	}
	scores, _ := vuln["scores"].([]any)
	for _, raw := range scores {
		out = append(out, stringsOf(raw.(map[string]any)["products"])...)
	}
	return out
}

func stringsOf(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func indexOf(row []string, name string) int {
	for idx, value := range row {
		if value == name {
			return idx
		}
	}
	return -1
}
