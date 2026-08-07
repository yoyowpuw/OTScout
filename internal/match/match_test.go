package match

import (
	"strings"
	"testing"
	"time"

	"github.com/yoyowpuw/OTScout/internal/advisory"
	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// testCorpus builds an in memory corpus, normalizing it the way sync does so the
// matcher sees exactly what it would see on a real run.
func testCorpus(t *testing.T, advisories ...advisory.Advisory) *advisory.Corpus {
	t.Helper()
	normalizer, err := normalize.New()
	if err != nil {
		t.Fatalf("normalizer: %v", err)
	}
	corpus := advisory.NewCorpus(t.TempDir())
	for idx := range advisories {
		advisories[idx].Normalize(normalizer)
		corpus.Advisories = append(corpus.Advisories, advisories[idx])
	}
	corpus.Reindex()
	corpus.ApplyEnrichment()
	return corpus
}

func testInventory(t *testing.T, assets ...asset.Asset) *asset.Inventory {
	t.Helper()
	normalizer, err := normalize.New()
	if err != nil {
		t.Fatalf("normalizer: %v", err)
	}
	inv := asset.NewInventory("test")
	for _, a := range assets {
		if a.ID == "" {
			a.ID = asset.NewID(a.Addresses)
		}
		inv.Upsert(a)
	}
	normalizer.Inventory(inv)
	return inv
}

func run(t *testing.T, corpus *advisory.Corpus, inv *asset.Inventory) *finding.Set {
	t.Helper()
	matcher, err := New(corpus, Options{})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	return matcher.Run(inv)
}

// foxmanAdvisory is the advisory that motivated this project: a Hitachi Energy
// product with the range "<R15A", which no generic version comparator can
// evaluate.
func foxmanAdvisory() advisory.Advisory {
	return advisory.Advisory{
		ID:        "cisa-icsa-00-000-01",
		Source:    "cisa-csaf",
		Title:     "Hitachi Energy FOXMAN-UN",
		URL:       "https://example.invalid/foxman",
		Published: time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC),
		Products: []advisory.Product{{
			ID:         "CSAFPID-0001",
			Name:       "Hitachi Energy FOXMAN-UN <R15A",
			VendorRaw:  "Hitachi Energy",
			ProductRaw: "FOXMAN-UN",
			VersionRaw: "<R15A",
		}},
		Vulnerabilities: []advisory.Vulnerability{{
			CVE: "CVE-2024-0001",
			Scores: []advisory.Score{{
				Version:   "3.1",
				BaseScore: 9.8,
				Severity:  advisory.SeverityCritical,
				Vector:    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			}},
			Status: map[advisory.Status][]string{
				advisory.StatusKnownAffected: {"CSAFPID-0001"},
			},
			Remediations: []advisory.Remediation{{
				Category: "vendor_fix",
				Details:  "Update to R15A or later",
				URL:      "https://example.invalid/fix",
			}},
		}},
	}
}

func foxmanAsset(firmware string) asset.Asset {
	return asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.5"},
		Identity: asset.Identity{
			Vendor:   "Hitachi Energy",
			Product:  "FOXMAN-UN",
			Firmware: firmware,
		},
	}
}

func TestMatchConfirmsTheFoxmanAdvisoryAgainstAnAffectedRelease(t *testing.T) {
	set := run(t, testCorpus(t, foxmanAdvisory()), testInventory(t, foxmanAsset("R14B")))

	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if f.Tier != finding.TierConfirmed {
		t.Errorf("tier = %q, want confirmed: %+v", f.Tier, f.Reasons)
	}
	if f.VersionCheck == nil {
		t.Fatal("a finding must carry its version check")
	}
	// The whole point of the per vendor comparator: a generic one cannot order
	// R14B against R15A at all.
	if f.VersionCheck.Comparator != "abb" {
		t.Errorf("comparator = %q, want abb", f.VersionCheck.Comparator)
	}
	if f.VersionCheck.Result != string(normalize.EvalAffected) {
		t.Errorf("version result = %q, want affected", f.VersionCheck.Result)
	}
	if len(f.CVEs) != 1 || f.CVEs[0] != "CVE-2024-0001" {
		t.Errorf("cves = %v", f.CVEs)
	}
	if f.CVSS != 9.8 || f.Severity != string(advisory.SeverityCritical) {
		t.Errorf("score = %v %q", f.CVSS, f.Severity)
	}
	if !f.FixAvailable {
		t.Error("the advisory offers a vendor fix, which the finding must say")
	}
}

func TestMatchRulesOutAReleaseTheAdvisoryDoesNotCover(t *testing.T) {
	set := run(t, testCorpus(t, foxmanAdvisory()), testInventory(t, foxmanAsset("R16B_PC4")))

	if len(set.Findings) != 0 {
		t.Fatalf("got %d findings, want none: %+v", len(set.Findings), set.Findings[0].Reasons)
	}
	// Silence is not enough. An operator has to be able to see that the corpus was
	// consulted and the device was dismissed on evidence, otherwise an empty
	// report is indistinguishable from a broken run.
	if set.Summary.RuledOutByVersion != 1 {
		t.Errorf("ruled out by version = %d, want 1", set.Summary.RuledOutByVersion)
	}
}

func TestMatchReportsLikelyWhenTheDeviceHidesItsFirmware(t *testing.T) {
	set := run(t, testCorpus(t, foxmanAdvisory()), testInventory(t, foxmanAsset("")))

	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	// Neither "affected" nor "safe" is defensible without a version, so the
	// answer has to be its own tier rather than a coin flip.
	if f.Tier != finding.TierLikely {
		t.Errorf("tier = %q, want likely", f.Tier)
	}
	if f.VersionCheck.Result != string(normalize.EvalIndeterminate) {
		t.Errorf("version result = %q, want indeterminate", f.VersionCheck.Result)
	}
	// The failed step is kept so that nobody redoes the check by hand.
	var found bool
	for _, r := range f.Reasons {
		if r.Kind == finding.ReasonVersionUnknown {
			found = true
			if r.Passed {
				t.Error("an unanswered version check must not be recorded as passed")
			}
			if r.Detail == "" {
				t.Error("every reason must explain itself")
			}
		}
	}
	if !found {
		t.Errorf("no version_unknown reason recorded: %+v", f.Reasons)
	}
}

func TestMatchIgnoresAnAssetThatOnlySharesAVendor(t *testing.T) {
	// This is the single most important negative case in the package. A vendor
	// gate on its own would attach every Siemens advisory to every Siemens
	// device, and an engineer handed that list stops using the tool.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-02",
		Source: "cisa-csaf",
		Title:  "Siemens SCALANCE W700",
		Products: []advisory.Product{{
			ID:         "CSAFPID-0001",
			VendorRaw:  "Siemens",
			ProductRaw: "SCALANCE W748-1",
			VersionRaw: "<V6.5",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-0002"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.9"},
		Identity: asset.Identity{
			Vendor:   "Siemens",
			Product:  "SIMATIC S7-1200",
			Firmware: "V4.2",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 0 {
		t.Fatalf("a shared vendor produced %d findings: %+v",
			len(set.Findings), set.Findings[0].Reasons)
	}
}

func TestMatchReportsALeadWhenTheAdvisoryNamesAModelTheDeviceDidNot(t *testing.T) {
	// The advisory names a specific CPU. The device knows only its family. The
	// range is satisfied, but which member of the family is on the wire is
	// exactly what nobody knows, so this cannot rise above a lead.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-03",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "CSAFPID-0001",
			VendorRaw:  "Siemens",
			FamilyRaw:  "SIMATIC S7-1200",
			ProductRaw: "CPU 1215C",
			VersionRaw: "<V4.5",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-0003"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.11"},
		Identity: asset.Identity{
			Vendor:   "Siemens",
			Family:   "SIMATIC S7-1200",
			Firmware: "V4.2",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if f.Tier != finding.TierPossible {
		t.Errorf("tier = %q, want possible: %+v", f.Tier, f.Reasons)
	}
	// The reason the finding is only a lead has to be on the record, or an
	// operator cannot tell it apart from a weak match of some other kind.
	var explained bool
	for _, r := range f.Reasons {
		if !r.Passed && strings.Contains(r.Detail, "CPU 1215C") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("the evidence should name the designation that went unconfirmed: %+v", f.Reasons)
	}
}

func TestMatchConfirmsAFamilyWideAdvisoryAgainstAFamilyLevelIdentity(t *testing.T) {
	// An advisory that says every S7-1200 is affected has settled the question for
	// a device known to be an S7-1200. Neither side named a model, and neither
	// needed to. Filing this as a lead would bury a large and very real class of
	// finding under the weakest tier.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-12",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:        "p1",
			VendorRaw: "Siemens",
			FamilyRaw: "SIMATIC S7-1200",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9100"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.12"},
		Identity:  asset.Identity{Vendor: "Siemens", Family: "SIMATIC S7-1200"},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	if got := set.Findings[0].Tier; got != finding.TierConfirmed {
		t.Errorf("tier = %q, want confirmed: %+v", got, set.Findings[0].Reasons)
	}
}

func TestMatchTreatsAnAdvisoryWithNoVersionAsCoveringEveryVersion(t *testing.T) {
	// A hardware advisory names a product and no version, which is the most
	// common shape in ICS. Reading that as "no version information" rather than
	// "every version" would silently drop a whole class of real findings.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-04",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "CSAFPID-0001",
			VendorRaw:  "Rockwell Automation",
			ProductRaw: "1756-L71",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-0004"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.20"},
		Identity: asset.Identity{
			Vendor:        "Rockwell Automation",
			CatalogNumber: "1756-L71",
			Product:       "1756-L71",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if f.Tier != finding.TierConfirmed {
		t.Errorf("tier = %q, want confirmed: %+v", f.Tier, f.Reasons)
	}
	var sawAll bool
	for _, r := range f.Reasons {
		if r.Kind == finding.ReasonVersionAllAffect {
			sawAll = true
		}
	}
	if !sawAll {
		t.Errorf("the evidence should say every version is affected: %+v", f.Reasons)
	}
}

func TestMatchAttributesOnlyTheCVEsThatNameTheMatchedProduct(t *testing.T) {
	// A CISA advisory routinely covers a dozen devices, where each CVE hits a
	// subset. Attributing all of them to every matched device would inflate every
	// report and is the fastest way to lose an engineer's trust.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-05",
		Source: "cisa-csaf",
		Products: []advisory.Product{
			{ID: "CSAFPID-0001", VendorRaw: "Moxa", ProductRaw: "EDS-405A"},
			{ID: "CSAFPID-0002", VendorRaw: "Moxa", ProductRaw: "EDS-508A"},
		},
		Vulnerabilities: []advisory.Vulnerability{
			{
				CVE:    "CVE-2024-1000",
				Status: map[advisory.Status][]string{advisory.StatusKnownAffected: {"CSAFPID-0001"}},
			},
			{
				CVE:    "CVE-2024-2000",
				Status: map[advisory.Status][]string{advisory.StatusKnownAffected: {"CSAFPID-0002"}},
			},
		},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.30"},
		Identity:  asset.Identity{Vendor: "Moxa", Product: "EDS-405A"},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	got := set.Findings[0].CVEs
	if len(got) != 1 || got[0] != "CVE-2024-1000" {
		t.Errorf("cves = %v, want only the one naming EDS-405A", got)
	}
}

func TestMatchAttributesEveryCVEWhenTheAdvisoryListsNoProductStatus(t *testing.T) {
	// Some sources, the ICS Advisory Project CSV among them, carry no product
	// status at all. Dropping every CVE in that case would silently discard a
	// whole source.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "icsa-00-000-06",
		Source: "ics-advisory-project",
		Products: []advisory.Product{
			{ID: "p1", VendorRaw: "Moxa", ProductRaw: "EDS-405A"},
		},
		Vulnerabilities: []advisory.Vulnerability{
			{CVE: "CVE-2024-3000"},
			{CVE: "CVE-2024-4000"},
		},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.31"},
		Identity:  asset.Identity{Vendor: "Moxa", Product: "EDS-405A"},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	if len(set.Findings[0].CVEs) != 2 {
		t.Errorf("cves = %v, want both", set.Findings[0].CVEs)
	}
}

func TestMatchEmitsOneFindingPerAdvisoryNotPerProductNode(t *testing.T) {
	// CERT@VDE advisories carry a hardware node and a firmware node for the same
	// device, and CISA trees list every variant. One finding per node would hand
	// an engineer a list they have to dismiss an entry at a time.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "vde-2024-001",
		Source: "csaf-certvde",
		Products: []advisory.Product{
			{ID: "hw", VendorRaw: "TECSON", FamilyRaw: "Hardware", ProductRaw: "LX-Net"},
			{ID: "fw1", VendorRaw: "TECSON", FamilyRaw: "Firmware",
				ProductRaw: "Firmware all versions installed on LX-Net", VersionRaw: "vers:all/*"},
			{ID: "fw2", VendorRaw: "TECSON", FamilyRaw: "Firmware",
				ProductRaw: "LX-Net", VersionRaw: "vers:all/*"},
		},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-5000"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.40"},
		Identity:  asset.Identity{Vendor: "TECSON", Product: "LX-Net"},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1 per advisory", len(set.Findings))
	}
	f := set.Findings[0]
	if len(f.AlsoMatched) == 0 {
		t.Error("the collapsed product nodes must still be listed as evidence")
	}
	if f.MatchedProductID == "" {
		t.Error("the finding must name which product node it settled on")
	}
}

func TestMatchPrefersAnOrderCodeOverAFamilyName(t *testing.T) {
	// Both nodes match. The order code names one orderable item and the family
	// name names a hundred, so the finding has to be built on the former or its
	// tier understates what is known.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-07",
		Source: "cisa-csaf",
		Products: []advisory.Product{
			{ID: "family", VendorRaw: "Siemens", FamilyRaw: "SIMATIC S7-1200"},
			{ID: "exact", VendorRaw: "Siemens", CatalogNumber: "6ES7214-1AG40-0XB0"},
		},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-6000"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.50"},
		Identity: asset.Identity{
			Vendor:        "Siemens",
			CatalogNumber: "6ES7214-1AG40-0XB0",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if f.MatchedProductID != "exact" {
		t.Errorf("settled on product %q, want the order code node", f.MatchedProductID)
	}
	if f.Tier != finding.TierConfirmed {
		t.Errorf("tier = %q, want confirmed", f.Tier)
	}
}

func TestMatchAcceptsAnOrderCodeWrittenWithDifferentSeparators(t *testing.T) {
	// One order code, two spellings. Everyone who writes an MLFB puts the spaces
	// and hyphens somewhere slightly different, so comparing them as ordinary
	// product names would fail on the single strongest identifier either side ever
	// carries.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-13",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:            "p1",
			VendorRaw:     "Siemens",
			CatalogNumber: "6ES7214-1AG40-0XB0",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9200"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.13"},
		Identity: asset.Identity{
			Vendor:        "Siemens",
			CatalogNumber: "6ES7 214-1AG40-0XB0",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	var viaCode bool
	for _, r := range set.Findings[0].Reasons {
		if r.Kind == finding.ReasonCatalogNumber {
			viaCode = true
		}
	}
	if !viaCode {
		t.Errorf("the match should be credited to the order code: %+v", set.Findings[0].Reasons)
	}
}

func TestMatchReadsAnOrderCodeSiemensPrintedInsideTheProductName(t *testing.T) {
	// This is the shape of nearly every real Siemens advisory, and Siemens is by a
	// wide margin the largest publisher of ICS advisories. A device that reports
	// its MLFB and nothing else has to reach these.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-14",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Siemens",
			FamilyRaw:  "SCALANCE",
			Name:       "SCALANCE M804PB (6GK5804-0AP00-2AA2)",
			ProductRaw: "SCALANCE M804PB (6GK5804-0AP00-2AA2)",
			VersionRaw: "vers:intdot/<6.4",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9300"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.14"},
		Identity: asset.Identity{
			Vendor:        "Siemens",
			CatalogNumber: "6GK5804-0AP00-2AA2",
			Firmware:      "6.2",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if f.Tier != finding.TierConfirmed {
		t.Errorf("tier = %q, want confirmed: %+v", f.Tier, f.Reasons)
	}
}

func TestMatchRejectsANodeWhoseOrderCodeIsNotTheDevicesOwn(t *testing.T) {
	// Both are Siemens, both are called SIMATIC, and the advisory names an order
	// code that is not this device's. They are different orderable items, and no
	// amount of overlap in the marketing names changes that.
	//
	// This was a real false positive found against the live CISA corpus: an
	// S7-1200 CPU picked up an advisory against a SIMATIC IOT2050 gateway because
	// the product line name "SIMATIC S7" sat inside "SIMATIC S7-1200".
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-16",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Siemens",
			Name:       "SIMATIC IOT2050 (6ES7647-0BA00-1YA2)",
			ProductRaw: "SIMATIC IOT2050 (6ES7647-0BA00-1YA2)",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9400"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.16"},
		Identity: asset.Identity{
			Vendor:        "Siemens",
			CatalogNumber: "6ES7 214-1AG40-0XB0",
			Firmware:      "V4.2.3",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 0 {
		t.Errorf("a mismatched order code produced %d findings: %+v",
			len(set.Findings), set.Findings[0].Reasons)
	}
}

func TestMatchDoesNotReadAProductLineAsMembershipOfAModelList(t *testing.T) {
	// A device that knows only that it is a SCALANCE has not been shown to be any
	// of the specific switches this advisory lists. Treating the line name as a
	// match on the list would attach it to every SCALANCE advisory ever published
	// as though the model were known.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-17",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Siemens",
			FamilyRaw:  "SCALANCE",
			ProductRaw: "SCALANCE XC-300/XR-300/XC-400/XR-500WG/XR-500 family",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9500"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.17"},
		Identity:  asset.Identity{Vendor: "Siemens", Family: "SCALANCE", Firmware: "6.2"},
	})

	set := run(t, corpus, inv)
	// It is still a lead, because the advisory does cover some SCALANCE switches.
	// What it must not be is a conclusion.
	for _, f := range set.Findings {
		if f.Tier != finding.TierPossible {
			t.Errorf("tier = %q, want possible at most: %+v", f.Tier, f.Reasons)
		}
	}
}

func TestMatchTreatsALongerNameWithOnlyFillerAddedAsTheSameProduct(t *testing.T) {
	// Schneider publishes "Modicon M340 Controller" where the device reports
	// "Modicon M340". The extra word is filler, so refusing the match here would
	// lose a real finding for no gain.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-18",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Schneider Electric",
			ProductRaw: "Modicon M340 Controller",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9600"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.18"},
		Identity:  asset.Identity{Vendor: "Schneider Electric", Product: "Modicon M340"},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
}

func TestMatchDoesNotTakeARegionSuffixForAnOrderCode(t *testing.T) {
	// The same product names carry brackets around region codes and hardware
	// revisions. Reading "(EU)" as an order code would attach advisories to
	// whatever else happened to be sold in Europe.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-15",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Siemens",
			Name:       "SCALANCE MUM856-1 (Europe and rest of world)",
			ProductRaw: "SCALANCE MUM856-1 (Europe and rest of world)",
		}},
	})
	if got := corpus.Advisories[0].Products[0].CatalogNumber; got != "" {
		t.Errorf("catalog number = %q, want it left empty", got)
	}
}

func TestMatchDoesNotMatchOnAGenericWordSharedByEveryAdvisory(t *testing.T) {
	// "Firmware" and "Controller" appear in thousands of advisory product nodes.
	// Matching on either would make the tool worse than useless, because the
	// findings would look plausible.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-08",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Moxa",
			FamilyRaw:  "Firmware",
			ProductRaw: "Firmware for the NPort 5100 series",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-7000"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.60"},
		Identity: asset.Identity{
			Vendor:  "Moxa",
			Product: "Firmware",
			Family:  "Firmware",
		},
	})

	set := run(t, corpus, inv)
	// The word "Firmware" is common to both sides and carries no information, so
	// a match on it would be an artefact of string overlap and nothing else.
	if len(set.Findings) != 0 {
		t.Errorf("a generic word produced %d findings: %+v",
			len(set.Findings), set.Findings[0].Reasons)
	}
}

func TestInformativeSeparatesDesignationsFromWordsEveryAdvisoryUses(t *testing.T) {
	for _, key := range []string{"firmware", "controller", "all versions", "plc", "cpu", "system"} {
		if informative(key) {
			t.Errorf("%q was treated as a designation", key)
		}
	}
	for _, key := range []string{"cpu 1214c", "lx net", "s7 1200", "eds 405a", "foxman un"} {
		if !informative(key) {
			t.Errorf("%q was treated as noise", key)
		}
	}
}

func TestMatchFindsADesignationInsideALongAdvisoryProductName(t *testing.T) {
	// The device reports a bare designation and the advisory spells out the full
	// marketing name. This is the ordinary case on the wire, so recall depends on
	// it working.
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-09",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Siemens",
			ProductRaw: "SIMATIC S7-1200 CPU 1214C DC/DC/DC",
			VersionRaw: "<V4.5",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-8000"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.70"},
		Identity: asset.Identity{
			Vendor:   "Siemens",
			Model:    "CPU 1214C",
			Firmware: "V4.2.3",
		},
	})

	set := run(t, corpus, inv)
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if f.Tier != finding.TierConfirmed {
		t.Errorf("tier = %q, want confirmed: %+v", f.Tier, f.Reasons)
	}
}

func TestMatchCarriesKEVAndEPSSThroughToTheFinding(t *testing.T) {
	corpus := testCorpus(t, foxmanAdvisory())
	corpus.KEV["CVE-2024-0001"] = advisory.KEVEntry{
		DateAdded:       time.Date(2024, 6, 1, 0, 0, 0, 0, time.UTC),
		KnownRansomware: true,
	}
	corpus.EPSS["CVE-2024-0001"] = advisory.EPSS{Score: 0.84, Percentile: 0.99}
	corpus.ApplyEnrichment()

	set := run(t, corpus, testInventory(t, foxmanAsset("R14B")))
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if !f.KEV {
		t.Error("a CVE in the KEV catalogue must be flagged")
	}
	if f.EPSS != 0.84 {
		t.Errorf("epss = %v, want 0.84", f.EPSS)
	}
	if set.Summary.KEVCount != 1 {
		t.Errorf("summary kev count = %d, want 1", set.Summary.KEVCount)
	}
}

func TestMatchSortsKnownExploitedAboveAHigherScoringUnexploitedFlaw(t *testing.T) {
	// For a plant operator, something being exploited right now outranks
	// something theoretically worse that nobody is using.
	exploited := foxmanAdvisory()
	exploited.ID = "cisa-exploited"
	exploited.Vulnerabilities[0].CVE = "CVE-2024-1111"
	exploited.Vulnerabilities[0].Scores[0].BaseScore = 7.5

	worse := foxmanAdvisory()
	worse.ID = "cisa-worse"
	worse.Vulnerabilities[0].CVE = "CVE-2024-2222"
	worse.Vulnerabilities[0].Scores[0].BaseScore = 10.0

	corpus := testCorpus(t, exploited, worse)
	corpus.KEV["CVE-2024-1111"] = advisory.KEVEntry{}
	corpus.ApplyEnrichment()

	set := run(t, corpus, testInventory(t, foxmanAsset("R14B")))
	if len(set.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(set.Findings))
	}
	if set.Findings[0].AdvisoryID != "cisa-exploited" {
		t.Errorf("first finding = %q, want the exploited one", set.Findings[0].AdvisoryID)
	}
}

func TestMatchCountsAssetsItCouldNotUse(t *testing.T) {
	// An empty findings list means one thing if nothing matched and quite another
	// if nothing was identifiable. An operator has to be able to tell which, or
	// they will read a broken ingest as a clean site.
	inv := testInventory(t,
		asset.Asset{Addresses: asset.Addresses{IPv4: "10.0.0.1"}},
		asset.Asset{
			Addresses: asset.Addresses{IPv4: "10.0.0.2"},
			Identity:  asset.Identity{Vendor: "Some Unlisted Startup", Product: "Widget"},
		},
		foxmanAsset("R14B"),
	)

	set := run(t, testCorpus(t, foxmanAdvisory()), inv)
	if set.Summary.AssetsConsidered != 3 {
		t.Errorf("considered = %d, want 3", set.Summary.AssetsConsidered)
	}
	if set.Summary.AssetsUnidentified != 1 {
		t.Errorf("unidentified = %d, want 1", set.Summary.AssetsUnidentified)
	}
	if set.Summary.AssetsUnknownVendo != 1 {
		t.Errorf("unknown vendor = %d, want 1", set.Summary.AssetsUnknownVendo)
	}
	if set.Summary.AssetsAffected != 1 {
		t.Errorf("affected = %d, want 1", set.Summary.AssetsAffected)
	}
}

func TestMatchMinTierDropsWeakerLeads(t *testing.T) {
	corpus := testCorpus(t, advisory.Advisory{
		ID:     "cisa-icsa-00-000-10",
		Source: "cisa-csaf",
		Products: []advisory.Product{{
			ID:         "p1",
			VendorRaw:  "Siemens",
			FamilyRaw:  "SIMATIC S7-1200",
			ProductRaw: "CPU 1217C",
		}},
		Vulnerabilities: []advisory.Vulnerability{{CVE: "CVE-2024-9000"}},
	})
	inv := testInventory(t, asset.Asset{
		Addresses: asset.Addresses{IPv4: "10.10.1.80"},
		Identity:  asset.Identity{Vendor: "Siemens", Family: "SIMATIC S7-1200"},
	})

	matcher, err := New(corpus, Options{MinTier: finding.TierLikely})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	if set := matcher.Run(inv); len(set.Findings) != 0 {
		t.Errorf("got %d findings, want none above the floor", len(set.Findings))
	}
}

func TestMatchSinceDropsOlderAdvisories(t *testing.T) {
	corpus := testCorpus(t, foxmanAdvisory())
	matcher, err := New(corpus, Options{Since: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	if set := matcher.Run(testInventory(t, foxmanAsset("R14B"))); len(set.Findings) != 0 {
		t.Errorf("got %d findings, want none from before the cutoff", len(set.Findings))
	}
}

func TestMatchProducesIdenticalOutputOnASecondRun(t *testing.T) {
	// Findings get committed and diffed between scans, so a run that reorders its
	// own output makes every baseline diff unreadable. Map iteration is the
	// obvious way to get this wrong, and this package iterates two of them.
	corpus := testCorpus(t, foxmanAdvisory(), func() advisory.Advisory {
		second := foxmanAdvisory()
		second.ID = "cisa-icsa-00-000-11"
		second.Vulnerabilities[0].CVE = "CVE-2024-0011"
		return second
	}())
	inv := testInventory(t, foxmanAsset("R14B"))

	first := run(t, corpus, inv)
	for attempt := 0; attempt < 20; attempt++ {
		again := run(t, corpus, inv)
		if len(again.Findings) != len(first.Findings) {
			t.Fatalf("run %d produced %d findings, first produced %d",
				attempt, len(again.Findings), len(first.Findings))
		}
		for idx := range again.Findings {
			if again.Findings[idx].ID != first.Findings[idx].ID {
				t.Fatalf("run %d reordered findings at %d: %q then %q",
					attempt, idx, first.Findings[idx].ID, again.Findings[idx].ID)
			}
		}
	}
}

func TestMatchRecordsTheEvidenceTrailBackToTheWire(t *testing.T) {
	// The evidence screen shows the raw bytes beside the advisory node. It can
	// only do that if the finding names the observations it was built from.
	a := foxmanAsset("R14B")
	a.ID = asset.NewID(a.Addresses)
	a.AddEvidence(asset.Evidence{
		Source:   asset.SourcePcap,
		Protocol: "s7comm",
		Response: asset.HexBytes{0x03, 0x00, 0x00, 0x1f},
	})

	set := run(t, testCorpus(t, foxmanAdvisory()), testInventory(t, a))
	if len(set.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(set.Findings))
	}
	f := set.Findings[0]
	if len(f.EvidenceIDs) != 1 {
		t.Errorf("evidence ids = %v, want the one observation", f.EvidenceIDs)
	}
	if f.AssetIdentity.Vendor != "hitachi-energy" {
		t.Errorf("asset identity vendor = %q, want the canonical id", f.AssetIdentity.Vendor)
	}
	if f.MatchedVendor == "" || f.MatchedProduct == "" {
		t.Error("the advisory side of the comparison must be recorded verbatim")
	}
}

func TestMatchNeedsNoCorpusToBeSafeToCall(t *testing.T) {
	if _, err := New(nil, Options{}); err == nil {
		t.Error("a nil corpus should be refused rather than panic later")
	}
	matcher, err := New(advisory.NewCorpus(t.TempDir()), Options{})
	if err != nil {
		t.Fatalf("new matcher: %v", err)
	}
	if set := matcher.Run(nil); len(set.Findings) != 0 {
		t.Error("a nil inventory should produce an empty set")
	}
}
