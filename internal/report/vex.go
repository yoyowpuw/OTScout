package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/version"
)

// CSAF 2.0, profile 5 (VEX). The requirements this file satisfies are in
// section 4.5 of the specification, and they are stricter than they look:
//
//   - Every product referenced anywhere must appear in /product_tree.
//   - Every vulnerability needs a cve or an ids entry, and a note.
//   - Every product in known_affected needs an action statement in
//     remediations. A status without one is not a valid VEX, which is the
//     specification saying that telling somebody they are exposed without
//     telling them what to do about it is not useful.
//   - Recommended test 6.2.2 extends that requirement to under_investigation,
//     which this file also satisfies.
const (
	csafVersion  = "2.0"
	csafCategory = "csaf_vex"
)

// VEXOptions are the parts of a VEX document that describe the issuer rather
// than the findings.
type VEXOptions struct {
	// PublisherName is the organisation stating the exposure. There is no
	// sensible default: a VEX is a statement by somebody, and this tool is not
	// the somebody.
	PublisherName string

	// PublisherNamespace is a URI identifying the issuer, required by the base
	// profile.
	PublisherNamespace string

	// TrackingID names this document. Defaults to a timestamped id.
	TrackingID string

	// TLP is the sharing label. A document listing which of your plant's devices
	// are exploitable is not public information, so the default is AMBER rather
	// than none.
	TLP string

	// IncludeAddresses puts device addresses in the product entries.
	//
	// Off by default. A VEX is made to be handed to an auditor, a regulator or a
	// partner, and the addresses of exploitable equipment are the part of an
	// inventory least suited to leaving the site. The document says how many
	// devices run each product either way, which is what the recipient needs.
	IncludeAddresses bool

	// Now is the document timestamp, for tests.
	Now time.Time
}

// tlpLabels are the values CSAF 2.0 accepts.
var tlpLabels = map[string]bool{"RED": true, "AMBER": true, "GREEN": true, "WHITE": true}

func (o *VEXOptions) applyDefaults() error {
	if strings.TrimSpace(o.PublisherName) == "" {
		return fmt.Errorf("a VEX document has to say who is making the statement; pass --publisher")
	}
	if strings.TrimSpace(o.PublisherNamespace) == "" {
		return fmt.Errorf("a VEX document needs a publisher namespace URI; pass --publisher-namespace")
	}
	if o.Now.IsZero() {
		o.Now = time.Now().UTC()
	}
	if o.TrackingID == "" {
		o.TrackingID = "OTSCOUT-" + o.Now.Format("20060102-150405")
	}
	if o.TLP == "" {
		o.TLP = "AMBER"
	}
	o.TLP = strings.ToUpper(o.TLP)
	if !tlpLabels[o.TLP] {
		return fmt.Errorf("TLP label %q is not one of RED, AMBER, GREEN or WHITE", o.TLP)
	}
	return nil
}

// VEX is a CSAF 2.0 document restricted to the VEX profile.
type VEX struct {
	Document        vexDocument     `json:"document"`
	ProductTree     vexProductTree  `json:"product_tree"`
	Vulnerabilities []vexVulnerable `json:"vulnerabilities"`
}

type vexDocument struct {
	Category     string           `json:"category"`
	CSAFVersion  string           `json:"csaf_version"`
	Title        string           `json:"title"`
	Lang         string           `json:"lang,omitempty"`
	Publisher    vexPublisher     `json:"publisher"`
	Tracking     vexTracking      `json:"tracking"`
	Distribution *vexDistribution `json:"distribution,omitempty"`
	Notes        []vexNote        `json:"notes,omitempty"`
}

type vexPublisher struct {
	// Category is "user": the issuer operates these products rather than
	// making them, which is the whole perspective this document is written from.
	Category         string `json:"category"`
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
}

type vexTracking struct {
	ID                 string       `json:"id"`
	Status             string       `json:"status"`
	Version            string       `json:"version"`
	InitialReleaseDate time.Time    `json:"initial_release_date"`
	CurrentReleaseDate time.Time    `json:"current_release_date"`
	Generator          vexGenerator `json:"generator"`
	RevisionHistory    []vexRevisio `json:"revision_history"`
}

type vexGenerator struct {
	Date   time.Time   `json:"date"`
	Engine vexEngineID `json:"engine"`
}

type vexEngineID struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type vexRevisio struct {
	Number  string    `json:"number"`
	Date    time.Time `json:"date"`
	Summary string    `json:"summary"`
}

type vexDistribution struct {
	TLP vexTLP `json:"tlp"`
}

type vexTLP struct {
	Label string `json:"label"`
}

type vexNote struct {
	Category string `json:"category"`
	Title    string `json:"title,omitempty"`
	Text     string `json:"text"`
}

type vexProductTree struct {
	FullProductNames []vexProduct `json:"full_product_names"`
}

type vexProduct struct {
	ProductID string `json:"product_id"`
	Name      string `json:"name"`
}

type vexVulnerable struct {
	CVE          string           `json:"cve,omitempty"`
	IDs          []vexExternalID  `json:"ids,omitempty"`
	Title        string           `json:"title,omitempty"`
	Notes        []vexNote        `json:"notes"`
	ProductStatu vexProductStatus `json:"product_status"`
	Scores       []vexScore       `json:"scores,omitempty"`
	Threats      []vexThreat      `json:"threats,omitempty"`
	Remediations []vexRemediation `json:"remediations"`
	References   []vexReference   `json:"references,omitempty"`
}

type vexExternalID struct {
	SystemName string `json:"system_name"`
	Text       string `json:"text"`
}

type vexProductStatus struct {
	KnownAffected     []string `json:"known_affected,omitempty"`
	UnderInvestigatio []string `json:"under_investigation,omitempty"`
}

type vexScore struct {
	Products []string   `json:"products"`
	CVSSV3   *vexCVSSv3 `json:"cvss_v3,omitempty"`
}

type vexCVSSv3 struct {
	Version      string  `json:"version"`
	VectorString string  `json:"vectorString"`
	BaseScore    float64 `json:"baseScore"`
	BaseSeverity string  `json:"baseSeverity"`
}

type vexThreat struct {
	Category   string    `json:"category"`
	Details    string    `json:"details"`
	ProductIDs []string  `json:"product_ids,omitempty"`
	Date       time.Time `json:"date,omitzero"`
}

type vexRemediation struct {
	Category   string   `json:"category"`
	Details    string   `json:"details"`
	ProductIDs []string `json:"product_ids,omitempty"`
	URL        string   `json:"url,omitempty"`
}

type vexReference struct {
	Category string `json:"category,omitempty"`
	Summary  string `json:"summary"`
	URL      string `json:"url"`
}

// productEntry is one distinct product in the inventory, and the assets running
// it.
//
// Products rather than assets are the unit here because that is what VEX states
// about. Twenty identical drives are one product entry with a count, not twenty
// entries, and the recipient of the document learns the same thing either way.
type productEntry struct {
	id      string
	name    string
	assets  map[string]bool
	address []string
}

// BuildVEX turns findings into a CSAF 2.0 VEX document.
func BuildVEX(set *finding.Set, opts VEXOptions) (*VEX, error) {
	if err := opts.applyDefaults(); err != nil {
		return nil, err
	}

	products, byFinding := collectProducts(set, opts.IncludeAddresses)

	doc := &VEX{
		Document: vexDocument{
			Category:    csafCategory,
			CSAFVersion: csafVersion,
			Title: fmt.Sprintf("Exposure of %s to %s",
				plural(len(products), "product"), plural(set.Summary.UniqueCVEs, "CVE")),
			Lang: "en-US",
			Publisher: vexPublisher{
				Category:  "user",
				Name:      opts.PublisherName,
				Namespace: opts.PublisherNamespace,
			},
			Tracking: vexTracking{
				ID:                 opts.TrackingID,
				Status:             "final",
				Version:            "1",
				InitialReleaseDate: opts.Now,
				CurrentReleaseDate: opts.Now,
				Generator: vexGenerator{
					Date:   opts.Now,
					Engine: vexEngineID{Name: "OTScout", Version: version.Short()},
				},
				RevisionHistory: []vexRevisio{{
					Number:  "1",
					Date:    opts.Now,
					Summary: "Initial assessment generated from an OTScout asset inventory",
				}},
			},
			Distribution: &vexDistribution{TLP: vexTLP{Label: opts.TLP}},
			Notes:        documentNotes(set, opts),
		},
	}

	for _, entry := range products {
		doc.ProductTree.FullProductNames = append(doc.ProductTree.FullProductNames,
			vexProduct{ProductID: entry.id, Name: entry.name})
	}

	doc.Vulnerabilities = buildVulnerabilities(set, byFinding, products)
	return doc, nil
}

// documentNotes explain what this document is and, just as importantly, what it
// is not.
//
// A VEX generated from a network inventory is a weaker claim than one written by
// a vendor who has read their own source. Saying so in the document is the only
// way the difference reaches somebody reading it through a tool.
func documentNotes(set *finding.Set, opts VEXOptions) []vexNote {
	notes := []vexNote{{
		Category: "description",
		Title:    "How this assessment was produced",
		Text: "Generated by OTScout from an asset inventory correlated against public " +
			"advisories. A product is listed as known_affected only where the vendor, the " +
			"product and the version all matched and the version fell inside an affected " +
			"range. Where the version could not be established or compared, the product is " +
			"listed as under_investigation rather than affected, because an inventory built " +
			"from network observation cannot confirm what an unreachable field is.",
	}}

	if !opts.IncludeAddresses {
		notes = append(notes, vexNote{
			Category: "other",
			Title:    "Device addresses",
			Text: "Device addresses are omitted from this document. Each product entry states " +
				"how many devices in the assessed inventory run it. Re-generate with addresses " +
				"included if this document stays inside the operating organisation.",
		})
	}

	if set.Summary.AssetsUnidentified > 0 {
		notes = append(notes, vexNote{
			Category: "other",
			Title:    "Coverage",
			Text: fmt.Sprintf(
				"%d of %d devices in the assessed inventory could not be identified and were not "+
					"assessed. Their absence from this document is not a statement that they are "+
					"unaffected.",
				set.Summary.AssetsUnidentified, set.Summary.AssetsConsidered),
		})
	}

	return notes
}

// collectProducts assigns a stable product id to each distinct product.
func collectProducts(set *finding.Set, includeAddresses bool) ([]*productEntry, map[string]string) {
	byName := make(map[string]*productEntry)
	for _, f := range set.Findings {
		name := productName(f)
		entry, ok := byName[name]
		if !ok {
			entry = &productEntry{name: name, assets: make(map[string]bool)}
			byName[name] = entry
		}
		if !entry.assets[f.AssetID] {
			entry.assets[f.AssetID] = true
			if includeAddresses && f.AssetAddress != "" {
				entry.address = append(entry.address, f.AssetAddress)
			}
		}
	}

	// Sorting by name rather than by first appearance keeps the ids stable
	// across runs, so two assessments of an unchanged plant produce identical
	// documents and a diff means something.
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	products := make([]*productEntry, 0, len(names))
	for idx, name := range names {
		entry := byName[name]
		entry.id = fmt.Sprintf("CSAFPID-%04d", idx+1)
		sort.Strings(entry.address)
		entry.name = decorateName(entry, includeAddresses)
		products = append(products, entry)
	}

	byFinding := make(map[string]string, len(set.Findings))
	for _, f := range set.Findings {
		byFinding[f.ID] = byName[productName(f)].id
	}
	return products, byFinding
}

// productName is the identity the finding was matched on, not the advisory's
// wording for it.
//
// This is the operator's device as their own tooling sees it. The advisory's own
// product string is recorded in the vulnerability notes, so a reader can see
// both sides of the comparison that produced the claim.
func productName(f finding.Finding) string {
	return f.AssetIdentity.Label()
}

func decorateName(entry *productEntry, includeAddresses bool) string {
	name := entry.name
	if count := len(entry.assets); count > 1 {
		name = fmt.Sprintf("%s (%d devices)", name, count)
	}
	if includeAddresses && len(entry.address) > 0 {
		name = fmt.Sprintf("%s [%s]", name, strings.Join(entry.address, ", "))
	}
	return name
}

// vulnKey groups findings into one vulnerability entry.
//
// A CVE is the unit wherever one exists, because that is what a reader will
// search for. An ICS advisory with no CVE assigned still has to be reportable,
// so it becomes an entry keyed by its own id.
type vulnKey struct {
	cve      string
	advisory string
}

func buildVulnerabilities(set *finding.Set, byFinding map[string]string, products []*productEntry) []vexVulnerable {
	grouped := make(map[vulnKey][]finding.Finding)
	var order []vulnKey

	for _, f := range set.Findings {
		keys := make([]vulnKey, 0, len(f.CVEs))
		for _, cve := range f.CVEs {
			keys = append(keys, vulnKey{cve: cve})
		}
		if len(keys) == 0 {
			keys = append(keys, vulnKey{advisory: f.AdvisoryID})
		}
		for _, key := range keys {
			if _, seen := grouped[key]; !seen {
				order = append(order, key)
			}
			grouped[key] = append(grouped[key], f)
		}
	}

	sort.Slice(order, func(i, j int) bool {
		if order[i].cve != order[j].cve {
			return order[i].cve < order[j].cve
		}
		return order[i].advisory < order[j].advisory
	})

	out := make([]vexVulnerable, 0, len(order))
	for _, key := range order {
		out = append(out, buildVulnerability(key, grouped[key], byFinding))
	}
	return out
}

func buildVulnerability(key vulnKey, findings []finding.Finding, byFinding map[string]string) vexVulnerable {
	entry := vexVulnerable{CVE: key.cve}
	if key.cve == "" {
		entry.IDs = []vexExternalID{{SystemName: findings[0].AdvisorySource, Text: key.advisory}}
	}
	entry.Title = findings[0].Title

	affected := newProductSet()
	investigating := newProductSet()
	var evidence []string

	for _, f := range findings {
		productID := byFinding[f.ID]
		if f.Tier == finding.TierConfirmed {
			affected.add(productID)
		} else {
			investigating.add(productID)
		}
		if line := evidenceLine(f); line != "" {
			evidence = append(evidence, line)
		}
	}

	// A product cannot be both. Where two devices of the same product landed in
	// different tiers, the stronger claim wins: one confirmed device is enough
	// to say the product is affected here.
	investigating.remove(affected)

	entry.ProductStatu = vexProductStatus{
		KnownAffected:     affected.sorted(),
		UnderInvestigatio: investigating.sorted(),
	}

	entry.Notes = vulnerabilityNotes(findings, evidence)
	entry.Scores = buildScores(findings, byFinding)
	entry.Threats = buildThreats(findings, affected, investigating)
	entry.Remediations = buildRemediations(findings, affected, investigating)
	entry.References = buildReferences(findings)
	return entry
}

func vulnerabilityNotes(findings []finding.Finding, evidence []string) []vexNote {
	notes := []vexNote{{
		Category: "description",
		Text:     noteText(findings[0]),
	}}

	// The evidence note is what separates this from a document that asserts.
	// It names the advisory's own product string next to the identity the device
	// reported, so a reader can judge the match rather than take it.
	if len(evidence) > 0 {
		sort.Strings(evidence)
		notes = append(notes, vexNote{
			Category: "details",
			Title:    "Why these products are listed",
			Text:     strings.Join(dedupe(evidence), "\n"),
		})
	}
	return notes
}

func noteText(f finding.Finding) string {
	if f.Title != "" {
		return f.Title
	}
	return fmt.Sprintf("Reported in %s. No summary was available in the advisory corpus.", f.AdvisoryID)
}

func evidenceLine(f finding.Finding) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s: matched the advisory entry %q", f.Tier, advisoryProduct(f))
	if f.MatchedVersion != "" {
		fmt.Fprintf(&sb, ", which the advisory scopes to %q", f.MatchedVersion)
	}
	if check := f.VersionCheck; check != nil {
		fmt.Fprintf(&sb, ". Version check: %s", check.Explanation)
	} else if f.Tier != finding.TierConfirmed {
		sb.WriteString(". No version was available to compare")
	}
	return sb.String()
}

// advisoryProduct is the advisory's own wording for the product node.
//
// It is used verbatim, with nothing prepended. A CSAF full product name
// routinely embeds the vendor and the version already, so pasting those back on
// produces strings like "ABB ABB ABB 800xA Base 6.2.0-0 6.2.0-0", which reads
// like a bug in the report and undermines the evidence it is there to present.
func advisoryProduct(f finding.Finding) string {
	if f.MatchedProduct != "" {
		return f.MatchedProduct
	}
	if f.MatchedVendor != "" {
		return f.MatchedVendor
	}
	return f.MatchedProductID
}

func buildScores(findings []finding.Finding, byFinding map[string]string) []vexScore {
	// One score entry per distinct vector, listing the products it covers. The
	// same CVE carries the same score for every device here, so emitting it once
	// per device would be noise.
	byVector := make(map[string]*vexScore)
	var order []string

	for _, f := range findings {
		if f.CVSSVector == "" || f.CVSS == 0 {
			continue
		}
		score, ok := byVector[f.CVSSVector]
		if !ok {
			score = &vexScore{CVSSV3: &vexCVSSv3{
				Version:      cvssVersion(f.CVSSVector),
				VectorString: f.CVSSVector,
				BaseScore:    f.CVSS,
				BaseSeverity: strings.ToUpper(f.Severity),
			}}
			byVector[f.CVSSVector] = score
			order = append(order, f.CVSSVector)
		}
		score.Products = appendUnique(score.Products, byFinding[f.ID])
	}

	out := make([]vexScore, 0, len(order))
	sort.Strings(order)
	for _, vector := range order {
		score := byVector[vector]
		sort.Strings(score.Products)
		out = append(out, *score)
	}
	return out
}

// cvssVersion reads the version out of the vector string rather than assuming.
// CSAF validates the score object against the schema for the version named in
// it, so a 3.0 vector labelled 3.1 is a document that fails validation.
func cvssVersion(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0"):
		return "3.0"
	case strings.HasPrefix(vector, "CVSS:3.1"):
		return "3.1"
	default:
		return "3.1"
	}
}

func buildThreats(findings []finding.Finding, affected, investigating *productSet) []vexThreat {
	var threats []vexThreat

	// KEV membership is exploit status, and it is the single most actionable
	// fact this document can carry. A CVE known to be exploited outranks a
	// theoretically worse one nobody is using.
	kev := newProductSet()
	var kevDetail string
	for _, f := range findings {
		if !f.KEV {
			continue
		}
		kev.addAll(affected)
		kev.addAll(investigating)
		kevDetail = "Listed in the CISA Known Exploited Vulnerabilities catalogue. " +
			"This vulnerability is being exploited in the wild."
	}
	if kev.len() > 0 {
		threats = append(threats, vexThreat{
			Category:   "exploit_status",
			Details:    kevDetail,
			ProductIDs: kev.sorted(),
		})
	}

	var maxEPSS float64
	for _, f := range findings {
		if f.EPSS > maxEPSS {
			maxEPSS = f.EPSS
		}
	}
	if maxEPSS > 0 {
		all := newProductSet()
		all.addAll(affected)
		all.addAll(investigating)
		threats = append(threats, vexThreat{
			Category: "exploit_status",
			Details: fmt.Sprintf(
				"EPSS puts the probability of exploitation in the next 30 days at %.1f percent.",
				maxEPSS*100),
			ProductIDs: all.sorted(),
		})
	}

	return threats
}

// buildRemediations satisfies the profile requirement that every affected
// product carries an action statement, and recommended test 6.2.2, which
// extends it to products under investigation.
//
// Where the advisory offers a fix, that is the statement. Where it does not,
// none_available is emitted with the reason, which the specification permits
// and which is more honest than silence.
// csafRemediationCategories are the five values CSAF 2.0 allows. A category
// outside the set makes the whole document fail validation, so an advisory that
// invented one is mapped to mitigation rather than passed through.
var csafRemediationCategories = map[string]bool{
	"mitigation":     true,
	"no_fix_planned": true,
	"none_available": true,
	"vendor_fix":     true,
	"workaround":     true,
}

// buildRemediations satisfies the profile requirement that every affected
// product carries an action statement, and recommended test 6.2.2, which
// extends it to products under investigation.
//
// The advisory's own remediations are emitted one per category rather than
// collapsed into a single entry. Collapsing them meant a workaround's text
// arriving under the category vendor_fix, which tells a machine the
// vulnerability is resolved when nobody said that.
func buildRemediations(findings []finding.Finding, affected, investigating *productSet) []vexRemediation {
	covered := newProductSet()
	covered.addAll(affected)
	covered.addAll(investigating)
	if covered.len() == 0 {
		return nil
	}
	products := covered.sorted()

	byCategory := make(map[string]*vexRemediation)
	var order []string
	for _, f := range findings {
		for _, remediation := range f.Remediations {
			category := strings.ToLower(strings.TrimSpace(remediation.Category))
			if !csafRemediationCategories[category] {
				category = "mitigation"
			}
			entry, ok := byCategory[category]
			if !ok {
				entry = &vexRemediation{Category: category, ProductIDs: products, URL: remediation.URL}
				byCategory[category] = entry
				order = append(order, category)
			}
			if entry.URL == "" {
				entry.URL = remediation.URL
			}
			if remediation.Details != "" && !strings.Contains(entry.Details, remediation.Details) {
				entry.Details = strings.TrimSpace(entry.Details + " " + remediation.Details)
			}
		}
	}

	// CSAF 2.0 section 3.2.3.12.1: vendor_fix contradicts none_available and
	// no_fix_planned for the same product, and every entry here covers the same
	// products. An advisory that carries both is telling two stories, and the
	// one where a fix exists is the one an operator can act on.
	if _, fixed := byCategory["vendor_fix"]; fixed {
		delete(byCategory, "none_available")
		delete(byCategory, "no_fix_planned")
	}

	sort.Strings(order)
	out := make([]vexRemediation, 0, len(order)+1)
	for _, category := range order {
		entry, ok := byCategory[category]
		if !ok {
			continue
		}
		if entry.Details == "" {
			// CSAF requires details, and a category with none says nothing.
			entry.Details = fmt.Sprintf(
				"The advisory records a remediation of category %s without describing it. "+
					"See the referenced advisory.", category)
		}
		out = append(out, *entry)
	}

	// An affected product with no advice at all still needs an action statement,
	// or the document is not a valid VEX. Saying that none exists is permitted,
	// and it is more useful than silence.
	if len(out) == 0 {
		out = append(out, vexRemediation{
			Category: "none_available",
			Details: "The advisory corpus records no vendor fix and no mitigation for this " +
				"vulnerability. Consult the referenced advisory, and treat network segmentation as " +
				"the control of first resort until one is published.",
			ProductIDs: products,
			URL:        firstReference(findings),
		})
	}

	// Products under investigation need a statement of their own, because the
	// action there is to establish the version rather than to apply a fix.
	if investigating.len() > 0 {
		out = append(out, vexRemediation{
			Category: "mitigation",
			Details: "Exposure is unconfirmed for these products. Establish the firmware version, " +
				"from the device or from maintenance records, and re-run the assessment. Until then " +
				"treat them as potentially affected.",
			ProductIDs: investigating.sorted(),
		})
	}
	return out
}

func firstReference(findings []finding.Finding) string {
	for _, f := range findings {
		if len(f.References) > 0 {
			return f.References[0]
		}
	}
	return ""
}

// maxReferences caps the bibliography carried per vulnerability.
//
// An ICS advisory routinely cites thirty five sources, and it covers twenty
// CVEs. Copying the whole list onto each of them produced a document where the
// references outweighed the findings seven to one and told the reader nothing
// they could not get by following the advisory itself.
const maxReferences = 8

func buildReferences(findings []finding.Finding) []vexReference {
	var refs []vexReference
	seen := make(map[string]bool)

	add := func(url, advisoryID string) {
		if url == "" || seen[url] || len(refs) >= maxReferences {
			return
		}
		seen[url] = true
		refs = append(refs, vexReference{Category: "external", Summary: advisoryID, URL: url})
	}

	// The advisory itself comes first, because it is the one link a reader
	// actually needs. The matcher puts the advisory URL at the head of the list
	// when the corpus recorded one, but plenty of CISA entries have none, and
	// then position one is whatever boilerplate the advisory happened to cite.
	for _, f := range findings {
		for _, url := range f.References {
			if isAdvisoryLink(url, f.AdvisoryID) {
				add(url, f.AdvisoryID)
			}
		}
	}
	for _, f := range findings {
		if len(f.References) > 0 && !isBoilerplate(f.References[0]) {
			add(f.References[0], f.AdvisoryID)
		}
	}

	// Then anything naming this CVE specifically, which is likelier to be about
	// the vulnerability than about the advisory's other twenty.
	cve := ""
	if len(findings) > 0 && len(findings[0].CVEs) > 0 {
		cve = findings[0].CVEs[0]
	}
	if cve != "" {
		for _, f := range findings {
			for _, url := range f.References {
				if strings.Contains(strings.ToUpper(url), cve) {
					add(url, f.AdvisoryID)
				}
			}
		}
	}

	for _, f := range findings {
		for _, url := range f.References {
			add(url, f.AdvisoryID)
		}
	}
	return refs
}

// isAdvisoryLink spots the advisory's own document among its citations.
//
// Vendors name the file after the advisory, so an id like VDE-2026-020 turns up
// in the path. The separators are stripped before comparing because the same
// advisory is written ICSA-26-085-01 in one place and icsa_26_085_01 in another.
func isAdvisoryLink(url, advisoryID string) bool {
	if url == "" {
		return false
	}
	// A document under /.well-known/csaf/ is the machine readable advisory
	// itself, which is the strongest reference there is. Vendors number these
	// by their own scheme, so the id comparison below will not find them.
	if strings.Contains(strings.ToLower(url), "/.well-known/csaf/") {
		return true
	}
	if advisoryID == "" {
		return false
	}
	return strings.Contains(squash(url), squash(advisoryID))
}

// isBoilerplate marks the links every advisory carries regardless of subject.
//
// A CWE definition and a CVSS calculator are not references about this
// vulnerability, and letting one take the first slot buries the advisory.
func isBoilerplate(url string) bool {
	lowered := strings.ToLower(url)
	for _, generic := range []string{
		"cwe.mitre.org", "first.org/cvss/calculator", "nvd.nist.gov/vuln-metrics",
	} {
		if strings.Contains(lowered, generic) {
			return true
		}
	}
	return false
}

func squash(value string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(value) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// WriteVEX serialises the document.
func WriteVEX(w io.Writer, doc *VEX) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("write VEX document: %w", err)
	}
	return nil
}

// productSet keeps product ids unique and ordered.
type productSet struct{ members map[string]bool }

func newProductSet() *productSet { return &productSet{members: make(map[string]bool)} }

func (s *productSet) add(id string) {
	if id != "" {
		s.members[id] = true
	}
}

func (s *productSet) addAll(other *productSet) {
	for id := range other.members {
		s.members[id] = true
	}
}

func (s *productSet) remove(other *productSet) {
	for id := range other.members {
		delete(s.members, id)
	}
}

func (s *productSet) len() int { return len(s.members) }

func (s *productSet) sorted() []string {
	out := make([]string, 0, len(s.members))
	for id := range s.members {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

func appendUnique(list []string, value string) []string {
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}

func dedupe(values []string) []string {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
