// Package match correlates an asset inventory against an advisory corpus.
//
// The output is a list of findings, each carrying the whole chain of reasoning
// that produced it. That is not decoration. In an OT plant a false positive costs
// an engineer a trip to a panel and an outage window, so a matcher that cannot be
// audited will be turned off, and a matcher that guesses will be distrusted for
// the answers it got right as well as the ones it got wrong.
//
// Three rules follow from that, and the rest of this package is their
// consequences:
//
//   - A shared vendor is never a match. Otherwise every Siemens advisory lands on
//     every Siemens device.
//   - A version that cannot be compared yields "likely", never "confirmed" and
//     never silence. Claiming either certainty would be fabrication.
//   - A version the corpus positively rules out removes the finding entirely, and
//     the fact that it was ruled out is counted, so the run can be audited for
//     what it dismissed as well as what it reported.
package match

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/advisory"
	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/normalize"
)

// Options configures a match run.
type Options struct {
	// MinTier drops findings weaker than this tier. The default keeps
	// everything, because an operator who wants a shorter list is better served
	// by filtering a complete one than by a tool that quietly withheld leads.
	MinTier finding.Tier
	// Since drops advisories published before this date, for a run that only
	// wants recent news.
	Since time.Time
	// Normalizer is the identity resolver. When nil the embedded tables are used.
	Normalizer *normalize.Normalizer
}

// Matcher holds the indexed corpus. Building one is the expensive part of a run,
// and it is reusable across inventories, which is what lets the server answer a
// re-match without rereading the corpus.
type Matcher struct {
	corpus     *advisory.Corpus
	normalizer *normalize.Normalizer
	opts       Options

	// byVendor maps a canonical vendor id to every advisory product node
	// published under it. Without this index a run is the product of every asset
	// and every advisory, which for a real site is millions of comparisons that
	// almost all fail on the vendor.
	byVendor map[string][]productRef
}

// productRef points at one product node inside the corpus.
type productRef struct {
	advisory int
	product  int
}

// New builds a matcher over a corpus.
func New(corpus *advisory.Corpus, opts Options) (*Matcher, error) {
	if corpus == nil {
		return nil, fmt.Errorf("no advisory corpus given")
	}
	normalizer := opts.Normalizer
	if normalizer == nil {
		var err error
		normalizer, err = normalize.New()
		if err != nil {
			return nil, err
		}
	}
	m := &Matcher{corpus: corpus, normalizer: normalizer, opts: opts}
	m.index()
	return m, nil
}

func (m *Matcher) index() {
	m.byVendor = make(map[string][]productRef, 256)
	for ai := range m.corpus.Advisories {
		adv := &m.corpus.Advisories[ai]
		if !m.opts.Since.IsZero() && !adv.Published.IsZero() && adv.Published.Before(m.opts.Since) {
			continue
		}
		for pi := range adv.Products {
			vendor := adv.Products[pi].Vendor
			if vendor == "" {
				// A product whose vendor the alias table does not recognise
				// cannot be reached from an asset, whose vendor went through the
				// same table. The sync command already reports these as the most
				// valuable contribution to make.
				continue
			}
			m.byVendor[vendor] = append(m.byVendor[vendor], productRef{advisory: ai, product: pi})
		}
	}
}

// IndexedVendors reports how many vendors the corpus can be reached by, which the
// CLI prints so an operator can tell a thin corpus from a thin inventory.
func (m *Matcher) IndexedVendors() int { return len(m.byVendor) }

// Run matches every asset in an inventory.
func (m *Matcher) Run(inv *asset.Inventory) *finding.Set {
	set := finding.NewSet("otscout match")
	if inv == nil {
		return set
	}

	summary := finding.Summary{AssetsConsidered: len(inv.Assets)}
	for idx := range inv.Assets {
		a := inv.Assets[idx]
		if a.Identity.Empty() {
			summary.AssetsUnidentified++
			continue
		}

		// The identity is normalized here rather than trusted.
		//
		// Inventories written by otscout ingest are already normalized, but an
		// inventory is a plain JSON file that an operator may have written by hand
		// or exported from another tool, and one that spells the vendor "Siemens
		// AG" would otherwise be silently compared against a corpus keyed by
		// "siemens" and match nothing at all. Failing to find anything is the
		// worst possible way for that to go wrong, because it looks like good
		// news. Normalization is idempotent, so this costs an already normalized
		// inventory nothing.
		a.Identity = m.normalizer.Identity(a.Identity).Result

		if a.Identity.Vendor == "" {
			// The device said something about itself but not enough to reach the
			// alias table. This is a different problem from saying nothing, and it
			// is one a contributed alias would fix, so it is counted apart.
			summary.AssetsUnknownVendo++
			continue
		}

		findings, ruledOut := m.matchAsset(&a)
		summary.RuledOutByVersion += ruledOut
		set.Findings = append(set.Findings, findings...)
	}

	set.Summary = summary
	set.Finalize()
	return set
}

// matchAsset produces at most one finding per advisory for one asset.
func (m *Matcher) matchAsset(a *asset.Asset) (out []finding.Finding, ruledOut int) {
	refs := m.byVendor[a.Identity.Vendor]
	if len(refs) == 0 {
		return nil, 0
	}
	comparator := m.normalizer.Comparator(a.Identity)

	// Candidates are collected per advisory so that a product tree listing
	// fourteen variants of one device produces one finding rather than fourteen.
	perAdvisory := make(map[int][]candidate, 8)
	for _, ref := range refs {
		adv := &m.corpus.Advisories[ref.advisory]
		product := adv.Products[ref.product]

		identity := compareIdentity(m.normalizer.Products, a.Identity, product)
		if identity.Strength == strengthNone {
			continue
		}

		eval := product.Version.Evaluate(a.Identity.Firmware, comparator)
		if eval.Result == normalize.EvalNotAffected {
			ruledOut++
			continue
		}

		perAdvisory[ref.advisory] = append(perAdvisory[ref.advisory], candidate{
			ref:      ref,
			product:  product,
			identity: identity,
			eval:     eval,
		})
	}

	out = make([]finding.Finding, 0, len(perAdvisory))
	for advisoryIdx, candidates := range perAdvisory {
		f, ok := m.buildFinding(a, advisoryIdx, candidates, comparator)
		if !ok {
			continue
		}
		if m.opts.MinTier != "" && f.Tier.Rank() < m.opts.MinTier.Rank() {
			continue
		}
		out = append(out, f)
	}
	return out, ruledOut
}

// candidate is one product node that survived both the identity and the version
// check.
type candidate struct {
	ref      productRef
	product  advisory.Product
	identity identityMatch
	eval     normalize.Evaluation
}

// beats orders candidates within one advisory, strongest conclusion first.
//
// A node the advisory did not describe more finely than we could match comes
// first, because that is what separates a conclusion from a lead. An advisory
// listing both a family wide entry and a specific model would otherwise be
// reported as a lead purely because the model node happened to sort earlier.
func (c candidate) beats(other candidate) bool {
	if c.identity.AdvisoryMoreSpecific != other.identity.AdvisoryMoreSpecific {
		return !c.identity.AdvisoryMoreSpecific
	}
	if c.identity.Strength != other.identity.Strength {
		return c.identity.Strength > other.identity.Strength
	}
	mine, theirs := evalRank(c.eval.Result), evalRank(other.eval.Result)
	if mine != theirs {
		return mine > theirs
	}
	// Nothing left to distinguish them, so the product id decides, purely so
	// that two runs over unchanged inputs produce identical output.
	return c.product.ID < other.product.ID
}

func evalRank(result normalize.EvalResult) int {
	if result == normalize.EvalAffected {
		return 2
	}
	return 1
}

func (m *Matcher) buildFinding(a *asset.Asset, advisoryIdx int, candidates []candidate,
	comparator normalize.Comparator) (finding.Finding, bool) {

	adv := &m.corpus.Advisories[advisoryIdx]

	sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].beats(candidates[j]) })
	best := candidates[0]

	tier := tierFor(best.identity, best.eval.Result)
	if tier == "" {
		return finding.Finding{}, false
	}

	// The CVEs are restricted to the vulnerabilities that actually list a matched
	// product as affected. An advisory covering twenty devices where one CVE hits
	// only one of them must not attribute that CVE to the other nineteen, and
	// getting this wrong is the difference between a report an engineer trusts and
	// one they spot-check and discard.
	matchedIDs := make(map[string]struct{}, len(candidates))
	for _, c := range candidates {
		matchedIDs[c.product.ID] = struct{}{}
	}

	f := finding.Finding{
		ID:           finding.NewID(a.ID, adv.ID, best.product.ID),
		AssetID:      a.ID,
		AssetAddress: a.Addresses.Primary(),
		AssetLabel:   a.Identity.Label(),
		AssetPurdue:  string(a.Purdue),
		AssetRole:    string(a.Role),

		AdvisoryID:     adv.ID,
		AdvisorySource: adv.Source,
		Title:          adv.Title,
		Published:      adv.Published,

		Tier: tier,

		MatchedVendor:    firstNonEmpty(best.product.VendorRaw, best.product.Vendor),
		MatchedProduct:   best.product.Label(),
		MatchedVersion:   best.product.VersionRaw,
		MatchedProductID: best.product.ID,

		AssetIdentity: a.Identity,
		EvidenceIDs:   evidenceIDs(a),

		VersionCheck: &finding.VersionCheck{
			AssetVersion: a.Identity.Firmware,
			Constraint:   constraintText(best.product),
			Comparator:   comparator.Name(),
			Result:       string(best.eval.Result),
			Explanation:  best.eval.Explanation,
		},
	}

	f.Reasons = append(f.Reasons, m.vendorReason(a, best.product))
	f.Reasons = append(f.Reasons, best.identity.Reasons...)
	f.Reasons = append(f.Reasons, versionReason(best))

	for _, c := range candidates[1:] {
		f.AlsoMatched = append(f.AlsoMatched, c.product.Label())
	}

	m.applyVulnerabilities(&f, adv, matchedIDs)
	f.Score = score(best.identity, best.eval.Result, f.KEV)
	return f, true
}

// tierFor maps an identity match and a version verdict onto a confidence tier.
//
// Two questions decide it, in this order.
//
// First, did the advisory name something finer than the match established? An
// advisory saying that every SIMATIC S7-1200 is affected settles the matter for a
// device known to be an S7-1200, even though neither side named a model. One
// naming CPU 1215C does not, because whether the S7-1200 on the wire is that
// model is exactly what nobody knows. Only the second case is a lead rather than
// a conclusion, and reading a family wide advisory as the weaker of the two would
// bury a large and very real class of finding under "possible".
//
// Second, given that the device is identified well enough, does its version fall
// in the affected range? An answer of yes is a conclusion. No answer at all is
// still worth reporting, but it is not the same thing and must not be dressed up
// as one.
func tierFor(identity identityMatch, result normalize.EvalResult) finding.Tier {
	if result == normalize.EvalNotAffected || identity.Strength == strengthNone {
		return ""
	}
	if identity.AdvisoryMoreSpecific {
		return finding.TierPossible
	}
	if result == normalize.EvalAffected {
		return finding.TierConfirmed
	}
	return finding.TierLikely
}

// score is a 0 to 1 confidence number for sorting inside a tier.
//
// It is not a probability and is not presented as one. The tier is what an
// operator acts on, and this exists so that two findings in the same tier come
// out in a defensible order.
func score(identity identityMatch, result normalize.EvalResult, kev bool) float64 {
	base := 0.0
	switch identity.Strength {
	case strengthCatalog:
		base = 0.6
	case strengthProduct:
		base = 0.5
	case strengthFamily:
		base = 0.4
	}
	if identity.AdvisoryMoreSpecific {
		base -= 0.2
	}
	if result == normalize.EvalAffected {
		base += 0.35
	}
	if kev {
		// Exploitation in the wild does not make the identity match any more
		// certain, so this is a small nudge rather than a jump. Priority, which
		// is what the table sorts on, is where KEV dominates.
		base += 0.05
	}
	if base > 1 {
		base = 1
	}
	return base
}

func (m *Matcher) vendorReason(a *asset.Asset, p advisory.Product) finding.Reason {
	detail := fmt.Sprintf("vendor %q resolved to %q on both sides",
		firstNonEmpty(a.Identity.VendorRaw, a.Identity.Vendor), a.Identity.Vendor)
	kind := finding.ReasonVendorExact
	if !strings.EqualFold(strings.TrimSpace(a.Identity.VendorRaw), strings.TrimSpace(p.VendorRaw)) {
		kind = finding.ReasonVendorAlias
		detail = fmt.Sprintf("device vendor %q and advisory vendor %q both resolve to %q in the alias table",
			firstNonEmpty(a.Identity.VendorRaw, a.Identity.Vendor),
			firstNonEmpty(p.VendorRaw, p.Vendor), a.Identity.Vendor)
	}
	return finding.Reason{Kind: kind, Detail: detail, Weight: 1, Passed: true}
}

func versionReason(c candidate) finding.Reason {
	reason := finding.Reason{Detail: c.eval.Explanation, Passed: true}
	switch {
	case c.eval.Result == normalize.EvalIndeterminate:
		reason.Kind = finding.ReasonVersionUnknown
		// Recorded as a failed step on purpose. An operator has to be able to see
		// that the version check ran and could not answer, or they will redo it
		// by hand.
		reason.Passed = false
	case c.product.Version.Kind == normalize.ConstraintAll:
		reason.Kind = finding.ReasonVersionAllAffect
	case c.product.Version.Kind == normalize.ConstraintEQ:
		reason.Kind = finding.ReasonVersionExact
	default:
		reason.Kind = finding.ReasonVersionInRange
	}
	return reason
}

// applyVulnerabilities fills in the CVE list, scores and remediations from the
// vulnerabilities that touch a matched product.
func (m *Matcher) applyVulnerabilities(f *finding.Finding, adv *advisory.Advisory,
	matchedIDs map[string]struct{}) {

	cves := make([]string, 0, len(adv.Vulnerabilities))
	remediations := make([]string, 0, 4)
	var best advisory.Score
	haveScore := false

	for _, v := range adv.Vulnerabilities {
		ids, precise := v.AffectedProducts()
		if precise && !anyMatched(ids, matchedIDs) {
			continue
		}
		if v.CVE != "" {
			cves = append(cves, v.CVE)
		}
		if candidate, ok := v.BestScore(); ok && (!haveScore || candidate.BetterThan(best)) {
			best, haveScore = candidate, true
		}
		if v.KEV != nil {
			f.KEV = true
		}
		if v.EPSS != nil && v.EPSS.Score > f.EPSS {
			f.EPSS = v.EPSS.Score
		}
		for _, rem := range v.Remediations {
			if len(rem.ProductIDs) > 0 && !anyMatched(rem.ProductIDs, matchedIDs) {
				continue
			}
			if rem.HasFix() {
				f.FixAvailable = true
			}
			if text := remediationText(rem); text != "" {
				remediations = append(remediations, text)
			}
		}
		for _, ref := range v.References {
			if ref.URL != "" {
				f.References = append(f.References, ref.URL)
			}
		}
	}

	f.CVEs = dedupe(cves)
	f.Remediations = dedupe(remediations)

	if adv.URL != "" {
		f.References = append([]string{adv.URL}, f.References...)
	}
	f.References = dedupe(f.References)

	if haveScore {
		f.CVSS = best.BaseScore
		f.CVSSVector = best.Vector
		f.Severity = string(best.Severity)
	}
	if f.Severity == "" {
		if severity := adv.Severity(); severity != advisory.SeverityUnknown {
			f.Severity = string(severity)
		}
	}
}

func remediationText(rem advisory.Remediation) string {
	parts := make([]string, 0, 3)
	if rem.Category != "" {
		parts = append(parts, rem.Category)
	}
	if rem.Details != "" {
		parts = append(parts, rem.Details)
	}
	if rem.URL != "" {
		parts = append(parts, rem.URL)
	}
	return strings.Join(parts, ": ")
}

func anyMatched(ids []string, matched map[string]struct{}) bool {
	for _, id := range ids {
		if _, ok := matched[id]; ok {
			return true
		}
	}
	return false
}

func constraintText(p advisory.Product) string {
	if p.VersionRaw != "" {
		return p.VersionRaw
	}
	return p.Version.Describe()
}

func evidenceIDs(a *asset.Asset) []string {
	out := make([]string, 0, len(a.Evidence))
	for _, ev := range a.Evidence {
		if ev.ID != "" {
			out = append(out, ev.ID)
		}
	}
	return out
}

func dedupe(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, dup := seen[value]; dup {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
