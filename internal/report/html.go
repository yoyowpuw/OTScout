package report

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/version"
)

//go:embed templates/report.html.tmpl
var templateFS embed.FS

// htmlTemplate is parsed once. html/template rather than text/template is the
// whole of the escaping story here: every value in this report came off a
// network, from a device that was under no obligation to be truthful about its
// own name, and a product string is exactly where somebody would put a script
// tag.
var htmlTemplate = template.Must(template.ParseFS(templateFS, "templates/report.html.tmpl"))

// HTMLOptions configure the rendered document.
type HTMLOptions struct {
	// Title heads the document. Defaults to something derived from the findings.
	Title string

	// Now is the render timestamp, for tests.
	Now time.Time
}

// htmlDocument is what the template sees. The fields are pre-rendered strings
// rather than the finding model, so that all the formatting decisions live in Go
// where they can be tested, and the template stays a layout.
type htmlDocument struct {
	Title         string
	GeneratedAt   string
	Generator     string
	InventoryPath string
	CorpusPath    string
	Coverage      string

	Summary finding.Summary

	Confirmed int
	Likely    int
	Possible  int

	Findings []htmlFinding
}

type htmlFinding struct {
	Tier        string
	TierMeaning string

	DeviceLabel string
	DeviceSub   string
	Address     string

	AdvisoryID string
	Title      string

	CVSS string
	EPSS string

	KEV          bool
	FixAvailable bool

	AssetIdentity  string
	MatchedProduct string
	VersionCheck   string
	AlsoMatched    string
	Remediation    string
	Reference      string
	Reasons        []htmlReason

	// Search is the lowercased haystack the client side filter matches against.
	Search string
}

type htmlReason struct {
	Detail string
	Passed bool
}

// WriteHTML renders a standalone report.
//
// The output is one file with no external references at all: no web font, no
// stylesheet, no script from anywhere else. That is not a style preference. This
// report is written on an air gapped network and read on a machine that may
// never have had a route to the internet, and a report that renders as unstyled
// text because it wanted a font is a report nobody trusts.
func WriteHTML(w io.Writer, set *finding.Set, opts HTMLOptions) error {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if opts.Title == "" {
		opts.Title = "OT exposure report"
	}

	doc := htmlDocument{
		Title:         opts.Title,
		GeneratedAt:   opts.Now.UTC().Format("2006-01-02 15:04 MST"),
		Generator:     "OTScout " + version.Short(),
		InventoryPath: set.InventoryPath,
		CorpusPath:    set.CorpusPath,
		Coverage:      coverageNote(set.Summary),
		Summary:       set.Summary,
		Confirmed:     set.Summary.ByTier[finding.TierConfirmed],
		Likely:        set.Summary.ByTier[finding.TierLikely],
		Possible:      set.Summary.ByTier[finding.TierPossible],
	}

	doc.Findings = make([]htmlFinding, 0, len(set.Findings))
	for _, f := range set.Findings {
		doc.Findings = append(doc.Findings, newHTMLFinding(f))
	}

	if err := htmlTemplate.ExecuteTemplate(w, "report.html.tmpl", doc); err != nil {
		return fmt.Errorf("render HTML report: %w", err)
	}
	return nil
}

// coverageNote states what the run could not see.
//
// A report that lists eleven findings and says nothing else invites the reading
// that there are eleven problems. If a third of the inventory was never
// identifiable, that is the more important number on the page.
func coverageNote(s finding.Summary) string {
	var parts []string

	if s.AssetsUnidentified > 0 {
		parts = append(parts, fmt.Sprintf(
			"%s of the %d assessed could not be identified well enough to compare against any advisory, "+
				"so nothing is claimed about them either way",
			plural(s.AssetsUnidentified, "device"), s.AssetsConsidered))
	}
	if s.AssetsUnknownVendo > 0 {
		parts = append(parts, fmt.Sprintf(
			"%s reported a vendor the normalization tables do not recognise, which is usually a gap in "+
				"those tables rather than an obscure device",
			plural(s.AssetsUnknownVendo, "device")))
	}
	if s.RuledOutByVersion > 0 {
		parts = append(parts, fmt.Sprintf(
			"%d candidate matches were ruled out because the firmware version fell outside the affected "+
				"range", s.RuledOutByVersion))
	}

	if len(parts) == 0 {
		return "Every device in the inventory was identified and compared against the corpus. " +
			"The corpus itself is only as current as the last sync, and an advisory published since " +
			"then will not appear here."
	}

	return "Coverage is partial: " + joinClauses(parts) + ". " +
		"The corpus is also only as current as the last sync."
}

func joinClauses(parts []string) string {
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + ", and " + parts[1]
	default:
		return strings.Join(parts[:len(parts)-1], ", ") + ", and " + parts[len(parts)-1]
	}
}

func newHTMLFinding(f finding.Finding) htmlFinding {
	out := htmlFinding{
		Tier:           string(f.Tier),
		TierMeaning:    f.Tier.Description(),
		DeviceLabel:    f.AssetLabel,
		DeviceSub:      deviceSub(f),
		Address:        f.AssetAddress,
		AdvisoryID:     f.AdvisoryID,
		Title:          f.Title,
		CVSS:           formatFloat(f.CVSS, 1),
		EPSS:           formatEPSS(f.EPSS),
		KEV:            f.KEV,
		FixAvailable:   f.FixAvailable,
		AssetIdentity:  f.AssetIdentity.Label(),
		MatchedProduct: matchedProduct(f),
		AlsoMatched:    strings.Join(f.AlsoMatched, ", "),
		Remediation:    strings.Join(finding.RemediationTexts(f.Remediations), " "),
	}

	if out.DeviceLabel == "" {
		out.DeviceLabel = f.AssetAddress
	}
	if check := f.VersionCheck; check != nil {
		out.VersionCheck = check.Explanation
	}
	if len(f.References) > 0 {
		out.Reference = f.References[0]
	}
	for _, reason := range f.Reasons {
		out.Reasons = append(out.Reasons, htmlReason{Detail: reason.Detail, Passed: reason.Passed})
	}

	out.Search = strings.ToLower(strings.Join([]string{
		out.DeviceLabel, out.Address, out.AdvisoryID, out.Title,
		out.AssetIdentity, out.MatchedProduct, string(f.Tier),
		strings.Join(f.CVEs, " "),
	}, " "))

	return out
}

func deviceSub(f finding.Finding) string {
	parts := make([]string, 0, 2)
	if f.AssetPurdue != "" {
		parts = append(parts, "Purdue "+f.AssetPurdue)
	}
	if f.AssetRole != "" {
		parts = append(parts, f.AssetRole)
	}
	return strings.Join(parts, ", ")
}

// matchedProduct shows the advisory's own wording, and its version scope
// separately when the wording does not already carry it.
func matchedProduct(f finding.Finding) string {
	name := advisoryProduct(f)
	if name == "" {
		return "not recorded"
	}
	if scope := f.MatchedVersion; scope != "" && !strings.Contains(name, scope) {
		name += ", scoped to " + scope
	}
	return name
}

// formatEPSS shows the probability as a percentage, because a bare 0.04731 gets
// read as a score out of one and quietly misjudged.
func formatEPSS(value float64) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatFloat(value*100, 'f', 1, 64) + "%"
}
