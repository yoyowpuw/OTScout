package report

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/yoyowpuw/OTScout/internal/finding"
)

// csvColumns is the header, and the order is the order somebody works the list
// in: what it is, where it is, how sure we are, how bad it is, and only then the
// reasoning.
//
// The evidence columns are last rather than absent. A spreadsheet is where most
// of this work actually gets done, and an analyst who cannot see why a row is
// there has to go back to the JSON to find out.
var csvColumns = []string{
	"finding_id",
	"tier",
	"tier_meaning",
	"asset_address",
	"asset_label",
	"asset_purdue",
	"asset_role",
	"vendor",
	"product",
	"firmware",
	"advisory_id",
	"advisory_source",
	"title",
	"published",
	"cves",
	"cvss",
	"cvss_vector",
	"severity",
	"kev",
	"epss",
	"priority",
	"fix_available",
	"matched_product",
	"matched_version",
	"version_check",
	"remediations",
	"references",
}

// WriteCSV renders findings as one row per finding.
//
// Excel reads a bare UTF-8 file as the local code page, which turns any vendor
// name with an accent into mojibake on a good many of the machines this will be
// opened on. A byte order mark is the only thing that reliably prevents it, and
// every other reader tolerates one.
func WriteCSV(w io.Writer, set *finding.Set) error {
	if _, err := io.WriteString(w, "\ufeff"); err != nil {
		return fmt.Errorf("write CSV: %w", err)
	}

	writer := csv.NewWriter(w)
	if err := writer.Write(csvColumns); err != nil {
		return fmt.Errorf("write CSV header: %w", err)
	}

	for _, f := range set.Findings {
		if err := writer.Write(csvRow(f)); err != nil {
			return fmt.Errorf("write CSV row for %s: %w", f.ID, err)
		}
	}

	writer.Flush()
	if err := writer.Error(); err != nil {
		return fmt.Errorf("write CSV: %w", err)
	}
	return nil
}

func csvRow(f finding.Finding) []string {
	published := ""
	if !f.Published.IsZero() {
		published = f.Published.UTC().Format("2006-01-02")
	}

	versionCheck := ""
	if f.VersionCheck != nil {
		versionCheck = f.VersionCheck.Explanation
	}

	return []string{
		f.ID,
		string(f.Tier),
		f.Tier.Description(),
		f.AssetAddress,
		f.AssetLabel,
		f.AssetPurdue,
		f.AssetRole,
		firstNonEmpty(f.AssetIdentity.Vendor, f.AssetIdentity.VendorRaw),
		firstNonEmpty(f.AssetIdentity.Product, f.AssetIdentity.ProductRaw, f.AssetIdentity.Family),
		firstNonEmpty(f.AssetIdentity.Firmware, f.AssetIdentity.FirmwareRaw),
		f.AdvisoryID,
		f.AdvisorySource,
		f.Title,
		published,
		strings.Join(f.CVEs, " "),
		formatFloat(f.CVSS, 1),
		f.CVSSVector,
		f.Severity,
		formatBool(f.KEV),
		formatFloat(f.EPSS, 5),
		formatFloat(f.Priority(), 1),
		formatBool(f.FixAvailable),
		advisoryProduct(f),
		f.MatchedVersion,
		versionCheck,
		strings.Join(finding.RemediationTexts(f.Remediations), " | "),
		strings.Join(referenceURLs(f), " "),
	}
}

// referenceURLs caps the bibliography for the same reason the VEX does: an
// advisory citing thirty five sources turns one spreadsheet cell into a wall
// that hides the advisory URL somebody actually wants to click. The findings
// document keeps the full list.
func referenceURLs(f finding.Finding) []string {
	if len(f.References) <= maxReferences {
		return f.References
	}
	return f.References[:maxReferences]
}

// firstNonEmpty falls back to the raw string a device actually reported.
//
// Normalization fills the canonical field only when it recognises the value, so
// a column bound to the canonical field alone goes blank for exactly the devices
// whose identity is most worth reading. The raw string is what the device said,
// and an operator can act on that.
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// formatFloat leaves a zero blank rather than printing it.
//
// A CVSS of 0.0 and an advisory that carries no score are different facts, and a
// column that shows 0.0 for both invites somebody to sort by it and conclude the
// unscored ones are harmless.
func formatFloat(value float64, decimals int) string {
	if value == 0 {
		return ""
	}
	return strconv.FormatFloat(value, 'f', decimals, 64)
}

func formatBool(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}
