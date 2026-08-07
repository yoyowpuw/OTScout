package normalize

import (
	"fmt"
	"strings"

	"github.com/yoyowpuw/OTScout/internal/asset"
)

// Normalizer applies the vendor, product and catalog tables to an identity.
type Normalizer struct {
	Vendors  *VendorTable
	Products *ProductTable
}

// New builds a normalizer from the embedded tables.
func New() (*Normalizer, error) {
	vendors, err := DefaultVendorTable()
	if err != nil {
		return nil, err
	}
	products, err := DefaultProductTable()
	if err != nil {
		return nil, err
	}
	return &Normalizer{Vendors: vendors, Products: products}, nil
}

// IdentityReport records what normalization did, so the evidence view can show
// the reasoning rather than only the result.
type IdentityReport struct {
	Vendor  VendorMatch     `json:"vendor"`
	Family  *FamilyMatch    `json:"family,omitempty"`
	Catalog *CatalogResult  `json:"catalog,omitempty"`
	Notes   []string        `json:"notes,omitempty"`
	Result  asset.Identity  `json:"result"`
	Input   asset.Identity  `json:"input"`
	Steps   []NormalizeStep `json:"steps,omitempty"`
}

// NormalizeStep is one decision taken while normalizing.
type NormalizeStep struct {
	Field  string      `json:"field"`
	From   string      `json:"from,omitempty"`
	To     string      `json:"to"`
	Method MatchMethod `json:"method"`
	Reason string      `json:"reason"`
}

// versionLabels are prefixes that vendors put in front of a firmware string
// without them being part of the version.
var versionLabels = []string{
	"firmware version", "firmware rev", "firmware", "fw version", "fw rev",
	"fw", "version", "ver.", "ver", "rev.", "rev", "release",
}

// CleanVersion strips labels and surrounding punctuation from a firmware string
// while leaving the version itself untouched. The V in V4.5 is part of how
// Siemens writes the version and is deliberately preserved.
func CleanVersion(raw string) string {
	out := strings.TrimSpace(raw)
	lower := strings.ToLower(out)
	for _, label := range versionLabels {
		if strings.HasPrefix(lower, label) {
			out = strings.TrimSpace(out[len(label):])
			lower = strings.ToLower(out)
			break
		}
	}
	out = strings.Trim(out, " \t:=,;()[]")
	return strings.Join(strings.Fields(out), " ")
}

// Identity normalizes an identity, filling in canonical fields without
// destroying the raw observations. The raw values are what the evidence view
// shows an operator, and discarding them would remove the ability to check the
// tool's reasoning.
func (n *Normalizer) Identity(in asset.Identity) IdentityReport {
	report := IdentityReport{Input: in, Result: in}
	out := &report.Result

	// Preserve the raw strings before anything overwrites the canonical fields.
	if out.VendorRaw == "" {
		out.VendorRaw = in.Vendor
	}
	if out.ProductRaw == "" {
		out.ProductRaw = in.Product
	}
	if out.FirmwareRaw == "" {
		out.FirmwareRaw = in.Firmware
	}

	// Step 1: the catalog number is the most reliable identifier a device
	// reports, so it is parsed first and can supply the vendor.
	if code := strings.TrimSpace(out.CatalogNumber); code != "" {
		if result, ok := ParseCatalog(code); ok {
			report.Catalog = &result
			if result.Normalized != "" {
				out.CatalogNumber = result.Normalized
			}
			report.Steps = append(report.Steps, NormalizeStep{
				Field:  "catalog_number",
				From:   code,
				To:     result.Normalized,
				Method: MatchExact,
				Reason: result.Explanation,
			})
		}
	}

	// Step 2: resolve the vendor. Candidates are tried strongest first.
	//
	// The canonical field is cleared first, so that it ends up holding either an
	// id from the alias table or nothing at all. Leaving an unresolved name in it
	// would have the matcher compare a display name on one side against a
	// canonical id on the other, which never matches and is invisible when it
	// fails. The raw name is safe in VendorRaw, and an empty canonical field is a
	// fact the corpus statistics can report and a contributor can fix.
	out.Vendor = ""
	vendorCandidates := []string{out.VendorRaw, in.Vendor}
	if report.Catalog != nil && report.Catalog.VendorID != "" {
		vendorCandidates = append([]string{report.Catalog.VendorID}, vendorCandidates...)
	}
	vendorCandidates = append(vendorCandidates, out.ProductRaw)

	for _, candidate := range vendorCandidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		match, ok := n.Vendors.LookupVendor(candidate)
		if !ok {
			continue
		}
		report.Vendor = match
		out.Vendor = match.ID
		report.Steps = append(report.Steps, NormalizeStep{
			Field:  "vendor",
			From:   candidate,
			To:     match.ID,
			Method: match.Method,
			Reason: fmt.Sprintf("resolved through %q in the vendor alias table", match.Matched),
		})
		break
	}
	if out.Vendor == "" && out.VendorRaw != "" {
		report.Notes = append(report.Notes,
			fmt.Sprintf("vendor %q is not in the alias table, so advisory matching will be limited", out.VendorRaw))
	}

	// Step 3: apply what the catalog number revealed, now that the vendor is
	// known and cannot be contradicted by it.
	if report.Catalog != nil {
		if out.Family == "" && report.Catalog.Family != "" {
			out.Family = report.Catalog.Family
		}
		if out.Model == "" && report.Catalog.Model != "" {
			out.Model = report.Catalog.Model
		}
	}

	// Step 4: resolve the product family from whatever product text exists.
	productCandidates := []string{out.ProductRaw, in.Product, out.Model, out.Family}
	for _, candidate := range productCandidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		match, ok := n.Products.LookupProduct(out.Vendor, candidate)
		if !ok {
			continue
		}
		report.Family = &match
		out.Family = match.Family.Display
		if out.Product == "" {
			out.Product = match.Family.Display
		}
		if out.Vendor == "" {
			out.Vendor = match.Family.Vendor
			report.Steps = append(report.Steps, NormalizeStep{
				Field:  "vendor",
				From:   candidate,
				To:     match.Family.Vendor,
				Method: match.Method,
				Reason: "inferred from the product family table",
			})
		}
		via := "family alias"
		if match.ViaModel {
			via = "model designation"
		}
		report.Steps = append(report.Steps, NormalizeStep{
			Field:  "family",
			From:   candidate,
			To:     match.Family.Display,
			Method: match.Method,
			Reason: fmt.Sprintf("matched %q as a %s", match.Matched, via),
		})
		break
	}

	// Step 5: clean the firmware string. Comparison happens later, in the
	// matcher, using the comparator this vendor is configured for.
	if cleaned := CleanVersion(out.Firmware); cleaned != out.Firmware {
		report.Steps = append(report.Steps, NormalizeStep{
			Field:  "firmware",
			From:   out.Firmware,
			To:     cleaned,
			Method: MatchExact,
			Reason: "stripped a label that is not part of the version",
		})
		out.Firmware = cleaned
	}
	if out.Firmware == "" && out.FirmwareRaw != "" {
		out.Firmware = CleanVersion(out.FirmwareRaw)
	}

	out.HardwareRev = strings.TrimSpace(out.HardwareRev)
	out.Serial = strings.TrimSpace(out.Serial)

	return report
}

// Comparator returns the firmware comparator for an identity, based on its
// resolved vendor.
func (n *Normalizer) Comparator(id asset.Identity) Comparator {
	return n.Vendors.ComparatorForVendor(id.Vendor)
}

// Inventory normalizes every asset in an inventory in place, returning the
// per-asset reports keyed by asset id for callers that want the reasoning.
func (n *Normalizer) Inventory(inv *asset.Inventory) map[string]IdentityReport {
	reports := make(map[string]IdentityReport, len(inv.Assets))
	for idx := range inv.Assets {
		a := &inv.Assets[idx]
		if a.Identity.Empty() {
			continue
		}
		report := n.Identity(a.Identity)
		a.Identity = report.Result
		reports[a.ID] = report
	}
	return reports
}
