package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/finding"
)

func writeFindings(t *testing.T, dir string) string {
	t.Helper()

	set := finding.NewSet("otscout match")
	set.Findings = []finding.Finding{
		{
			ID: "a:ICSA-1:p", AssetID: "a", AssetAddress: "10.0.0.1", AssetLabel: "PLC",
			AdvisoryID: "ICSA-1", Tier: finding.TierConfirmed, CVEs: []string{"CVE-2024-0001"},
			AssetIdentity: asset.Identity{Vendor: "siemens", Product: "S7-300", Firmware: "3.2"},
		},
		{
			ID: "b:ICSA-2:p", AssetID: "b", AssetAddress: "10.0.0.2", AssetLabel: "Drive",
			AdvisoryID: "ICSA-2", Tier: finding.TierPossible,
			AssetIdentity: asset.Identity{Vendor: "abb", Family: "ACS"},
		},
	}
	set.Summary.AssetsConsidered = 2

	path := filepath.Join(dir, "site.json")
	if err := set.Save(path); err != nil {
		t.Fatalf("save findings: %v", err)
	}
	return path
}

func runReport(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := NewRootCommand()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(append([]string{"report"}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// TestTheDefaultNameDoesNotRepeatTheFormat. findings.csv.csv is the kind of
// thing nobody notices until a folder of them goes to a customer.
func TestTheDefaultNameDoesNotRepeatTheFormat(t *testing.T) {
	dir := t.TempDir()
	findings := writeFindings(t, dir)

	for format, want := range map[string]string{
		"csv":  "site.csv",
		"html": "site.html",
		// VEX keeps the format in the name because it lands as JSON beside the
		// findings JSON it came from.
		"vex": "site.vex.json",
	} {
		args := []string{"--findings", findings, "--format", format}
		if format == "vex" {
			args = append(args, "--publisher", "Example", "--publisher-namespace", "https://example.org")
		}
		if _, err := runReport(t, args...); err != nil {
			t.Fatalf("report --format %s: %v", format, err)
		}
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			listDir(t, dir)
			t.Errorf("--format %s did not produce %s", format, want)
		}
	}
}

func TestAnUnknownFormatIsRefused(t *testing.T) {
	dir := t.TempDir()
	findings := writeFindings(t, dir)

	if _, err := runReport(t, "--findings", findings, "--format", "pdf"); err == nil {
		t.Error("--format pdf was accepted")
	}
}

// TestMinTierFiltersTheOutputButNotTheCounters. The run counters describe what
// was assessed, and recomputing them from what survived a filter would report a
// plant that was never looked at.
func TestMinTierFiltersTheOutputButNotTheCounters(t *testing.T) {
	dir := t.TempDir()
	findings := writeFindings(t, dir)
	output := filepath.Join(dir, "confirmed.csv")

	stdout, err := runReport(t,
		"--findings", findings, "--format", "csv", "--min-tier", "confirmed", "--output", output)
	if err != nil {
		t.Fatalf("report: %v", err)
	}

	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if strings.Contains(string(body), "ICSA-2") {
		t.Error("a possible tier finding survived --min-tier confirmed")
	}
	if !strings.Contains(string(body), "ICSA-1") {
		t.Error("the confirmed finding was filtered out")
	}
	if !strings.Contains(stdout, "1 of 2 findings") {
		t.Errorf("the summary does not say what was dropped: %s", stdout)
	}
}

// TestAFailedRenderLeavesTheOldReportInPlace. A truncated file cannot be told
// apart from a report of a quiet network, which is the worst way for this to
// fail.
func TestAFailedRenderLeavesTheOldReportInPlace(t *testing.T) {
	dir := t.TempDir()
	findings := writeFindings(t, dir)
	output := filepath.Join(dir, "site.vex.json")

	if err := os.WriteFile(output, []byte("previous good report"), 0o644); err != nil {
		t.Fatalf("seed the old report: %v", err)
	}

	// No publisher, so the VEX build fails after the output path is decided.
	if _, err := runReport(t, "--findings", findings, "--format", "vex", "--output", output); err == nil {
		t.Fatal("a VEX with no publisher was accepted")
	}

	body, err := os.ReadFile(output)
	if err != nil {
		t.Fatalf("read the old report: %v", err)
	}
	if string(body) != "previous good report" {
		t.Errorf("a failed render overwrote the previous report with %q", body)
	}

	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".vex.json.") {
			t.Errorf("a temporary file was left behind: %s", entry.Name())
		}
	}
}

func listDir(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		t.Logf("  %s", entry.Name())
	}
}
