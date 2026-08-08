package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/report"
)

// reportSuffixes are what a rendered report is called when the caller does not
// name a file.
//
// The VEX one keeps the format in the name because it is JSON alongside the
// findings JSON it came from, and two files called findings.json in a handover
// folder is how the wrong one gets sent.
var reportSuffixes = map[string]string{
	"csv":  ".csv",
	"vex":  ".vex.json",
	"html": ".html",
}

func newReportCommand(opts *Options) *cobra.Command {
	var (
		findingsPath string
		format       string
		outputPath   string
		minTier      string
		title        string
		publisher    string
		namespace    string
		trackingID   string
		tlp          string
		addresses    bool
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Render findings as CSV, VEX or a standalone HTML file",
		Long: `report renders a findings document into a form somebody else can read.

Three formats, for three different readers:

  csv   one row per finding, for the spreadsheet where triage actually happens.
        Written with a byte order mark, because Excel reads a bare UTF-8 file as
        the local code page and mangles any vendor name with an accent in it.

  vex   a CSAF 2.0 document under the VEX profile, for tooling and for auditors.
        Only confirmed findings are stated as known_affected. Anything weaker is
        under_investigation, because a VEX is read by machines and repeated by
        people, and a guess that travels as a fact is worse than no document.
        Device addresses are left out unless you ask for them.

  html  one self contained file. No web font, no stylesheet, no script from
        anywhere else, so it renders the same on an air gapped laptop as it does
        on a workstation, and it will still render in ten years.

Nothing here touches the network.

Examples:

  otscout report --format csv
  otscout report --format html --output site-report.html
  otscout report --format vex --publisher "Example Water Authority" \
    --publisher-namespace https://example.org
  otscout report --format csv --min-tier confirmed`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			format = strings.ToLower(strings.TrimSpace(format))
			if _, ok := reportSuffixes[format]; !ok {
				return fmt.Errorf("unknown format %q, expected csv, vex or html", format)
			}

			tier, err := parseTier(minTier)
			if err != nil {
				return err
			}

			set, err := finding.Load(findingsPath)
			if err != nil {
				return err
			}
			kept := filterByTier(set, tier)

			if outputPath == "" {
				outputPath = defaultReportPath(findingsPath, format)
			}

			written, err := writeReport(outputPath, func(w io.Writer) error {
				return renderReport(w, format, kept, report.VEXOptions{
					PublisherName:      publisher,
					PublisherNamespace: namespace,
					TrackingID:         trackingID,
					TLP:                tlp,
					IncludeAddresses:   addresses,
				}, report.HTMLOptions{Title: title})
			})
			if err != nil {
				return err
			}

			opts.progressf(out, "wrote %s (%s)\n", outputPath, humanBytes(written))
			printReportSummary(out, format, set, kept, tier, addresses)
			return nil
		},
	}

	cmd.Flags().StringVarP(&findingsPath, "findings", "f", "findings.json", "findings document to render")
	cmd.Flags().StringVar(&format, "format", "csv", "output format: csv, vex or html")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "where to write, derived from the findings name when unset")
	cmd.Flags().StringVar(&minTier, "min-tier", "", "drop findings weaker than this tier: confirmed, likely or possible")
	cmd.Flags().StringVar(&title, "title", "", "heading for the HTML report")
	cmd.Flags().StringVar(&publisher, "publisher", "", "organisation issuing the VEX document")
	cmd.Flags().StringVar(&namespace, "publisher-namespace", "", "URI identifying the VEX publisher")
	cmd.Flags().StringVar(&trackingID, "tracking-id", "", "VEX document id, generated from the timestamp when unset")
	cmd.Flags().StringVar(&tlp, "tlp", "AMBER", "sharing label for the VEX document: RED, AMBER, GREEN or WHITE")
	cmd.Flags().BoolVar(&addresses, "include-addresses", false,
		"put device addresses in the VEX document, for copies that stay in house")

	return cmd
}

func renderReport(w io.Writer, format string, set *finding.Set, vexOpts report.VEXOptions, htmlOpts report.HTMLOptions) error {
	switch format {
	case "csv":
		return report.WriteCSV(w, set)
	case "html":
		return report.WriteHTML(w, set, htmlOpts)
	case "vex":
		doc, err := report.BuildVEX(set, vexOpts)
		if err != nil {
			return err
		}
		return report.WriteVEX(w, doc)
	default:
		return fmt.Errorf("unknown format %q", format)
	}
}

// writeReport renders to a temporary file and moves it into place.
//
// A report that fails halfway leaves a truncated file behind, and the next
// person to open it has no way to tell that from a report of a quiet network.
// Writing beside the target and renaming means the path either holds the last
// good report or the new one.
func writeReport(path string, render func(io.Writer) error) (int64, error) {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return 0, fmt.Errorf("create output directory: %w", err)
		}
	}

	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return 0, fmt.Errorf("create temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	counter := &countingWriter{w: bufio.NewWriter(tmp)}
	if err := render(counter); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := counter.w.Flush(); err != nil {
		tmp.Close()
		return 0, fmt.Errorf("write report: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close report: %w", err)
	}

	// Windows will not rename onto an existing file.
	_ = os.Remove(path)
	if err := os.Rename(tmpName, path); err != nil {
		return 0, fmt.Errorf("move report into place: %w", err)
	}
	return counter.n, nil
}

type countingWriter struct {
	w interface {
		io.Writer
		Flush() error
	}
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	written, err := c.w.Write(p)
	c.n += int64(written)
	return written, err
}

// filterByTier drops findings below the floor, leaving the run counters intact.
//
// The counters describe the inputs rather than the output, so recomputing them
// from what survived the filter would report a plant that was never assessed.
func filterByTier(set *finding.Set, floor finding.Tier) *finding.Set {
	if floor == "" {
		return set
	}

	filtered := *set
	filtered.Findings = make([]finding.Finding, 0, len(set.Findings))
	for _, f := range set.Findings {
		if f.Tier.Rank() >= floor.Rank() {
			filtered.Findings = append(filtered.Findings, f)
		}
	}
	filtered.Finalize()
	return &filtered
}

func defaultReportPath(findingsPath, format string) string {
	base := strings.TrimSuffix(filepath.Base(findingsPath), filepath.Ext(findingsPath))
	if base == "" {
		base = "report"
	}
	return filepath.Join(filepath.Dir(findingsPath), base+reportSuffixes[format])
}

func printReportSummary(out io.Writer, format string, full, kept *finding.Set, floor finding.Tier, addresses bool) {
	if floor != "" && len(kept.Findings) != len(full.Findings) {
		fmt.Fprintf(out, "%d of %d findings are %s or stronger\n",
			len(kept.Findings), len(full.Findings), floor)
	} else {
		fmt.Fprintf(out, "%s\n", plural(len(kept.Findings), "finding"))
	}

	if format != "vex" {
		return
	}

	// The VEX reader gets one number that the findings document does not make
	// obvious: how much of what was found is being asserted rather than
	// qualified. That is the difference between a document that will be argued
	// with and one that will be believed.
	confirmed := kept.Summary.ByTier[finding.TierConfirmed]
	investigating := len(kept.Findings) - confirmed
	fmt.Fprintf(out, "  %s stated as known_affected\n", plural(confirmed, "product finding"))
	fmt.Fprintf(out, "  %s stated as under_investigation\n", plural(investigating, "product finding"))
	if !addresses {
		fmt.Fprintln(out, "  device addresses omitted, pass --include-addresses to keep them")
	}
}
