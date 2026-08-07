package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/advisory"
)

func newSyncCommand(opts *Options) *cobra.Command {
	var (
		dir       string
		sourceIDs []string
		providers []string
		sinceDays int
		offline   bool
		maxDocs   int
		list      bool
	)

	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Download and normalize the advisory corpus",
		Long: `sync builds the local advisory corpus that the match step correlates against.

It downloads from the public advisory feeds, reduces every one of them to the same
shape, resolves vendor and product names through the normalization tables and
parses each version range. Doing that work once, here, is what keeps a match run
from reparsing several thousand range strings.

This command talks to the internet and is not meant to run on a plant network. Run
it on a connected machine, then copy the corpus directory to the air-gapped side
and use --offline there.

Only sources that are public domain are enabled by default, so a corpus built with
no flags can be redistributed. Vendor feeds carry their own terms and have to be
asked for by name.

A vendor that is not built in can be added with --csaf-provider, which accepts a
domain and finds the feed the way the CSAF specification says to: by reading that
vendor's security.txt, then the well-known path.

Examples:

  otscout sync
  otscout sync --list
  otscout sync --source cisa-csaf --source cisa-kev
  otscout sync --source siemens-csaf --source cert-vde-csaf
  otscout sync --csaf-provider nozominetworks.com
  otscout sync --since 30
  otscout sync --offline`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			if list {
				printSourceCatalog(out)
				return nil
			}

			var since time.Time
			if sinceDays > 0 {
				since = time.Now().UTC().AddDate(0, 0, -sinceDays)
			}

			var progress io.Writer
			if !opts.Quiet {
				progress = cmd.ErrOrStderr()
			}

			report, err := advisory.Sync(cmd.Context(), advisory.SyncOptions{
				Dir:           dir,
				SourceIDs:     sourceIDs,
				CSAFProviders: providers,
				Since:         since,
				Offline:       offline,
				MaxDocs:       maxDocs,
				Progress:      progress,
			})
			if err != nil {
				return err
			}

			printSyncSummary(out, opts, report, dir)

			// A partial corpus is still worth having, so the sync is not aborted,
			// but the exit status has to say something went wrong or a scheduled
			// job would report success while quietly going stale.
			if len(report.Failed) > 0 {
				return fmt.Errorf("%d of %d sources could not be synced: %s",
					len(report.Failed), len(report.Sources), strings.Join(report.Failed, ", "))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&dir, "dir", "d", "corpus", "directory to hold the advisory corpus")
	cmd.Flags().StringSliceVar(&sourceIDs, "source", nil, "source to sync, repeatable, defaults to the public domain sources")
	cmd.Flags().StringSliceVar(&providers, "csaf-provider", nil, "extra CSAF provider given as a domain or a provider-metadata.json URL, repeatable")
	cmd.Flags().IntVar(&sinceDays, "since", 0, "only fetch advisories changed in the last N days, 0 for everything")
	cmd.Flags().BoolVar(&offline, "offline", false, "use the local cache and make no network requests")
	cmd.Flags().IntVar(&maxDocs, "max-documents", 0, "stop each source after this many documents, 0 for no limit")
	cmd.Flags().BoolVar(&list, "list", false, "print the available sources and their terms, then exit")

	return cmd
}

func printSourceCatalog(out io.Writer) {
	fmt.Fprintln(out, "advisory sources")
	fmt.Fprintln(out)

	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tDEFAULT\tREDISTRIBUTABLE\tNAME")
	for _, source := range advisory.Sources() {
		info := source.Info()
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
			info.ID, yesNo(info.DefaultEnabled), yesNo(info.Redistributable), info.Name)
	}
	tw.Flush()

	fmt.Fprintln(out)
	for _, source := range advisory.Sources() {
		info := source.Info()
		fmt.Fprintf(out, "%s\n", info.ID)
		fmt.Fprintf(out, "  %s\n", info.Summary)
		fmt.Fprintf(out, "  home    %s\n", info.Homepage)
		fmt.Fprintf(out, "  licence %s\n", info.License)
		if !info.Redistributable {
			// This is the question that decides whether a built corpus can be
			// published, and the answer is easier to give now than later.
			fmt.Fprintf(out, "  note    check the terms before publishing a corpus built from this source\n")
		}
		fmt.Fprintln(out)
	}
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func printSyncSummary(out io.Writer, opts *Options, report *advisory.SyncReport, dir string) {
	stats := report.Corpus.Stats()

	opts.progressf(out, "wrote %s\n", dir)

	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "advisories\t%d\n", stats.Advisories)
	fmt.Fprintf(tw, "products\t%d\n", stats.Products)
	fmt.Fprintf(tw, "cves\t%d\n", stats.CVEs)
	fmt.Fprintf(tw, "known exploited\t%d\n", stats.KEV)
	fmt.Fprintf(tw, "epss scores\t%d\n", stats.EPSS)
	fmt.Fprintf(tw, "requests\t%d\n", report.Fetch.Requests)
	fmt.Fprintf(tw, "unchanged\t%d\n", report.Fetch.NotModified)
	fmt.Fprintf(tw, "downloaded\t%s\n", humanBytes(report.Fetch.Bytes))
	tw.Flush()

	fmt.Fprintln(out)
	fmt.Fprintln(out, "sources")
	tw = tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	for _, state := range report.Sources {
		status := fmt.Sprintf("%d advisories", state.Advisories)
		switch {
		case state.Error != "":
			status = "failed"
		case state.Kind == string(advisory.KindEnrichment):
			status = fmt.Sprintf("%d records", state.Records)
		}
		fmt.Fprintf(tw, "  %s\t%s\n", state.ID, status)
	}
	tw.Flush()

	for _, state := range report.Sources {
		if state.Error != "" {
			fmt.Fprintf(out, "\n%s failed: %s\n", state.ID, state.Error)
		}
	}

	// Parse quality is the number that decides whether the matcher can do
	// anything useful, so it is printed rather than buried in the manifest.
	if stats.UnresolvedVendors > 0 || stats.UnparsedRanges > 0 {
		fmt.Fprintln(out)
		tw = tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
		fmt.Fprintf(tw, "products with an unrecognised vendor\t%d\n", stats.UnresolvedVendors)
		fmt.Fprintf(tw, "products with an unparsed version range\t%d\n", stats.UnparsedRanges)
		tw.Flush()
		fmt.Fprintln(out, "\nan unrecognised vendor or range weakens matching for that product.")
		fmt.Fprintln(out, "adding an alias or a range form is the single most useful contribution to make.")
	}

	if !opts.Verbose {
		return
	}

	if len(stats.BySource) > 0 {
		fmt.Fprintln(out, "\nadvisories by source")
		printCountTable(out, stats.BySource, 0)
	}
	if len(stats.ByVendor) > 0 {
		fmt.Fprintln(out, "\ntop vendors")
		printCountTable(out, stats.ByVendor, 15)
	}
	for _, state := range report.Sources {
		for _, warning := range state.Warnings {
			fmt.Fprintf(out, "warning: %s: %s\n", state.ID, warning)
		}
	}
}

// printCountTable prints a count map ordered by count, keeping the output stable
// by breaking ties on the name.
func printCountTable(out io.Writer, counts map[string]int, limit int) {
	type row struct {
		name  string
		count int
	}
	rows := make([]row, 0, len(counts))
	for name, count := range counts {
		rows = append(rows, row{name, count})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].count != rows[j].count {
			return rows[i].count > rows[j].count
		}
		return rows[i].name < rows[j].name
	})
	if limit > 0 && len(rows) > limit {
		rows = rows[:limit]
	}

	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	for _, r := range rows {
		fmt.Fprintf(tw, "  %s\t%d\n", r.name, r.count)
	}
	tw.Flush()
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for value := n / unit; value >= unit; value /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGT"[exp])
}
