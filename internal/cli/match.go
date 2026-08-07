package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/advisory"
	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/finding"
	"github.com/yoyowpuw/OTScout/internal/match"
)

func newMatchCommand(opts *Options) *cobra.Command {
	var (
		inventoryPath string
		corpusDir     string
		outputPath    string
		minTier       string
		sinceDays     int
		limit         int
	)

	cmd := &cobra.Command{
		Use:   "match",
		Short: "Correlate an inventory against the advisory corpus",
		Long: `match correlates the asset inventory against the local advisory corpus.

Every finding carries the whole chain of reasoning behind it: which vendor alias
resolved, which product designation matched, which version range was evaluated by
which comparator, and what that evaluation returned. In a plant a false positive
costs an engineer a trip to a panel, so a match that cannot explain itself is
worth less than no match at all.

Findings are graded into three tiers:

  confirmed  the device is identified well enough for the advisory to apply, and
             its version falls inside an affected range
  likely     the device is identified, but its version could not be compared, so
             neither affected nor safe can be claimed
  possible   the advisory names a designation more specific than the device
             reported, which makes this a lead rather than a conclusion

A device whose version the corpus positively rules out produces no finding, and
the count of those is reported, so that an empty result can be told apart from a
run that did nothing.

This command sends no packets and needs no network.

Examples:

  otscout match
  otscout match --inventory assets.json --corpus corpus/
  otscout match --min-tier likely
  otscout match --since 90 --output findings.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			tier, err := parseTier(minTier)
			if err != nil {
				return err
			}

			inv, err := asset.LoadInventory(inventoryPath)
			if err != nil {
				return err
			}
			corpus, err := advisory.LoadCorpus(corpusDir)
			if err != nil {
				return err
			}

			var since time.Time
			if sinceDays > 0 {
				since = time.Now().UTC().AddDate(0, 0, -sinceDays)
			}

			matcher, err := match.New(corpus, match.Options{MinTier: tier, Since: since})
			if err != nil {
				return err
			}

			set := matcher.Run(inv)
			set.InventoryPath = inventoryPath
			set.CorpusPath = corpusDir

			if err := set.Save(outputPath); err != nil {
				return err
			}

			opts.progressf(out, "wrote %s\n", outputPath)
			printMatchSummary(out, opts, set, matcher, limit)
			return nil
		},
	}

	cmd.Flags().StringVarP(&inventoryPath, "inventory", "i", "assets.json", "inventory to match")
	cmd.Flags().StringVarP(&corpusDir, "corpus", "c", "corpus", "advisory corpus directory")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "findings.json", "where to write the findings")
	cmd.Flags().StringVar(&minTier, "min-tier", "", "drop findings weaker than this tier: confirmed, likely or possible")
	cmd.Flags().IntVar(&sinceDays, "since", 0, "only consider advisories published in the last N days, 0 for all")
	cmd.Flags().IntVar(&limit, "top", 10, "how many findings to print, 0 for none")

	return cmd
}

func parseTier(value string) (finding.Tier, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return "", nil
	case string(finding.TierConfirmed):
		return finding.TierConfirmed, nil
	case string(finding.TierLikely):
		return finding.TierLikely, nil
	case string(finding.TierPossible):
		return finding.TierPossible, nil
	default:
		return "", fmt.Errorf("unknown tier %q, expected confirmed, likely or possible", value)
	}
}

func printMatchSummary(out io.Writer, opts *Options, set *finding.Set, matcher *match.Matcher, limit int) {
	s := set.Summary

	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "findings\t%d\n", s.Total)
	fmt.Fprintf(tw, "  confirmed\t%d\n", s.ByTier[finding.TierConfirmed])
	fmt.Fprintf(tw, "  likely\t%d\n", s.ByTier[finding.TierLikely])
	fmt.Fprintf(tw, "  possible\t%d\n", s.ByTier[finding.TierPossible])
	fmt.Fprintf(tw, "assets affected\t%d of %d\n", s.AssetsAffected, s.AssetsConsidered)
	fmt.Fprintf(tw, "unique cves\t%d\n", s.UniqueCVEs)
	fmt.Fprintf(tw, "known exploited\t%d\n", s.KEVCount)
	fmt.Fprintf(tw, "vendor fix available\t%d\n", s.FixAvailable)
	fmt.Fprintf(tw, "ruled out by version\t%d\n", s.RuledOutByVersion)
	tw.Flush()

	// An empty findings list means one thing if nothing matched and quite another
	// if nothing could be identified, and reading the second as the first would
	// have an operator call a site clean when the ingest was simply thin.
	if s.AssetsUnidentified > 0 || s.AssetsUnknownVendo > 0 {
		fmt.Fprintln(out)
		tw = tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
		fmt.Fprintf(tw, "assets that reported nothing about themselves\t%d\n", s.AssetsUnidentified)
		fmt.Fprintf(tw, "assets whose vendor is not in the alias table\t%d\n", s.AssetsUnknownVendo)
		tw.Flush()
		if s.AssetsUnknownVendo > 0 {
			fmt.Fprintln(out, "\nan asset whose vendor cannot be resolved is matched against nothing.")
			fmt.Fprintln(out, "adding the alias is the single most useful contribution to make.")
		}
	}

	if opts.Verbose {
		fmt.Fprintf(out, "\ncorpus reachable by %d vendors\n", matcher.IndexedVendors())
	}

	if limit <= 0 || len(set.Findings) == 0 {
		return
	}

	shown := set.Findings
	if len(shown) > limit {
		shown = shown[:limit]
	}

	fmt.Fprintln(out)
	tw = tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "  TIER\tASSET\tDEVICE\tADVISORY\tSEVERITY\tFLAGS")
	for _, f := range shown {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\t%s\n",
			f.Tier, f.AssetAddress, truncate(f.AssetLabel, 28), f.AdvisoryID,
			severityCell(f), flagCell(f))
	}
	tw.Flush()

	if len(set.Findings) > len(shown) {
		fmt.Fprintf(out, "\n%d more in the output file\n", len(set.Findings)-len(shown))
	}
}

func severityCell(f finding.Finding) string {
	if f.CVSS > 0 {
		return fmt.Sprintf("%s %.1f", firstNonEmptyString(f.Severity, "unrated"), f.CVSS)
	}
	return firstNonEmptyString(f.Severity, "unrated")
}

// flagCell spells the flags out in words. Severity is never conveyed by colour
// alone anywhere in this project, and a terminal that has been piped to a file
// has no colour at all.
func flagCell(f finding.Finding) string {
	flags := make([]string, 0, 3)
	if f.KEV {
		flags = append(flags, "exploited")
	}
	if f.EPSS >= 0.1 {
		flags = append(flags, fmt.Sprintf("epss %.2f", f.EPSS))
	}
	if f.FixAvailable {
		flags = append(flags, "fix")
	}
	if len(flags) == 0 {
		return "-"
	}
	return strings.Join(flags, ", ")
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 3 {
		return value[:width]
	}
	return value[:width-3] + "..."
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
