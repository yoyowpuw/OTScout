package cli

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/asset"
	"github.com/yoyowpuw/OTScout/internal/ingest"
)

func newIngestCommand(opts *Options) *cobra.Command {
	var (
		pcapPaths []string
		zeekPaths []string
		nmapPaths []string
		outPath   string
		merge     bool
		maxPkts   int
	)

	cmd := &cobra.Command{
		Use:   "ingest",
		Short: "Build an inventory from captures and scan output, sending nothing",
		Long: `ingest reads data that already exists and turns it into an asset inventory.

No socket is opened and no packet is sent. Every asset it produces comes from a
packet capture, a Zeek log or an Nmap XML file that you supply, so it is safe to
run against a production plant with no notice period and no change window.

Sources may be combined and are read from most to least authoritative, so a
device identity taken from a real protocol response is never overwritten by a
weaker guess from a banner.

Examples:

  otscout ingest --pcap plant.pcapng -o assets.json
  otscout ingest --zeek /opt/zeek/logs/current -o assets.json
  otscout ingest --pcap span.pcap --nmap audit.xml --zeek logs/ -o assets.json`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()

			pcapFiles, err := expandInputs(pcapPaths)
			if err != nil {
				return err
			}
			nmapFiles, err := expandInputs(nmapPaths)
			if err != nil {
				return err
			}

			var progress io.Writer
			if !opts.Quiet {
				progress = cmd.ErrOrStderr()
			}

			result, err := ingest.Run(cmd.Context(), ingest.Options{
				PcapFiles:         pcapFiles,
				ZeekPaths:         zeekPaths,
				NmapFiles:         nmapFiles,
				MaxPacketsPerFile: maxPkts,
				Progress:          progress,
			})
			if err != nil {
				return err
			}

			inv := result.Inventory
			if merge {
				existing, err := asset.LoadInventory(outPath)
				if err != nil {
					return fmt.Errorf("merge into %s: %w", outPath, err)
				}
				existing.Merge(inv)
				inv = existing
			}

			if err := inv.Save(outPath); err != nil {
				return err
			}

			printIngestSummary(out, opts, result, outPath)
			return nil
		},
	}

	cmd.Flags().StringSliceVar(&pcapPaths, "pcap", nil, "packet capture in pcap or pcapng format, repeatable, globs allowed")
	cmd.Flags().StringSliceVar(&zeekPaths, "zeek", nil, "Zeek log file or a directory of them, repeatable")
	cmd.Flags().StringSliceVar(&nmapPaths, "nmap", nil, "Nmap XML output file, repeatable, globs allowed")
	cmd.Flags().StringVarP(&outPath, "out", "o", "assets.json", "path to write the inventory to")
	cmd.Flags().BoolVar(&merge, "merge", false, "merge into the existing inventory at the output path instead of replacing it")
	cmd.Flags().IntVar(&maxPkts, "max-packets", 0, "stop reading each capture after this many packets, 0 for no limit")

	return cmd
}

// expandInputs resolves shell globs so the command behaves the same on a shell
// that does not expand them, which on Windows is every shell.
func expandInputs(patterns []string) ([]string, error) {
	out := make([]string, 0, len(patterns))
	seen := make(map[string]bool, len(patterns))
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		matches := []string{pattern}
		if strings.ContainsAny(pattern, "*?[") {
			found, err := filepath.Glob(pattern)
			if err != nil {
				return nil, fmt.Errorf("bad file pattern %q: %w", pattern, err)
			}
			if len(found) == 0 {
				return nil, fmt.Errorf("no files match %q", pattern)
			}
			sort.Strings(found)
			matches = found
		}
		for _, match := range matches {
			if !seen[match] {
				seen[match] = true
				out = append(out, match)
			}
		}
	}
	return out, nil
}

func printIngestSummary(out io.Writer, opts *Options, result *ingest.Result, outPath string) {
	stats := result.Inventory.Stats()

	opts.progressf(out, "wrote %s\n", outPath)
	tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
	fmt.Fprintf(tw, "assets\t%d\n", stats.Assets)
	fmt.Fprintf(tw, "identified\t%d\n", stats.Identified)
	fmt.Fprintf(tw, "flows\t%d\n", stats.Flows)
	fmt.Fprintf(tw, "segmentation issues\t%d\n", stats.Segmentation)
	fmt.Fprintf(tw, "packets read\t%d\n", result.Stats.PacketsRead)
	fmt.Fprintf(tw, "files read\t%d\n", result.Stats.FilesRead)
	tw.Flush()

	if len(stats.ByProtocol) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "protocols observed")
		tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
		names := make([]string, 0, len(stats.ByProtocol))
		for name := range stats.ByProtocol {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			fmt.Fprintf(tw, "  %s\t%d\n", name, stats.ByProtocol[name])
		}
		tw.Flush()
	}

	if len(stats.ByPurdue) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "purdue placement")
		tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
		for _, level := range asset.PurdueOrder {
			if count := stats.ByPurdue[level]; count > 0 {
				fmt.Fprintf(tw, "  %s\t%d\t%s\n", level, count, level.Description())
			}
		}
		if count := stats.ByPurdue[asset.PurdueUnknown]; count > 0 {
			fmt.Fprintf(tw, "  unplaced\t%d\t%s\n", count, asset.PurdueUnknown.Description())
		}
		tw.Flush()
	}

	for _, warning := range result.Stats.Warnings {
		fmt.Fprintf(out, "warning: %s\n", warning)
	}

	opts.verbosef(out, "\nrecords read\n")
	if opts.Verbose {
		tw := tabwriter.NewWriter(out, 0, 8, 2, ' ', 0)
		kinds := make([]string, 0, len(result.Stats.RecordsRead))
		for kind := range result.Stats.RecordsRead {
			kinds = append(kinds, kind)
		}
		sort.Strings(kinds)
		for _, kind := range kinds {
			fmt.Fprintf(tw, "  %s\t%d\n", kind, result.Stats.RecordsRead[kind])
		}
		tw.Flush()
	}
}
