// Package cli wires the otscout subcommands together.
package cli

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/yoyowpuw/OTScout/internal/version"
)

// Options carries settings shared by every subcommand.
type Options struct {
	Quiet   bool
	Verbose bool
}

// NewRootCommand builds the top level command tree.
func NewRootCommand() *cobra.Command {
	opts := &Options{}

	root := &cobra.Command{
		Use:   "otscout",
		Short: "Safe ICS asset discovery and vulnerability correlation",
		Long: `otscout builds an inventory of industrial control system assets and
correlates it against public security advisories.

Two paths produce an inventory. The passive path reads packet captures, Zeek logs
and Nmap output, and sends nothing. The active path sends a small number of
read-only identification requests, under a safety engine that refuses anything
capable of changing device state.

Start with the passive path. It carries no risk to a running process and is
usually enough to see what the correlation step can do for you.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Short(),
	}

	root.PersistentFlags().BoolVarP(&opts.Quiet, "quiet", "q", false, "suppress progress output")
	root.PersistentFlags().BoolVarP(&opts.Verbose, "verbose", "v", false, "print detailed progress output")

	root.SetVersionTemplate("{{.Name}} {{.Version}}\n")

	root.AddCommand(
		newVersionCommand(),
		newIngestCommand(opts),
		newSyncCommand(opts),
		newMatchCommand(opts),
		newSafetyCommand(),
		newProbeCommand(opts),
		newTemplatesCommand(opts),
		newReportCommand(opts),
		newServeCommand(opts),
	)

	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintln(cmd.OutOrStdout(), version.Full())
			return nil
		},
	}
}

// progressf writes a progress line unless the user asked for quiet output.
func (o *Options) progressf(w io.Writer, format string, args ...any) {
	if o.Quiet {
		return
	}
	fmt.Fprintf(w, format, args...)
}

// verbosef writes a line only when verbose output was requested.
func (o *Options) verbosef(w io.Writer, format string, args ...any) {
	if !o.Verbose || o.Quiet {
		return
	}
	fmt.Fprintf(w, format, args...)
}
