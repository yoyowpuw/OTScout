package cli

import (
	"errors"

	"github.com/spf13/cobra"
)

// errNotImplemented is returned by commands whose implementation has not landed
// yet. Each stub here is removed as its feature is built.
var errNotImplemented = errors.New("not implemented yet")

func stub(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			return errNotImplemented
		},
	}
}

func newReportCommand(_ *Options) *cobra.Command {
	return stub("report", "Render findings as CSV, VEX or a standalone HTML file")
}

func newServeCommand(_ *Options) *cobra.Command {
	return stub("serve", "Serve the local review interface")
}
