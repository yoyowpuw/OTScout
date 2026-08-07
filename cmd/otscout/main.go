// Command otscout is the single binary entry point.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/yoyowpuw/OTScout/internal/cli"
)

func main() {
	// Interrupt cancels the root context so an active scan stops sending
	// packets the moment the operator asks it to. Anything that talks to a
	// control network has to be interruptible without hesitation.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCommand()
	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)

	if err := root.ExecuteContext(ctx); err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(os.Stderr, "otscout: interrupted, stopped cleanly")
			os.Exit(130)
		}
		fmt.Fprintf(os.Stderr, "otscout: %v\n", err)
		os.Exit(1)
	}
}
