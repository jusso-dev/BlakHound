// Command blakhound is a local-first AWS attack-path discovery CLI and MCP
// server. All analysis is deterministic and runs against a local SQLite graph;
// no data leaves the machine and no AWS resource is ever modified.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/blakhound/blakhound/internal/cli"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	root := cli.RootCommand()
	root.SetContext(ctx)
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
