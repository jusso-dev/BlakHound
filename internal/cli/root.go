// Package cli wires the Cobra command tree. Handlers stay thin and delegate to
// the app.Service layer so the CLI and MCP behave identically.
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/blakhound/blakhound/internal/app"
	"github.com/blakhound/blakhound/internal/config"
	"github.com/blakhound/blakhound/internal/graph"
)

var cfg = &config.Config{}
var regionsFlag string
var servicesFlag string

// RootCommand builds the root command tree.
func RootCommand() *cobra.Command { return newRootCmd() }

// Execute runs the root command.
func Execute() error {
	return newRootCmd().Execute()
}

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "blakhound",
		Short:         "BlakHound — local-first AWS attack-path discovery CLI and MCP server",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			cfg.Regions = config.SplitList(regionsFlag)
			cfg.Normalize()
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&cfg.Profile, "profile", "", "AWS profile")
	pf.StringVar(&cfg.Region, "region", "", "AWS region")
	pf.StringVar(&regionsFlag, "regions", "", "comma-separated AWS regions")
	pf.StringVar(&cfg.AccountID, "account-id", "", "expected AWS account id")
	pf.StringVar(&cfg.RoleARN, "role-arn", "", "role to assume for collection")
	pf.StringVar(&cfg.ExternalID, "external-id", "", "external id for AssumeRole")
	pf.StringVar(&cfg.DBPath, "db", "", "SQLite database path (default ~/.blakhound/blakhound.db)")
	pf.StringVarP(&cfg.Output, "output", "o", "table", "output format: table|json|yaml")
	pf.StringVar(&cfg.LogLevel, "log-level", "info", "log level: debug|info|warn|error")
	pf.BoolVar(&cfg.NoColor, "no-color", false, "disable colour output")
	pf.BoolVar(&cfg.Quiet, "quiet", false, "suppress progress output")

	root.AddCommand(
		newVersionCmd(),
		newAuthCmd(),
		newCollectCmd(),
		newScanCmd(),
		newFindingsCmd(),
		newFindingCmd(),
		newPathCmd(),
		newWhoCanAccessCmd(),
		newWhatCanAccessCmd(),
		newExplainCmd(),
		newGraphCmd(),
		newSearchCmd(),
		newNodeCmd(),
		newEdgeCmd(),
		newDBCmd(),
		newDoctorCmd(),
		newMCPCmd(),
	)
	for _, mk := range extraCommands {
		root.AddCommand(mk())
	}
	return root
}

// withService opens the store and builds a Service for a command.
func withService(ctx context.Context, fn func(ctx context.Context, svc *app.Service) error) error {
	store, err := graph.Open(ctx, cfg.DBPath)
	if err != nil {
		return err
	}
	defer store.Close()
	return fn(ctx, app.New(store, cfg))
}

// emit writes v as JSON when output=json, otherwise calls the table writer.
func emit(v any, table func()) {
	if cfg.Output == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(v)
		return
	}
	table()
}

func errf(format string, a ...any) error { return fmt.Errorf(format, a...) }
