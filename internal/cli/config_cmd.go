package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/blakhound/blakhound/internal/app"
	"github.com/blakhound/blakhound/internal/graph"
	"github.com/blakhound/blakhound/pkg/models"
)

func init() {
	extraCommands = append(extraCommands, newConfigCmd, newProfilesCmd, newAdminsCmd, newCrossAccountCmd)
}

// extraCommands is appended to the root command tree in newRootCmd.
var extraCommands []func() *cobra.Command

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "Configuration helpers"}
	cmd.AddCommand(&cobra.Command{
		Use: "show", Short: "Show effective configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			view := map[string]any{
				"db": cfg.DBPath, "profile": cfg.Profile, "region": cfg.Region,
				"regions": cfg.Regions, "output": cfg.Output, "log_level": cfg.LogLevel,
			}
			emit(view, func() {
				fmt.Printf("db:       %s\nprofile:  %s\nregion:   %s\noutput:   %s\n", cfg.DBPath, cfg.Profile, cfg.Region, cfg.Output)
			})
			return nil
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "init", Short: "Create the default data directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := filepath.Dir(cfg.DBPath)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				return err
			}
			fmt.Printf("data directory ready: %s\n", dir)
			return nil
		},
	})
	return cmd
}

func newProfilesCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "profiles",
		Short: "List AWS profiles from the shared config file",
		RunE: func(cmd *cobra.Command, args []string) error {
			path := os.Getenv("AWS_CONFIG_FILE")
			if path == "" {
				home, _ := os.UserHomeDir()
				path = filepath.Join(home, ".aws", "config")
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("read aws config: %w", err)
			}
			var profiles []string
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					name := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
					name = strings.TrimPrefix(name, "profile ")
					profiles = append(profiles, name)
				}
			}
			emit(profiles, func() {
				for _, p := range profiles {
					fmt.Println(p)
				}
			})
			return nil
		},
	}
}

func newAdminsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "admins",
		Short: "List principals with effective administrator findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				all, err := svc.Store.ListFindings(ctx, graph.FindingFilter{})
				if err != nil {
					return err
				}
				var findings []models.Finding
				for _, f := range all {
					if f.RuleID == "BH-AWS-IAM-007" {
						findings = append(findings, f)
					}
				}
				emit(findings, func() { printFindings(findings) })
				return nil
			})
		},
	}
}

func newCrossAccountCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cross-account",
		Short: "List roles with external or wildcard trust",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				roles, err := svc.Store.NodesByType(ctx, models.NodeIAMRole)
				if err != nil {
					return err
				}
				type row struct {
					Role  string `json:"role"`
					Edges int    `json:"external_edges"`
				}
				var out []row
				for _, r := range roles {
					in, _ := svc.Store.InEdges(ctx, r.ID, []string{models.EdgeExternalTrust, models.EdgeCrossAccountAccess})
					if len(in) > 0 {
						out = append(out, row{Role: r.Name, Edges: len(in)})
					}
				}
				emit(out, func() {
					for _, r := range out {
						fmt.Printf("%-40s %d external trust edge(s)\n", r.Role, r.Edges)
					}
				})
				return nil
			})
		},
	}
}
