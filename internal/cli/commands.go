package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/jusso-dev/BlakHound/internal/app"
	"github.com/jusso-dev/BlakHound/internal/awsclient"
	"github.com/jusso-dev/BlakHound/internal/config"
	"github.com/jusso-dev/BlakHound/internal/graph"
	"github.com/jusso-dev/BlakHound/internal/version"
	"github.com/jusso-dev/BlakHound/pkg/models"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		RunE: func(cmd *cobra.Command, args []string) error {
			info := map[string]any{
				"version": version.Version, "commit": version.Commit,
				"build_date": version.BuildDate, "schema_version": version.SchemaVersion,
			}
			emit(info, func() {
				fmt.Printf("blakhound %s (commit %s, built %s, schema v%d)\n",
					version.Version, version.Commit, version.BuildDate, version.SchemaVersion)
			})
			return nil
		},
	}
}

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "auth", Short: "Authentication helpers"}
	check := &cobra.Command{
		Use:   "check",
		Short: "Verify AWS credentials and print the caller identity",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			awsCfg, err := awsclient.Load(ctx, cfg)
			if err != nil {
				return err
			}
			ident, err := awsclient.WhoAmI(ctx, awsCfg)
			if err != nil {
				return err
			}
			emit(ident, func() {
				fmt.Printf("Account: %s\nARN:     %s\nUserID:  %s\n", ident.Account, ident.ARN, ident.UserID)
			})
			return nil
		},
	}
	cmd.AddCommand(check)
	return cmd
}

func newDoctorCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run environment and database health checks",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			type check struct {
				Name   string `json:"name"`
				Status string `json:"status"`
				Detail string `json:"detail"`
			}
			var checks []check
			// DB perms.
			if fi, err := os.Stat(cfg.DBPath); err == nil {
				mode := fi.Mode().Perm()
				st := "ok"
				if mode&0o077 != 0 {
					st = "warn"
				}
				checks = append(checks, check{"database-permissions", st, fmt.Sprintf("%s mode %o", cfg.DBPath, mode)})
			} else {
				checks = append(checks, check{"database", "info", "no database yet at " + cfg.DBPath})
			}
			// AWS identity.
			if awsCfg, err := awsclient.Load(ctx, cfg); err != nil {
				checks = append(checks, check{"aws-credentials", "warn", err.Error()})
			} else if ident, err := awsclient.WhoAmI(ctx, awsCfg); err != nil {
				checks = append(checks, check{"aws-credentials", "warn", err.Error()})
			} else {
				checks = append(checks, check{"aws-credentials", "ok", ident.ARN})
			}
			checks = append(checks, check{"mcp-stdio", "ok", "server available via 'blakhound mcp'"})
			emit(checks, func() {
				for _, c := range checks {
					fmt.Printf("[%-4s] %s: %s\n", strings.ToUpper(c.Status), c.Name, c.Detail)
				}
			})
			return nil
		},
	}
}

func newDBCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "db", Short: "Database maintenance"}
	cmd.AddCommand(&cobra.Command{
		Use: "info", Short: "Show database statistics",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				nc, ec, err := svc.Store.Counts(ctx)
				if err != nil {
					return err
				}
				snaps, _ := svc.Store.ListSnapshots(ctx)
				info := map[string]any{"path": svc.Store.Path(), "node_counts": nc, "edge_counts": ec, "snapshots": len(snaps)}
				emit(info, func() {
					fmt.Printf("Database: %s\nSnapshots: %d\nNodes:\n", svc.Store.Path(), len(snaps))
					for _, k := range sortedStrKeys(nc) {
						fmt.Printf("  %-24s %d\n", k, nc[k])
					}
					fmt.Println("Edges:")
					for _, k := range sortedStrKeys(ec) {
						fmt.Printf("  %-24s %d\n", k, ec[k])
					}
				})
				return nil
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "vacuum", Short: "Compact the database",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				_, err := svc.Store.DB().ExecContext(ctx, "VACUUM")
				return err
			})
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use: "migrate", Short: "Apply pending migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				fmt.Println("migrations applied")
				return nil
			})
		},
	})
	var yes bool
	reset := &cobra.Command{
		Use: "reset", Short: "Delete the database (requires confirmation)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !yes {
				return errf("refusing to delete %s without --yes", cfg.DBPath)
			}
			if err := os.Remove(cfg.DBPath); err != nil && !os.IsNotExist(err) {
				return err
			}
			_ = os.Remove(cfg.DBPath + "-wal")
			_ = os.Remove(cfg.DBPath + "-shm")
			fmt.Printf("deleted %s\n", cfg.DBPath)
			return nil
		},
	}
	reset.Flags().BoolVar(&yes, "yes", false, "confirm deletion")
	cmd.AddCommand(reset)
	return cmd
}

func newCollectCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "collect",
		Short: "Collect a read-only AWS inventory into the local graph",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				res, err := svc.Collect(ctx, app.CollectOptions{
					Services: config.SplitList(servicesFlag), Regions: cfg.Regions, Force: force,
				})
				if err != nil {
					return err
				}
				emit(res, func() {
					fmt.Printf("Collected account %s as %s\n", res.AccountID, res.CallerARN)
					fmt.Printf("Snapshot %s: %d nodes, %d edges (+%d derived), %d API requests\n",
						res.SnapshotID, res.Nodes, res.Edges, res.DerivedEdges, res.APIRequests)
					printWarnings(res.Warnings)
				})
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "force a fresh collection")
	cmd.Flags().StringVar(&servicesFlag, "services", "", "comma-separated services (default all)")
	return cmd
}

func newScanCmd() *cobra.Command {
	var severity, category string
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Run attack-rule detections and record findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				findings, err := svc.Scan(ctx)
				if err != nil {
					return err
				}
				findings = filterFindings(findings, severity, category)
				emit(findings, func() { printFindings(findings) })
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&severity, "severity", "", "filter by severity")
	cmd.Flags().StringVar(&category, "category", "", "filter by category")
	return cmd
}

func newFindingsCmd() *cobra.Command {
	var status string
	cmd := &cobra.Command{
		Use:   "findings",
		Short: "List recorded findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				f := graph.FindingFilter{}
				if status != "" {
					f.Status = []string{status}
				}
				list, err := svc.Store.ListFindings(ctx, f)
				if err != nil {
					return err
				}
				emit(list, func() { printFindings(list) })
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&status, "status", "", "filter by status")
	return cmd
}

func newFindingCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "finding", Short: "Inspect or manage a finding"}
	cmd.AddCommand(&cobra.Command{
		Use: "show <id>", Short: "Show a finding", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				f, err := svc.Store.GetFinding(ctx, args[0])
				if err != nil {
					return err
				}
				if f == nil {
					return errf("finding not found: %s", args[0])
				}
				emit(f, func() {
					fmt.Printf("%s  %s  [%s]\n%s\n\n%s\n", strings.ToUpper(f.Severity), f.ID, f.RuleID, f.Title, f.Description)
					for _, m := range f.Remediation {
						fmt.Printf("Remediation: %s\n", m.Description)
					}
					fmt.Printf("Evidence: %s\n", strings.Join(f.EvidenceIDs, ", "))
				})
				return nil
			})
		},
	})
	var reason, ticket string
	sup := &cobra.Command{
		Use: "suppress <id>", Short: "Suppress a finding", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if reason == "" {
				return errf("--reason is required")
			}
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				f, err := svc.Store.GetFinding(ctx, args[0])
				if err != nil || f == nil {
					return errf("finding not found: %s", args[0])
				}
				user := os.Getenv("USER")
				return svc.Store.Suppress(ctx, f.Fingerprint, reason, user, ticket, time.Now().UTC())
			})
		},
	}
	sup.Flags().StringVar(&reason, "reason", "", "suppression reason (required)")
	sup.Flags().StringVar(&ticket, "ticket", "", "optional ticket reference")
	cmd.AddCommand(sup)
	cmd.AddCommand(&cobra.Command{
		Use: "unsuppress <id>", Short: "Remove a suppression", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				f, err := svc.Store.GetFinding(ctx, args[0])
				if err != nil || f == nil {
					return errf("finding not found: %s", args[0])
				}
				return svc.Store.Unsuppress(ctx, f.Fingerprint)
			})
		},
	})
	return cmd
}

func filterFindings(in []models.Finding, severity, category string) []models.Finding {
	if severity == "" && category == "" {
		return in
	}
	var out []models.Finding
	for _, f := range in {
		if severity != "" && f.Severity != severity {
			continue
		}
		if category != "" && f.Category != category {
			continue
		}
		out = append(out, f)
	}
	return out
}
