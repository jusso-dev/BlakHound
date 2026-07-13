package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/blakhound/blakhound/internal/app"
	"github.com/blakhound/blakhound/internal/mcp"
)

func newMCPCmd() *cobra.Command {
	var transport, listen string
	var allowRemote bool
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Run the read-only MCP server (stdio by default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return withService(cmd.Context(), func(ctx context.Context, svc *app.Service) error {
				server := mcp.NewServer(svc, os.Stderr)
				switch transport {
				case "http":
					return serveHTTP(ctx, server, listen, allowRemote)
				default:
					// stdio: protocol on stdout, logs on stderr.
					return server.ServeStdio(ctx, os.Stdin, os.Stdout)
				}
			})
		},
	}
	cmd.Flags().StringVar(&transport, "transport", "stdio", "stdio|http")
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "HTTP listen address")
	cmd.Flags().BoolVar(&allowRemote, "allow-remote", false, "allow binding to non-localhost addresses")
	return cmd
}

func serveHTTP(ctx context.Context, server *mcp.Server, listen string, allowRemote bool) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if !allowRemote && host != "127.0.0.1" && host != "localhost" && host != "::1" {
		return fmt.Errorf("refusing to bind %s without --allow-remote (localhost only by default)", listen)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", server.HTTPHandler(ctx))
	fmt.Fprintf(os.Stderr, "blakhound mcp: http server on %s\n", listen)
	srv := &http.Server{Addr: listen, Handler: mux}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
