// mcp.go — `reconftw mcp serve` subcommand (working per CONTEXT D-01 / Phase 8).
//
// Replaces the Phase-8 stub in stub_subcommands.go. Provides the real
// newMCPCmd + newMCPServeCmd + runMCPServeCmd cobra subcommand chain.
//
// Security obligations (from threat model T-08-04-01 through T-08-04-07):
//
//   - T-08-04-01: HTTP transport binds 127.0.0.1 only (D-05) — enforced in
//     internal/mcp/server.go runMCPServeHTTP.
//   - T-08-04-02: BearerAuthMiddleware wraps the entire mux before the MCP
//     protocol handler — enforced in internal/mcp/server.go.
//   - T-08-04-03: MCP API key registered with Redactor BEFORE the first log
//     line (XCUT-07) — registerSecrets is called here before NewMCPServer.
//   - MCP-07: cfg.MCP.Enabled gate — returns an error if disabled.
//
// Config load pattern (mirror of runSubsCmd in stub_subcommands.go):
//
//	parseEarlyFlags → config.Load → registerSecrets → scheduler → NewMCPServer → Start

package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/sync/semaphore"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	mcplib "github.com/six2dez/reconftw/internal/mcp"
)

// newMCPCmd returns the cobra "mcp" subcommand with a "serve" sub-subcommand.
// This replaces the Phase-8 stub previously in stub_subcommands.go.
func newMCPCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Model Context Protocol server (opt-in, set mcp.enabled = true to use)",
		Long: `Start the reconFTW MCP server to expose recon modes as MCP tools.

Supported transports:
  stdio  — trusted local pipe (stdin/stdout); suitable for Claude Desktop
  http   — HTTP/SSE; binds 127.0.0.1 only (D-05); requires Bearer token auth

The MCP server is disabled by default. Enable via:
  mcp.enabled = true in reconftw.toml (or RECONFTW_MCP_ENABLED=true env var)

An API key is required for both transports:
  mcp.api_key = "your-key-min-16-chars" in reconftw.toml
  or RECONFTW_MCP_API_KEY environment variable`,
		// SilenceUsage: let errors print usage from root (consistent with other cmds).
	}
	cmd.AddCommand(newMCPServeCmd())
	return cmd
}

// newMCPServeCmd returns the "mcp serve" subcommand.
func newMCPServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the MCP server (stdio or HTTP/SSE transport)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPServeCmd(cmd)
		},
	}
	// Transport and port can be overridden from the CLI (per ADR §8.1 + CONTEXT).
	cmd.Flags().String("transport", "", "Transport override: stdio or http (default: from mcp.transport in config)")
	cmd.Flags().Int("port", 0, "HTTP port override (default: from mcp.port in config)")
	return cmd
}

// runMCPServeCmd is the extracted RunE body for newMCPServeCmd.
//
// Initialization order (mirrors main.run STEP 4-7 pattern):
//  1. parseEarlyFlags → explicit --config / --secrets paths
//  2. config.Load → full 8-source config merge
//  3. MCP.Enabled guard (MCP-07) — fail fast if disabled
//  4. CLI flag overrides for transport + port
//  5. api_key validation — required for both transports (D-07)
//  6. registerSecrets → Redactor registration BEFORE first log line (XCUT-07 / T-08-04-03)
//  7. Construct shared scheduler (D-03 / Pitfall 3 — single instance for all sessions)
//  8. NewMCPServer → RegisterTools + RegisterResources
//  9. Start(ctx) → stdio or HTTP transport dispatch
func runMCPServeCmd(cmd *cobra.Command) error {
	ctx := cmd.Context()

	// Step 1: Pre-cobra early flags (W14 pattern from main.go).
	efs := parseEarlyFlags(os.Args[1:])

	// Step 2: Load config via the 8-source merge chain.
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: efs.configPath,
		SecretsPath:        efs.secretsPath,
	})
	if err != nil {
		return fmt.Errorf("mcp: config load: %w", err)
	}

	// Step 3: MCP.Enabled guard (MCP-07). Default is false — opt-in required.
	if !cfg.MCP.Enabled {
		return fmt.Errorf("mcp: disabled in config; set mcp.enabled = true in reconftw.toml or RECONFTW_MCP_ENABLED=true")
	}

	// Step 4: Apply CLI flag overrides (transport and port) AFTER config load,
	// so CLI always wins over config (standard CLI-over-config pattern).
	if transport, _ := cmd.Flags().GetString("transport"); transport != "" {
		cfg.MCP.Transport = transport
	}
	if port, _ := cmd.Flags().GetInt("port"); port > 0 {
		cfg.MCP.Port = port
	}

	// Step 5: api_key validation — required for both transports (D-07).
	// For stdio, the key is required at startup even though Bearer auth is only
	// used for HTTP (security principle: reject misconfig early).
	if string(cfg.MCP.APIKey) == "" {
		return fmt.Errorf("mcp: api_key is required; set mcp.api_key in reconftw.toml or RECONFTW_MCP_API_KEY env")
	}

	// Step 6: Register secrets with the Redactor BEFORE any log line that could
	// reference the API key (XCUT-07 / T-08-04-03).
	// registerSecrets is in cmd/reconftw/main.go and covers cfg.MCP.APIKey among
	// all 9 log.Secret-typed config fields.
	rdct := &log.Redactor{}
	registerSecrets(cfg, rdct)

	// Step 7: Build the per-scan scheduler factory + shared global limiter.
	// D-03 allows multiple concurrent MCP scan sessions. Each session must get
	// its OWN *scheduler.Scheduler because appctx.Boot wires per-scan RunTask /
	// Checkpoint / Hash onto the scheduler struct — sharing one instance across
	// concurrent sessions would race on (and corrupt) those fields, routing one
	// scan's checkpoints to another session's store. Instead, every scan gets a
	// fresh scheduler from newSched, and they all share ONE process-wide Limiter
	// (weight = MaxJobs) so total in-flight tasks across all sessions cannot
	// exceed PARALLEL_MAX_JOBS (MCP-05). The shared semaphore — not a shared
	// struct — is the correct global-concurrency primitive.
	maxJobs := cfg.Concurrency.MaxJobs
	if maxJobs <= 0 {
		maxJobs = 4 // mirror scheduler.NewScheduler's normalization
	}
	globalLimiter := semaphore.NewWeighted(int64(maxJobs))
	heartbeat := cfg.Concurrency.HeartbeatSeconds
	newSched := func() *scheduler.Scheduler {
		s := scheduler.NewScheduler(maxJobs, heartbeat, nil, nil)
		s.Limiter = globalLimiter // shared global cap (MCP-05)
		return s
	}

	// Step 8: Construct the MCPServer (registers tools + resources, builds go-sdk server).
	//
	// The RESOLVED config and the explicit paths that produced it are the
	// startup snapshot (F7): every scan carries efs.configPath / efs.secretsPath
	// in its RunOptions and re-resolves from them, and the report tool renders
	// with this cfg. Before this, only cfg.MCP was passed on and every scan
	// re-ran config.Load with no explicit paths — a server started with
	// --config scanned under a different configuration than the operator chose.
	mcpSrv := mcplib.NewMCPServer(ctx, cfg, efs.configPath, efs.secretsPath, newSched, rdct, Version)
	// Whatever ends this command — SIGINT, a transport error, a normal return —
	// must also end the scans it started. Start cancels on its own exit paths;
	// this defer is the belt to that braces, and costs nothing (Cancel is
	// idempotent). An orphaned scan keeps spawning external tool processes long
	// after the operator believes the server stopped (F9).
	defer mcpSrv.Cancel()

	// Step 9: Start the server (blocks until ctx is cancelled or an error occurs).
	return mcpSrv.Start(ctx)
}
