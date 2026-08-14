// Package mcp — MCP tool registrations.
//
// RegisterTools adds all 7 MCP tools to the server using AddTool with typed
// input structs and jsonschema tags: recon, subs, web, vulns, osint, monitor
// and report. All seven execute the same handlers the CLI uses (MCP-02);
// monitor and report were stubs answering {"status":"not_implemented"} until
// they were wired to RunMonitorAsync and RenderReportsForTarget.
//
// Each real tool handler follows this pattern (D-02 async + D-06 scope + A2 fallback):
//
//  1. Extract sessionID from req.GetSession() (A1 — *mcp.ServerSession cast verified).
//  2. A2 FALLBACK (W2): if session scope is nil (stdio transport / test), capture
//     the first call's target as the implicit fixed session scope via SetScope BEFORE
//     CheckScope. Subsequent calls with a different target are rejected.
//  3. CheckScope: hard-reject (ErrOutOfScope) if target is not in session scope (D-06).
//  4. Generate a crypto/rand runID (128-bit entropy — T-08-04-06).
//  5. Register the runID in the SessionRegistry.
//  6. Launch a goroutine with the appropriate RunXxxAsync handler.
//  7. Return {"run_id":"…","resource":"scan://…/findings"} immediately (non-blocking).
//
// report is SYNCHRONOUS — it reads the store and writes files in seconds, so it
// returns the rendered paths directly rather than a run_id whose findings
// resource would never change.
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// --- Tool input schema types -----------------------------------------------

// SubsInput is the typed input struct for the "subs" tool.
// go-sdk reflects on this type at registration time to infer the JSON Schema.
// Fields without json:"...,omitempty" are treated as required by the schema infer.
type SubsInput struct {
	Target string `json:"target"           jsonschema:"Target domain for subdomain enumeration"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"Preview tasks without executing tools"`
}

// WebInput is the typed input struct for the "web" tool.
type WebInput struct {
	Target string `json:"target"           jsonschema:"Target domain for web analysis"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"Preview tasks without executing tools"`
	Hosts  string `json:"hosts,omitempty"   jsonschema:"Path to seed host list file (optional)"`
}

// VulnsInput is the typed input struct for the "vulns" tool.
type VulnsInput struct {
	Target string `json:"target"           jsonschema:"Target domain for vulnerability scanning"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"Preview tasks without executing tools"`
	URLs   string `json:"urls,omitempty"    jsonschema:"Path to seed URL list file (optional)"`
}

// OSINTInput is the typed input struct for the "osint" tool.
type OSINTInput struct {
	Target string `json:"target"           jsonschema:"Target domain for OSINT collection"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"Preview tasks without executing tools"`
}

// MonitorInput is the typed input struct for the "monitor" tool (Phase-10 stub).
type MonitorInput struct {
	Target   string `json:"target"            jsonschema:"Target domain to monitor"`
	Interval string `json:"interval,omitempty" jsonschema:"Polling interval (e.g. 1h, 30m)"`
	Cycles   int    `json:"cycles,omitempty"   jsonschema:"Number of monitor cycles (0 = infinite)"`
}

// ReportInput is the typed input struct for the "report" tool (Phase-10 stub).
type ReportInput struct {
	Target string `json:"target" jsonschema:"Target domain to generate report for"`
}

// --- RegisterTools ---------------------------------------------------------

// RegisterTools registers all 7 MCP tools on srv.
//
// Parameters:
//   - srv: the go-sdk *mcp.Server
//   - newSched: factory producing a FRESH per-scan scheduler per tool call; all
//     produced schedulers share one process-wide Limiter so concurrent D-03
//     sessions stay within PARALLEL_MAX_JOBS (MCP-05) while each scan owns its
//     RunTask/Checkpoint/Hash (no cross-session race)
//   - registry: session registry for scope lookup + run tracking
//   - rdct: redactor (unused by tools directly; passed for future log integration)
//   - cfg: MCP config (unused by tools directly; available for future per-tool flags)
//   - mcpSrv: the MCPServer owning the scanCtx used by scan goroutines (W4 — goroutine lifecycle)
func RegisterTools(srv *mcp.Server, newSched func() *scheduler.Scheduler, registry *SessionRegistry, rdct *log.Redactor, cfg *config.MCPConfig, mcpSrv *MCPServer) {
	// Silence unused-parameter lint if redactor/cfg not used yet.
	_ = rdct
	_ = cfg

	// 1. recon — the composite recon pipeline (subs → web → osint), identical to
	// the CLI `recon` subcommand.
	//
	// This used to call RunSubsAsync, a Phase-9-era placeholder: the tool was
	// named recon, described as recon, and ran subdomain enumeration only, so an
	// MCP client asking for recon silently got a fraction of it. MCP-02 requires
	// the CLI and MCP to invoke identical pipeline logic.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "recon",
		Description: "Run the full recon pipeline: subdomain enumeration, web probing and analysis, and OSINT collection (no vulnerability scanning — use the vulns tool for that).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args SubsInput) (*mcp.CallToolResult, any, error) {
		runRecon := func(ctx context.Context, opts handlers.RunOptions) error {
			return handlers.RunCompositeAsync(ctx, opts, handlers.ModeRecon)
		}
		return realToolHandler(mcpSrv.scanCtx, req, args.Target, args.DryRun, "", newSched, registry, srv, runRecon)
	})

	// 2. subs — passive + active subdomain enumeration pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "subs",
		Description: "Run subdomain enumeration (passive + active + permut + takeover).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args SubsInput) (*mcp.CallToolResult, any, error) {
		return realToolHandler(mcpSrv.scanCtx, req, args.Target, args.DryRun, "", newSched, registry, srv, handlers.RunSubsAsync)
	})

	// 3. web — web probe + analysis pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "web",
		Description: "Run web probe + analysis pipeline (HTTP probing, WAF detection, URL crawl, JS analysis).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args WebInput) (*mcp.CallToolResult, any, error) {
		return realToolHandler(mcpSrv.scanCtx, req, args.Target, args.DryRun, args.Hosts, newSched, registry, srv, handlers.RunWebAsync)
	})

	// 4. vulns — vulnerability scanning pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vulns",
		Description: "Run vulnerability scanning pipeline (XSS, SQLi, SSRF, SSTI, CRLF, LFI, Nuclei DAST).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args VulnsInput) (*mcp.CallToolResult, any, error) {
		return realToolHandler(mcpSrv.scanCtx, req, args.Target, args.DryRun, args.URLs, newSched, registry, srv, handlers.RunVulnsAsync)
	})

	// 5. osint — OSINT collection pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "osint",
		Description: "Run OSINT collection pipeline (domain info, emails, GitHub leaks, Google dorks, cloud enum).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args OSINTInput) (*mcp.CallToolResult, any, error) {
		return realToolHandler(mcpSrv.scanCtx, req, args.Target, args.DryRun, "", newSched, registry, srv, handlers.RunOSINTAsync)
	})

	// 6. monitor — recurring composite cycles with cross-cycle diffing.
	//
	// This and `report` below were registered as tools that answered
	// {"status":"not_implemented"}. Advertising a capability the server does
	// not have is worse than not advertising it: a client discovers the tool,
	// calls it, gets a success-shaped response and no scan. Both now run the
	// same handlers the CLI uses (MCP-02).
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "monitor",
		Description: "Run monitor mode: repeated recon cycles with cross-cycle diffing, reporting newly discovered assets and findings.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args MonitorInput) (*mcp.CallToolResult, any, error) {
		interval, err := parseMonitorInterval(args.Interval)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf(`{"error":"invalid_interval","message":%q}`, err.Error()),
				}},
				IsError: true,
			}, nil, nil
		}
		runMonitor := func(ctx context.Context, opts handlers.RunOptions) error {
			return handlers.RunMonitorAsync(ctx, opts, handlers.MonitorOptions{
				Mode:      handlers.ModeRecon,
				Interval:  interval,
				MaxCycles: args.Cycles,
			})
		}
		return realToolHandler(mcpSrv.scanCtx, req, args.Target, false, "", newSched, registry, srv, runMonitor)
	})

	// 7. report — regenerate reports for the latest completed scan.
	//
	// Synchronous: report rendering reads the store and writes files in
	// seconds, so there is nothing for the async run/notify machinery to do —
	// and returning a run_id whose findings resource would never change is
	// exactly the kind of success-shaped non-answer the stub gave.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "report",
		Description: "Regenerate reports (HTML/JSON/CSV/SARIF) for a target's latest completed scan from the store. Runs no scan.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args ReportInput) (*mcp.CallToolResult, any, error) {
		var sessionID string
		if sess, ok := req.GetSession().(*mcp.ServerSession); ok && sess != nil {
			sessionID = sess.ID()
		}
		// Same D-06 scope guard the scanning tools apply: a report exposes a
		// target's findings, so it must be scope-checked like a scan.
		if _, exists := registry.Lookup(sessionID); !exists {
			registry.Register(sessionID, "", nil)
			registry.SetScope(sessionID, NewSessionScope([]string{args.Target}))
		}
		if err := CheckScope(sessionID, args.Target, registry); err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf(`{"error":"out_of_scope","message":%q}`, err.Error()),
				}},
				IsError: true,
			}, nil, nil
		}
		paths, err := handlers.RenderReportsForTarget(ctx, args.Target)
		if err != nil {
			return &mcp.CallToolResult{
				Content: []mcp.Content{&mcp.TextContent{
					Text: fmt.Sprintf(`{"error":"report_failed","message":%q}`, err.Error()),
				}},
				IsError: true,
			}, nil, nil
		}
		body, _ := json.Marshal(map[string]any{"target": args.Target, "reports": paths})
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
		}, nil, nil
	})
}

// parseMonitorInterval turns the tool's "1h"/"30m" string into a Duration.
// Empty means "use the configured default", signalled as 0.
func parseMonitorInterval(s string) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("interval %q is not a duration (try 30m, 1h): %w", s, err)
	}
	if d < 0 {
		return 0, fmt.Errorf("interval %q must not be negative", s)
	}
	return d, nil
}

// --- helpers ---------------------------------------------------------------

// runFunc is the shared function signature for RunXxxAsync handlers.
type runFunc func(ctx context.Context, opts handlers.RunOptions) error

// realToolHandler implements the D-02 async + D-06 scope-guard + A2 fallback
// pattern shared by all real tool handlers (recon, subs, web, vulns, osint).
//
// Steps:
//  1. Extract sessionID from req.GetSession() (A1 type assertion).
//  2. A2 FALLBACK (W2): if session scope is nil, capture first call's target.
//  3. CheckScope: hard-reject out-of-scope targets (D-06).
//  4. Generate crypto/rand runID (T-08-04-06 128-bit entropy).
//  5. Register the runID in the SessionRegistry.
//  6. Launch goroutine via launchScanAndNotify (non-blocking return, D-02).
//  7. Return {"run_id":"…","resource":"scan://…/findings"} immediately.
func realToolHandler(
	ctx context.Context,
	req *mcp.CallToolRequest,
	target string,
	dryRun bool,
	extraFile string,
	newSched func() *scheduler.Scheduler,
	registry *SessionRegistry,
	srv *mcp.Server,
	fn runFunc,
) (*mcp.CallToolResult, any, error) {
	// Step 1: Extract sessionID (A1 — *mcp.ServerSession cast verified in sdk_assumptions_test.go).
	var sessionID string
	if sess, ok := req.GetSession().(*mcp.ServerSession); ok && sess != nil {
		sessionID = sess.ID()
	}
	// sessionID may be "" for in-memory transports (A2 partial).

	// Step 2: A2 FALLBACK (W2).
	// If this session has no scope entry yet (ID="" or not yet registered by InitializedHandler),
	// capture the first tool call's target as the implicit fixed session scope.
	// BEFORE CheckScope, so CheckScope sees a non-nil scope.
	entry, exists := registry.Lookup(sessionID)
	if !exists || entry.Scope == nil {
		// First tool call for this session: capture target as implicit session scope.
		// SetScope is a no-op if sessionID is not registered yet; we register first.
		if !exists {
			registry.Register(sessionID, "", nil)
		}
		registry.SetScope(sessionID, NewSessionScope([]string{target}))
	}

	// Step 3: CheckScope — hard-reject out-of-scope targets (D-06).
	// This validates the target against the now-set scope.
	if err := CheckScope(sessionID, target, registry); err != nil {
		return &mcp.CallToolResult{
			Content: []mcp.Content{&mcp.TextContent{
				Text: fmt.Sprintf(`{"error":"out_of_scope","message":%q}`, err.Error()),
			}},
			IsError: true,
		}, nil, nil
	}

	// Step 4: Generate crypto/rand runID — 16 random bytes → 32 hex chars (128-bit entropy).
	// T-08-04-06: unpredictable runIDs prevent cross-session resource URI guessing.
	runID, err := newRunID()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp: failed to generate run ID: %w", err)
	}

	resourceURI := "scan://" + runID + "/findings"

	// Step 5: Register the runID against the session that launched it. Ownership
	// is what authorises later resource reads and subscriptions — an
	// unpredictable runID makes URIs hard to guess, but guessability is not an
	// access-control model.
	registry.RegisterRun(runID, sessionID)

	// Step 6: Launch scan goroutine (D-02 async — handler returns immediately).
	// ctx here is mcpSrv.scanCtx (the server-lifetime context), NOT the tool
	// call context. The scan must outlive the MCP request/response cycle (D-02).
	// Using mcpSrv.scanCtx instead of context.Background() allows tests to
	// cancel all scan goroutines via t.Cleanup(srv.Cancel) (W4 — goleak-compliant).
	// srv is passed in from RegisterTools (closure captures the *mcp.Server).
	//
	// Create a FRESH per-scan scheduler (newSched). Each concurrent session gets
	// its own Scheduler so the per-scan RunTask/Checkpoint/Hash fields wired by
	// appctx.Boot never race across D-03 concurrent sessions; all per-scan
	// schedulers share one process-wide Limiter (set by the factory) so they
	// collectively cannot exceed PARALLEL_MAX_JOBS (MCP-05).
	go launchScanAndNotify(ctx, runID, handlers.RunOptions{
		Target:    target,
		DryRun:    dryRun,
		ExtraFile: extraFile,
		Scheduler: newSched(),
	}, srv, registry, fn)

	// Step 7: Return immediately with run_id + resource URI.
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: fmt.Sprintf(`{"run_id":%q,"resource":%q}`, runID, resourceURI),
			},
		},
	}, nil, nil
}

// launchScanAndNotify runs fn in a goroutine, sending server.ResourceUpdated
// notifications at each stage via a ProgressSink channel, and a final
// notification when the scan completes (or fails).
//
// Uses context.Background() so the scan is not cancelled when the tool call
// context is cancelled (D-02: tool call context ends immediately after return).
func launchScanAndNotify(
	ctx context.Context,
	runID string,
	opts handlers.RunOptions,
	srv *mcp.Server,
	registry *SessionRegistry,
	fn runFunc,
) {
	// Wire a ProgressSink so we can emit ResourceUpdated on each stage boundary.
	progressCh := make(chan handlers.StageEvent, 32)
	opts.ProgressSink = progressCh

	// Record the workspace as soon as BootReconApp resolves it. The registry was
	// seeded with an empty workdir and nothing ever filled it in, so
	// scan://<runID>/findings returned empty content for every successful scan.
	// AfterBoot is the earliest point the path exists.
	prevAfterBoot := opts.AfterBoot
	opts.AfterBoot = func(boot handlers.AppBoot) {
		registry.SetWorkDir(runID, boot.WorkDir)
		if prevAfterBoot != nil {
			prevAfterBoot(boot)
		}
	}

	// Drain the ProgressSink in a separate goroutine and emit ResourceUpdated.
	drainDone := make(chan struct{})
	go func() {
		defer close(drainDone)
		for range progressCh {
			// Notify all subscribed clients that findings may have been updated.
			_ = NotifyFindingsUpdated(ctx, srv, runID)
		}
	}()

	// Run the scan synchronously (within this goroutine).
	runErr := fn(ctx, opts)

	// Close ProgressSink to unblock the drain goroutine.
	close(progressCh)
	<-drainDone

	// Record the real outcome. The pipeline error used to be discarded with
	// `_ =` and MarkComplete was called unconditionally, so a scan that failed
	// outright still reported success to the client — SessionStatusFailed
	// existed but nothing could ever reach it.
	if runErr != nil {
		registry.MarkFailed(runID, runErr)
	} else {
		registry.MarkComplete(runID)
	}

	// Notify either way: the resource content changed (or the status did), and
	// a client waiting on it must be released rather than left hanging.
	_ = NotifyFindingsUpdated(ctx, srv, runID)
}

// newRunID generates a cryptographically-random 32-hex-character run ID
// (16 bytes = 128-bit entropy). T-08-04-06 requires unpredictable IDs.
func newRunID() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("mcp: rand.Read: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
