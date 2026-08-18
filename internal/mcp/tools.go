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

// toolDeps is the wiring every tool handler needs. It exists so the tool
// closures are one-liners and so the handler bodies can be driven directly by a
// test with a chosen session ID — fabricating an *mcp.ServerSession with a
// non-empty ID() is not possible from outside the SDK, and the first-call scope
// bug (F8) only reproduces on a session that HAS an id.
//
// base is the immutable RunOptions template built from the startup snapshot.
// Every call copies it by VALUE and fills in the per-call fields, so two
// concurrent scans can never observe each other's options (T-15-15-08).
type toolDeps struct {
	srv      *mcp.Server
	newSched func() *scheduler.Scheduler
	registry *SessionRegistry
	rdct     *log.Redactor
	cfg      *config.Config
	base     handlers.RunOptions
	//nolint:containedctx // the server's scan-lifetime context, by design (W4)
	scanCtx context.Context
}

// newToolDeps builds the tool wiring, including the immutable RunOptions
// template that carries the startup configuration snapshot into every run.
//
// ConfigPath / SecretsPath: the explicit --config / --secrets the server was
// started with. handlers.ResolveRunPlan feeds them straight back into
// config.Load, so each run resolves the operator's configuration into its OWN
// instance instead of re-loading defaults (F7 / T-15-15-07).
//
// OutputDir / LogLevel: taken from the RESOLVED config so a mid-flight edit of
// the config file cannot move a running server's workspaces or change its log
// level. Both are left empty when the resolved config leaves them empty, so the
// normal fallbacks (workspaces/, the config file's level) still apply.
func newToolDeps(
	srv *mcp.Server,
	newSched func() *scheduler.Scheduler,
	registry *SessionRegistry,
	rdct *log.Redactor,
	cfg *config.Config,
	configPath, secretsPath string,
	scanCtx context.Context,
) *toolDeps {
	base := handlers.RunOptions{
		ConfigPath:  configPath,
		SecretsPath: secretsPath,
	}
	if cfg != nil {
		base.OutputDir = cfg.Paths.DataDir
		base.LogLevel = cfg.Output.LogLevel
	}
	return &toolDeps{
		srv:      srv,
		newSched: newSched,
		registry: registry,
		rdct:     rdct,
		cfg:      cfg,
		base:     base,
		scanCtx:  scanCtx,
	}
}

// runOptions returns a per-call copy of the snapshot template. The copy is the
// isolation: handlers.ResolveRunPlan applies this run's ConfigTransform to the
// config IT loads, never to anything shared.
func (d *toolDeps) runOptions(target string, dryRun bool, extraFile string) handlers.RunOptions {
	opts := d.base // value copy — never a shared pointer
	opts.Target = target
	opts.DryRun = dryRun
	opts.ExtraFile = extraFile
	opts.Scheduler = d.newSched()
	return opts
}

// RegisterTools registers the MCP tools on srv.
//
// Parameters:
//   - srv: the go-sdk *mcp.Server
//   - newSched: factory producing a FRESH per-scan scheduler per tool call; all
//     produced schedulers share one process-wide Limiter so concurrent D-03
//     sessions stay within PARALLEL_MAX_JOBS (MCP-05) while each scan owns its
//     RunTask/Checkpoint/Hash (no cross-session race)
//   - registry: session registry for scope lookup + run tracking
//   - rdct: the server's redactor, carrying the secrets registered at startup;
//     it reaches the report renderer and the client-facing error paths
//   - cfg: the RESOLVED *config.Config the server was started with — its data
//     dir and log level travel with every run
//   - configPath / secretsPath: the explicit --config / --secrets paths that
//     produced cfg; every run re-resolves from them (F7)
//   - mcpSrv: the MCPServer owning the scanCtx used by scan goroutines (W4 — goroutine lifecycle)
func RegisterTools(
	srv *mcp.Server,
	newSched func() *scheduler.Scheduler,
	registry *SessionRegistry,
	rdct *log.Redactor,
	cfg *config.Config,
	configPath, secretsPath string,
	mcpSrv *MCPServer,
) {
	d := newToolDeps(srv, newSched, registry, rdct, cfg, configPath, secretsPath, mcpSrv.scanCtx)
	mcpSrv.tools = d

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
	}, func(_ context.Context, req *mcp.CallToolRequest, args SubsInput) (*mcp.CallToolResult, any, error) {
		runRecon := func(ctx context.Context, opts handlers.RunOptions) error {
			return handlers.RunCompositeAsync(ctx, opts, handlers.ModeRecon)
		}
		return d.launch(sessionIDFromRequest(req), args.Target, args.DryRun, "", runRecon)
	})

	// 2. subs — passive + active subdomain enumeration pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "subs",
		Description: "Run subdomain enumeration (passive + active + permut + takeover).",
	}, func(_ context.Context, req *mcp.CallToolRequest, args SubsInput) (*mcp.CallToolResult, any, error) {
		return d.launch(sessionIDFromRequest(req), args.Target, args.DryRun, "", handlers.RunSubsAsync)
	})

	// 3. web — web probe + analysis pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "web",
		Description: "Run web probe + analysis pipeline (HTTP probing, WAF detection, URL crawl, JS analysis).",
	}, func(_ context.Context, req *mcp.CallToolRequest, args WebInput) (*mcp.CallToolResult, any, error) {
		return d.launch(sessionIDFromRequest(req), args.Target, args.DryRun, args.Hosts, handlers.RunWebAsync)
	})

	// 4. vulns — vulnerability scanning pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "vulns",
		Description: "Run vulnerability scanning pipeline (XSS, SQLi, SSRF, SSTI, CRLF, LFI, Nuclei DAST).",
	}, func(_ context.Context, req *mcp.CallToolRequest, args VulnsInput) (*mcp.CallToolResult, any, error) {
		return d.launch(sessionIDFromRequest(req), args.Target, args.DryRun, args.URLs, handlers.RunVulnsAsync)
	})

	// 5. osint — OSINT collection pipeline.
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "osint",
		Description: "Run OSINT collection pipeline (domain info, emails, GitHub leaks, Google dorks, cloud enum).",
	}, func(_ context.Context, req *mcp.CallToolRequest, args OSINTInput) (*mcp.CallToolResult, any, error) {
		return d.launch(sessionIDFromRequest(req), args.Target, args.DryRun, "", handlers.RunOSINTAsync)
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
	}, func(_ context.Context, req *mcp.CallToolRequest, args MonitorInput) (*mcp.CallToolResult, any, error) {
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
		return d.launch(sessionIDFromRequest(req), args.Target, false, "", runMonitor)
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
		return d.report(ctx, sessionIDFromRequest(req), args)
	})
}

// report is the body of the report tool: scope-guard, render, answer with the
// manifest. Split out of the closure so a test can drive it with a chosen
// session ID (see toolDeps).
func (d *toolDeps) report(ctx context.Context, sessionID string, args ReportInput) (*mcp.CallToolResult, any, error) {
	// Same D-06 scope guard the scanning tools apply: a report exposes a
	// target's findings, so it must be scope-checked like a scan.
	if _, exists := d.registry.Lookup(sessionID); !exists {
		d.registry.Register(sessionID, "", nil)
		d.registry.SetScope(sessionID, NewSessionScope([]string{args.Target}))
	}
	if err := CheckScope(sessionID, args.Target, d.registry); err != nil {
		return toolErrorf("out_of_scope", err), nil, nil
	}
	// The server's RESOLVED config and redactor. The render therefore reads the
	// operator's data dir and scrubs the operator's registered secrets. This
	// call site used to pass cfg=nil behind a TODO, because MCPServer held only
	// the MCP config slice — so an operator with paths.data_dir set got "data"
	// on the MCP report path (F7 / T-15-11-05). The snapshot closes it.
	result, err := handlers.RenderReportsForTarget(ctx, d.cfg, d.rdct, args.Target, "", false)
	if err != nil {
		return toolErrorf("report_failed", err), nil, nil
	}
	// The response lists what THIS render wrote, from the manifest.
	body, _ := json.Marshal(map[string]any{
		"target":  args.Target,
		"scan_id": result.ScanID,
		"dir":     result.Dir,
		"reports": result.Files,
	})
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(body)}},
	}, nil, nil
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

// sessionIDFromRequest extracts the MCP session ID from a tool call.
//
// A1 (sdk_assumptions_test.go): the session is always an *mcp.ServerSession.
// The ID is "" for in-memory transports, which is a legitimate session key —
// every capture and ownership check treats it as one.
func sessionIDFromRequest(req *mcp.CallToolRequest) string {
	if sess, ok := req.GetSession().(*mcp.ServerSession); ok && sess != nil {
		return sess.ID()
	}
	return ""
}

// toolErrorf builds the shared {"error":…,"message":…} tool-error response.
// One helper so every tool's error shape is identical by construction rather
// than by five copies of the same fmt.Sprintf.
func toolErrorf(code string, err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{
			Text: fmt.Sprintf(`{"error":%q,"message":%q}`, code, err.Error()),
		}},
		IsError: true,
	}
}

// launch implements the D-02 async + D-06 scope-guard pattern shared by all
// scanning tool handlers (recon, subs, web, vulns, osint, monitor).
//
// Steps:
//  1. Capture the session scope if it is not set yet (first tool call).
//  2. CheckScope: hard-reject out-of-scope targets (D-06).
//  3. Generate crypto/rand runID (T-08-04-06 128-bit entropy).
//  4. Register the runID in the SessionRegistry.
//  5. Launch goroutine via launchScanAndNotify (non-blocking return, D-02).
//  6. Return {"run_id":"…","resource":"scan://…/findings"} immediately.
func (d *toolDeps) launch(
	sessionID string,
	target string,
	dryRun bool,
	extraFile string,
	fn runFunc,
) (*mcp.CallToolResult, any, error) {
	ctx := d.scanCtx
	registry := d.registry
	srv := d.srv

	// Step 1: capture the first tool call's target as the implicit fixed
	// session scope, BEFORE CheckScope so CheckScope sees a non-nil scope.
	entry, exists := registry.Lookup(sessionID)
	if !exists || entry.Scope == nil {
		if !exists {
			registry.Register(sessionID, "", nil)
		}
		registry.SetScope(sessionID, NewSessionScope([]string{target}))
	}

	// Step 2: CheckScope — hard-reject out-of-scope targets (D-06).
	// This validates the target against the now-set scope.
	if err := CheckScope(sessionID, target, registry); err != nil {
		return toolErrorf("out_of_scope", err), nil, nil
	}

	// Step 3: Generate crypto/rand runID — 16 random bytes → 32 hex chars (128-bit entropy).
	// T-08-04-06: unpredictable runIDs prevent cross-session resource URI guessing.
	runID, err := newRunID()
	if err != nil {
		return nil, nil, fmt.Errorf("mcp: failed to generate run ID: %w", err)
	}

	resourceURI := "scan://" + runID + "/findings"

	// Step 4: Register the runID against the session that launched it. Ownership
	// is what authorises later resource reads and subscriptions — an
	// unpredictable runID makes URIs hard to guess, but guessability is not an
	// access-control model.
	registry.RegisterRun(runID, sessionID)

	// Step 5: Launch scan goroutine (D-02 async — handler returns immediately).
	// ctx here is the server-lifetime scan context, NOT the tool call context:
	// the scan must outlive the MCP request/response cycle (D-02), and the
	// server context is what Cancel() and transport shutdown cancel (W4).
	//
	// The options are a copy of the startup snapshot template, so this run
	// carries the operator's --config / --secrets / data dir / log level and
	// resolves them into its OWN config instance (F7). It also gets a FRESH
	// per-scan scheduler: each concurrent session owns its RunTask/Checkpoint/
	// Hash fields (no D-03 cross-session race) while all per-scan schedulers
	// share one process-wide Limiter so they collectively cannot exceed
	// PARALLEL_MAX_JOBS (MCP-05).
	go launchScanAndNotify(ctx, runID, d.runOptions(target, dryRun, extraFile), srv, registry, fn)

	// Step 6: Return immediately with run_id + resource URI.
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
