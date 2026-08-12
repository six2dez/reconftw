// websocket.go — WebsocketTask: WebSocket endpoint detection via HTTP Upgrade probe (D-V3).
//
// WebsocketTask is a D-V3 fold-in from web.sh websocket_checks(), routed to
// the vulns pipeline per plan 06-08 (VULN-14 parity completeness gate).
//
// INPUT: artefacts/urls.jsonl — URL corpus from Phase 5.
//
//	Empty → StatusSkipped (best_effort per D-V7).
//
// ARG VECTOR:
//
//	httpx -l inputs/websocket_targets.txt -websocket -silent -json
//
// httpx -websocket flag identifies hosts that respond to HTTP Upgrade with
// 101 Switching Protocols. The -json output includes a "websocket" boolean.
//
// Non-zero exit → log.Debug (best_effort per D-V7, ADR §7).
//
// V1 EQUIVALENT (web.sh websocket_checks:2603):
// v1 uses curl with Connection:Upgrade/Upgrade:websocket headers per wss:// URL,
// checking for HTTP 101 response. v2 uses httpx -websocket which is equivalent
// and produces structured JSONL output — an improvement on v1's curl loop.
//
// Additionally: cross-origin test (v1 websocket_misconfig.txt) is recorded when
// httpx reports websocket=true — the origin misconfiguration check is deferred
// to a subsequent manual step (httpx -websocket does not test cross-origin).
//
// OUTPUT: artefacts/websocket.jsonl — single-writer; direct app.Tree.Append OK
// (doc.go: single-writer artefacts do NOT go through the staging+merge pipeline).
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-08-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// WebsocketTask detects WebSocket endpoints via HTTP Upgrade probe (D-V3).
type WebsocketTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *WebsocketTask) Name() string { return "vulns.websocket" }

// Module returns the owning module group.
func (t *WebsocketTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *WebsocketTask) Description() string {
	return "WebSocket endpoint detection via HTTP Upgrade probe (httpx -websocket)"
}

// Enabled reads cfg.Vulns.Websocket.Enabled.
func (t *WebsocketTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.Websocket.Enabled }

// DependsOn declares GFTask as the DAG root dependency.
func (t *WebsocketTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes httpx -websocket against the URL corpus.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — StatusSkipped if empty.
//  2. Write URLs to inputs/websocket_targets.txt.
//  3. Run httpx -l inputs/websocket_targets.txt -websocket -silent -json.
//     On error → log.Debug (best_effort).
//  4. Parse JSONL output for websocket:true hosts.
//  5. Write artefacts/websocket.jsonl via app.Tree.Append (single-writer).
func (t *WebsocketTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "httpx"

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	urls, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.websocket: read URL corpus error (best_effort)", "err", err)
	}
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.websocket: no URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.websocket: mkdir inputs/: %w", err)
	}

	// Step 2: Write URLs to inputs/websocket_targets.txt.
	targetsFile := filepath.Join(inputsDir, "websocket_targets.txt")
	if wErr := os.WriteFile(targetsFile,
		[]byte(strings.Join(urls, "\n")+"\n"), 0o644); wErr != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.websocket: write websocket_targets.txt: %w", wErr)
	}

	// Context cancellation check.
	select {
	case <-ctx.Done():
		return task.Result{Status: task.StatusCancelled},
			fmt.Errorf("vulns.websocket: cancelled: %w", ctx.Err())
	default:
	}

	// Step 3: Run httpx -websocket via Backend.Run.
	// v2 uses httpx -websocket -json instead of v1's per-URL curl loop.
	// -duc: disable update check (mandatory; dev Mac DNS block).
	args := []string{
		"-l", targetsFile,
		"-websocket",
		"-silent",
		"-json",
		"-duc", // disable update check (memory/project_local_dns_block)
	}

	res, runErr := app.Tools.Run(ctx, toolName, args)
	if runErr != nil && app.Log != nil {
		app.Log.Debug("vulns.websocket: httpx error (best_effort)", "err", runErr)
	}
	// A hard failure (unregistered binary, spawn/rate-limit error) returns a nil
	// res; guard it so a missing httpx degrades to skipped, never a nil-pointer
	// panic (same class as the testssl live all-mode regression, 2026-08).
	if res == nil {
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Step 4: Parse JSONL output for websocket:true hosts.
	records := parseWebsocketOutput(res.Stdout)

	// Step 5: Write artefacts/websocket.jsonl via direct app.Tree.Append (single-writer).
	if len(records) > 0 {
		var lines [][]byte
		for _, rec := range records {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			if wErr := app.Tree.Append("websocket", lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.websocket: Tree.Append failed",
					"records", len(lines), "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.websocket: completed", "endpoints", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"endpoints": len(records)},
	}, nil
}

// websocketRecord is the artefacts/websocket.jsonl schema for a WebSocket endpoint.
type websocketRecord struct {
	URL       string `json:"url"`
	Host      string `json:"host"`
	Websocket bool   `json:"websocket"`
	Type      string `json:"type"` // "websocket-endpoint"
}

// httpxWebsocketLine is the subset of httpx JSONL output fields consumed for
// WebSocket detection. httpx -websocket emits a "websocket" boolean field.
type httpxWebsocketLine struct {
	URL       string `json:"url"`
	Host      string `json:"host"`
	Websocket bool   `json:"websocket"`
}

// parseWebsocketOutput parses httpx JSONL stdout for websocket:true entries.
func parseWebsocketOutput(data []byte) []websocketRecord {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var records []websocketRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var hl httpxWebsocketLine
		if err := json.Unmarshal(line, &hl); err != nil {
			continue
		}
		if !hl.Websocket {
			continue
		}
		url := hl.URL
		if url == "" {
			url = hl.Host
		}
		records = append(records, websocketRecord{
			URL:       url,
			Host:      hl.Host,
			Websocket: true,
			Type:      "websocket-endpoint",
		})
	}
	return records
}

// init self-registers WebsocketTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&WebsocketTask{}) }
