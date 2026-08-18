// waymore.go — WaymoreTask: passive URL collection via waymore.
//
// Name: "web.waymore"  DependsOn: ["web.httpx"]
//
// WaymoreTask runs waymore against the target domain to collect historical
// URLs from web archives, and writes URLRecord entries to artefacts/urls.jsonl.
//
// ARG VECTOR (RESEARCH §waymore — verbatim v1 form, web.sh:1882):
//
//	waymore -i <domain> -mode U -oU <stagingfile>
//
// XCUT-09 (Pitfall 5): waymore can run 30m+; Backend.Stream is MANDATORY
// to deliver heartbeat events and avoid CI kill.
//
// [ASSUMED A4: waymore -mode U -oU flags are current — verify at install (DoD-1).]
//
// Axiom: LocalBackend only (D-W13).
// T-05-15: out-of-scope URLs filtered by extract/urls.ExtractURLs domain check.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/internal/extract/urls"
)

// WaymoreTask runs waymore passive URL collection.
type WaymoreTask struct{}

func (t *WaymoreTask) Name() string        { return "web.waymore" }
func (t *WaymoreTask) Module() string      { return "web" }
func (t *WaymoreTask) Description() string { return "Passive URL collection (waymore → urls.jsonl)" }
func (t *WaymoreTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.URLs.PassiveEnabled
}
func (t *WaymoreTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes waymore and appends URL records to urls.jsonl.
// Uses Backend.Stream for XCUT-09 heartbeat (30m+ runtime; Pitfall 5).
func (t *WaymoreTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "waymore"

	// Prepare staging file for waymore output (-oU writes URLs to this file).
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.waymore: mkdir inputs/: %w", err)
	}
	stagingFile := filepath.Join(inputsDir, "waymore_urls.txt.tmp")

	// Build arg vector (RESEARCH §waymore verbatim v1 form web.sh:1882).
	// [ASSUMED A4: -mode U -oU flags are current]
	args := []string{
		"-i", app.Target.Domain,
		"-mode", "U",
		"-oU", stagingFile,
	}

	// XCUT-09: Backend.Stream is mandatory for waymore (30m timeout; Pitfall 5).
	eventCh, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		if app.Log != nil {
			app.Log.Info("web.waymore: binary absent or failed — skipping",
				"err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Drain stream (collect any stdout lines as fallback in case -oU not honored).
	//
	// F6 (phase 15): ACCUMULATOR shape — latch the terminal Event.Err inside the
	// loop and check it after. Without this, a waymore that exits non-zero part
	// way through the archive fetch was treated as a complete pass, and the
	// -oU staging file read below could be truncated or left over from an
	// earlier run.
	var stdoutLines []string
	var streamErr error
	for ev := range eventCh {
		if ev.Err != nil {
			if streamErr == nil {
				streamErr = ev.Err
			}
			continue
		}
		if ev.IsErr {
			continue
		}
		line := strings.TrimSpace(string(ev.Line))
		if line != "" {
			stdoutLines = append(stdoutLines, line)
		}
	}
	if streamErr != nil {
		// Do NOT read stagingFile and do NOT stage the partial stdout lines.
		return task.Result{Status: task.StatusErrored},
			terminalStreamError(toolName, streamErr)
	}

	// Read output file (-oU writes URLs here); fall back to streamed stdout.
	var raw []byte
	if data, rerr := os.ReadFile(stagingFile); rerr == nil && len(data) > 0 { //nolint:gosec
		raw = data
	} else if len(stdoutLines) > 0 {
		raw = []byte(strings.Join(stdoutLines, "\n"))
	}

	// Extract and scope-filter URLs.
	records, _ := urlsextract.ExtractURLs(raw, "waymore", app.Target.Domain)

	// F3 (phase 15): the old `if len(records) == 0 { return StatusDone }`
	// short-circuit left a previous run's inputs/urls.waymore.jsonl for the urls
	// merge to republish. waymore RAN (absent binary returned StatusSkipped
	// above), so stage unconditionally and let StageJSONL clear it.
	var lines [][]byte
	for _, rec := range records {
		b, merr := json.Marshal(rec)
		if merr != nil {
			continue
		}
		lines = append(lines, b)
	}
	stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.waymore.jsonl")
	if wErr := output.StageJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
		app.Log.Debug("web.waymore: staging write failed",
			"path", stagingPath, "err", wErr)
	}

	// Clean up staging file.
	os.Remove(stagingFile) //nolint:errcheck

	if app.Log != nil {
		app.Log.Debug("web.waymore: completed", "urls_found", len(records))
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_found": len(records)},
	}, nil
}

func init() { task.Register(&WaymoreTask{}) }
