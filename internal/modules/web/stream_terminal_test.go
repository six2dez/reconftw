// stream_terminal_test.go — F6 (phase 15, plan 15-13 Task 2) acceptance gate 5
// for the web package, asserted in BOTH directions.
//
// The two directions are not symmetric and confusing them is the whole risk:
//
//	TERMINAL  the tool RAN and exited non-zero => task.StatusErrored, and the
//	          staging file is NOT parsed (its contents are partial, or left over
//	          from an earlier run).
//	DISPATCH  the tool is not on PATH; Stream() itself errors and the stream
//	          never ran => task.StatusSkipped. Escalating this would fail whole
//	          runs on any host with an incomplete toolchain.
package web_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/task"
)

// ---------------------------------------------------------------------------
// TERMINAL — gate 5.
// ---------------------------------------------------------------------------

// TestArjunExitSevenErrorsAndDoesNotParseStaging drives web.arjun with a stub
// that emits ONE partial line and then a terminal Event.Err, exactly like a tool
// that wrote half its results and exited 7.
//
// It asserts three things, and all three matter:
//  1. the task returns task.StatusErrored;
//  2. the tool's output file is NOT parsed into results — proven by seeding it
//     with a record that would otherwise be reported;
//  3. no findings staging is produced, so a partial scan cannot reach the merge.
func TestArjunExitSevenErrorsAndDoesNotParseStaging(t *testing.T) {
	workDir := t.TempDir()
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "urls.jsonl"),
		`{"url":"https://api.example.com/a?id=1"}`)

	// Seed the -oT output file arjun would read. A run that ignored the terminal
	// error would parse this and report a finding.
	staleOut := filepath.Join(workDir, "artefacts", "arjun_output.txt.tmp")
	writeLinesFile(t, staleOut, "https://api.example.com/STALE?leftover=1")

	be := &webMockBackend{
		streamLines: []string{"partial output line"},
		streamErr:   errors.New("exit status 7"),
	}
	app := newWebApp(t, workDir, be, "arjun")
	app.Cfg.Advanced.Deep = true

	res, err := lookupWebTask(t, "web.arjun").Run(context.Background(), app)
	if res.Status != task.StatusErrored {
		t.Errorf("status = %q, want errored (the tool ran and exited 7)", res.Status)
	}
	if err == nil {
		t.Error("a terminal stream error must be returned, not swallowed")
	}
	if res.Stats["params"] != 0 {
		t.Errorf("params = %d, want 0 — the staging file must NOT be parsed after a "+
			"terminal error; its contents are partial or from a previous run",
			res.Stats["params"])
	}
	staging := filepath.Join(workDir, "inputs", "findings.arjun.jsonl")
	if _, sErr := os.Stat(staging); !os.IsNotExist(sErr) {
		body, _ := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		t.Errorf("a partially-complete scan must not reach the findings merge, but %s "+
			"was written: %q", staging, string(body))
	}
}

// TestKatanaExitSevenErrorsAndDiscardsPartialCorpus covers the ACCUMULATOR shape
// (katana keeps its own range loop rather than using backend.Collect): a crawl
// that emits URLs and then dies must not have those URLs staged.
func TestKatanaExitSevenErrorsAndDiscardsPartialCorpus(t *testing.T) {
	workDir := t.TempDir()
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		`{"url":"https://api.example.com","host":"api.example.com"}`)

	be := &webMockBackend{
		streamLines: []string{"https://api.example.com/partial"},
		streamErr:   errors.New("exit status 7"),
	}
	app := newWebApp(t, workDir, be, "katana")
	app.Cfg.Web.URLs.ActiveEnabled = true

	res, err := lookupWebTask(t, "web.katana").Run(context.Background(), app)
	if res.Status != task.StatusErrored {
		t.Errorf("status = %q, want errored", res.Status)
	}
	if err == nil {
		t.Error("a terminal stream error must be returned, not swallowed")
	}
	staging := filepath.Join(workDir, "inputs", "urls.katana.jsonl")
	if _, sErr := os.Stat(staging); !os.IsNotExist(sErr) {
		body, _ := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
		t.Errorf("half a crawl must not be published as this run's URL set, but %s was "+
			"written: %q", staging, string(body))
	}
}

// ---------------------------------------------------------------------------
// DISPATCH — the over-escalation guard.
// ---------------------------------------------------------------------------

// TestArjunAbsentBinaryStaysSkipped is the companion that stops this migration
// turning every host without an optional tool into a failed scan.
func TestArjunAbsentBinaryStaysSkipped(t *testing.T) {
	workDir := t.TempDir()
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "urls.jsonl"),
		`{"url":"https://api.example.com/a?id=1"}`)

	be := &webMockBackend{dispatchErr: errors.New("arjun: executable file not found in $PATH")}
	app := newWebApp(t, workDir, be, "arjun")
	app.Cfg.Advanced.Deep = true

	res, err := lookupWebTask(t, "web.arjun").Run(context.Background(), app)
	if err != nil {
		t.Errorf("a missing binary must not produce an error, got: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want skipped — Stream()'s own error means the tool was "+
			"never dispatched, and escalating it fails runs on hosts that simply did not "+
			"install an optional tool", res.Status)
	}
}

// TestKatanaAbsentBinaryStaysSkipped is the same guard for the accumulator shape.
func TestKatanaAbsentBinaryStaysSkipped(t *testing.T) {
	workDir := t.TempDir()
	writeLinesFile(t, filepath.Join(workDir, "artefacts", "hosts.jsonl"),
		`{"url":"https://api.example.com","host":"api.example.com"}`)

	be := &webMockBackend{dispatchErr: errors.New("katana: executable file not found in $PATH")}
	app := newWebApp(t, workDir, be, "katana")
	app.Cfg.Web.URLs.ActiveEnabled = true

	res, err := lookupWebTask(t, "web.katana").Run(context.Background(), app)
	if err != nil {
		t.Errorf("a missing binary must not produce an error, got: %v", err)
	}
	if res.Status != task.StatusSkipped {
		t.Errorf("status = %q, want skipped", res.Status)
	}
}
