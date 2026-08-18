// stream_terminal_test.go — behavioural proof of the F6 terminal-error contract
// for the vulns package (acceptance gate 5, plan 15-14 Task 2).
//
// The stream-contract AST ratchet proves the Drain/Collect helper is CALLED at
// every site. It cannot prove the result is ACTED ON: `_ = backend.Drain(ch)`
// satisfies shape 1 (recorded as a detector limitation in the 15-13 SUMMARY).
// These tests are what actually pin the behaviour, and they are written in both
// directions on purpose:
//
//	TERMINAL — the scanner RAN and exited 7. Must yield task.StatusErrored, must
//	           NOT parse its output file, and must NOT touch the staging file
//	           (neither publish a partial result nor clear a real one).
//	DISPATCH — the scanner is not on PATH. Must keep its existing
//	           task.StatusSkipped / log-and-continue handling. `vulns` and
//	           `osint` are PolicyBestEffort (internal/core/scheduler/policy.go)
//	           and an incomplete optional toolchain must never fail a run.
//
// The escalation boundary is the whole point: over-escalating a missing optional
// scanner is as much a defect as swallowing a crash.
package vulns

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
)

// ---------------------------------------------------------------------------
// TERMINAL — exit 7 must error and must not publish
// ---------------------------------------------------------------------------

// TestCRLFExitSevenErrorsAndDoesNotParseOutput is gate 5 for a vulns task whose
// drain is immediately followed by os.ReadFile of the tool's own -o path.
//
// crlfuzz emits one partial hit, then exits 7. Before this migration the channel
// simply closed, the -o file (holding the PREVIOUS run's hits, since nothing
// clears it) was parsed, and those stale injections were published as this run's
// findings with StatusDone. Now the task errors and the file is never read.
func TestCRLFExitSevenErrorsAndDoesNotParseOutput(t *testing.T) {
	be := newStageFakeBackend()
	be.streamLines["crlfuzz"] = []string{"partial output line"}
	be.terminalErr["crlfuzz"] = errors.New("exit status 7")
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/")

	// A PREVIOUS run's crlfuzz output sitting at the -o path, exactly as it
	// would be on a real workspace.
	inputs := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputs, 0o755); err != nil {
		t.Fatalf("mkdir inputs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputs, "findings.crlfuzz.txt"),
		[]byte("https://stale.example.com/%0d%0aSet-Cookie:STALE-PREVIOUS-RUN\n"), 0o644); err != nil {
		t.Fatalf("seed stale crlfuzz output: %v", err)
	}
	staging := seedStaging(t, app, "findings.crlf.jsonl")

	res, err := (&CRLFTask{}).Run(context.Background(), app)
	if res.Status != "errored" {
		t.Fatalf("status = %q, want errored (crlfuzz ran and exited 7)", res.Status)
	}
	if err == nil {
		t.Fatalf("a terminal stream error must be RETURNED, not swallowed")
	}
	if !isTerminalStreamError(err) {
		t.Fatalf("err must be marked terminal so callers can tell it from a dispatch "+
			"failure, got %v", err)
	}
	// The staging file must be untouched: a crashed scanner may neither publish
	// a partial result nor retract a real one.
	mustBePreserved(t, staging, "crlfuzz exited 7")
}

// TestSmugglingUnaffectedByStreamContract is a negative control for the sweep:
// SmugglingTask uses app.Tools.Run, not Stream, so it is not a gate-5 site and
// keeps returning StatusDone. Without this, a future refactor could quietly
// route it through Stream and lose the terminal check with nothing failing.
func TestSmugglingUnaffectedByStreamContract(t *testing.T) {
	src, err := os.ReadFile("smuggling.go")
	if err != nil {
		t.Fatalf("read smuggling.go: %v", err)
	}
	if strings.Contains(string(src), "app.Tools.Stream(") {
		t.Fatalf("smuggling.go now calls app.Tools.Stream — it must consume the terminal " +
			"error with one of the four accepted shapes (see stream_contract_test.go)")
	}
}

// TestSQLiSqlmapExitSevenErrorsAndDiscardsPartial is gate 5 through a HELPER
// that returns (records, error) into a Run which logs scanner errors
// best-effort. Without the errToolStreamEnded marker the error would have been
// swallowed exactly as before F6 and the ratchet would have gone green with no
// behavioural change at all.
func TestSQLiSqlmapExitSevenErrorsAndDiscardsPartial(t *testing.T) {
	cfg := &config.Config{}
	cfg.Vulns.SQLi = config.VulnSQLi{Enabled: true, SQLMap: true, Ghauri: false}

	be := newStageFakeBackend()
	be.streamLines["sqlmap"] = []string{"[INFO] parameter 'id' appears to be injectable"}
	be.terminalErr["sqlmap"] = errors.New("exit status 7")
	app := newStageTestApp(t, be, cfg)
	seedGFBucket(t, app, "sqli", "https://a.example.com/?id=1")
	staging := seedStaging(t, app, "findings.sqli.jsonl")

	res, err := (&SQLiTask{}).Run(context.Background(), app)
	if res.Status != "errored" {
		t.Fatalf("status = %q, want errored (sqlmap ran and exited 7)", res.Status)
	}
	if !isTerminalStreamError(err) {
		t.Fatalf("the helper's terminal error must reach Run marked as terminal, got %v", err)
	}
	mustBePreserved(t, staging, "sqlmap exited 7")
}

// TestSSTITInjAExitSevenErrorsAndDoesNotReadReports is T-15-14-01: the highest
// consequence site in the vulns sweep. runTInjA drains and then reads the TInjA
// report DIRECTORY, whose contents are not cleared between runs — so a TInjA
// killed mid-scan used to have LAST run's reports parsed and published as this
// run's verdict, with nothing recording that the scan died.
func TestSSTITInjAExitSevenErrorsAndDoesNotReadReports(t *testing.T) {
	cfg := &config.Config{}
	cfg.Vulns.SSTI = config.VulnSSTI{Enabled: true, Engine: "TInjA"}

	be := newStageFakeBackend()
	be.streamLines["TInjA"] = []string{"scanning"}
	be.terminalErr["TInjA"] = errors.New("exit status 7")
	app := newStageTestApp(t, be, cfg)
	seedGFBucket(t, app, "ssti", "https://a.example.com/?q=1")
	staging := seedStaging(t, app, "findings.ssti.jsonl")

	// A PREVIOUS run's TInjA report claiming a confirmed SSTI.
	reportDir := filepath.Join(app.Target.WorkDir, "inputs", "TInjA_reports")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("mkdir report dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportDir, "stale.jsonl"),
		[]byte(`{"url":"https://stale-tinja.example.com/?q=1","isWebpageVulnerable":true}`+"\n"),
		0o644); err != nil {
		t.Fatalf("seed stale report: %v", err)
	}

	res, err := (&SSTITask{}).Run(context.Background(), app)
	if res.Status != "errored" {
		t.Fatalf("status = %q, want errored (TInjA ran and exited 7)", res.Status)
	}
	if !isTerminalStreamError(err) {
		t.Fatalf("err must be marked terminal, got %v", err)
	}
	// The stale report must NOT have been promoted into staging.
	body, rErr := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if rErr != nil {
		t.Fatalf("staging must be preserved untouched: %v", rErr)
	}
	if strings.Contains(string(body), "stale-tinja.example.com") {
		t.Fatalf("a crashed TInjA published the PREVIOUS run's report as this run's "+
			"finding — the exact F6 failure gate 5 exists to stop:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// DISPATCH — an absent scanner must still SKIP, never error
// ---------------------------------------------------------------------------

// TestCRLFAbsentBinaryStaysNonErrored pins the other side of the escalation
// boundary. crlfuzz is not installed, so Stream() itself fails; that is a
// DISPATCH failure and must keep its best-effort handling.
func TestCRLFAbsentBinaryStaysNonErrored(t *testing.T) {
	be := newStageFakeBackend()
	be.errs["crlfuzz"] = errors.New("exec: \"crlfuzz\": executable file not found in $PATH")
	app := newStageTestApp(t, be, nil)
	seedURLCorpus(t, app, "https://a.example.com/")

	res, err := (&CRLFTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("an absent optional scanner must not return an error: %v", err)
	}
	if res.Status == "errored" {
		t.Fatalf("an absent binary was escalated to errored — vulns is PolicyBestEffort " +
			"and an incomplete optional toolchain must not fail a run")
	}
}

// TestSQLiAbsentBinaryStaysNonErrored — the helper-return variant of the same
// boundary. A dispatch error inside runSQLMap must NOT carry the terminal
// marker, so Run logs it best-effort instead of escalating.
func TestSQLiAbsentBinaryStaysNonErrored(t *testing.T) {
	cfg := &config.Config{}
	cfg.Vulns.SQLi = config.VulnSQLi{Enabled: true, SQLMap: true, Ghauri: false}

	be := newStageFakeBackend()
	be.errs["sqlmap"] = errors.New("exec: \"sqlmap\": executable file not found in $PATH")
	app := newStageTestApp(t, be, cfg)
	seedGFBucket(t, app, "sqli", "https://a.example.com/?id=1")
	staging := seedStaging(t, app, "findings.sqli.jsonl")

	res, err := (&SQLiTask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("an absent optional scanner must not return an error: %v", err)
	}
	if res.Status == "errored" {
		t.Fatalf("an absent binary was escalated to errored")
	}
	mustBePreserved(t, staging, "sqlmap is not installed")
}

// ---------------------------------------------------------------------------
// The SSTImap locator fix must be undisturbed by this sweep
// ---------------------------------------------------------------------------

// TestSSTImapConfirmationWithoutURLFallsBackToTargetDomain is a regression guard
// for a SEPARATE, already-landed fix that this sweep edits the same loop as.
//
// When SSTImap confirms an SSTI but the URL cannot be extracted from the line,
// recording "" yields an empty Host, and output.FilterInScope DROPS a record
// with no locator — silently discarding a CONFIRMED critical finding. The fix
// falls back to app.Target.Domain, the least-specific locator that is still
// true. This test proves the accumulator migration did not reintroduce the
// empty-locator data loss, and that the resulting finding SURVIVES the scope
// gate rather than merely existing.
func TestSSTImapConfirmationWithoutURLFallsBackToTargetDomain(t *testing.T) {
	cfg := &config.Config{}
	cfg.Vulns.SSTI = config.VulnSSTI{Enabled: true, Engine: "SSTImap"}

	be := newStageFakeBackend()
	// A confirmation line with NO URL in it — the exact shape that used to
	// produce an empty locator.
	be.streamLines["sstimap"] = []string{"[+] Template injection confirmed on parameter q"}
	app := newStageTestApp(t, be, cfg)
	seedGFBucket(t, app, "ssti", "https://a.example.com/?q=1")

	res, err := (&SSTITask{}).Run(context.Background(), app)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if res.Status != "done" {
		t.Fatalf("status = %q, want done", res.Status)
	}

	staging := filepath.Join(app.Target.WorkDir, "inputs", "findings.ssti.jsonl")
	body, rErr := os.ReadFile(staging) //nolint:gosec // test-controlled temp path
	if rErr != nil {
		t.Fatalf("a CONFIRMED SSTI must reach staging even without an extractable URL: %v", rErr)
	}
	if !strings.Contains(string(body), app.Target.Domain) {
		t.Fatalf("the confirmation fell back to an EMPTY locator instead of %q — the scope "+
			"gate would discard a confirmed critical finding:\n%s", app.Target.Domain, body)
	}

	// And it must survive the scope gate, not merely exist on disk.
	lines := [][]byte{[]byte(strings.TrimSpace(string(body)))}
	if err := attachTree(app); err != nil {
		t.Fatalf("attach tree: %v", err)
	}
	kept, _ := output.FilterInScope(app.Tree, "findings", lines)
	if len(kept) == 0 {
		t.Fatalf("the fallback locator did not survive output.FilterInScope — the finding " +
			"is dropped at the scope boundary, which is the bug the fallback exists to fix")
	}
}
