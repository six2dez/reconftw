// stderr_terminal_test.go — the terminal stream error carries the tool's own stderr.
//
// THE STRING THIS FILE EXISTS TO KILL. Every failure in the first end-to-end v2
// run reached the operator as "tool stream ended badly: exit status 1" — for five
// different root causes. The tool's own account of what went wrong was already in
// memory (LocalBackend read it, ToolError.Stderr carried it) and was shown to
// nobody. Reproduced with puredns' real message, the same shape now reads
// "unable to load public resolvers: open t: no such file or directory".

package backend

import (
	"context"
	stderrors "errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// plantShellTool writes an executable /bin/sh stub and returns a *Tool for it.
func plantShellTool(t *testing.T, name, body string) *Tool {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub tool uses a POSIX shell")
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil { //nolint:gosec // test fixture must be executable
		t.Fatalf("plant %s: %v", name, err)
	}
	return &Tool{Name: name, Path: p}
}

// collectTerminalErr streams the tool and returns the terminal Event.Err.
func collectTerminalErr(t *testing.T, tool *Tool) error {
	t.Helper()
	be := NewLocalBackend(0)
	ch, err := be.Stream(context.Background(), tool, nil)
	if err != nil {
		t.Fatalf("Stream dispatch: %v", err)
	}
	var termErr error
	for ev := range ch {
		if ev.Err != nil {
			termErr = ev.Err
		}
	}
	return termErr
}

const sentinelStderr = "unable to load public resolvers: open t: no such file or directory"

// TestStreamTerminalErrorCarriesStderr is the HEADLINE observable.
func TestStreamTerminalErrorCarriesStderr(t *testing.T) {
	tool := plantShellTool(t, "stubfail", `echo "`+sentinelStderr+`" >&2; exit 1`)

	termErr := collectTerminalErr(t, tool)
	if termErr == nil {
		t.Fatal("a tool that exited 1 produced no terminal error")
	}
	if !strings.Contains(termErr.Error(), sentinelStderr) {
		t.Errorf("terminal error does not carry the tool's stderr.\n got: %v\nwant it to contain: %q",
			termErr, sentinelStderr)
	}
}

// TestStreamTerminalErrorSurvivesModuleWrapping: the operator reads the string at
// the TOP of the stack, so the sentence must survive the module's own wrap.
func TestStreamTerminalErrorSurvivesModuleWrapping(t *testing.T) {
	tool := plantShellTool(t, "stubfail2", `echo "`+sentinelStderr+`" >&2; exit 1`)

	termErr := collectTerminalErr(t, tool)
	// This is verbatim the shape internal/modules/subdomains/resolve.go uses.
	wrapped := fmt.Errorf("%s: tool stream ended badly: %w", tool.Name, termErr)

	if !strings.Contains(wrapped.Error(), sentinelStderr) {
		t.Errorf("the module-wrapped error the operator actually sees lost the stderr.\n got: %v", wrapped)
	}
}

// TestStreamTerminalErrorIsToolError: the sentinel bridge must keep working, so
// callers never resort to string matching (ADR §6).
func TestStreamTerminalErrorIsToolError(t *testing.T) {
	tool := plantShellTool(t, "stubfail3", `echo boom >&2; exit 1`)

	termErr := collectTerminalErr(t, tool)
	if !stderrors.Is(termErr, coreerrors.ErrTool) {
		t.Errorf("errors.Is(termErr, ErrTool) is false — the sentinel bridge is broken: %v", termErr)
	}
	var te *coreerrors.ToolError
	if !stderrors.As(termErr, &te) {
		t.Fatalf("terminal error does not unwrap to *ToolError: %v", termErr)
	}
	if te.ExitCode != 1 {
		t.Errorf("ExitCode = %d, want 1", te.ExitCode)
	}
}

// TestStreamStderrTailIsBoundedAndKeepsTheEnd: the retained bytes are the LAST
// ones, because the end of a stderr burst is where the failure is reported.
func TestStreamStderrTailIsBoundedAndKeepsTheEnd(t *testing.T) {
	tool := plantShellTool(t, "stubchatty", `
echo "FIRST_MARKER" >&2
i=0
while [ $i -lt 400 ]; do echo "padding line to overflow the stderr cap ................" >&2; i=$((i+1)); done
echo "LAST_MARKER" >&2
exit 1`)

	termErr := collectTerminalErr(t, tool)
	var te *coreerrors.ToolError
	if !stderrors.As(termErr, &te) {
		t.Fatalf("no *ToolError: %v", termErr)
	}
	if len(te.Stderr) > stderrCap {
		t.Errorf("Stderr is %d bytes, want <= stderrCap (%d)", len(te.Stderr), stderrCap)
	}
	if !strings.Contains(te.Stderr, "LAST_MARKER") {
		t.Error("the tail dropped the END of stderr — that is where the failure is reported")
	}
	if strings.Contains(te.Stderr, "FIRST_MARKER") {
		t.Error("the tail kept the START of an 8KiB burst, so it is not a tail")
	}
}

// TestStreamZeroExitWithStderrIsNotAnError: many tools log progress to stderr.
// Treating that as failure would break every one of them.
func TestStreamZeroExitWithStderrIsNotAnError(t *testing.T) {
	tool := plantShellTool(t, "stubnoisy", `echo "progress: 50%" >&2; echo result; exit 0`)

	if termErr := collectTerminalErr(t, tool); termErr != nil {
		t.Errorf("a tool that exited 0 after writing to stderr produced a terminal error: %v", termErr)
	}
}

// TestStreamStderrLinesStillDelivered: the accumulator is a TEE, not a redirect.
// Modules filter stderr with `if ev.IsErr { continue }` and that must not change.
func TestStreamStderrLinesStillDelivered(t *testing.T) {
	tool := plantShellTool(t, "stubtee", `echo "to-stderr" >&2; echo "to-stdout"; exit 0`)

	be := NewLocalBackend(0)
	ch, err := be.Stream(context.Background(), tool, nil)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	var sawStderrLine, sawStdoutLine bool
	for ev := range ch {
		switch {
		case ev.IsErr && strings.Contains(string(ev.Line), "to-stderr"):
			sawStderrLine = true
		case !ev.IsErr && strings.Contains(string(ev.Line), "to-stdout"):
			sawStdoutLine = true
		}
	}
	if !sawStderrLine {
		t.Error("stderr lines are no longer delivered as Events — the tee became a redirect")
	}
	if !sawStdoutLine {
		t.Error("stdout lines were lost")
	}
}

// TestRecorderEndRecordCarriesStderr: the same tail reaches logs/tools.jsonl, so
// the answer is greppable after the fact and not only visible in a live terminal.
func TestRecorderEndRecordCarriesStderr(t *testing.T) {
	tool := plantShellTool(t, "stubrec", `echo "`+sentinelStderr+`" >&2; exit 1`)

	path := filepath.Join(t.TempDir(), "logs", "tools.jsonl")
	reg := NewToolRegistry()
	reg.Register(tool)
	r := NewRunner(NewLocalBackend(0), reg, nil)
	r.Recorder = NewToolRecorder(path, nil)

	ch, err := r.Stream(context.Background(), tool.Name, nil)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	for range ch { //nolint:revive // drain
	}
	if err := r.Recorder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var found bool
	for _, rec := range readRecords(t, path) {
		if rec.Phase == PhaseEnd && strings.Contains(rec.StderrTail, sentinelStderr) {
			found = true
		}
	}
	if !found {
		t.Errorf("no end record in tools.jsonl carries the tool's stderr — the failure "+
			"is not greppable after the run; records: %+v", readRecords(t, path))
	}
}
