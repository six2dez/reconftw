// Package ui_test exercises StageProgress TTY/non-TTY behavior.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-10-PLAN.md Task 1.
package ui_test

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/ui"
)

// TestStageProgress_NonTTY_PlainText verifies that a non-TTY writer (bytes.Buffer)
// produces plain text output with NO ANSI escape bytes in the output.
//
// ANSI escape bytes start with \033 (ESC, 0x1B). If any appear in non-TTY output,
// the test fails — downstream piped consumers (grep, jq, CI log parsers) would
// receive corrupted input.
func TestStageProgress_NonTTY_PlainText(t *testing.T) {
	buf := &bytes.Buffer{}
	// bytes.Buffer is not an *os.File → IsTTY returns false → plain-text path.
	p := ui.NewStageProgress(buf, false, ui.VerbosityNormal)
	p.StageStart("passive", 3)
	p.TaskStart("subdomains.passive.crt")
	p.TaskDone("subdomains.passive.crt", ui.BadgeOK, 500*time.Millisecond)
	p.StageDone("passive", 42)

	out := buf.String()

	// Must have produced some output.
	if out == "" {
		t.Fatal("non-TTY StageProgress produced no output")
	}

	// CRITICAL: zero ANSI escape bytes (ESC = 0x1b = \033).
	if strings.ContainsRune(out, '\033') {
		t.Errorf("non-TTY output contains ANSI escape code (\\033): %q", out)
	}

	// Must contain the task name.
	if !strings.Contains(out, "subdomains.passive.crt") {
		t.Errorf("output missing task name: %q", out)
	}
}

// TestStageProgress_QuietMode_SuppressesDone verifies that VerbosityQuiet suppresses
// TaskDone output for non-FAIL badges. FAIL must still surface.
func TestStageProgress_QuietMode_SuppressesDone(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewStageProgress(buf, false, ui.VerbosityQuiet)
	p.StageStart("passive", 2)

	// OK should be suppressed in quiet mode.
	p.TaskStart("subdomains.passive.crt")
	p.TaskDone("subdomains.passive.crt", ui.BadgeOK, time.Second)

	// FAIL must surface even in quiet mode.
	p.TaskStart("subdomains.passive.github")
	p.TaskDone("subdomains.passive.github", ui.BadgeFAIL, time.Second)

	out := buf.String()

	if strings.Contains(out, "subdomains.passive.crt") {
		t.Errorf("quiet mode emitted OK badge output: %q", out)
	}
	if !strings.Contains(out, "subdomains.passive.github") {
		t.Errorf("quiet mode suppressed FAIL badge — must always emit: %q", out)
	}
}

// TestStageProgress_NoANSI_WhenNoColor verifies that NoColor=true produces zero
// ANSI escape codes regardless of TTY state.
func TestStageProgress_NoANSI_WhenNoColor(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewStageProgress(buf, true /* noColor */, ui.VerbosityNormal)
	p.StageStart("resolve", 1)
	p.TaskStart("subdomains.active.dnsx")
	p.TaskDone("subdomains.active.dnsx", ui.BadgeOK, 2*time.Second)
	p.StageDone("resolve", 10)

	out := buf.String()
	if strings.ContainsRune(out, '\033') {
		t.Errorf("NoColor=true output contains \\033 ANSI escape: %q", out)
	}
}

// TestStageProgress_ThreadSafe verifies that concurrent TaskStart/TaskDone calls
// from multiple goroutines do not trigger a data race. Run with -race.
func TestStageProgress_ThreadSafe(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	// Wrap buf in a mutex-safe writer to avoid false positives from concurrent
	// writes to the bytes.Buffer (bytes.Buffer itself is not goroutine-safe).
	mw := &mutexWriter{w: buf}
	p := ui.NewStageProgress(mw, false, ui.VerbosityNormal)
	p.StageStart("passive", 10)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			name := "task." + string(rune('a'+n))
			p.TaskStart(name)
			p.TaskDone(name, ui.BadgeOK, time.Duration(n)*time.Millisecond)
		}(i)
	}
	wg.Wait()
	p.StageDone("passive", 10)
}

// mutexWriter is a thread-safe io.Writer wrapper for bytes.Buffer in tests.
type mutexWriter struct {
	mu sync.Mutex
	w  *bytes.Buffer
}

func (m *mutexWriter) Write(p []byte) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.w.Write(p)
}
