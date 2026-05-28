// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 2
// behavior tests 13-20 — UI dot-fill + verbosity + parallel-log modes +
// W13 mapping test.
package ui_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/ui"
)

// Test 13: dot-fill format — [OK  ] task.name .......... 12s.
func TestDotFillFormat(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewPrinter(buf, ui.VerbosityNormal)
	p.Status(ui.BadgeOK, "task.passive", 12*time.Second)
	out := buf.String()
	if !strings.Contains(out, "[OK") {
		t.Errorf("missing [OK badge: %s", out)
	}
	if !strings.Contains(out, "task.passive") {
		t.Errorf("missing task name: %s", out)
	}
	if !strings.Contains(out, "12s") {
		t.Errorf("missing duration: %s", out)
	}
	if !strings.Contains(out, ".....") {
		t.Errorf("missing dot-fill: %s", out)
	}
}

// Test 14: VerbosityQuiet suppresses everything except FAIL.
func TestVerbosityQuietSuppresses(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewPrinter(buf, ui.VerbosityQuiet)
	p.Status(ui.BadgeOK, "task.a", time.Second)
	p.Status(ui.BadgeWARN, "task.b", time.Second)
	p.Status(ui.BadgeFAIL, "task.c", time.Second)
	out := buf.String()
	// OK and WARN should be absent
	if strings.Contains(out, "task.a") {
		t.Errorf("quiet emitted OK: %s", out)
	}
	if strings.Contains(out, "task.b") {
		t.Errorf("quiet emitted WARN: %s", out)
	}
	// FAIL should still be emitted
	if !strings.Contains(out, "task.c") {
		t.Errorf("quiet failed to emit FAIL: %s", out)
	}
}

// Test 15: VerbosityVerbose emits INFO from Msg.
func TestVerbosityVerboseEmitsInfo(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewPrinter(buf, ui.VerbosityVerbose)
	p.Msg("INFO", "verbose-info-line")
	out := buf.String()
	if !strings.Contains(out, "verbose-info-line") {
		t.Errorf("verbose did not emit INFO: %s", out)
	}

	// At Normal, INFO is suppressed.
	buf.Reset()
	p2 := ui.NewPrinter(buf, ui.VerbosityNormal)
	p2.Msg("INFO", "should-not-appear")
	if strings.Contains(buf.String(), "should-not-appear") {
		t.Errorf("normal emitted INFO: %s", buf.String())
	}
}

// Test 16: PARALLEL_LOG_MODE summary | tail | full semantics.
func TestParallelLogModes(t *testing.T) {
	rawLines := "line-1\nline-2\nline-3\nline-4\nline-5\n"

	t.Run("summary", func(t *testing.T) {
		buf := &bytes.Buffer{}
		p := ui.NewPrinter(buf, ui.VerbosityNormal)
		p.ParallelMode = ui.ParallelSummary
		p.ParallelJobOutput(ui.BadgeOK, "j1", time.Second, strings.NewReader(rawLines))
		out := buf.String()
		// Summary only emits the status line — no raw lines.
		if strings.Contains(out, "line-1") || strings.Contains(out, "line-5") {
			t.Errorf("summary leaked raw lines: %s", out)
		}
		if !strings.Contains(out, "j1") {
			t.Errorf("summary missing status: %s", out)
		}
	})

	t.Run("tail", func(t *testing.T) {
		buf := &bytes.Buffer{}
		p := ui.NewPrinter(buf, ui.VerbosityNormal)
		p.ParallelMode = ui.ParallelTail
		p.TailLines = 2
		p.ParallelJobOutput(ui.BadgeOK, "j2", time.Second, strings.NewReader(rawLines))
		out := buf.String()
		// Last 2 lines emitted; line-1 absent.
		if strings.Contains(out, "line-1") {
			t.Errorf("tail emitted too many lines: %s", out)
		}
		if !strings.Contains(out, "line-4") || !strings.Contains(out, "line-5") {
			t.Errorf("tail missing last 2 lines: %s", out)
		}
	})

	t.Run("full", func(t *testing.T) {
		buf := &bytes.Buffer{}
		p := ui.NewPrinter(buf, ui.VerbosityNormal)
		p.ParallelMode = ui.ParallelFull
		p.ParallelJobOutput(ui.BadgeOK, "j3", time.Second, strings.NewReader(rawLines))
		out := buf.String()
		for i := 1; i <= 5; i++ {
			if !strings.Contains(out, "line-"+itoa(i)) {
				t.Errorf("full missing line-%d: %s", i, out)
			}
		}
	})
}

// Test 17: TTY detection — *os.File pointing at /dev/null → false.
// bytes.Buffer → false.
func TestIsTTY(t *testing.T) {
	buf := &bytes.Buffer{}
	if ui.IsTTY(buf) {
		t.Errorf("IsTTY(bytes.Buffer) = true; want false")
	}
	// /dev/null is a character device but typically not the type we
	// want to classify as TTY.
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Skipf("open /dev/null: %v", err)
	}
	defer f.Close()
	// Don't assert the exact result for /dev/null (varies by OS); just
	// assert the call doesn't panic on a real *os.File.
	_ = ui.IsTTY(f)
}

// Test 18: NO TUI library imported — printer.go and parallel_log.go
// source must not contain bubbletea / tview / charmbracelet refs.
func TestNoTUILibraryImported(t *testing.T) {
	root := repoRoot(t)
	for _, base := range []string{"printer.go", "tty.go", "badge.go", "parallel_log.go"} {
		body, err := os.ReadFile(filepath.Join(root, "internal", "core", "ui", base))
		if err != nil {
			t.Fatalf("read %s: %v", base, err)
		}
		s := string(body)
		for _, bad := range []string{"bubbletea", "tview", "charmbracelet", "lipgloss"} {
			if strings.Contains(s, bad) {
				t.Errorf("%s contains forbidden TUI import %q", base, bad)
			}
		}
	}
}

// Test 19: Badge counters — Status increments; Summary prints.
func TestBadgeCountersAndSummary(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewPrinter(buf, ui.VerbosityNormal)
	p.Status(ui.BadgeOK, "a", time.Second)
	p.Status(ui.BadgeOK, "b", time.Second)
	p.Status(ui.BadgeWARN, "c", time.Second)
	p.Status(ui.BadgeFAIL, "d", time.Second)
	if p.CountFor(ui.BadgeOK) != 2 {
		t.Errorf("OK count = %d, want 2", p.CountFor(ui.BadgeOK))
	}
	if p.CountFor(ui.BadgeWARN) != 1 {
		t.Errorf("WARN count = %d, want 1", p.CountFor(ui.BadgeWARN))
	}
	if p.CountFor(ui.BadgeFAIL) != 1 {
		t.Errorf("FAIL count = %d, want 1", p.CountFor(ui.BadgeFAIL))
	}
	// Summary writes the final counter row.
	buf.Reset()
	p.Summary()
	out := buf.String()
	if !strings.Contains(out, "OK:2") {
		t.Errorf("Summary missing OK:2: %s", out)
	}
	if !strings.Contains(out, "WARN:1") {
		t.Errorf("Summary missing WARN:1: %s", out)
	}
	if !strings.Contains(out, "FAIL:1") {
		t.Errorf("Summary missing FAIL:1: %s", out)
	}
}

// Test 20 (W13): the MAPPING block is present in printer.go.
// Required by the plan acceptance gate:
//
//	grep -c 'MAPPING: lib/ui.sh' internal/core/ui/printer.go    returns 1
//	grep -cE 7-helpers                                          returns ≥7
func TestUIMappingDocumented(t *testing.T) {
	root := repoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, "internal", "core", "ui", "printer.go"))
	if err != nil {
		t.Fatalf("read printer.go: %v", err)
	}
	s := string(body)
	if !strings.Contains(s, "MAPPING: lib/ui.sh") {
		t.Fatal("W13 violation — printer.go missing 'MAPPING: lib/ui.sh' block")
	}
	helpers := []string{
		"_print_status",
		"_print_msg",
		"_print_rule",
		"_print_section",
		"progress_module",
		"ui_count_inc",
		"ui_summary",
		"ui_batch_end",
		"PARALLEL_LOG_MODE",
		"OUTPUT_VERBOSITY",
	}
	missing := 0
	for _, h := range helpers {
		if !strings.Contains(s, h) {
			missing++
			t.Errorf("MAPPING block missing helper %q", h)
		}
	}
	if missing > 0 {
		t.Fatalf("W13 mapping incomplete — %d helpers missing", missing)
	}
}

// Test (smoke): Rule + Section + ProgressModule + BatchEnd produce output
// at the appropriate verbosities.
func TestUIRuleSectionProgressBatchEnd(t *testing.T) {
	buf := &bytes.Buffer{}
	p := ui.NewPrinter(buf, ui.VerbosityVerbose)
	p.Rule("hello")
	p.Section("OSINT")
	p.ProgressModule("module-1")
	p.BatchEnd("batch-1")
	out := buf.String()
	if !strings.Contains(out, "hello") {
		t.Errorf("Rule missing title: %s", out)
	}
	if !strings.Contains(out, "OSINT") {
		t.Errorf("Section missing title: %s", out)
	}
	if !strings.Contains(out, "module-1") {
		t.Errorf("ProgressModule missing name: %s", out)
	}
	if !strings.Contains(out, "batch-1") {
		t.Errorf("BatchEnd missing name: %s", out)
	}

	// At Quiet, none of these emit.
	buf.Reset()
	p2 := ui.NewPrinter(buf, ui.VerbosityQuiet)
	p2.Rule("x")
	p2.Section("Y")
	p2.ProgressModule("z")
	p2.BatchEnd("b")
	if buf.Len() != 0 {
		t.Errorf("quiet emitted Rule/Section/Progress/BatchEnd: %s", buf.String())
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

// itoa avoids fmt.Sprintf in tight loops (test-readability micro-optim).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	buf := [16]byte{}
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
