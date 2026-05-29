// Package ui — StageProgress type.
//
// StageProgress renders task names only; never tool stdout/stderr. (XCUT-07)
//
// This file extends the existing internal/core/ui package with a reusable
// live-progress type for the subs pipeline (GAP-3 closure) and for Phases 5-7
// (web/vulns/osint reuse the same StageProgress API).
//
// Design constraints (from VERIFICATION.md GAP-3, 04-10-PLAN.md):
//   - NO TUI library — only stdlib + ANSI escape string constants.
//   - ALL ANSI emission is gated on (isTTY || forceTTY) && !noColor && verbosity > Quiet.
//   - Thread-safe: a sync.Mutex protects all mutable state.
//   - The production type has NO exported test hooks of any kind.
//     The only test-override is the unexported forceTTY field, set only from
//     internal tests (package ui) that can reach unexported fields.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-10-PLAN.md Task 1.
package ui

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// ANSI terminal escape sequences. Emitted only when isTTY is true and
// NoColor is false. Never emitted to non-TTY writers (pipes, files, CI).
const (
	ansiEraseLine = "\r\033[K" // carriage return + erase to end of line
	ansiYellow    = "\033[33m"
	ansiGreen     = "\033[32m"
	ansiReset     = "\033[0m"
)

// spinnerFrames provides a 4-frame spinner cycle. Frame advances on each
// TaskStart/TaskDone call.
var spinnerFrames = []rune{'|', '/', '-', '\\'}

// StageProgress is a TTY-aware in-place progress bar for a sequential
// pipeline of named stages, each containing N tasks.
//
// TTY mode: in-place ANSI cursor-move redraws with a spinner character cycling
// per task start/end; shows stage name, current tool name, elapsed, task counts.
//
// Non-TTY / --quiet / NoColor mode: plain single-line output per task
// completion (mirrors Printer.Status format), with no ANSI escape codes.
//
// Thread-safe: RunStage may call the RunTask closure from multiple goroutines
// concurrently. All mutable state is protected by mu.
type StageProgress struct {
	w          io.Writer
	isTTY      bool
	forceTTY   bool // UNEXPORTED — set only from internal tests (progress_internal_test.go)
	noColor    bool
	verbosity  Verbosity
	mu         sync.Mutex
	stageName  string
	taskCount  int
	doneCount  int
	stageStart time.Time
	spinFrame  int
}

// NewStageProgress constructs a StageProgress. IsTTY(w) is evaluated once
// at construction time; subsequent writes do not re-evaluate TTY state.
//
// noColor disables all ANSI color/cursor sequences regardless of TTY state.
// verbosity mirrors the Printer.Verbosity values (VerbosityQuiet/Normal/Verbose).
func NewStageProgress(w io.Writer, noColor bool, verbosity Verbosity) *StageProgress {
	return &StageProgress{
		w:         w,
		isTTY:     IsTTY(w),
		noColor:   noColor,
		verbosity: verbosity,
	}
}

// effectiveTTY returns true when the ANSI in-place path should activate.
// Production code never sets forceTTY; it exists solely for internal tests.
func (p *StageProgress) effectiveTTY() bool {
	return (p.isTTY || p.forceTTY) && !p.noColor
}

// StageStart signals the beginning of a named stage with taskCount tasks.
// Resets per-stage counters. In effective-TTY mode, prints an initial
// progress line; in non-TTY / quiet mode, prints a plain section header
// (VerbosityVerbose only to match Printer.Section semantics).
func (p *StageProgress) StageStart(stageName string, taskCount int) {
	p.mu.Lock()
	p.stageName = stageName
	p.taskCount = taskCount
	p.doneCount = 0
	p.stageStart = time.Now()
	tty := p.effectiveTTY()
	quiet := p.verbosity == VerbosityQuiet
	p.mu.Unlock()

	if quiet {
		return
	}
	if tty {
		fmt.Fprintf(p.w, "%s%s▸ [%s] starting... (0/%d tasks)",
			ansiEraseLine, ansiGreen, stageName, taskCount)
	} else if p.verbosity >= VerbosityNormal {
		fmt.Fprintf(p.w, "▸ [%s] starting... (%d tasks)\n", stageName, taskCount)
	}
}

// TaskStart signals that a task has begun. Advances the spinner frame.
// In effective-TTY mode, overwrites the current line with spinner + task name.
// In non-TTY / quiet mode, this is a no-op (output is deferred to TaskDone).
func (p *StageProgress) TaskStart(taskName string) {
	p.mu.Lock()
	p.spinFrame = (p.spinFrame + 1) % len(spinnerFrames)
	frame := spinnerFrames[p.spinFrame]
	tty := p.effectiveTTY()
	quiet := p.verbosity == VerbosityQuiet
	p.mu.Unlock()

	if quiet || !tty {
		return
	}
	fmt.Fprintf(p.w, "%s%s  %c %s%s",
		ansiEraseLine, ansiYellow, frame, taskName, ansiReset)
}

// TaskDone signals that a task has completed with a status badge and duration.
//
// TTY mode: overwrites the current line with the completed status line, then
// emits a newline so the line is preserved in the scroll buffer.
//
// Non-TTY mode: mirrors Printer.Status dot-fill format (plain text, no ANSI).
//
// VerbosityQuiet: only FAIL badges are emitted; all other badges are suppressed.
//
// XCUT-07: only taskName (a developer-controlled dot-namespaced string) and
// badge/duration are rendered. No tool stdout or stderr flows into this method.
func (p *StageProgress) TaskDone(taskName string, badge Badge, dur time.Duration) {
	p.mu.Lock()
	p.doneCount++
	done := p.doneCount
	total := p.taskCount
	tty := p.effectiveTTY()
	quiet := p.verbosity == VerbosityQuiet
	p.mu.Unlock()

	// Quiet mode suppresses everything except FAIL.
	if quiet && badge != BadgeFAIL {
		return
	}

	if tty {
		color := ansiGreen
		if badge == BadgeFAIL {
			color = "\033[31m" // red
		} else if badge == BadgeWARN {
			color = "\033[33m" // yellow
		}
		fmt.Fprintf(p.w, "%s%s[%-5s]%s %s  (%d/%d done)  %s\n",
			ansiEraseLine, color, string(badge), ansiReset,
			taskName, done, total, formatDuration(dur))
	} else {
		// Plain text: mirror Printer.Status dot-fill format.
		const pad = 26
		display := taskName
		if len(display) > pad {
			display = display[:pad-3] + "..."
		}
		gap := pad - len(display)
		if gap < 1 {
			gap = 1
		}
		dots := strings.Repeat(".", gap)
		fmt.Fprintf(p.w, "[%-5s] %s %s %s\n",
			string(badge), display, dots, formatDuration(dur))
	}
}

// StageDone signals that a stage has completed and foundCount items were found.
//
// Emits a summary line. In effective-TTY mode, the line starts on a new line
// (TaskDone already appended \n). In non-TTY mode, also on a new line.
//
// VerbosityQuiet suppresses StageDone output entirely.
func (p *StageProgress) StageDone(stageName string, foundCount int) {
	p.mu.Lock()
	elapsed := time.Since(p.stageStart)
	quiet := p.verbosity == VerbosityQuiet
	p.mu.Unlock()

	if quiet {
		return
	}
	fmt.Fprintf(p.w, "  [stage %s complete — %d found in %s]\n",
		stageName, foundCount, formatDuration(elapsed))
}
