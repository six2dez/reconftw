// Package ui — StageProgress type.
//
// XCUT-07 AT THIS SINK. This header used to read "StageProgress renders task
// names only; never tool stdout/stderr", and that stopped being true the moment
// plan 16-01 made errors.ToolError.Error() append the tool's own stderr tail.
// That string becomes task.Result.Reason via task.ToolDegraded and arrives here
// through TaskDoneReason, so tool-controlled bytes — which routinely echo the
// operator's argv and configuration back, `-t <token>`, an auth failure quoting
// a bearer, a URL with an API key in the query string — were being written
// verbatim to the operator's screen and to everything that captures it.
//
// The fix is NOT to stop carrying the stderr: that message is why a failure now
// reads "unable to load public resolvers: open t: no such file or directory"
// instead of "exit status 1". The fix is to redact where the bytes LEAVE the
// process, which is XCUT-07's own stated posture. So:
//
//	Tool-derived text DOES reach this sink, and every byte of it passes through
//	the redactor installed by SetRedactor before it is formatted.
//
// A nil redactor degrades to no redaction and is the zero value, so a
// construction site that never calls SetRedactor behaves exactly as before —
// which is why the wiring is asserted end-to-end through the compiled binary
// (cmd/reconftw/redaction_e2e_test.go) and not only here.
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
	// redactor scrubs registered secrets from tool-derived reason text before it
	// is rendered. Guarded by mu like every other mutable field: SetRedactor may
	// be called from the command layer while a stage is already running.
	redactor Redactor
}

// Redactor is the one method this package needs to scrub a secret from a line
// it is about to write.
//
// Declared here as a one-method interface rather than importing
// internal/core/log, for the same reason and in the same shape as
// backend.Redactor: the ui package stays free of a log dependency it would need
// for exactly one call, and a test can supply a trivial stub. *log.Redactor
// satisfies it structurally.
type Redactor interface {
	Redact(string) string
}

// SetRedactor installs the redactor applied to every Reason this progress writer
// renders. Passing nil (or never calling it) keeps the pre-existing behaviour
// byte-for-byte, so no construction site is forced to change.
//
// It is a setter rather than a NewStageProgress parameter deliberately: the
// redactor a run uses is the SAME instance the tool recorder holds, and at the
// five StageProgress construction sites that instance is already in hand from
// the enclosing RunOptions. A new positional parameter would have silently
// accepted nil at any site the author forgot, which is the split-brain failure
// this plan exists to remove, reintroduced one layer up.
func (p *StageProgress) SetRedactor(r Redactor) {
	p.mu.Lock()
	p.redactor = r
	p.mu.Unlock()
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
		_, _ = fmt.Fprintf(p.w, "%s%s▸ [%s] starting... (0/%d tasks)",
			ansiEraseLine, ansiGreen, stageName, taskCount)
	} else if p.verbosity >= VerbosityNormal {
		_, _ = fmt.Fprintf(p.w, "▸ [%s] starting... (%d tasks)\n", stageName, taskCount)
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
	_, _ = fmt.Fprintf(p.w, "%s%s  %c %s%s",
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
// XCUT-07: this entry point renders only taskName (a developer-controlled
// dot-namespaced string) and badge/duration — it passes an EMPTY reason. Its
// sibling TaskDoneReason does carry tool-derived text; see the package header
// for why that text is redacted here rather than suppressed upstream.
func (p *StageProgress) TaskDone(taskName string, badge Badge, dur time.Duration) {
	p.taskDone(taskName, badge, dur, "")
}

// TaskDoneReason is TaskDone with the one-sentence explanation a non-OK result
// carries (task.Result.Reason).
//
// Without it the Reason field is invisible and the whole no-silent-success rule
// is decoration: an operator reads "[SKIP] web.nuclei 0s" and learns nothing,
// which is exactly the state that let a config-only capability sit disabled while
// the templates were installed on the box.
//
// reason is TOOL-DERIVED and therefore untrusted: task.ToolDegraded builds it
// from errors.ToolError.Error(), which embeds up to 300 bytes of the tool's own
// stderr. It is passed through the installed Redactor inside taskDone before any
// formatting.
func (p *StageProgress) TaskDoneReason(taskName string, badge Badge, dur time.Duration, reason string) {
	p.taskDone(taskName, badge, dur, reason)
}

func (p *StageProgress) taskDone(taskName string, badge Badge, dur time.Duration, reason string) {
	p.mu.Lock()
	p.doneCount++
	done := p.doneCount
	total := p.taskCount
	tty := p.effectiveTTY()
	quiet := p.verbosity == VerbosityQuiet
	rdct := p.redactor
	p.mu.Unlock()

	// THE SEAM. reason is the only untrusted input to this method, and this is
	// the last point before it is formatted into bytes bound for the operator's
	// terminal. Redacting here rather than at the construction site in
	// task.ToolDegraded is deliberate: there is exactly one sink to protect,
	// whereas there are many places a Reason can be built.
	if rdct != nil && reason != "" {
		reason = rdct.Redact(reason)
	}

	// Quiet mode suppresses everything except FAIL.
	if quiet && badge != BadgeFAIL {
		return
	}

	if tty {
		color := ansiGreen
		switch badge {
		case BadgeFAIL:
			color = "\033[31m" // red
		case BadgeWARN:
			color = "\033[33m" // yellow
		}
		_, _ = fmt.Fprintf(p.w, "%s%s[%-5s]%s %s  (%d/%d done)  %s%s\n",
			ansiEraseLine, color, string(badge), ansiReset,
			taskName, done, total, formatDuration(dur), reasonSuffix(badge, reason))
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
		_, _ = fmt.Fprintf(p.w, "[%-5s] %s %s %s%s\n",
			string(badge), display, dots, formatDuration(dur), reasonSuffix(badge, reason))
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
	_, _ = fmt.Fprintf(p.w, "  [stage %s complete — %d found in %s]\n",
		stageName, foundCount, formatDuration(elapsed))
}

// reasonSuffix renders a Reason for a non-OK badge only.
//
// Deliberately suppressed on OK: a Done result needs no explanation, and printing
// one on every successful task would bury the ones that matter — the same reason
// the rule says a Done result must carry an EMPTY Reason.
func reasonSuffix(badge Badge, reason string) string {
	if reason == "" || badge == BadgeOK {
		return ""
	}
	const cap = 90
	r := strings.Join(strings.Fields(reason), " ")
	if len(r) > cap {
		r = r[:cap-1] + "\u2026"
	}
	return "  " + r
}
