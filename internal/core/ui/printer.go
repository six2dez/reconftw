// Package ui provides reconFTW v2's terminal UI presentation layer.
//
// Ports the dot-fill semantics from lib/ui.sh (the v1 bash UI module) to
// Go. Honours OUTPUT_VERBOSITY=0/1/2 and PARALLEL_LOG_MODE=summary|tail|full
// per the v1 contract.
//
// NO TUI library imported. Per RESEARCH.md library blacklist (see
// research/STACK.md §"library blacklist"), no full-screen TUI dependency
// is permitted in this package. Plain text output over an io.Writer
// (stderr by default).
//
// Phase 3 Plan 5 split:
//   - Plan 05 Task 1 ships only the Printer type skeleton (enough for
//     `internal/core/appctx/appctx.go` to declare `UI *ui.Printer`).
//   - Plan 05 Task 2 ships the full implementation (Status / Msg / Rule /
//     Section / ProgressModule / Summary / BatchEnd / parallel-log modes
//   - the W13 behavior-map MAPPING comment block).
//
// MAPPING: lib/ui.sh → internal/core/ui/printer.go
//
//	lib/ui.sh helper           v2 method                   Notes
//	------------------------   -------------------------   ------------------------------------
//	_print_status BADGE NAME   Printer.Status(badge, name, duration)
//	                                                       Dot-fill format with verbosity gate
//	_print_msg LEVEL MSG       Printer.Msg(level, msg)     Honours OUTPUT_VERBOSITY
//	_print_rule TITLE          Printer.Rule(title)         Thin ─── separator
//	_print_section TITLE       Printer.Section(title)      Section header with rule
//	progress_module NAME       Printer.ProgressModule(name)
//	                                                       Module-level progress indicator
//	ui_count_inc BADGE         Printer.countInc(badge)     OK/WARN/FAIL/SKIP/CACHE counters
//	ui_summary                 Printer.Summary()           Final counter summary
//	ui_batch_end NAME          Printer.BatchEnd(name)      Parallel job batch close
//	PARALLEL_LOG_MODE=summary  Printer.ParallelMode = "summary"
//	PARALLEL_LOG_MODE=tail     Printer.ParallelMode = "tail"  (uses Printer.TailLines)
//	PARALLEL_LOG_MODE=full     Printer.ParallelMode = "full"
//	OUTPUT_VERBOSITY=0/1/2     Printer.Verbosity = VerbosityQuiet/Normal/Verbose
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Verbosity controls which message levels the Printer emits. Mirrors v1
// OUTPUT_VERBOSITY=0/1/2 semantics.
type Verbosity int

const (
	// VerbosityQuiet emits only FAIL.
	VerbosityQuiet Verbosity = 0
	// VerbosityNormal emits OK/WARN/FAIL/SKIP (the default).
	VerbosityNormal Verbosity = 1
	// VerbosityVerbose emits all of the above + INFO + ProgressModule.
	VerbosityVerbose Verbosity = 2
)

// Badge enumerates the status badges printed in dot-fill lines.
type Badge string

const (
	BadgeOK    Badge = "OK"
	BadgeWARN  Badge = "WARN"
	BadgeFAIL  Badge = "FAIL"
	BadgeSKIP  Badge = "SKIP"
	BadgeCACHE Badge = "CACHE"
	BadgeINFO  Badge = "INFO"
)

// ParallelMode mirrors v1 PARALLEL_LOG_MODE=summary|tail|full.
type ParallelMode string

const (
	ParallelSummary ParallelMode = "summary"
	ParallelTail    ParallelMode = "tail"
	ParallelFull    ParallelMode = "full"
)

// Printer is the v2 terminal UI presenter. Constructed by appctx.Boot via
// NewPrinter(os.Stderr, cfg.Output.Verbosity).
//
// Plan 05 Task 2 ships the full implementation + tests (verbatim port of
// lib/ui.sh dot-fill semantics).
//
// Thread-safety: the counters map is mu-protected; the io.Writer is
// expected to be safe for concurrent writes (os.Stderr satisfies this).
type Printer struct {
	W            io.Writer
	Verbosity    Verbosity
	ParallelMode ParallelMode
	TailLines    int
	NoColor      bool

	mu     sync.Mutex
	counts map[Badge]int
}

// NewPrinter constructs a Printer wrapping w at the given verbosity.
// w may be nil — defaults to os.Stderr. NoColor is auto-derived from TTY
// detection; callers may override the field after construction.
func NewPrinter(w io.Writer, verbosity Verbosity) *Printer {
	if w == nil {
		w = os.Stderr
	}
	p := &Printer{
		W:            w,
		Verbosity:    verbosity,
		ParallelMode: ParallelSummary,
		TailLines:    20,
		counts:       map[Badge]int{},
	}
	// NO_COLOR convention + non-TTY default → no color.
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		p.NoColor = true
	}
	if !IsTTY(w) {
		p.NoColor = true
	}
	return p
}

// Status emits the dot-fill status line per v1 lib/ui.sh _print_status:
//
//	[BADGE] name<padding>.......... duration
//
// VerbosityQuiet suppresses everything except FAIL. INFO badges are
// suppressed unless VerbosityVerbose.
//
// The counter for badge is always incremented (so the Summary line is
// accurate even at VerbosityQuiet — the operator wants the run summary
// regardless of which individual lines were shown).
func (p *Printer) Status(badge Badge, name string, dur time.Duration) {
	p.countInc(badge)
	if !p.shouldEmit(badge) {
		return
	}
	const pad = 26
	display := name
	if len(display) > pad {
		display = display[:pad-3] + "..."
	}
	gap := pad - len(display)
	if gap < 1 {
		gap = 1
	}
	dots := strings.Repeat(".", gap)
	fmt.Fprintf(p.W, "[%-5s] %s %s %s\n", string(badge), display, dots, formatDuration(dur))
}

// Msg emits an INFO/WARN/FAIL/OK message line. Mirrors v1 _print_msg.
// INFO suppressed unless VerbosityVerbose.
func (p *Printer) Msg(level string, msg string) {
	switch strings.ToUpper(level) {
	case "INFO":
		if p.Verbosity < VerbosityVerbose {
			return
		}
	case "OK", "WARN", "FAIL":
		if p.Verbosity < VerbosityNormal {
			// Allow FAIL even at quiet level — operator must see errors.
			if strings.ToUpper(level) != "FAIL" {
				return
			}
		}
	}
	fmt.Fprintf(p.W, "%-5s %s\n", strings.ToUpper(level), msg)
}

// Rule emits a thin ─── separator line, optionally prefixed with title.
// Mirrors v1 lib/common.sh _print_rule.
func (p *Printer) Rule(title string) {
	if p.Verbosity < VerbosityNormal {
		return
	}
	if title != "" {
		fmt.Fprintf(p.W, "─── %s ───────────────────────────────────────────────\n", title)
	} else {
		fmt.Fprintln(p.W, "────────────────────────────────────────────────────────")
	}
}

// Section emits a section header with timestamp — mirrors v1
// _print_module_start (used by _print_section for major phases like
// "OSINT", "Subdomains", etc.).
func (p *Printer) Section(title string) {
	if p.Verbosity < VerbosityNormal {
		return
	}
	fmt.Fprintf(p.W, "\n── %s ───────────────────────────────────────────────\n", strings.ToUpper(title))
	fmt.Fprintf(p.W, "Started: %s\n", time.Now().UTC().Format(time.RFC3339))
}

// ProgressModule emits a module-level progress indicator. Mirrors v1
// progress_module function in modules/core.sh. Suppressed unless
// VerbosityVerbose.
func (p *Printer) ProgressModule(name string) {
	if p.Verbosity < VerbosityVerbose {
		return
	}
	fmt.Fprintf(p.W, "▸ %s\n", name)
}

// BatchEnd closes a parallel-batch UI block per v1 ui_batch_end semantics.
// VerbosityQuiet emits nothing; VerbosityNormal+ emits a summary line.
func (p *Printer) BatchEnd(name string) {
	if p.Verbosity < VerbosityNormal {
		return
	}
	p.mu.Lock()
	ok := p.counts[BadgeOK]
	warn := p.counts[BadgeWARN]
	fail := p.counts[BadgeFAIL]
	skip := p.counts[BadgeSKIP]
	cache := p.counts[BadgeCACHE]
	p.mu.Unlock()
	fmt.Fprintf(p.W, "── %s: ok:%d warn:%d fail:%d skip:%d cache:%d ──\n",
		name, ok, warn, fail, skip, cache)
}

// shouldEmit applies the verbosity gate for Status.
func (p *Printer) shouldEmit(badge Badge) bool {
	switch badge {
	case BadgeFAIL:
		return true // always emit FAIL
	case BadgeINFO:
		return p.Verbosity >= VerbosityVerbose
	default:
		return p.Verbosity >= VerbosityNormal
	}
}

// formatDuration mirrors v1 format_duration (lib/common.sh) — seconds
// for short, m+s for ≥1 min. Defensive against negative durations.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	mins := int(d.Minutes())
	secs := int(d.Seconds()) % 60
	return fmt.Sprintf("%dm%02ds", mins, secs)
}
