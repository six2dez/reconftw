// Package ui provides reconFTW v2's terminal UI presentation layer.
//
// Ports the dot-fill semantics from lib/ui.sh (the v1 bash UI module) to
// Go. Honours OUTPUT_VERBOSITY=0/1/2 and PARALLEL_LOG_MODE=summary|tail|full
// per the v1 contract.
//
// NO TUI library imported. Per RESEARCH.md library blacklist, no
// bubbletea / tview / charmbracelet TUI dependency. Plain text output
// over an io.Writer (stderr by default).
//
// Phase 3 Plan 5 split:
//   - Plan 05 Task 1 ships only the Printer type skeleton (enough for
//     `internal/core/appctx/appctx.go` to declare `UI *ui.Printer`).
//   - Plan 05 Task 2 ships the full implementation (Status / Msg / Rule /
//     Section / ProgressModule / Summary / BatchEnd / parallel-log modes
//     + the W13 behavior-map MAPPING comment block).
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
	"io"
	"os"
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
// Plan 05 Task 1 ships only the type skeleton (so AppContext compiles);
// Plan 05 Task 2 ships the full implementation + tests.
type Printer struct {
	W            io.Writer
	Verbosity    Verbosity
	ParallelMode ParallelMode
	TailLines    int
	NoColor      bool

	// Counters incremented per badge by countInc; printed by Summary.
	counts map[Badge]int
}

// NewPrinter constructs a Printer wrapping w at the given verbosity.
// w may be nil — defaults to os.Stderr.
//
// Plan 05 Task 2 expands this constructor (TTY detection, color setup).
func NewPrinter(w io.Writer, verbosity Verbosity) *Printer {
	if w == nil {
		w = os.Stderr
	}
	return &Printer{
		W:            w,
		Verbosity:    verbosity,
		ParallelMode: ParallelSummary,
		TailLines:    20,
		counts:       map[Badge]int{},
	}
}
