// Source: lib/ui.sh — ui_count_inc / ui_counts_summary semantics. Phase 3
// Plan 5 Task 2.
//
// Counters mirror v1: OK / WARN / FAIL / SKIP / CACHE. Plus INFO (V2
// addition) since v2 surfaces INFO badges via Status when verbose.

package ui

import "fmt"

// countInc increments the counter for badge by 1. Thread-safe via
// the Printer's per-instance mutex (declared with the Printer struct
// in printer.go).
func (p *Printer) countInc(badge Badge) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.counts == nil {
		p.counts = map[Badge]int{}
	}
	p.counts[badge]++
}

// CountFor returns the current count for badge (test hook + Summary helper).
func (p *Printer) CountFor(badge Badge) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.counts[badge]
}

// Summary writes the final OK/WARN/FAIL/SKIP/CACHE counter row. Mirrors
// v1 ui_counts_summary printf format:
//
//	OK:N WARN:N FAIL:N SKIP:N CACHE:N
//
// VerbosityQuiet still emits the summary line — operators expect a
// terminal status row even in quiet mode.
func (p *Printer) Summary() {
	p.mu.Lock()
	ok := p.counts[BadgeOK]
	warn := p.counts[BadgeWARN]
	fail := p.counts[BadgeFAIL]
	skip := p.counts[BadgeSKIP]
	cache := p.counts[BadgeCACHE]
	p.mu.Unlock()
	_, _ = fmt.Fprintf(p.W, "OK:%d WARN:%d FAIL:%d SKIP:%d CACHE:%d\n",
		ok, warn, fail, skip, cache)
}
