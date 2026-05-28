// Source: lib/ui.sh — PARALLEL_LOG_MODE summary|tail|full semantics.
// Ports v1 _parallel_emit_job_output (parallel.sh / common.sh) to Go.
//
// The three modes:
//
//	summary  — one badge line per completed parallel job (default)
//	tail     — last N lines of the job's captured stdout (TailLines)
//	full     — complete captured stdout, verbatim
//
// VerbosityQuiet honored across all three modes (only FAIL surfaces).

package ui

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"time"
)

// ParallelJobOutput renders the output of a completed parallel job per
// the Printer's configured ParallelMode. For summary mode, calls Status
// with the badge. For tail mode, prints the last TailLines lines. For
// full mode, prints the entire output verbatim.
//
// reader is the captured job stdout — typically a *bytes.Buffer in tests,
// a *bufio.Scanner-wrapped pipe in production.
func (p *Printer) ParallelJobOutput(badge Badge, jobName string, dur time.Duration, reader io.Reader) {
	switch p.ParallelMode {
	case ParallelSummary:
		p.Status(badge, jobName, dur)

	case ParallelTail:
		p.Status(badge, jobName, dur)
		p.emitTail(reader, p.TailLines)

	case ParallelFull:
		p.Status(badge, jobName, dur)
		p.emitFull(reader)

	default:
		// Unknown mode → fall back to summary.
		p.Status(badge, jobName, dur)
	}
}

// emitTail prints the last n lines from r. Uses a small ring buffer to
// avoid loading the full stdout into memory.
func (p *Printer) emitTail(r io.Reader, n int) {
	if r == nil || n <= 0 {
		return
	}
	scan := bufio.NewScanner(r)
	// Match v1 1MiB initial / 10MiB max buffer for streaming-tool output.
	buf := make([]byte, 1<<20)
	scan.Buffer(buf, 10<<20)
	ring := make([]string, 0, n)
	for scan.Scan() {
		line := scan.Text()
		if len(ring) >= n {
			ring = ring[1:]
		}
		ring = append(ring, line)
	}
	for _, l := range ring {
		fmt.Fprintf(p.W, "  %s\n", l)
	}
}

// emitFull streams r verbatim to the Printer's writer, indented for
// readability.
func (p *Printer) emitFull(r io.Reader) {
	if r == nil {
		return
	}
	scan := bufio.NewScanner(r)
	buf := make([]byte, 1<<20)
	scan.Buffer(buf, 10<<20)
	for scan.Scan() {
		fmt.Fprintf(p.W, "  %s\n", strings.TrimRight(scan.Text(), "\r"))
	}
}
