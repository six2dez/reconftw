// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 3 (streaming)
// Pitfall reference: .planning/research/PITFALLS.md §1.4 (stdin race — use -l file mode)
//
// Spike-vs-prod difference: in production, large host sets (>1000) would use a persistent
// writer with incremental atomic flushes. This spike buffers up to 1000 lines in memory
// then flushes atomically — acceptable for the spike's scope (hackerone.com ~few hundred hosts).
package httpxprobe

import (
	"context"
	"os"

	"github.com/six2dez/reconftw/spike/go/internal/output"
	"github.com/six2dez/reconftw/spike/go/internal/proc"
	"github.com/six2dez/reconftw/spike/go/internal/ui"
)

// Run invokes httpx with the locked minimal flag set and writes NDJSON-shaped host records
// to outFile via atomic write at end. The locked flags are:
//
//	-l <subsFile> -silent -json -status-code -title -tech-detect -no-color -threads 50 -timeout 10
//
// Source pattern: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.2
// Locked: spike/README.md §Slice Locked
func Run(ctx context.Context, subsFile string, outFile string) error {
	// Validate subsFile exists and is non-empty before invoking httpx.
	// Per RESEARCH.md PITFALL 1.4 — never pipe via stdin; always file mode (-l flag).
	info, err := os.Stat(subsFile)
	if err != nil {
		ui.Skip("httpx", "subs file not found: "+subsFile)
		return nil
	}
	if info.Size() == 0 {
		ui.Skip("httpx", "subs file is empty: "+subsFile)
		return nil
	}

	ui.Info("httpx: probing hosts from " + subsFile)

	// Locked 8 flags per RESEARCH.md §1.2 and spike/README.md §Slice Locked.
	args := []string{
		"-l", subsFile,
		"-silent",
		"-json",
		"-status-code",
		"-title",
		"-tech-detect",
		"-no-color",
		"-threads", "50",
		"-timeout", "10",
	}

	// Collect lines in memory; flush to outFile atomically at end.
	// For memory safety at scale (M5 RSS): flush when buffer exceeds 1000 lines.
	var lines [][]byte
	const flushAt = 1000

	err = proc.Run(ctx, "httpx", args, func(line []byte) error {
		if len(line) == 0 {
			return nil
		}
		// Each line is already valid JSON from httpx -json; no re-parsing needed.
		lineCopy := make([]byte, len(line))
		copy(lineCopy, line)
		lines = append(lines, lineCopy)

		// Intermediate flush at 1000 lines (spike simplification — production would
		// use a persistent writer with incremental atomic flushes).
		if len(lines) >= flushAt {
			if ferr := output.WriteJSONL(outFile, lines); ferr != nil {
				ui.Warn("httpx: intermediate flush failed: " + ferr.Error())
			}
			lines = lines[:0]
		}
		return nil
	})
	if err != nil {
		ui.Warn("httpx: subprocess error: " + err.Error())
		// Don't return error — partial results are fine for the spike.
	}

	if len(lines) == 0 {
		ui.Info("httpx: no hosts responded")
		return nil
	}

	// Final atomic write of remaining lines (or all lines if < flushAt).
	return output.WriteJSONL(outFile, lines)
}
