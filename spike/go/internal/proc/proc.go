// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
// Stub Run() for Task 1; real implementation in Task 2 (Plan 01-02 Task 2).
package proc

import "context"

// Run executes name+args under process-group isolation (Setpgid: true). On ctx cancel,
// the entire process group receives SIGTERM, then SIGKILL after 5s WaitDelay grace.
// stdout is streamed line-by-line through lineFn; nil lineFn means stdout is discarded.
//
// lineFn signature is `func([]byte) error` (B4 fix per cross-AI review):
//   - For streaming-friendly sources (NDJSON like subfinder, httpx), callers parse
//     each line and may return a non-nil error to abort the subprocess early.
//   - For buffered sources (JSON-array like crt.sh), callers simply append the line
//     to a bytes.Buffer and return nil; the source-specific package then parses
//     the accumulated buffer AFTER proc.Run returns. This dual-mode usage is the
//     reason lineFn returns error: it removes the ambiguity Task 3 crt.go would
//     otherwise face (mid-implementation workaround for missing abort semantics).
//
// Returns the cmd's wait error (nil = clean exit).
//
// Source pattern: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 1
// Pitfall reference: .planning/research/PITFALLS.md §1.2 (process-group escape, top-impact)
func Run(ctx context.Context, name string, args []string, lineFn func([]byte) error) error {
	return nil
}
