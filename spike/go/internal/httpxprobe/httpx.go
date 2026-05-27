// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 3
// Stub Run() for Task 1; real implementation in Task 3 (Plan 01-02 Task 3).
package httpxprobe

import (
	"context"
	"io"
)

// Run invokes httpx with the locked minimal flag set and writes NDJSON host records.
// Stub implementation — replaced in Task 3.
func Run(ctx context.Context, hosts []string, out io.Writer) error { return nil }
