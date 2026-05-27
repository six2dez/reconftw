// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2
// Stub AtomicWriter for Task 1; real implementation in Task 2 (Plan 01-02 Task 2).
package output

import "io"

// AtomicWriter returns a WriteCloser that writes atomically to path.
// Stub implementation — replaced in Task 2.
func AtomicWriter(path string) (io.WriteCloser, error) { return nil, nil }
