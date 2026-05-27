// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 2
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2
// Pitfall reference: .planning/research/PITFALLS.md §3.1 (atomic write, top-5)
package output

import (
	"os"
	"path/filepath"
)

// WriteJSONL writes lines (each already serialized JSON) to target atomically.
// 4-step pattern: tempfile (same dir as target) + fsync + rename + parent-dir fsync.
// The parent-dir fsync is the often-forgotten step (most implementations stop at 3).
//
// Source: .planning/phases/01-language-adr-spike/01-RESEARCH.md §Pattern 2
// Pitfall reference: .planning/research/PITFALLS.md §3.1 (atomic write, top-5)
func WriteJSONL(target string, lines [][]byte) error {
	dir, base := filepath.Split(target)
	if dir == "" {
		dir = "."
	}

	// Ensure the target directory exists.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	// Step 1: Create tempfile in same directory as target (same filesystem — avoids
	// cross-device rename failure).
	tmp, err := os.CreateTemp(dir, base+".tmp.*")
	if err != nil {
		return err
	}
	// Cleanup on error path: remove the tempfile if we return early.
	// On success, os.Rename has moved it to target and the original tmp.Name() no longer exists.
	defer os.Remove(tmp.Name()) //nolint:errcheck

	// Write all lines.
	for _, line := range lines {
		if _, err := tmp.Write(line); err != nil {
			return err
		}
		if _, err := tmp.Write([]byte("\n")); err != nil {
			return err
		}
	}

	// Step 2: fsync the tempfile (ensures data bytes are on persistent storage).
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Step 3: Atomic rename (on POSIX filesystems, rename(2) is atomic if both
	// paths are on the same filesystem — which CreateTemp above ensures).
	if err := os.Rename(tmp.Name(), target); err != nil {
		return err
	}

	// Step 4: fsync the parent directory (CRITICAL — often missed).
	// Without this step, a crash between rename and directory-update can leave the
	// directory pointing to the old target, effectively losing the rename. This is
	// the step most atomic-write implementations forget.
	parentFD, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer parentFD.Close() //nolint:errcheck

	return parentFD.Sync()
}
