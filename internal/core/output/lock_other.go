//go:build !unix

// Non-unix backing for the workspace lock: there isn't one.
//
// syscall.Flock does not exist outside unix, and reconFTW supports Linux and
// macOS only (CLAUDE.md). This file exists so the package still COMPILES on a
// hypothetical Windows toolchain while REFUSING to run unlocked. Silently
// running without mutual exclusion would reintroduce F4 — two runs blending
// into one workspace — on exactly the platform nobody is watching.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-09-PLAN.md
package output

import (
	"errors"
	"fmt"
	"os"
	"runtime"
)

// errLockBusy is declared here only so the platform-independent code in lock.go
// compiles. It is never returned on this platform: acquisition fails outright
// rather than reporting contention.
var errLockBusy = errors.New("output: workspace lock is held by another process")

// flockExclusiveNonBlocking always fails on an unsupported platform. The error
// deliberately does NOT wrap errLockBusy: this is not contention, it is an
// unsupported build, and a caller must not present it as "target already
// running".
func flockExclusiveNonBlocking(_ *os.File) error {
	return fmt.Errorf("workspace locking is not supported on %s", runtime.GOOS)
}

// flockUnlock is a no-op: nothing can have been locked on this platform.
func flockUnlock(_ *os.File) error { return nil }
