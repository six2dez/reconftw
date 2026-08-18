//go:build unix

// Unix (Linux + macOS) backing for the workspace lock. reconFTW supports
// exactly these platforms (CLAUDE.md), and syscall.Flock exists on both.
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-09-PLAN.md
package output

import (
	"errors"
	"os"
	"syscall"
)

// errLockBusy is the internal, platform-agnostic signal that the flock is held
// by someone else. AcquireWorkspaceLock translates it into the exported
// ErrWorkspaceBusy sentinel with the holder's identity attached.
var errLockBusy = errors.New("output: workspace lock is held by another process")

// flockExclusiveNonBlocking takes LOCK_EX|LOCK_NB on f.
//
// LOCK_NB is load-bearing: without it a second run BLOCKS on the first for an
// unbounded time, which is indistinguishable from a hang and is not the design
// (the second run must be rejected). Do not "simplify" this to a blocking
// acquire.
//
// EWOULDBLOCK (== EAGAIN on both Linux and darwin) means "held by someone
// else"; EINTR means a signal arrived mid-syscall and the call must simply be
// retried.
func flockExclusiveNonBlocking(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		switch {
		case err == nil:
			return nil
		case errors.Is(err, syscall.EINTR):
			continue
		case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN):
			return errLockBusy
		default:
			return err
		}
	}
}

// flockUnlock releases the advisory lock held on f. Closing the descriptor
// would release it too; unlocking explicitly keeps the release ordering in
// Lock.Release observable and testable.
func flockUnlock(f *os.File) error {
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		if errors.Is(err, syscall.EINTR) {
			continue
		}
		return err
	}
}
