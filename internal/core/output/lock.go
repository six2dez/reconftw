// Workspace ownership (F4 / acceptance gate 4).
//
// AcquireWorkspaceLock gives a target workspace a single owner for the
// duration of a run. Two concurrent runs against the SAME target otherwise
// share inputs/, artefacts/, checkpoints.db, logs/ and reports/: producer
// staging writes from run 1 and run 2 interleave into the same inputs/*.jsonl
// glob, and a merge can execute while another producer is still writing, so
// the merged artefact becomes a blend of two runs with no way to tell which
// line came from which. The scheduler's global Limiter caps concurrent
// PROCESSES, not workspace ownership, so it does not help here.
//
// DELIBERATE DEPARTURE FROM CLAUDE.md. The v1 bash framework documents a
// single-operator contract — "no locking, no multi-user state, no concurrent
// runs against the same target dir". v2 ships an MCP server that accepts
// concurrent tool calls from any authorised client, and a CLI run can race an
// MCP run, so that assumption no longer holds. This lock is that assumption
// being retired on purpose; it is not scope creep and must not be reverted as
// such.
//
// WHAT THIS LOCK CANNOT COVER, BY CONSTRUCTION: WorkspaceInit itself.
// The lock file lives INSIDE the directory WorkspaceInit creates — and, on the
// first run after upgrading to canonical target identities, adoptLegacyWorkspace
// may os.Rename that whole directory onto a new slug. There is no ordering that
// fixes this: a directory cannot be locked before its name has been decided.
// Callers therefore acquire the lock immediately AFTER WorkspaceInit returns
// and never before. The pre-lock window is made safe a different way — legacy
// adoption is CONVERGENT rather than exclusive: a lost os.Rename race whose
// winner produced the new-slug directory re-stats that directory and returns
// success instead of an error (see adoptLegacyWorkspace in init.go). Moving
// AcquireWorkspaceLock above WorkspaceInit would lock a path that is about to
// be renamed away, which is strictly worse than the window it would "fix".
//
// Source: .planning/phases/15-release-gates-run-isolation-store-integrity/15-09-PLAN.md
package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LockFileName is the per-workspace lock file. It is exported so tests (and
// operators) can assert on its presence or absence — a dry run, which creates
// no workspace at all, must never produce one.
const LockFileName = ".run.lock"

// ErrWorkspaceBusy is returned (wrapped) when another live run already owns the
// workspace. It is a sentinel so callers can errors.Is it and surface a clean
// "target already running" message instead of string-matching an errno.
var ErrWorkspaceBusy = errors.New("output: workspace is already in use by another run")

// lockAcquireAttempts bounds the inode-revalidation retry below. Two attempts
// is enough in practice (a losing revalidation means some other process just
// unlinked the file, which cannot repeat indefinitely without a live holder);
// the bound exists so a pathological loop cannot hang a run.
const lockAcquireAttempts = 3

// LockPayload is the JSON object written into the lock file by the holder. It
// exists so a rejection can NAME who holds the workspace rather than reporting
// an anonymous "busy".
type LockPayload struct {
	// PID is the operating-system process id of the holder.
	PID int `json:"pid"`
	// StartedAt is when the lock was acquired, RFC3339 in UTC.
	StartedAt string `json:"started_at"`
	// Kind / Canonical / Slug mirror the workspace's .target-identity.json, so
	// the lock file is self-describing even if it is inspected in isolation.
	// They are best-effort: an unreadable identity marker leaves them empty and
	// never fails an acquisition.
	Kind      string `json:"kind,omitempty"`
	Canonical string `json:"canonical,omitempty"`
	Slug      string `json:"slug,omitempty"`
}

// Lock is an acquired advisory lock on one workspace directory. The zero value
// is not usable; obtain one from AcquireWorkspaceLock. A nil *Lock is safe to
// Release (it is a no-op), so callers can defer a release unconditionally.
type Lock struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	released bool
}

// Path returns the absolute-or-relative path of the lock file this Lock holds.
// It returns "" for a nil Lock.
func (l *Lock) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// AcquireWorkspaceLock takes an exclusive, NON-BLOCKING advisory lock on
// <workspaceDir>/.run.lock and returns a *Lock the caller must Release.
//
// Non-blocking is the whole design. A blocking acquire would queue the second
// run behind the first for an unbounded time, which looks exactly like a hang
// and lets a client pin an arbitrary number of waiting goroutines on one
// target. The second run is REJECTED instead, with an error satisfying
// errors.Is(err, ErrWorkspaceBusy) and naming the holder's PID.
//
// STALE LOCKS NEED NO TIMEOUT, PID PROBE OR AUTO-BREAK. An advisory flock is
// released by the KERNEL when the holding process dies, however it dies —
// SIGKILL, panic, power loss on the process. So a lock FILE left behind by a
// crashed run carries no flock and is acquired by the next run immediately,
// while a lock that genuinely refuses to be acquired means a live holder exists
// right now. Every "stale lock" heuristic (an age cut-off, signalling the PID,
// a force-break flag) is therefore not a robustness feature but a way to break
// a LIVE lock — a PID can be recycled, and a long-running scan is not stale.
// None is implemented, on purpose.
//
// See this file's package comment for the WorkspaceInit boundary: this function
// must be called AFTER WorkspaceInit, never before.
func AcquireWorkspaceLock(workspaceDir string) (*Lock, error) {
	if strings.TrimSpace(workspaceDir) == "" {
		return nil, fmt.Errorf("output: AcquireWorkspaceLock: empty workspaceDir")
	}
	path := filepath.Join(workspaceDir, LockFileName)

	var lastErr error
	for attempt := 0; attempt < lockAcquireAttempts; attempt++ {
		l, retry, err := tryAcquire(path)
		if err == nil {
			return l, nil
		}
		lastErr = err
		if !retry {
			return nil, err
		}
	}
	return nil, lastErr
}

// tryAcquire performs one open → flock → revalidate → stamp cycle. retry is
// true only for the benign "the file we locked was unlinked underneath us"
// case described below.
func tryAcquire(path string) (_ *Lock, retry bool, _ error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644) //nolint:gosec // path built from a sanitized workspace slug
	if err != nil {
		return nil, false, fmt.Errorf("output: AcquireWorkspaceLock: open %s: %w", path, err)
	}

	if err := flockExclusiveNonBlocking(f); err != nil {
		if errors.Is(err, errLockBusy) {
			// Read the holder's stamp best-effort BEFORE closing our handle, so
			// the rejection can name who owns the workspace.
			holder := describeHolder(path)
			_ = f.Close()
			return nil, false, fmt.Errorf("output: AcquireWorkspaceLock: %s%s: %w", path, holder, ErrWorkspaceBusy)
		}
		_ = f.Close()
		return nil, false, fmt.Errorf("output: AcquireWorkspaceLock: flock %s: %w", path, err)
	}

	// Inode revalidation. Release unlinks the lock file, so this sequence is
	// possible: we open the file and get inode X; the holder then unlinks and
	// unlocks X; our flock on X now succeeds even though the path no longer
	// names X, and a third process that creates a fresh inode Y at the same path
	// would ALSO succeed — two "owners" of one workspace. Confirming that the
	// inode we locked is still the inode the path names closes that window.
	// A mismatch is benign and retryable, never an error to the caller.
	same, statErr := sameFile(f, path)
	if statErr != nil || !same {
		_ = flockUnlock(f)
		_ = f.Close()
		return nil, true, fmt.Errorf("output: AcquireWorkspaceLock: %s was replaced during acquisition", path)
	}

	l := &Lock{f: f, path: path}
	if err := l.stamp(); err != nil {
		_ = l.Release()
		return nil, false, err
	}
	return l, false, nil
}

// stamp records the owner inside the lock file.
//
// This is the ONE place in this package that legitimately bypasses the atomic
// write-temp-then-rename rule enforced everywhere else (WriteFile / WriteJSONL).
// A rename would install a DIFFERENT inode at the path, and the flock lives on
// the inode our descriptor holds — so an "atomic" write would silently drop the
// lock and leave a lock file nobody owns. The payload is therefore written
// through the same descriptor that holds the flock: truncate, seek, write.
// Correctness does not depend on this write; it is diagnostic metadata for the
// rejection message, so a torn payload degrades the error text, never the
// mutual exclusion.
func (l *Lock) stamp() error {
	id, err := readIdentityMarker(filepath.Dir(l.path))
	payload := LockPayload{
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err == nil {
		payload.Kind = id.Kind
		payload.Canonical = id.Canonical
		payload.Slug = id.Slug
	}

	buf, mErr := json.Marshal(payload)
	if mErr != nil {
		return fmt.Errorf("output: AcquireWorkspaceLock: marshal lock payload: %w", mErr)
	}
	if tErr := l.f.Truncate(0); tErr != nil {
		return fmt.Errorf("output: AcquireWorkspaceLock: truncate %s: %w", l.path, tErr)
	}
	if _, sErr := l.f.Seek(0, io.SeekStart); sErr != nil {
		return fmt.Errorf("output: AcquireWorkspaceLock: seek %s: %w", l.path, sErr)
	}
	if _, wErr := l.f.Write(buf); wErr != nil {
		return fmt.Errorf("output: AcquireWorkspaceLock: write %s: %w", l.path, wErr)
	}
	_ = l.f.Sync()
	return nil
}

// Release drops the lock. It is idempotent: a second (or nth) call returns nil
// without touching the filesystem, so callers may both defer it and call it
// explicitly at an earlier exit point. A nil *Lock releases successfully, which
// is what makes an unconditional `defer boot.Close()` safe on a dry-run boot
// that holds no lock.
//
// The lock file is REMOVED while the flock is still held, then unlocked, then
// closed. Removing after unlocking would risk deleting a SUCCESSOR's lock file
// (it may have already created and locked a new one at the same path). The
// removal is cosmetic housekeeping either way — correctness comes from the
// flock plus the inode revalidation in tryAcquire.
func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.released {
		return nil
	}
	l.released = true

	if l.f == nil {
		return nil
	}

	if err := os.Remove(l.path); err != nil && !os.IsNotExist(err) {
		// Best-effort: a lock file that cannot be removed is harmless (the next
		// acquirer re-opens and re-locks it); failing the release would be worse.
		_ = err
	}
	unlockErr := flockUnlock(l.f)
	closeErr := l.f.Close()
	l.f = nil

	if unlockErr != nil {
		return fmt.Errorf("output: Lock.Release: unlock %s: %w", l.path, unlockErr)
	}
	if closeErr != nil {
		return fmt.Errorf("output: Lock.Release: close %s: %w", l.path, closeErr)
	}
	return nil
}

// describeHolder reads the holder's stamp best-effort and renders it as a
// parenthesised suffix for the busy error, e.g.
// " (held by PID 4242 since 2026-08-18T09:12:03Z)". It returns "" when the
// payload is missing, unreadable or malformed — a rejection with a vaguer
// message is still a correct rejection.
func describeHolder(path string) string {
	data, err := os.ReadFile(path) //nolint:gosec // path built from a sanitized workspace slug
	if err != nil || len(data) == 0 {
		return ""
	}
	var p LockPayload
	if err := json.Unmarshal(data, &p); err != nil || p.PID == 0 {
		return ""
	}
	if p.StartedAt == "" {
		return fmt.Sprintf(" (held by PID %d)", p.PID)
	}
	return fmt.Sprintf(" (held by PID %d since %s)", p.PID, p.StartedAt)
}

// sameFile reports whether the open descriptor and the path currently name the
// same file (same device + inode).
func sameFile(f *os.File, path string) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	pi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return os.SameFile(fi, pi), nil
}
