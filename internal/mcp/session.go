// Package mcp — session registry.
//
// SessionRegistry is the source of truth mapping a runID to its
// associated scope, work directory, and completion status. It is the
// shared state that tool handlers write to (Register, SetScope,
// MarkComplete) and resource handlers read from (Lookup, WorkDir).
//
// Thread-safety: all methods use sync.RWMutex (write-lock for mutations,
// read-lock for reads) following the same pattern as internal/core/log.Redactor.
package mcp

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// SessionStatus is the lifecycle state of a session entry.
type SessionStatus string

const (
	// SessionStatusRunning indicates the scan is in progress.
	SessionStatusRunning SessionStatus = "running"
	// SessionStatusComplete indicates the scan finished successfully.
	SessionStatusComplete SessionStatus = "complete"
	// SessionStatusFailed indicates the scan terminated with an error.
	SessionStatusFailed SessionStatus = "failed"
	// SessionStatusCancelled indicates the run was cancelled by its owner
	// through the cancel_scan tool. It is distinct from failed: the operator
	// asked for it, so it is not an error to investigate.
	SessionStatusCancelled SessionStatus = "cancelled"
)

// isTerminal reports whether a status can no longer change on its own.
// Terminal entries are the only ones the sweeper may reclaim.
func (s SessionStatus) isTerminal() bool {
	switch s {
	case SessionStatusComplete, SessionStatusFailed, SessionStatusCancelled:
		return true
	default:
		return false
	}
}

// Registry reclamation bounds (T-15-15-05). A long-lived MCP server accumulates
// one entry per run for as long as it lives; an authorised client could grow it
// without limit just by starting scans, which is a trivially reachable memory
// exhaustion vector. Only TERMINAL entries are reclaimable — a running scan and
// a live session's scope must never disappear underneath their owner.
const (
	// completedEntryTTL is how long a terminal entry stays readable. It must be
	// long enough for a client to come back and read the status of a scan it
	// launched, and short enough to bound a server that runs for weeks.
	completedEntryTTL = 1 * time.Hour
	// maxTerminalEntries caps terminal entries regardless of age, evicting
	// oldest-first. The TTL alone does not bound a burst of short scans.
	maxTerminalEntries = 512
	// terminalSweepInterval is how often the server-owned sweeper runs.
	terminalSweepInterval = 5 * time.Minute
)

// SessionEntry holds the metadata for a registered scan session.
//
// Lookup returns entries BY VALUE. Handing out the internal pointer while the
// mutex is released let readers observe Status/WorkDir mid-write from the scan
// goroutine — a data race that no amount of locking inside the registry could
// fix, because the escape happened after the lock was dropped.
type SessionEntry struct {
	RunID   string
	WorkDir string
	Scope   *SessionScope
	Status  SessionStatus
	// Owner is the MCP session ID that launched this run. Resource reads and
	// subscriptions are authorised against it: knowing a runID is not
	// authorisation to read its findings. Empty means "no owner recorded"
	// (session-scope entries, whose RunID is itself the session ID).
	Owner string
	// Err is the failure reason when Status is SessionStatusFailed.
	Err string
	// TerminalAt is when the entry reached a terminal status. Zero while the
	// run is still going. The sweeper reclaims on it.
	TerminalAt time.Time
	// cancel stops this run. It is unexported so a Lookup copy cannot be used
	// to cancel a run the caller does not own — cancellation goes through
	// CancelRunOwnedBy, which checks ownership under the same lock.
	cancel context.CancelFunc
}

// SessionRegistry maps runIDs to their SessionEntry values.
// All methods are safe for concurrent use from multiple goroutines.
type SessionRegistry struct {
	mu      sync.RWMutex
	entries map[string]*SessionEntry
}

// NewSessionRegistry returns an initialised, empty registry.
func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		entries: make(map[string]*SessionEntry),
	}
}

// Register records a new session entry.
// It panics if runID is already registered — the caller MUST use unique
// run IDs (use crypto/rand in the handler layer; see Plan 08-04).
func (r *SessionRegistry) Register(runID, workDir string, scope *SessionScope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[runID]; exists {
		panic("mcp: session already registered: " + runID)
	}
	r.entries[runID] = &SessionEntry{
		RunID:   runID,
		WorkDir: workDir,
		Scope:   scope,
		Status:  SessionStatusRunning,
	}
}

// Lookup returns a COPY of the entry for runID and a flag indicating whether
// it exists. Returns (zero, false) when runID is not found; never panics.
//
// The copy is the point: the scan goroutine mutates Status, WorkDir and Err
// concurrently with readers, so returning the live pointer raced.
func (r *SessionRegistry) Lookup(runID string) (SessionEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[runID]
	if !ok {
		return SessionEntry{}, false
	}
	return *entry, true
}

// RegisterRun records a scan run owned by ownerSessionID with no cancel hook.
// Callers that can cancel their run use RegisterRunWithCancel.
func (r *SessionRegistry) RegisterRun(runID, ownerSessionID string) {
	r.RegisterRunWithCancel(runID, ownerSessionID, nil)
}

// RegisterRunWithCancel records a scan run owned by ownerSessionID together with
// the CancelFunc that stops it.
//
// The cancel hook is stored WITH the entry, in one locked write, so a
// cancel_scan call can never observe a registered run that has no way to be
// cancelled. A nil cancel is allowed (tests, and pre-existing callers), but
// CancelRunOwnedBy then refuses: an entry with no way to stop it is not a
// cancellable run.
func (r *SessionRegistry) RegisterRunWithCancel(runID, ownerSessionID string, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entries[runID]; exists {
		panic("mcp: session already registered: " + runID)
	}
	r.entries[runID] = &SessionEntry{
		RunID:  runID,
		Owner:  ownerSessionID,
		Status: SessionStatusRunning,
		cancel: cancel,
	}
}

// CancelRunOwnedBy cancels runID if — and only if — sessionID may act on it.
// It reports whether the run was cancelled by this call.
//
// Unknown run and not-your-run return the SAME false, and the caller returns the
// SAME message for both, so cancel_scan cannot be used to enumerate other
// sessions' run ids (T-15-15-03). Cancelling an already-terminal run is a no-op
// that returns false: there is nothing left to stop.
//
// An entry with NO cancel hook is refused too. That is what separates a run from
// a session-scope entry, whose RunID is the session id and which carries no
// owner: without this check, naming another session's id would mark that
// session's entry cancelled and hand it to the sweeper, silently destroying a
// live session's captured scope.
//
// The CancelFunc is invoked AFTER the lock is released. Cancelling wakes the
// scan goroutine, which calls straight back into the registry (MarkFailed /
// MarkComplete); calling it under the lock would make that a lock-ordering
// hazard for no benefit.
func (r *SessionRegistry) CancelRunOwnedBy(runID, sessionID string) bool {
	r.mu.Lock()
	entry, ok := r.entries[runID]
	if !ok || entry.cancel == nil ||
		(entry.Owner != "" && entry.Owner != sessionID) ||
		entry.Status.isTerminal() {
		r.mu.Unlock()
		return false
	}
	cancel := entry.cancel
	entry.Status = SessionStatusCancelled
	entry.TerminalAt = time.Now()
	r.mu.Unlock()

	cancel()
	return true
}

// SweepTerminal reclaims terminal entries: everything that reached a terminal
// status before cutoff, and then — regardless of age — the oldest terminal
// entries beyond maxTerminalEntries. It returns how many entries it removed.
//
// Running entries and session-scope entries are never touched: dropping a live
// session's scope would silently revoke its authorisation state.
//
// The cutoff is a parameter rather than an internal clock read so a test can
// drive reclamation deterministically instead of sleeping for the production
// TTL.
func (r *SessionRegistry) SweepTerminal(cutoff time.Time) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := 0
	terminal := make([]*SessionEntry, 0, len(r.entries))
	for id, entry := range r.entries {
		if !entry.Status.isTerminal() {
			continue
		}
		if !entry.TerminalAt.IsZero() && entry.TerminalAt.Before(cutoff) {
			delete(r.entries, id)
			removed++
			continue
		}
		terminal = append(terminal, entry)
	}

	if len(terminal) > maxTerminalEntries {
		sort.Slice(terminal, func(i, j int) bool {
			return terminal[i].TerminalAt.Before(terminal[j].TerminalAt)
		})
		for _, entry := range terminal[:len(terminal)-maxTerminalEntries] {
			delete(r.entries, entry.RunID)
			removed++
		}
	}
	return removed
}

// Len returns the number of entries currently held. Used by the reclamation
// tests and useful for operational assertions.
func (r *SessionRegistry) Len() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.entries)
}

// OwnedBy reports whether runID exists and is readable by sessionID.
//
// An entry with no recorded owner is readable by anyone: those are the
// session-scope entries whose RunID *is* the session ID, plus runs registered
// before ownership tracking existed. Scan runs always carry an owner.
func (r *SessionRegistry) OwnedBy(runID, sessionID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[runID]
	if !ok {
		return false
	}
	return entry.Owner == "" || entry.Owner == sessionID
}

// SetWorkDir records the resolved workspace directory for runID.
//
// Without this the registry kept the empty string it was registered with, so
// the scan://<runID>/findings resource resolved to no workdir and returned an
// empty result for every successful scan. Callers wire it from the AfterBoot
// hook, which is the first point the workspace path is known.
func (r *SessionRegistry) SetWorkDir(runID, workDir string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[runID]; ok {
		entry.WorkDir = workDir
	}
}

// MarkFailed sets the status of runID to SessionStatusFailed and records why.
// It is a no-op when runID is not found.
//
// A CANCELLED run stays cancelled. The pipeline error a cancelled scan returns
// is "context canceled" — reporting that as a failure would tell the operator
// their own cancellation broke something.
func (r *SessionRegistry) MarkFailed(runID string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[runID]
	if !ok {
		return
	}
	if entry.Status == SessionStatusCancelled {
		return
	}
	entry.Status = SessionStatusFailed
	entry.TerminalAt = time.Now()
	if err != nil {
		entry.Err = err.Error()
	}
}

// SetScope sets the scope for sessionID unconditionally.
// It is a no-op when sessionID is not found (graceful for async initialise paths).
//
// Tools and resources MUST NOT call this: use CaptureScopeIfUnset, which is
// atomic. SetScope remains for explicit, non-racing scope assignment (tests and
// any future path that scopes a session from InitializeParams).
func (r *SessionRegistry) SetScope(sessionID string, scope *SessionScope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[sessionID]; ok {
		entry.Scope = scope
	}
}

// CaptureScopeIfUnset sets the session's scope to target, but only if the
// session has no usable scope yet. It reports whether THIS call captured it.
//
// It is the single scope-capture path for every tool and resource, and it takes
// the registry mutex ONCE for the whole read-modify-write. The two call sites it
// replaced were both non-atomic and one was simply wrong:
//
//   - the scanning tools did Lookup → Register → SetScope with the lock released
//     between each step, so two concurrent first calls could capture two
//     DIFFERENT targets. Scope is this server's authorisation boundary, so that
//     is an authorisation bypass, not a race-condition nuisance (T-15-15-01).
//   - the report tool captured only when the session did NOT exist. A session
//     pre-registered by InitializedHandler with a nil scope EXISTS, so nothing
//     captured and CheckScope then rejected the first ordinary report call for
//     an empty scope (F8, acceptance gate 6).
//
// "Already scoped" is the normal case and returns (false, nil) — it is not an
// error. The error is reserved for a genuinely invalid request: an empty target
// would install a fail-closed scope that rejects everything, including itself,
// which is far more confusing than a rejection at the door.
//
// A session that is not registered yet is registered here, so a caller never
// needs the Register/SetScope dance that made the old sequence racy.
func (r *SessionRegistry) CaptureScopeIfUnset(sessionID, target string) (bool, error) {
	if strings.TrimSpace(target) == "" {
		return false, fmt.Errorf("mcp: cannot capture session scope from an empty target")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.entries[sessionID]
	if !ok {
		entry = &SessionEntry{RunID: sessionID, Status: SessionStatusRunning}
		r.entries[sessionID] = entry
	}
	if !entry.Scope.isEmpty() {
		return false, nil // already scoped — the normal case for every call after the first
	}
	entry.Scope = NewSessionScope([]string{target})
	return true, nil
}

// WorkDir returns the work directory for runID, or "" if not found.
func (r *SessionRegistry) WorkDir(runID string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if entry, ok := r.entries[runID]; ok {
		return entry.WorkDir
	}
	return ""
}

// MarkComplete sets the status of runID to SessionStatusComplete.
// It is a no-op when runID is not found, and leaves a cancelled run cancelled.
func (r *SessionRegistry) MarkComplete(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[runID]; ok {
		if entry.Status == SessionStatusCancelled {
			return
		}
		entry.Status = SessionStatusComplete
		entry.TerminalAt = time.Now()
	}
}
