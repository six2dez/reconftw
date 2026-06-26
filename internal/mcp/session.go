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

import "sync"

// SessionStatus is the lifecycle state of a session entry.
type SessionStatus string

const (
	// SessionStatusRunning indicates the scan is in progress.
	SessionStatusRunning SessionStatus = "running"
	// SessionStatusComplete indicates the scan finished successfully.
	SessionStatusComplete SessionStatus = "complete"
	// SessionStatusFailed indicates the scan terminated with an error.
	SessionStatusFailed SessionStatus = "failed"
)

// SessionEntry holds the metadata for a registered scan session.
type SessionEntry struct {
	RunID   string
	WorkDir string
	Scope   *SessionScope
	Status  SessionStatus
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

// Lookup returns the entry for runID and a flag indicating whether it exists.
// Returns (nil, false) when runID is not found; never panics.
func (r *SessionRegistry) Lookup(runID string) (*SessionEntry, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.entries[runID]
	return entry, ok
}

// SetScope sets the scope for sessionID.
// It is a no-op when sessionID is not found (graceful for async initialise paths).
func (r *SessionRegistry) SetScope(sessionID string, scope *SessionScope) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[sessionID]; ok {
		entry.Scope = scope
	}
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
// It is a no-op when runID is not found.
func (r *SessionRegistry) MarkComplete(runID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if entry, ok := r.entries[runID]; ok {
		entry.Status = SessionStatusComplete
	}
}
