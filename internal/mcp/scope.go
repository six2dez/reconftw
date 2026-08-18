// Package mcp — session scope guard (D-06 hard-reject).
//
// SessionScope wraps output.DefaultScopeFilter to provide per-session
// scope sandboxing. It re-uses the existing anchored scope-check
// semantics (same wildcard and exact-host matching as the CLI scope
// filter) rather than re-implementing them.
//
// CheckScope is the public API consumed by tool handlers. It is fail-closed:
// an unknown session, an uninitialised scope, or an out-of-scope target all
// return an error wrapping ErrOutOfScope. No partial scan work starts before
// CheckScope returns nil.
//
// THREAT: T-08-02-03 (D-06 scope widening via tool args) — mitigated by the
// fail-closed semantics of every branch in CheckScope.
package mcp

import (
	"errors"
	"fmt"

	"github.com/six2dez/reconftw/internal/core/output"
)

// ErrOutOfScope is the sentinel error returned by CheckScope and
// SessionScope.Contains-derived helpers when a target is not within the
// session's allowed scope.
//
// Callers use errors.Is(err, mcp.ErrOutOfScope) to distinguish scope
// rejections from other failures.
var ErrOutOfScope = errors.New("out of scope")

// SessionScope is a per-session scope container backed by output.DefaultScopeFilter.
// It provides the same anchored hostname matching semantics as the CLI scope filter.
// A nil SessionScope (or one built with empty patterns) is fail-closed:
// Contains always returns false.
type SessionScope struct {
	filter *output.DefaultScopeFilter
}

// NewSessionScope returns a SessionScope backed by a DefaultScopeFilter with
// the given patterns.  If patterns is nil or empty the resulting scope
// is fail-closed (Contains always returns false).
func NewSessionScope(patterns []string) *SessionScope {
	return &SessionScope{
		filter: &output.DefaultScopeFilter{Patterns: patterns},
	}
}

// isEmpty reports whether this scope can never admit anything: a nil receiver,
// a nil filter, or no patterns at all. CaptureScopeIfUnset uses it to decide
// whether a session still needs its scope captured — a scope that admits
// nothing is not a captured scope, it is the absence of one, and treating the
// two as different is how the first report call ended up rejected (F8).
func (s *SessionScope) isEmpty() bool {
	return s == nil || s.filter == nil || len(s.filter.Patterns) == 0
}

// Contains reports whether target is within this session's scope.
// Returns false for a nil receiver or nil/empty filter (fail-closed).
func (s *SessionScope) Contains(target string) bool {
	if s == nil || s.filter == nil {
		return false
	}
	return s.filter.IsInScope(target)
}

// CheckScope looks up sessionID in registry and validates that target is
// within the session's scope. It is fail-closed: any of the following
// conditions return a non-nil error wrapping ErrOutOfScope:
//
//   - sessionID not found in registry
//   - session has no scope set (uninitialised)
//   - target is not within the session scope
//
// Returns nil only when target is in scope.
func CheckScope(sessionID, target string, registry *SessionRegistry) error {
	entry, ok := registry.Lookup(sessionID)
	if !ok {
		return fmt.Errorf("mcp: session %q not found: %w", sessionID, ErrOutOfScope)
	}
	if entry.Scope == nil {
		return fmt.Errorf("mcp: session %q scope not initialized: %w", sessionID, ErrOutOfScope)
	}
	if !entry.Scope.Contains(target) {
		return fmt.Errorf("mcp: target %q not in session scope for session %q: %w", target, sessionID, ErrOutOfScope)
	}
	return nil
}
