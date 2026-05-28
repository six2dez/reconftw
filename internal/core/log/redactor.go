// Source: ADR 0002 §10.2 lines 2429-2464 (lifted verbatim except for
// doc comments). Implements Layer 2 of the two-layer redaction defense.
//
// The Redactor is thread-safe: all methods are safe for concurrent use
// from any number of goroutines. Internally protected by sync.RWMutex
// (write-lock on Register, read-lock on Redact) so the common Redact
// hot path (called once per slog Record) does not block other Redacts.
//
// The "len(value) <= 4" skip rule (ADR §10.2 line 2442) avoids redacting
// common short strings like "true", "http", "tcp", "json". Short values
// would over-redact ordinary log lines without providing meaningful
// secret protection.

package log

import (
	"strings"
	"sync"
)

// Redactor holds a set of substrings that must never appear in log output.
// Thread-safe: all methods safe for concurrent use from multiple goroutines.
type Redactor struct {
	mu      sync.RWMutex
	secrets []string
}

// Register adds a secret value to the redaction list.
// Called once per secret field immediately after config load (see ADR §10.3
// build order: logger → config load → Register → AppContext.Boot).
// Values with length ≤ 4 are ignored (too short to be a meaningful secret;
// avoids redacting common short strings like "true" or "http").
// MUST be called BEFORE the first log line that could reference this value.
// Dedup: registering the same value twice is a no-op (single entry retained).
func (r *Redactor) Register(value string) {
	if len(value) <= 4 {
		return // too short to be meaningful
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.secrets {
		if s == value {
			return // dedup: already registered
		}
	}
	r.secrets = append(r.secrets, value)
}

// Redact replaces all registered secret substrings in s with "***".
// Called on every string value passing through the handler chain.
// Read-lock only — multiple concurrent Redact calls share access.
func (r *Redactor) Redact(s string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, secret := range r.secrets {
		s = strings.ReplaceAll(s, secret, "***")
	}
	return s
}
