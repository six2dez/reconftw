// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 1.
//
// MockCheckpoint — in-memory implementation of checkpoint.Interface
// (introduced in Plan 03 per W15). Plan 04+ Scheduler tests substitute
// this for *checkpoint.Store to avoid SQLite I/O.
package testutil

import (
	"context"
	stderrors "errors"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Record mirrors the *checkpoint.Store row shape (subset). Exposed by
// MockCheckpoint.AllRecords for test assertions.
type Record struct {
	TaskName    string
	Target      string
	InputHash   string
	Status      checkpoint.Status
	StartedAt   time.Time
	FinishedAt  *time.Time
	OutputPaths []string
	ErrorClass  string
}

// MockCheckpoint is the in-memory fake satisfying checkpoint.Interface.
// Records are keyed by (taskName \x00 target \x00 inputHash) for O(1)
// lookup. All operations are guarded by an internal sync.RWMutex.
type MockCheckpoint struct {
	mu      sync.RWMutex
	records map[string]*Record
}

// NewMockCheckpoint constructs an empty MockCheckpoint.
func NewMockCheckpoint() *MockCheckpoint {
	return &MockCheckpoint{records: map[string]*Record{}}
}

// Begin records that the task is about to execute. Idempotent — re-Begin
// on the same triple resets the row to StatusInProgress with a fresh
// started_at (mirrors *Store.Begin INSERT OR REPLACE semantics).
func (m *MockCheckpoint) Begin(_ context.Context, taskName, target, inputHash string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordKey(taskName, target, inputHash)
	m.records[key] = &Record{
		TaskName:  taskName,
		Target:    target,
		InputHash: inputHash,
		Status:    checkpoint.StatusInProgress,
		StartedAt: time.Now().UTC(),
	}
	return nil
}

// Complete records the terminal state. runErr nil → StatusDone; non-nil →
// StatusErrored with errorClass populated via the classifyError walk.
func (m *MockCheckpoint) Complete(_ context.Context, taskName, target, inputHash string,
	outputPaths []string, runErr error,
) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := recordKey(taskName, target, inputHash)
	rec, ok := m.records[key]
	if !ok {
		// No prior Begin — create a fresh record with the terminal status.
		// Mirrors the resilient *Store.Complete behaviour.
		rec = &Record{
			TaskName:  taskName,
			Target:    target,
			InputHash: inputHash,
			StartedAt: time.Now().UTC(),
		}
		m.records[key] = rec
	}
	now := time.Now().UTC()
	rec.FinishedAt = &now
	rec.OutputPaths = append([]string(nil), outputPaths...)
	if runErr != nil {
		rec.Status = checkpoint.StatusErrored
		rec.ErrorClass = classifyError(runErr)
	} else {
		rec.Status = checkpoint.StatusDone
	}
	return nil
}

// Done reports whether (taskName, target, inputHash) has a StatusDone row.
// Returns false (and nil error) for both "no row" and "non-done status".
func (m *MockCheckpoint) Done(_ context.Context, taskName, target, inputHash string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[recordKey(taskName, target, inputHash)]
	if !ok {
		return false, nil
	}
	return rec.Status == checkpoint.StatusDone, nil
}

// AllRecords returns every recorded checkpoint row, sorted by
// (taskName, target, inputHash). The returned slice contains shallow
// copies — mutating fields affects the next AllRecords call but the
// slice itself is independent.
func (m *MockCheckpoint) AllRecords() []Record {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Record, 0, len(m.records))
	for _, rec := range m.records {
		out = append(out, *rec)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TaskName != out[j].TaskName {
			return out[i].TaskName < out[j].TaskName
		}
		if out[i].Target != out[j].Target {
			return out[i].Target < out[j].Target
		}
		return out[i].InputHash < out[j].InputHash
	})
	return out
}

// Reset clears all recorded checkpoints. Use between tests to reset state.
func (m *MockCheckpoint) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.records = map[string]*Record{}
}

// recordKey joins the triple with a null-byte separator (same idea as
// checkpoint.InputHash) to avoid prefix-collision keys.
func recordKey(taskName, target, inputHash string) string {
	var sb strings.Builder
	sb.WriteString(taskName)
	sb.WriteByte(0)
	sb.WriteString(target)
	sb.WriteByte(0)
	sb.WriteString(inputHash)
	return sb.String()
}

// classifyError walks the 7-class typed-error hierarchy (mirrors
// internal/core/checkpoint/store.go's classifyError). Returns the short
// type name on match, or "Unknown" when no class matches.
func classifyError(err error) string {
	if err == nil {
		return ""
	}
	var te *coreerrors.ToolError
	if stderrors.As(err, &te) {
		return "ToolError"
	}
	var tt *coreerrors.ToolTimeout
	if stderrors.As(err, &tt) {
		return "ToolTimeout"
	}
	var oos *coreerrors.OutOfScope
	if stderrors.As(err, &oos) {
		return "OutOfScope"
	}
	var af *coreerrors.AxiomFailure
	if stderrors.As(err, &af) {
		return "AxiomFailure"
	}
	var ce *coreerrors.ConfigError
	if stderrors.As(err, &ce) {
		return "ConfigError"
	}
	var se *coreerrors.ScopeError
	if stderrors.As(err, &se) {
		return "ScopeError"
	}
	var cm *coreerrors.ChecksumMismatch
	if stderrors.As(err, &cm) {
		return "ChecksumMismatch"
	}
	return "Unknown"
}
