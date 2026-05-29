// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 1.
//
// MockOutputTree — in-memory implementation of output.Interface
// (introduced in Plan 03 per W15). Plan 04+ Task tests substitute this
// for *output.OutputTree to avoid filesystem I/O and to assert the
// post-Append state via Lines("artefact").
package testutil

import (
	"sync"
)

// MockOutputTree is the in-memory fake satisfying output.Interface.
// Appended batches are deep-copied (caller can mutate the source slice
// without leaking into stored state) and held under sync.RWMutex.
type MockOutputTree struct {
	mu      sync.RWMutex
	appends map[string][][]byte
}

// NewMockOutputTree constructs an empty MockOutputTree.
func NewMockOutputTree() *MockOutputTree {
	return &MockOutputTree{appends: map[string][][]byte{}}
}

// Append stores a deep copy of each line under the artefact name. Empty
// batches are a no-op (mirrors *OutputTree.Append).
//
// REPLACE semantics (mirrors production OutputTree per ADR §3.2 "merged
// set written at end of Task"): callers MUST dedup + merge their findings
// before calling Append; the mock replaces the artefact's contents on
// each call.
func (m *MockOutputTree) Append(artefact string, lines [][]byte) error {
	if len(lines) == 0 {
		return nil
	}
	copies := make([][]byte, 0, len(lines))
	for _, line := range lines {
		copies = append(copies, append([]byte(nil), line...))
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appends[artefact] = copies
	return nil
}

// InScope admits all hosts (the mock does not model scope filtering, so
// MergeStage's pre-Append scope filter is a pass-through under test).
func (m *MockOutputTree) InScope(_ string) bool { return true }

// Lines returns the appended lines for an artefact as []string (for easy
// assertion). Returns an empty slice if the artefact has not been written.
func (m *MockOutputTree) Lines(artefact string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	raw, ok := m.appends[artefact]
	if !ok {
		return nil
	}
	out := make([]string, len(raw))
	for i, b := range raw {
		out[i] = string(b)
	}
	return out
}

// Reset clears all stored artefacts. Use between tests to reset state.
func (m *MockOutputTree) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.appends = map[string][][]byte{}
}
