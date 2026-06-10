// Package testutil ships in-memory mocks satisfying the Phase 3 kernel
// interfaces (backend.Backend, checkpoint.Interface, output.Interface) so
// Phase 4-12 module tests can exercise Task logic WITHOUT spawning
// subprocesses, writing to disk, or opening a SQLite database.
//
// Source: ADR 0002 §9.3 lines 2270-2326 (Foundation Wave 0 Requirements —
// MockBackend / MockCheckpoint / MockOutputTree) + .planning/phases/
// 03-foundation-kernel/03-07-PLAN.md Task 1.
//
// FOUND-15 (REQUIREMENTS.md): "Test mocks shipped alongside real
// implementations: MockBackend (deterministic outputs), MockCheckpoint
// (in-memory), MockOutputTree (in-memory file system)."
//
// IMPORT BOUNDARY: testutil is allowed to be imported from `*_test.go`
// files in any package. Importing from production code (non-_test.go) is
// a Phase 3 boundary violation — convention enforces this; future work
// MAY add a lint rule to enforce it programmatically.
//
// NO SUBPROCESS: MockBackend never calls exec.Command — it reads fixture
// files directly. This keeps it compatible with the FOUND-10 raw-
// subprocess lint rule (the rule's allowlist covers LocalBackend only).
package testutil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// MockBackendConfig configures a MockBackend at construction.
//
// FixturesDir is the directory under which `<tool-name>/<scenario>.txt`
// (or `.jsonl`) fixtures live. Defaults to "fixtures" when empty.
//
// Scenario is the active scenario name (e.g. "example.com"). May be
// changed mid-test via MockBackend.SetScenario.
//
// Capacity is the value returned by Capacity(). Defaults to 4.
type MockBackendConfig struct {
	FixturesDir string
	Scenario    string
	Capacity    int
}

// MockBackend is the in-memory fake satisfying backend.Backend.
//
// Behavior:
//   - Exec reads <FixturesDir>/<tool.Name>/<Scenario>.txt (with .jsonl
//     fallback) and returns *backend.Result{Stdout: content}.
//   - SetExitCode(n) makes the NEXT Exec return *coreerrors.ToolError{ExitCode: n}.
//   - SetError(err) makes the NEXT Exec return that error.
//   - Stream opens the same fixture file, scans line-by-line, yields
//     each as backend.Event{Line, Source: tool.Name} on the returned
//     channel, closes channel on EOF or ctx cancellation.
//   - HealthCheck returns the configured healthCheckErr (nil by default).
//   - Capacity returns the configured int.
//
// MockBackend is safe for concurrent use via internal sync.RWMutex.
type MockBackend struct {
	mu             sync.RWMutex
	fixturesDir    string
	scenario       string
	capacity       int
	exitCode       int
	runError       error
	healthCheckErr error
	lastEnv        []string // env passed to the most recent ExecEnv/StreamEnv call
}

// NewMockBackend constructs a MockBackend with the given config.
func NewMockBackend(cfg MockBackendConfig) *MockBackend {
	fd := cfg.FixturesDir
	if fd == "" {
		fd = "fixtures"
	}
	cap := cfg.Capacity
	if cap <= 0 {
		cap = 4
	}
	return &MockBackend{
		fixturesDir: fd,
		scenario:    cfg.Scenario,
		capacity:    cap,
	}
}

// SetScenario changes the active scenario for subsequent Exec/Stream calls.
func (m *MockBackend) SetScenario(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scenario = s
}

// SetExitCode makes the NEXT Exec return *ToolError with this exit code.
// Cleared after the next Exec call. Use 0 to disable.
func (m *MockBackend) SetExitCode(code int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exitCode = code
}

// SetError makes the NEXT Exec return this error. Cleared after the next
// Exec call.
func (m *MockBackend) SetError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.runError = err
}

// SetHealthCheckError makes HealthCheck return this error on every call
// until cleared via SetHealthCheckError(nil).
func (m *MockBackend) SetHealthCheckError(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.healthCheckErr = err
}

// SetCapacity sets the Capacity() return value.
func (m *MockBackend) SetCapacity(c int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.capacity = c
}

// LastEnv returns a copy of the env slice passed to the most recent ExecEnv /
// StreamEnv call (nil if the last call used the nil-env Exec/Stream path). Used
// by tests to assert env-capable dispatch forwards the expected entries.
func (m *MockBackend) LastEnv() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.lastEnv...)
}

// Exec reads the fixture file and returns a *Result, or *ToolError /
// configured error per setter state. Honors ctx.Done() (returns ctx.Err()
// when cancelled before fixture read).
func (m *MockBackend) Exec(ctx context.Context, t *backend.Tool, args []string) (*backend.Result, error) {
	return m.ExecEnv(ctx, t, args, nil)
}

// ExecEnv records env (for LastEnv assertions) then behaves like Exec — fixture
// content is independent of env, so the returned Result is unchanged. This lets
// tests assert that the env-capable call path (e.g. RunEnv) forwards the expected
// "KEY=VALUE" entries without spawning a subprocess.
func (m *MockBackend) ExecEnv(ctx context.Context, t *backend.Tool, _ []string, env []string) (*backend.Result, error) {
	m.mu.Lock()
	m.lastEnv = append([]string(nil), env...)
	m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	m.mu.Lock()
	exitCode := m.exitCode
	runErr := m.runError
	m.exitCode = 0
	m.runError = nil
	fd := m.fixturesDir
	scenario := m.scenario
	m.mu.Unlock()

	if runErr != nil {
		return nil, runErr
	}

	data, err := readFixture(fd, t.Name, scenario)
	if err != nil {
		return nil, &coreerrors.ToolError{
			Tool:     t.Name,
			ExitCode: 127, // "command not found"-equivalent for missing fixture
			Inner:    err,
		}
	}

	if exitCode != 0 {
		return nil, &coreerrors.ToolError{
			Tool:     t.Name,
			ExitCode: exitCode,
			Stderr:   "mock: configured exit code",
			Inner:    fmt.Errorf("mock: exit %d", exitCode),
		}
	}

	return &backend.Result{
		Stdout:   data,
		ExitCode: 0,
		Duration: time.Millisecond,
	}, nil
}

// Stream reads the fixture file, splits into lines, yields each as a
// backend.Event on the returned channel. Closes channel on EOF or
// ctx cancellation.
func (m *MockBackend) Stream(ctx context.Context, t *backend.Tool, args []string) (<-chan backend.Event, error) {
	return m.StreamEnv(ctx, t, args, nil)
}

// StreamEnv records env (for LastEnv assertions) then behaves like Stream.
func (m *MockBackend) StreamEnv(ctx context.Context, t *backend.Tool, _ []string, env []string) (<-chan backend.Event, error) {
	m.mu.Lock()
	m.lastEnv = append([]string(nil), env...)
	m.mu.Unlock()

	m.mu.RLock()
	fd := m.fixturesDir
	scenario := m.scenario
	m.mu.RUnlock()

	data, err := readFixture(fd, t.Name, scenario)
	if err != nil {
		return nil, &coreerrors.ToolError{
			Tool:     t.Name,
			ExitCode: 127,
			Inner:    err,
		}
	}

	ch := make(chan backend.Event)
	go func() {
		defer close(ch)
		// Use bufio.Scanner with 1MiB initial / 10MiB max — matches LocalBackend
		// buffer sizing per RESEARCH.md §Pattern 3 (handles long httpx JSON lines).
		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)
		for scanner.Scan() {
			line := append([]byte(nil), scanner.Bytes()...) // copy out of scanner buf
			select {
			case <-ctx.Done():
				return
			case ch <- backend.Event{Line: line, Source: t.Name}:
			}
		}
	}()
	return ch, nil
}

// HealthCheck returns the configured healthCheckErr (nil by default).
func (m *MockBackend) HealthCheck(_ context.Context) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.healthCheckErr
}

// Capacity returns the configured concurrent-invocation capacity.
func (m *MockBackend) Capacity() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.capacity
}

// readFixture resolves <fixturesDir>/<tool>/<scenario>.txt or .jsonl and
// returns the raw file contents. Tries .txt first, then .jsonl.
func readFixture(fixturesDir, tool, scenario string) ([]byte, error) {
	candidates := []string{
		filepath.Join(fixturesDir, tool, scenario+".txt"),
		filepath.Join(fixturesDir, tool, scenario+".jsonl"),
	}
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err == nil {
			return data, nil
		}
	}
	return nil, fmt.Errorf("fixture not found: tried %v", candidates)
}
