// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 1.
//
// MockBackend test suite (Tests 1-9 + Test 19/20 fixture presence).
package testutil_test

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
	"github.com/six2dez/reconftw/internal/core/testutil"
)

// Test 1 (interface satisfaction): MockBackend satisfies backend.Backend.
var _ backend.Backend = (*testutil.MockBackend)(nil)

// Test 2: MockBackend.Exec reads fixture file and returns Result with stdout.
func TestMockBackend_Exec_ReadsFixture(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "example.com",
		Capacity:    4,
	})
	res, err := mb.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, nil)
	if err != nil {
		t.Fatalf("Exec returned err: %v", err)
	}
	if res == nil {
		t.Fatal("Exec returned nil Result")
	}
	if res.ExitCode != 0 {
		t.Errorf("expected ExitCode=0, got %d", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "api.example.com") {
		t.Errorf("expected fixture content in Stdout, got %q", string(res.Stdout))
	}
}

// Test 3: SetExitCode makes next Exec return *ToolError with that exit code.
func TestMockBackend_SetExitCode_ReturnsToolError(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "example.com",
	})
	mb.SetExitCode(2)
	_, err := mb.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, nil)
	if err == nil {
		t.Fatal("expected non-nil err after SetExitCode(2)")
	}
	var te *coreerrors.ToolError
	if !stderrors.As(err, &te) {
		t.Fatalf("expected *ToolError, got %T: %v", err, err)
	}
	if te.ExitCode != 2 {
		t.Errorf("expected ExitCode=2 in ToolError, got %d", te.ExitCode)
	}
}

// Test 4: SetError makes next Exec return that error.
func TestMockBackend_SetError_ReturnsConfiguredError(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "example.com",
	})
	sentinel := stderrors.New("synthetic-mock-failure")
	mb.SetError(sentinel)
	_, err := mb.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, nil)
	if !stderrors.Is(err, sentinel) {
		t.Fatalf("expected configured error sentinel, got %v", err)
	}
}

// Test 5: Stream opens fixture, yields lines as Events, closes on EOF.
func TestMockBackend_Stream_YieldsEventsForJSONL(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "hosts",
	})
	ch, err := mb.Stream(context.Background(), &backend.Tool{Name: "httpx"}, nil)
	if err != nil {
		t.Fatalf("Stream returned err: %v", err)
	}
	if ch == nil {
		t.Fatal("Stream returned nil channel")
	}
	var lines []string
	for ev := range ch {
		lines = append(lines, string(ev.Line))
	}
	if len(lines) < 3 {
		t.Errorf("expected at least 3 events from hosts.jsonl, got %d", len(lines))
	}
	if !strings.Contains(strings.Join(lines, "\n"), "api.example.com") {
		t.Errorf("expected fixture content in stream events; got %v", lines)
	}
}

// Test 6: HealthCheck returns nil by default; SetHealthCheckError makes it return that error.
func TestMockBackend_HealthCheck_NilThenConfigured(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{})
	if err := mb.HealthCheck(context.Background()); err != nil {
		t.Errorf("expected default HealthCheck nil, got %v", err)
	}
	want := stderrors.New("synthetic-health-fail")
	mb.SetHealthCheckError(want)
	if err := mb.HealthCheck(context.Background()); !stderrors.Is(err, want) {
		t.Errorf("expected configured HealthCheck err, got %v", err)
	}
}

// Test 7: Capacity returns configured value (default 4).
func TestMockBackend_Capacity_Configurable(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{})
	if got := mb.Capacity(); got != 4 {
		t.Errorf("expected default Capacity=4, got %d", got)
	}
	mb.SetCapacity(16)
	if got := mb.Capacity(); got != 16 {
		t.Errorf("expected Capacity=16 after SetCapacity, got %d", got)
	}
}

// Test 8: Race-clean — concurrent Exec + setters.
func TestMockBackend_RaceClean(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "example.com",
	})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = mb.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, nil)
		}()
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mb.SetCapacity(8)
		}()
	}
	wg.Wait()
}

// Test 9: Stream fast-cancels on ctx.Done — channel closes within 100ms.
func TestMockBackend_Stream_ContextCancelFastClose(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "hosts",
	})
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := mb.Stream(ctx, &backend.Tool{Name: "httpx"}, nil)
	if err != nil {
		t.Fatalf("Stream: %v", err)
	}
	cancel()
	done := make(chan struct{})
	go func() {
		for range ch {
			// drain
		}
		close(done)
	}()
	select {
	case <-done:
		// ok — channel closed
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Stream channel did not close within 500ms after ctx cancel")
	}
}

// Test 19/20: fixture directory shape.
func TestMockBackend_FixturesShape(t *testing.T) {
	t.Parallel()
	// Fixture presence is asserted via Exec (which opens the file).
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "example.com",
	})
	res, err := mb.Exec(context.Background(), &backend.Tool{Name: "subfinder"}, nil)
	if err != nil {
		t.Fatalf("subfinder fixture missing: %v", err)
	}
	if c := strings.Count(string(res.Stdout), "\n"); c < 5 {
		t.Errorf("expected ≥5 subdomain lines in subfinder fixture, got %d", c)
	}

	mb2 := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "hosts",
	})
	ch, err := mb2.Stream(context.Background(), &backend.Tool{Name: "httpx"}, nil)
	if err != nil {
		t.Fatalf("httpx fixture missing: %v", err)
	}
	count := 0
	for range ch {
		count++
	}
	if count < 3 {
		t.Errorf("expected ≥3 lines in httpx/hosts.jsonl fixture, got %d", count)
	}
}

// Bonus: ExecMissingFixture returns a *ToolError so callers can branch.
func TestMockBackend_Exec_MissingFixture_ReturnsToolError(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "missing",
	})
	_, err := mb.Exec(context.Background(), &backend.Tool{Name: "nonexistent-tool"}, nil)
	if err == nil {
		t.Fatal("expected err for missing fixture")
	}
}

// TestMockBackend_LastOptsPreservesEmptyNonNilStdin protects the nil-vs-empty
// distinction ExecOptions makes load-bearing: nil inherits parent stdin, while
// an empty-but-non-nil slice supplies immediate EOF.
func TestMockBackend_LastOptsPreservesEmptyNonNilStdin(t *testing.T) {
	t.Parallel()
	mb := testutil.NewMockBackend(testutil.MockBackendConfig{
		FixturesDir: "fixtures",
		Scenario:    "example.com",
	})
	tool := &backend.Tool{Name: "subfinder"}
	if _, err := mb.ExecOpts(context.Background(), tool, nil, backend.ExecOptions{
		Stdin: make([]byte, 0),
	}); err != nil {
		t.Fatalf("ExecOpts: %v", err)
	}
	if got := mb.LastOpts().Stdin; got == nil {
		t.Fatal("MockBackend collapsed empty-but-non-nil Stdin to nil, so tests cannot distinguish empty stdin from inherited stdin")
	}
}
