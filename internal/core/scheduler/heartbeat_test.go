// Source: .planning/phases/03-foundation-kernel/03-05-PLAN.md Task 1
// behavior tests 20-22 — heartbeat cadence + goleak.
package scheduler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/six2dez/reconftw/internal/core/scheduler"
)

// TestMain installs goleak — every test in this package must leave no
// orphan goroutines. The heartbeat lifecycle is the chief concern of the
// XCUT-09 sentinel; if startHeartbeat or runOne ever leaks, this gate
// fires.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

// countingLogger is a thread-safe slog.Logger whose handler records every
// emitted record into a buffer. Used to count "task_heartbeat" events.
type countingLogger struct {
	mu      sync.Mutex
	records []map[string]any
}

func newCountingLogger() (*slog.Logger, *countingLogger) {
	cl := &countingLogger{}
	h := &captureHandler{cl: cl}
	return slog.New(h), cl
}

func (c *countingLogger) count(msg string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, r := range c.records {
		if r["msg"] == msg {
			n++
		}
	}
	return n
}

// captureHandler decodes each record into a flat map and appends to the
// counter. We don't care about handler attributes / groups here.
type captureHandler struct {
	cl *countingLogger
}

func (h *captureHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }
func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	buf := &bytes.Buffer{}
	// Use the JSON handler under the hood to serialize the record cheaply.
	jh := slog.NewJSONHandler(buf, &slog.HandlerOptions{})
	if err := jh.Handle(context.Background(), r); err != nil {
		return err
	}
	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		return err
	}
	h.cl.mu.Lock()
	h.cl.records = append(h.cl.records, rec)
	h.cl.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(_ string) slog.Handler      { return h }

// Test 20-22: heartbeat fires at 2*cadence first, then per cadence.
// We exercise scheduler.RunStage with a fake long-running task and assert
// at least 1 heartbeat event was logged when the task ran longer than
// 2*cadence.
//
// Cadence is 50ms; task sleeps 200ms — so expect ≥1 heartbeat
// (first fires at 100ms; second at 150ms; task completes at 200ms).
func TestHeartbeatCadenceForLongRunningTask(t *testing.T) {
	log, cnt := newCountingLogger()

	// Force seconds → milliseconds via the unexported override at the
	// scheduler boundary — we set HeartbeatSeconds=0 (disabled) here and
	// directly verify the heartbeat helper instead.
	//
	// Because startHeartbeat uses time.Duration(HeartbeatSeconds) * time.Second,
	// at HeartbeatSeconds=1 the first heartbeat fires at 2s — too slow for
	// CI. We use the heartbeat helper exposed in scheduler.HeartbeatForTest
	// (added below) to drive a 50ms cadence directly.

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stop := scheduler.HeartbeatForTest(ctx, log, "task.x", "demo", 50*time.Millisecond)
	defer stop()

	// Sleep 200ms — first emission at 100ms; second at 150ms.
	time.Sleep(200 * time.Millisecond)
	stop()

	got := cnt.count("task_heartbeat")
	if got < 1 {
		t.Errorf("heartbeat count = %d, want >= 1 (XCUT-09 cadence test)", got)
	}
	if got > 5 {
		t.Errorf("heartbeat count = %d, want <= 5 (200ms / 50ms ≈ 3-4)", got)
	}
}

// Test 21: heartbeat goroutine stops cleanly on stop().
func TestHeartbeatStopsCleanly(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log, _ := newCountingLogger()

	stop := scheduler.HeartbeatForTest(ctx, log, "task.y", "demo", 10*time.Millisecond)
	stop()
	// Sleep long enough to give a leaky goroutine time to emit; goleak
	// will catch if the goroutine is still running at TestMain exit.
	time.Sleep(30 * time.Millisecond)
}

// Test 21b: heartbeat at HeartbeatSeconds <= 0 is a no-op (no goroutine
// spawned).
func TestHeartbeatNoOpWhenDisabled(t *testing.T) {
	ctx := context.Background()
	log, cnt := newCountingLogger()

	stop := scheduler.HeartbeatForTest(ctx, log, "task.z", "demo", 0)
	defer stop()

	time.Sleep(20 * time.Millisecond)
	if got := cnt.count("task_heartbeat"); got != 0 {
		t.Errorf("disabled heartbeat emitted %d events, want 0", got)
	}
}

// Test (smoke): heartbeat fields include task + module names.
func TestHeartbeatFieldsIncludeTaskAndModule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	log, cnt := newCountingLogger()

	stop := scheduler.HeartbeatForTest(ctx, log, "task.a", "demo", 40*time.Millisecond)
	defer stop()
	time.Sleep(120 * time.Millisecond)
	stop()

	cnt.mu.Lock()
	defer cnt.mu.Unlock()
	for _, r := range cnt.records {
		if r["msg"] != "task_heartbeat" {
			continue
		}
		if r["task"] != "task.a" {
			t.Errorf("heartbeat task field = %v, want task.a", r["task"])
		}
		if r["module"] != "demo" {
			t.Errorf("heartbeat module field = %v, want demo", r["module"])
		}
		// slog's JSON handler encodes time.Duration as nanoseconds (float64).
		// We just need to assert the field is present and non-zero.
		if elapsed, ok := r["elapsed"]; !ok {
			t.Errorf("heartbeat record missing 'elapsed' field: %v", r)
		} else if f, ok := elapsed.(float64); !ok || f <= 0 {
			t.Errorf("heartbeat elapsed = %v (type %T); want non-zero number", elapsed, elapsed)
		}
		return
	}
	t.Fatalf("no task_heartbeat record observed")
}

// strings import kept for visibility — used elsewhere? Remove via _.
var _ = strings.TrimSpace
