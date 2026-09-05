// SPDX-License-Identifier: MIT

package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/config"
)

// gateLocal records which tool the local leg was asked to run.
type gateLocal struct {
	mu    sync.Mutex
	tools []string
}

func (g *gateLocal) Exec(_ context.Context, t *Tool, _ []string) (*Result, error) {
	g.mu.Lock()
	g.tools = append(g.tools, t.Name)
	g.mu.Unlock()
	return &Result{Stdout: []byte("ok\n")}, nil
}

func (g *gateLocal) ExecEnv(ctx context.Context, t *Tool, a []string, _ []string) (*Result, error) {
	return g.Exec(ctx, t, a)
}

func (g *gateLocal) Stream(_ context.Context, _ *Tool, _ []string) (<-chan Event, error) {
	ch := make(chan Event)
	close(ch)
	return ch, nil
}

func (g *gateLocal) StreamEnv(ctx context.Context, t *Tool, a []string, _ []string) (<-chan Event, error) {
	return g.Stream(ctx, t, a)
}

func (g *gateLocal) ExecOpts(ctx context.Context, t *Tool, a []string, _ ExecOptions) (*Result, error) {
	return g.Exec(ctx, t, a)
}

func (g *gateLocal) StreamOpts(ctx context.Context, t *Tool, a []string, _ ExecOptions) (<-chan Event, error) {
	return g.Stream(ctx, t, a)
}
func (g *gateLocal) HealthCheck(_ context.Context) error { return nil }
func (g *gateLocal) Capacity() int                       { return 1 }

// A dispatch that was QUEUED behind the gate when the fleet was abandoned must
// go local, not to a fleet already known to be unusable. On 2026-09-04 the
// fleet was abandoned at 22:39:25 and two queued dispatches still went out at
// 22:40 and 22:41 because the only check was at Exec entry.
func TestQueuedDispatchGoesLocalOnceFleetIsAbandoned(t *testing.T) {
	local := &gateLocal{}
	cfg := &config.Config{}
	cfg.Axiom.FleetName = "test-fleet"
	a := NewAxiomBackendWithLocal(cfg, NewToolRegistry(), nil, local)

	in := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(in, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a.dispatchSem <- struct{}{} // hold the gate: the next Exec queues behind it
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = a.Exec(context.Background(), &Tool{Name: "tlsx", InputFlag: "-l"}, []string{"-l", in})
	}()
	time.Sleep(100 * time.Millisecond) // let it block on the gate
	a.markDisabled("test: fleet abandoned while a dispatch was queued")
	<-a.dispatchSem // release the gate
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("queued Exec never returned")
	}

	local.mu.Lock()
	defer local.mu.Unlock()
	for _, name := range local.tools {
		if name == "axiom-scan" {
			t.Fatal("a dispatch queued behind the gate was sent to an abandoned fleet")
		}
	}
	if len(local.tools) != 1 || local.tools[0] != "tlsx" {
		t.Errorf("expected exactly one local run of tlsx, got %v", local.tools)
	}
}

// A dispatch that cannot get the gate within axiomQueueWait must run LOCALLY
// with its budget intact — not wait until its own deadline and then fail the
// task with a plain context error nothing falls back from. That was the
// 2026-09-05 run: tlsx queued for its entire 5m budget, the stage failed on it,
// and the scan exited 1.
func TestQueuedDispatchRunsLocallyWhenTheGateStaysBusy(t *testing.T) {
	local := &gateLocal{}
	cfg := &config.Config{}
	cfg.Axiom.FleetName = "test-fleet"
	a := NewAxiomBackendWithLocal(cfg, NewToolRegistry(), nil, local)
	in := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(in, []byte("a\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	a.dispatchSem <- struct{}{} // another dispatch holds the fleet for the whole test
	defer func() { <-a.dispatchSem }()
	orig := axiomQueueWait
	axiomQueueWait = 200 * time.Millisecond // measure the bound, not thirty real seconds
	defer func() { axiomQueueWait = orig }()

	// The task has a deadline comfortably LONGER than the queue bound.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	start := time.Now()
	res, err := a.Exec(ctx, &Tool{Name: "tlsx", InputFlag: "-l"}, []string{"-l", in, "-san"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Exec returned %v after %v — a queued tool failed instead of running locally", err, elapsed)
	}
	if string(res.Stdout) != "ok\n" {
		t.Errorf("stdout = %q, want the local leg's result", res.Stdout)
	}
	if elapsed < axiomQueueWait || elapsed > axiomQueueWait+2*time.Second {
		t.Errorf("fell back after %v, want ≈%v (bounded queue wait)", elapsed, axiomQueueWait)
	}
	_, ledger := a.DistributionSummary()
	if reason := ledger["tlsx"]; !strings.Contains(reason, "busy") {
		t.Errorf("ledger reason = %q, want it to say the fleet was busy", reason)
	}
}
