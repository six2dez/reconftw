// SPDX-License-Identifier: MIT
//
// Tests 1, 3, 4, 6, 7, 9, 16-18 from .planning/phases/03-foundation-kernel/03-04-PLAN.md Task 1.
// Ring 1 + Ring 2 (unit + integration without external tool dependencies).
// Uses POSIX-stable binaries: /bin/echo, /bin/false, /bin/sleep.
//
// Per Blocker 7: this test file MUST NOT reference backend.Default — fresh
// *ToolRegistry{} instances only.
package backend_test

import (
	"context"
	stderrors "errors"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Test 1: LocalBackend satisfies Backend at compile time.
var _ backend.Backend = (*backend.LocalBackend)(nil)

// Test 3: LocalBackend.HealthCheck returns nil (always healthy in Phase 3).
func TestLocalBackend_HealthCheck_ReturnsNil(t *testing.T) {
	b := backend.NewLocalBackend(0)
	if err := b.HealthCheck(context.Background()); err != nil {
		t.Fatalf("LocalBackend.HealthCheck() = %v, want nil", err)
	}
}

// Test 4: LocalBackend.Capacity() returns runtime.NumCPU() * 2.
func TestLocalBackend_Capacity_ReturnsCPUCountTimesTwo(t *testing.T) {
	b := backend.NewLocalBackend(0)
	want := runtime.NumCPU() * 2
	if got := b.Capacity(); got != want {
		t.Fatalf("LocalBackend.Capacity() = %d, want %d", got, want)
	}
}

// Test 6: Exec on /bin/echo returns Stdout containing "hello\n" and ExitCode == 0.
func TestLocalBackend_Exec_EchoReturnsStdoutAndZeroExit(t *testing.T) {
	b := backend.NewLocalBackend(0)
	res, err := b.Exec(context.Background(), &backend.Tool{Name: "echo", Path: "/bin/echo"}, []string{"hello"})
	if err != nil {
		t.Fatalf("Exec(/bin/echo hello) returned err=%v, want nil", err)
	}
	if res.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", res.ExitCode)
	}
	if string(res.Stdout) != "hello\n" {
		t.Errorf("Stdout = %q, want %q", string(res.Stdout), "hello\n")
	}
	if res.Duration <= 0 {
		t.Errorf("Duration = %v, want > 0", res.Duration)
	}
}

// Test 7: Exec on /bin/false returns *ToolError; W9 — Stderr truncated to last ≤ 1KB.
func TestLocalBackend_Exec_NonZeroExit_ReturnsToolErrorWithTruncatedStderr(t *testing.T) {
	b := backend.NewLocalBackend(0)
	res, err := b.Exec(context.Background(), &backend.Tool{Name: "false", Path: "/bin/false"}, nil)
	if res != nil {
		t.Logf("res=%+v (may be returned for non-zero exit with captured streams; OK)", res)
	}
	var te *coreerrors.ToolError
	if !stderrors.As(err, &te) {
		t.Fatalf("Exec(/bin/false) error is not *ToolError: %T %v", err, err)
	}
	if te.Tool != "false" {
		t.Errorf("ToolError.Tool = %q, want %q", te.Tool, "false")
	}
	if te.ExitCode == 0 {
		t.Errorf("ToolError.ExitCode = 0, want non-zero")
	}
	// W9 — explicit stderr-truncation assertion (ADR §6 line 1806 — 1KB cap).
	if len(te.Stderr) > 1024 {
		t.Errorf("ToolError.Stderr length = %d bytes, want <= 1024 (W9 truncation)", len(te.Stderr))
	}
}

// Test 7b: Exec on a stream that produces > 1KB of stderr is truncated to 1KB.
// Uses `sh -c` to emit a bounded large stream to stderr and exit non-zero.
// Asserts the <= 1KB invariant explicitly per W9.
func TestLocalBackend_Exec_LargeStderr_TruncatedTo1KB(t *testing.T) {
	b := backend.NewLocalBackend(0)
	// Print 5000 'X' bytes to stderr via awk, then exit 7. Bounded — no streaming pipe.
	// printf would be portable but its repeat semantics aren't POSIX; awk is on every Linux + macOS.
	res, err := b.Exec(
		context.Background(),
		&backend.Tool{Name: "sh", Path: "/bin/sh"},
		[]string{"-c", "awk 'BEGIN { for (i=0; i<5000; i++) printf \"X\" > \"/dev/stderr\" }'; exit 7"},
	)
	_ = res
	var te *coreerrors.ToolError
	if !stderrors.As(err, &te) {
		t.Fatalf("Exec error is not *ToolError: %T %v", err, err)
	}
	// W9 — explicit stderr-truncation assertion.
	if len(te.Stderr) > 1024 {
		t.Errorf("ToolError.Stderr length = %d bytes, want <= 1024 (W9 truncation, ADR §6 line 1806)", len(te.Stderr))
	}
	// Sanity: there should actually BE stderr (otherwise the test is vacuous).
	if len(te.Stderr) == 0 {
		t.Errorf("ToolError.Stderr is empty — expected truncated large-stderr content")
	}
}

// Test 9: Exec on a non-existent binary returns *ToolError.
func TestLocalBackend_Exec_MissingBinary_ReturnsToolError(t *testing.T) {
	b := backend.NewLocalBackend(0)
	_, err := b.Exec(context.Background(), &backend.Tool{
		Name: "no-such-tool-foo-bar-baz",
		Path: "/no/such/path/to/foo-bar-baz",
	}, nil)
	if err == nil {
		t.Fatalf("Exec on missing binary returned nil err, want *ToolError")
	}
	var te *coreerrors.ToolError
	if !stderrors.As(err, &te) {
		t.Fatalf("Exec on missing binary error is not *ToolError: %T %v", err, err)
	}
	if te.Tool != "no-such-tool-foo-bar-baz" {
		t.Errorf("ToolError.Tool = %q, want missing-binary name", te.Tool)
	}
}

// Test 16: Tool struct exposes the documented fields (incl. Critical per Blocker 5).
func TestTool_StructFields_MatchADRWithCriticalExtension(t *testing.T) {
	tt := reflect.TypeOf(backend.Tool{})
	want := []string{"Name", "Path", "Version", "DefaultArgs", "Timeout", "Critical", "InputFlag"}
	got := make([]string, tt.NumField())
	for i := 0; i < tt.NumField(); i++ {
		got[i] = tt.Field(i).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Tool struct fields = %v, want %v (ADR §5.2 + Critical + InputFlag extensions; InputFlag added Phase 4 plan 04-00 for Axiom input-file split)", got, want)
	}
	if tt.NumField() != len(want) {
		t.Errorf("Tool NumField = %d, want %d", tt.NumField(), len(want))
	}
	// Spot-check the type of Critical.
	f, ok := tt.FieldByName("Critical")
	if !ok || f.Type.Kind().String() != "bool" {
		t.Errorf("Tool.Critical missing or not bool kind: ok=%v kind=%v", ok, f.Type.Kind())
	}
}

// Test 17: Event struct exposes Line []byte, Source string, IsErr bool (ADR §5.2 lines 1636-1641).
func TestEvent_StructFields(t *testing.T) {
	et := reflect.TypeOf(backend.Event{})
	if et.NumField() != 3 {
		t.Errorf("Event NumField = %d, want 3", et.NumField())
	}
	check := func(name, kind string) {
		f, ok := et.FieldByName(name)
		if !ok {
			t.Errorf("Event missing field %q", name)
			return
		}
		if f.Type.Kind().String() != kind && f.Type.String() != kind {
			t.Errorf("Event.%s kind=%v string=%v, want %q", name, f.Type.Kind(), f.Type.String(), kind)
		}
	}
	check("Line", "[]uint8")
	check("Source", "string")
	check("IsErr", "bool")
}

// Test 18: Result struct exposes Stdout, Stderr ([]byte), ExitCode int, Duration time.Duration.
func TestResult_StructFields(t *testing.T) {
	rt := reflect.TypeOf(backend.Result{})
	if rt.NumField() != 4 {
		t.Errorf("Result NumField = %d, want 4", rt.NumField())
	}
	checkType := func(name, want string) {
		f, ok := rt.FieldByName(name)
		if !ok {
			t.Errorf("Result missing field %q", name)
			return
		}
		got := f.Type.String()
		if got != want {
			t.Errorf("Result.%s type = %q, want %q", name, got, want)
		}
	}
	checkType("Stdout", "[]uint8")
	checkType("Stderr", "[]uint8")
	checkType("ExitCode", "int")
	checkType("Duration", "time.Duration")
}

// Auxiliary: Stream yields events for a short, bounded command. Ring-1 coverage
// for the Stream code path so the smoke-only kill-tree tests don't gate basic
// stream-event verification. Uses `printf` to emit two lines and exit cleanly.
func TestLocalBackend_Stream_BoundedOutput_YieldsEventsAndCloses(t *testing.T) {
	b := backend.NewLocalBackend(0)
	ch, err := b.Stream(
		context.Background(),
		&backend.Tool{Name: "sh", Path: "/bin/sh"},
		[]string{"-c", "printf 'alpha\\nbeta\\n'; echo 'errline' 1>&2; exit 0"},
	)
	if err != nil {
		t.Fatalf("Stream returned err=%v, want nil", err)
	}
	var lines []string
	var sawErr bool
	timeout := time.After(5 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				goto done
			}
			lines = append(lines, string(ev.Line))
			if ev.IsErr {
				sawErr = true
			}
		case <-timeout:
			t.Fatalf("Stream channel did not close within 5s; lines so far: %v", lines)
		}
	}
done:
	if len(lines) < 3 {
		t.Errorf("Stream emitted %d lines, want >= 3 (alpha+beta+errline): %v", len(lines), lines)
	}
	if !sawErr {
		t.Errorf("Stream did not yield any IsErr=true events from stderr")
	}
}

// Auxiliary: Exec with deadline-cancelled ctx returns *ToolTimeout (not part of
// numbered list but covers the timeout path inline so the Ring-1 tests cover
// the deadline branch).
func TestLocalBackend_Exec_DeadlineExceeded_ReturnsToolTimeout(t *testing.T) {
	b := backend.NewLocalBackend(1 * time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := b.Exec(ctx, &backend.Tool{Name: "sleep", Path: "/bin/sleep"}, []string{"5"})
	if err == nil {
		t.Fatalf("Exec(/bin/sleep 5) under 100ms deadline returned nil err")
	}
	var tt *coreerrors.ToolTimeout
	if !stderrors.As(err, &tt) {
		t.Fatalf("Exec deadline-exceeded error is not *ToolTimeout: %T %v", err, err)
	}
	if tt.Tool != "sleep" {
		t.Errorf("ToolTimeout.Tool = %q, want %q", tt.Tool, "sleep")
	}
}

// Phase 07-09 GAP-02: env seam — a requested KEY=VALUE reaches the child process.
// Uses `sh -c 'echo $GH_TOKEN'` so the child must read the injected env var to
// produce the expected stdout. Proves the env entry crosses the process boundary.
func TestLocalBackend_ExecEnv_ChildSeesEnv(t *testing.T) {
	b := backend.NewLocalBackend(0)
	const want = "FAKE_GH_TOKEN_env_seam_AAAA"
	res, err := b.ExecEnv(
		context.Background(),
		&backend.Tool{Name: "sh", Path: "/bin/sh"},
		[]string{"-c", "echo $GH_TOKEN"},
		[]string{"GH_TOKEN=" + want},
	)
	if err != nil {
		t.Fatalf("ExecEnv returned err=%v, want nil", err)
	}
	got := strings.TrimSpace(string(res.Stdout))
	if got != want {
		t.Fatalf("child stdout = %q, want %q (GH_TOKEN did not reach the child env)", got, want)
	}
}

// Phase 07-09 GAP-02: the env seam appends to os.Environ() — it does NOT clear the
// inherited baseline. A var already present in the parent (PATH) must still be
// visible to the child when an explicit env entry is also requested.
func TestLocalBackend_ExecEnv_PreservesBaselineEnv(t *testing.T) {
	b := backend.NewLocalBackend(0)
	res, err := b.ExecEnv(
		context.Background(),
		&backend.Tool{Name: "sh", Path: "/bin/sh"},
		[]string{"-c", "echo $PATH"},
		[]string{"GH_TOKEN=irrelevant"},
	)
	if err != nil {
		t.Fatalf("ExecEnv returned err=%v, want nil", err)
	}
	if strings.TrimSpace(string(res.Stdout)) == "" {
		t.Fatal("child $PATH is empty — env seam dropped the os.Environ() baseline")
	}
}

// Phase 07-09 GAP-02: backward-compat — Exec (nil env) is byte-for-byte identical
// to ExecEnv(..., nil). Both leave cmd.Env nil, so the child inherits the parent
// env exactly as before the seam was added.
func TestLocalBackend_Exec_NilEnv_UnchangedBehavior(t *testing.T) {
	b := backend.NewLocalBackend(0)
	tool := &backend.Tool{Name: "echo", Path: "/bin/echo"}

	resExec, errExec := b.Exec(context.Background(), tool, []string{"hello"})
	if errExec != nil {
		t.Fatalf("Exec returned err=%v, want nil", errExec)
	}
	resEnv, errEnv := b.ExecEnv(context.Background(), tool, []string{"hello"}, nil)
	if errEnv != nil {
		t.Fatalf("ExecEnv(nil) returned err=%v, want nil", errEnv)
	}
	if string(resExec.Stdout) != "hello\n" {
		t.Errorf("Exec stdout = %q, want %q", string(resExec.Stdout), "hello\n")
	}
	if string(resExec.Stdout) != string(resEnv.Stdout) || resExec.ExitCode != resEnv.ExitCode {
		t.Errorf("Exec and ExecEnv(nil) diverged: Exec=%q/%d ExecEnv=%q/%d",
			string(resExec.Stdout), resExec.ExitCode, string(resEnv.Stdout), resEnv.ExitCode)
	}
}
