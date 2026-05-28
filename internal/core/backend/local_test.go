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
// Uses `sh -c` to pipe a large stream to stderr. Asserts the < 1KB invariant explicitly.
func TestLocalBackend_Exec_LargeStderr_TruncatedTo1KB(t *testing.T) {
	b := backend.NewLocalBackend(0)
	// /bin/sh -c 'yes ABCDEFGHIJ | head -c 5000 >&2; exit 7'
	// Generates ~5KB of stderr, then exits non-zero.
	res, err := b.Exec(
		context.Background(),
		&backend.Tool{Name: "sh", Path: "/bin/sh"},
		[]string{"-c", "yes ABCDEFGHIJ 1>&2 | head -c 5000 1>&2; exit 7"},
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
	want := []string{"Name", "Path", "Version", "DefaultArgs", "Timeout", "Critical"}
	got := make([]string, tt.NumField())
	for i := 0; i < tt.NumField(); i++ {
		got[i] = tt.Field(i).Name
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Tool struct fields = %v, want %v (ADR §5.2 + Blocker 5 Critical extension)", got, want)
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
