// healthcheck_test.go — D-04 + Blocker 5 (FOUND-08 two-tier semantics).
package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

// newTestCfg returns a config that satisfies the runHealthCheck contract.
func newTestCfg() *config.Config {
	return &config.Config{
		Concurrency: config.ConcurrencyConfig{KillGraceSeconds: 5},
		Output:      config.OutputConfig{Verbosity: 1},
	}
}

// Test 1 (D-04): runHealthCheck with empty registry returns nil (Phase 3 baseline).
//
// Note: the ui.Printer truncates labels longer than 26 chars; the "Phase 3
// baseline" annotation we'd like to see appears in the WIDE name we pass
// into Status — but the printer truncates. We assert on truncation-safe
// substrings ("config.parse", "backend.local", "tools (0") instead.
func TestHealthCheckEmptyRegistryOK(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cfg := newTestCfg()
	reg := backend.NewToolRegistry() // Blocker 7 — fresh registry

	err := runHealthCheck(cmd, nil, cfg, reg)
	if err != nil {
		t.Errorf("empty registry should produce nil, got %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "config.parse") {
		t.Errorf("expected config.parse line in output, got %q", output)
	}
	if !strings.Contains(output, "backend.local") {
		t.Errorf("expected backend.local line in output, got %q", output)
	}
	// "tools (0 registered..." gets truncated by printer pad=26, but the
	// prefix "tools (0" is preserved.
	if !strings.Contains(output, "tools (0") {
		t.Errorf("expected '0 registered' phase-3-baseline note prefix, got %q", output)
	}
}

// Test 2 (Blocker 5): missing-critical tool produces FAIL + *exitCodeError{code:1}.
//
// Tool name is kept short so the ui.Printer's pad=26 truncation doesn't
// hide the "(critical)" annotation we're asserting on.
func TestHealthCheckCriticalFail(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cfg := newTestCfg()
	reg := backend.NewToolRegistry()
	// Short tool name + Critical:true so missing → FAIL annotated "(critical)".
	reg.Register(&backend.Tool{Name: "miss-c", Critical: true})

	err := runHealthCheck(cmd, nil, cfg, reg)
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("expected *exitCodeError, got %T: %v", err, err)
	}
	if ec.code != 1 {
		t.Errorf("expected exit code 1, got %d", ec.code)
	}
	output := out.String()
	if !strings.Contains(output, "FAIL") {
		t.Errorf("expected FAIL line in output, got %q", output)
	}
	if !strings.Contains(output, "critical") {
		t.Errorf("expected '(critical)' annotation in output, got %q", output)
	}
}

// Test 3 (Blocker 5): missing-required-but-NOT-critical tool produces WARN + exit 0.
func TestHealthCheckRequiredWarn(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cfg := newTestCfg()
	reg := backend.NewToolRegistry()
	// Short name + Critical:false → WARN only, exit 0.
	reg.Register(&backend.Tool{Name: "miss-r", Critical: false})

	err := runHealthCheck(cmd, nil, cfg, reg)
	if err != nil {
		t.Errorf("missing-but-non-critical tool should not fail health-check, got %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN line in output, got %q", output)
	}
	if !strings.Contains(output, "required") {
		t.Errorf("expected '(required)' annotation in output, got %q", output)
	}
}

// Test 4: Present tool on PATH produces OK badge.
func TestHealthCheckPresentToolOK(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cfg := newTestCfg()
	reg := backend.NewToolRegistry()
	// `sh` is reliably present on every reconFTW-supported platform.
	reg.Register(&backend.Tool{Name: "sh", Critical: true})

	err := runHealthCheck(cmd, nil, cfg, reg)
	if err != nil {
		t.Errorf("present tool should produce nil, got %v", err)
	}
	output := out.String()
	if !strings.Contains(output, "OK") || !strings.Contains(output, "tool.sh") {
		t.Errorf("expected [OK] tool.sh line, got %q", output)
	}
}

// Test 5: nil cfg produces FAIL on config.parse + critical fail (exit 1).
func TestHealthCheckNilCfgFails(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	reg := backend.NewToolRegistry()

	err := runHealthCheck(cmd, nil, nil, reg)
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("expected *exitCodeError when cfg is nil, got %T", err)
	}
	if ec.code != 1 {
		t.Errorf("expected exit code 1, got %d", ec.code)
	}
	output := out.String()
	if !strings.Contains(output, "FAIL") || !strings.Contains(output, "config.parse") {
		t.Errorf("expected [FAIL] config.parse line, got %q", output)
	}
}

// Test 6 (D-04): cobra subcommand 'health-check' is registered on root.
func TestHealthCheckSubcommandWired(t *testing.T) {
	root := newRootCmd(nil, newTestCfg())
	var got bool
	for _, c := range root.Commands() {
		if c.Name() == "health-check" && !c.Hidden {
			got = true
			break
		}
	}
	if !got {
		t.Errorf("health-check subcommand not registered (or hidden — should be visible)")
	}
}
