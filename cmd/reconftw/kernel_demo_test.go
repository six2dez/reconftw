// kernel_demo_test.go — W16 hidden kernel-demo subcommand semantics.
package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// Test 1 (W16): kernel-demo is registered with Hidden:true.
func TestKernelDemoSubcommandHidden(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	var demo bool
	for _, c := range root.Commands() {
		if c.Name() == "kernel-demo" {
			demo = true
			if !c.Hidden {
				t.Errorf("kernel-demo should be Hidden:true (W16); got Hidden=%v", c.Hidden)
			}
		}
	}
	if !demo {
		t.Errorf("kernel-demo subcommand not registered")
	}
}

// Test 2 (W16): kernel-demo is NOT listed in --help output.
func TestKernelDemoNotInHelp(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"--help"})
	_ = root.Execute()
	if strings.Contains(out.String(), "kernel-demo") {
		t.Errorf("kernel-demo should not appear in --help, got: %q", out.String())
	}
}

// Test 3: With nil app (no --target supplied to main), kernel-demo returns
// *exitCodeError{code:2} so the operator knows --target is required.
func TestKernelDemoRequiresTarget(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	root.SetArgs([]string{"kernel-demo"})
	root.SetErr(&bytes.Buffer{})
	err := root.Execute()
	var ec *exitCodeError
	if !errors.As(err, &ec) {
		t.Fatalf("expected *exitCodeError, got %T: %v", err, err)
	}
	if ec.code != 2 {
		t.Errorf("expected exit code 2 (missing --target), got %d", ec.code)
	}
	if !strings.Contains(ec.msg, "--target") {
		t.Errorf("error msg should reference --target requirement, got %q", ec.msg)
	}
}

// Test 4 (Phase 4 hand-off): kernel_demo.go file header documents the Phase
// 4 plan-01 deletion requirement.
//
// This is an "operator-visible TODO" gate — if Phase 4 plan-01 forgets to
// delete this file, the test fails on a stale ban check below.
func TestKernelDemoFileHeaderCitesPhase4Deletion(t *testing.T) {
	src := readCmdReconftwSource(t, "kernel_demo.go")
	wantTokens := []string{
		"W16",       // CONTEXT amendment citation
		"D-07",      // ADR §0 D-07 non-breaking authorization
		"Phase 4",   // Phase 4 plan-01 deletion target
		"Hidden",    // Hidden:true semantic
		"noop.demo", // Task name invoked
	}
	for _, tk := range wantTokens {
		if !strings.Contains(src, tk) {
			t.Errorf("kernel_demo.go header missing token %q (citation required by W16/D-07)", tk)
		}
	}
}
