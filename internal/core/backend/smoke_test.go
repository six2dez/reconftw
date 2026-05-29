//go:build realtools

// Package backend_test — real-tool arg smoke test.
//
// TestRealToolArgSmoke probes each registered tool binary with --help and
// asserts that the output does NOT contain "flag provided but not defined" or
// "unknown flag", which are the sentinels for arg drift against the installed CLI.
//
// BUILD TAG: this file is gated by //go:build realtools so that a plain
// `go test ./...` does NOT require any external binaries. Normal CI is hermetic.
// Run manually with:
//
//	go test -tags realtools ./internal/core/backend/...
//
// For the crt regression guard specifically the test also runs:
//
//	crt probe.example.com (harmless — probes the binary, not a real target)
//
// and verifies the output does not contain "flag provided but not defined"
// (confirming the positional-arg fix from passive.go Task 1 holds).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-08-PLAN.md Task 2.
package backend_test

import (
	"bytes"
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// TestRealToolArgSmoke iterates over every tool registered in backend.Default
// and probes each binary with --help. The test fails if any binary emits
// "flag provided but not defined" or "unknown flag", which indicate arg drift.
//
// Tools not on PATH are skipped (not failed) so the test stays hermetic on
// environments without the full toolchain installed.
//
// Special case — crt regression guard: if the crt binary is on PATH, the test
// additionally runs `crt probe.example.com` (positional domain, no -d flag)
// to confirm the GAP-1 fix in passive.go holds.
func TestRealToolArgSmoke(t *testing.T) {
	for _, tool := range backend.Default.All() {
		tool := tool // capture range variable
		t.Run(tool.Name, func(t *testing.T) {
			// Locate binary on PATH.
			binPath, err := exec.LookPath(tool.Name)
			if err != nil {
				t.Skipf("binary %q not on PATH — skipping (not a CI failure)", tool.Name)
				return
			}

			// Probe with --help. Use a 5-second timeout to avoid stalling the test
			// suite on a tool that hangs on --help (some interactive CLIs do).
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binPath, "--help")
			var out bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &out
			// Ignore exit code — many tools exit 1 or 2 on --help; that is not
			// the failure condition we are testing for.
			_ = cmd.Run()

			combined := out.String()
			if strings.Contains(combined, "flag provided but not defined") {
				t.Errorf("%s: --help output contains 'flag provided but not defined' — arg drift detected:\n%s",
					tool.Name, combined)
			}
			if strings.Contains(combined, "unknown flag") {
				t.Errorf("%s: --help output contains 'unknown flag' — arg drift detected:\n%s",
					tool.Name, combined)
			}

			// crt regression guard (GAP-1): confirm the positional-arg fix holds.
			// Run `crt probe.example.com` — a harmless invocation that exercises
			// the crt binary's arg parsing without returning real CT records.
			if tool.Name == "crt" {
				crtCtx, crtCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer crtCancel()

				// Pass domain positionally (no -d flag) — this is the fixed behaviour.
				crtCmd := exec.CommandContext(crtCtx, binPath, "probe.example.com")
				var crtOut bytes.Buffer
				crtCmd.Stdout = &crtOut
				crtCmd.Stderr = &crtOut
				_ = crtCmd.Run()

				crtCombined := crtOut.String()
				if strings.Contains(crtCombined, "flag provided but not defined") {
					t.Errorf("crt regression: positional invocation produced 'flag provided but not defined'"+
						" — GAP-1 fix may have regressed:\n%s", crtCombined)
				}
			}
		})
	}
}
