// e2e_healthcheck_test.go — health-check must not contradict itself.
//
// `reconftw install --health-check` passed cfg=nil, so check 1 reported
// [FAIL] config.parse on a healthy machine and the command exited 1 — while
// the closing message read "0 critical health checks failed", because it
// printed missingCriticalCount (missing TOOLS) rather than the number of
// failed critical CHECKS. Exit 1 plus "0 failed" is worse than either alone:
// scripted callers see failure, humans read success.
package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
)

func TestE2EHealthCheckMessageNamesTheFailure(t *testing.T) {
	t.Parallel()
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetContext(t.Context())

	// nil cfg forces the config.parse critical failure.
	err := runHealthCheck(cmd, nil, nil, backend.NewToolRegistry())
	if err == nil {
		t.Fatal("a failed critical check must return an error")
	}
	msg := err.Error()
	if strings.Contains(msg, "0 critical") {
		t.Errorf("message claims zero failures while returning an error: %q", msg)
	}
	if !strings.Contains(msg, "config.parse") {
		t.Errorf("message must name the failed check, got %q", msg)
	}
}

func TestE2EHealthCheckPassesWithLoadedConfig(t *testing.T) {
	t.Parallel()
	cfg, err := config.Load(config.LoadOptions{})
	if err != nil {
		t.Skipf("config.Load failed in this environment: %v", err)
	}
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetContext(t.Context())

	// Empty registry → no tools, so no missing-critical failures either.
	if err := runHealthCheck(cmd, nil, cfg, backend.NewToolRegistry()); err != nil {
		t.Errorf("health-check with a loaded config must pass, got %v", err)
	}
}
