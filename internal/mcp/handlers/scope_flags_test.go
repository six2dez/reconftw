package handlers_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/v5/internal/mcp/handlers"
)

// TestResolveRunPlanAppliesScopeListFlags: --include-file / --exclude-file land
// on cfg.Subdomains.Scope and an unreadable list fails before any boot.
func TestResolveRunPlanAppliesScopeListFlags(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inc := filepath.Join(dir, "in.txt")
	exc := filepath.Join(dir, "out.txt")
	for _, p := range []string{inc, exc} {
		if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	plan, err := handlers.ResolveRunPlan(handlers.RunOptions{
		Target:      "example.com",
		OutputDir:   filepath.Join(dir, "ws"),
		IncludeFile: inc,
		ExcludeFile: exc,
	})
	if err != nil {
		t.Fatalf("ResolveRunPlan: %v", err)
	}
	if plan.Cfg.Subdomains.Scope.IncludeFile != inc || plan.Cfg.Subdomains.Scope.ExcludeFile != exc {
		t.Fatalf("scope files not applied: include=%q exclude=%q",
			plan.Cfg.Subdomains.Scope.IncludeFile, plan.Cfg.Subdomains.Scope.ExcludeFile)
	}

	_, err = handlers.ResolveRunPlan(handlers.RunOptions{
		Target:      "example.com",
		OutputDir:   filepath.Join(dir, "ws"),
		ExcludeFile: filepath.Join(dir, "missing.txt"),
	})
	if err == nil {
		t.Fatal("missing --exclude-file must fail ResolveRunPlan")
	}
	if !strings.Contains(err.Error(), "subdomains.scope.exclude_file") {
		t.Errorf("error should name the key, got %q", err.Error())
	}
}
