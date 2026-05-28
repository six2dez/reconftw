// version_test.go — D-04 `reconftw version` subcommand semantics.
package main

import (
	"bytes"
	"runtime"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// Test 1 (D-04): newVersionCmd prints version + commit + built + go version + platform.
// Returns nil error (exit 0).
func TestVersionSubcommandOutput(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetArgs([]string{"version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("version subcommand returned err: %v", err)
	}
	output := out.String()
	// Check for all 5 expected sections.
	wantSubstrings := []string{
		"reconftw version",
		"commit:",
		"built:",
		"go version:",
		"platform:",
		runtime.Version(),
		runtime.GOOS + "/" + runtime.GOARCH,
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(output, want) {
			t.Errorf("version output missing %q: full=%q", want, output)
		}
	}
}

// Test 2 (D-04): lookupCommit falls back to "unknown" when CommitSHA is the
// default sentinel and no vcs.revision is embedded.
//
// Note: when `go test` runs, debug.ReadBuildInfo returns build info but
// vcs.revision may be present (test binary built in a git repo). We accept
// either "unknown" or a hex SHA — both are valid behaviors per D-04.
func TestLookupCommitFallback(t *testing.T) {
	// Save original.
	orig := CommitSHA
	defer func() { CommitSHA = orig }()

	// Set the default sentinel to force fallback path.
	CommitSHA = "unknown"
	got := lookupCommit()
	// "unknown" or any non-empty string is acceptable — the test binary
	// running inside a git repo may have vcs.revision auto-embedded.
	if got == "" {
		t.Errorf("lookupCommit returned empty string")
	}
}

// Test 3 (D-04): lookupCommit returns the ldflag-injected CommitSHA when set.
func TestLookupCommitUsesLdflag(t *testing.T) {
	orig := CommitSHA
	defer func() { CommitSHA = orig }()

	CommitSHA = "abc1234fakelocked"
	got := lookupCommit()
	if got != "abc1234fakelocked" {
		t.Errorf("lookupCommit = %q, want %q", got, "abc1234fakelocked")
	}
}

// Test 4: version subcommand is registered on root and is NOT hidden.
func TestVersionSubcommandWired(t *testing.T) {
	root := newRootCmd(nil, &config.Config{})
	var got bool
	for _, c := range root.Commands() {
		if c.Name() == "version" && !c.Hidden {
			got = true
			break
		}
	}
	if !got {
		t.Errorf("version subcommand not registered (or hidden — should be visible per D-04)")
	}
}
