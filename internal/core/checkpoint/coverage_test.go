// Extra coverage for store.go branches that the behaviour tests do not
// hit naturally: every classifyError class, NewStore error paths, and
// Close on a nil store.
package checkpoint_test

import (
	"context"
	stderrors "errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// One subtest per error class to walk every classifyError branch.
func TestCheckpointClassifyErrorAllClasses(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"ToolError", &coreerrors.ToolError{Tool: "x", ExitCode: 1, Inner: stderrors.New("boom")}, "ToolError"},
		{"ToolTimeout", &coreerrors.ToolTimeout{Tool: "x", Timeout: time.Second}, "ToolTimeout"},
		{"OutOfScope", &coreerrors.OutOfScope{Value: "evil.com", Reason: "x"}, "OutOfScope"},
		{"AxiomFailure", &coreerrors.AxiomFailure{Operation: "exec", Inner: stderrors.New("boom")}, "AxiomFailure"},
		{"ConfigError", &coreerrors.ConfigError{File: "x", Line: 1, Key: "k", Message: "m"}, "ConfigError"},
		{"ScopeError", &coreerrors.ScopeError{Input: "x", Reason: "m"}, "ScopeError"},
		{"ChecksumMismatch", &coreerrors.ChecksumMismatch{URL: "u", Expected: "e", Got: "g"}, "ChecksumMismatch"},
		{"Unknown", stderrors.New("generic"), "Unknown"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "x.db")
			s, err := checkpoint.NewStore(path)
			if err != nil {
				t.Fatalf("NewStore: %v", err)
			}
			defer func() { _ = s.Close() }()
			ctx := context.Background()
			if err := s.Begin(ctx, "t", "tg", "h"); err != nil {
				t.Fatalf("Begin: %v", err)
			}
			if err := s.Complete(ctx, "t", "tg", "h", nil, tc.err); err != nil {
				t.Fatalf("Complete: %v", err)
			}
			var got string
			if err := s.RawDB().QueryRow(
				`SELECT error_class FROM tasks WHERE task_name=? AND target=? AND input_hash=?`,
				"t", "tg", "h",
			).Scan(&got); err != nil {
				t.Fatalf("Scan: %v", err)
			}
			if got != tc.want {
				t.Fatalf("error_class = %q; want %q", got, tc.want)
			}
		})
	}
}

// Close on a nil store is a no-op.
func TestCheckpointStoreNilClose(t *testing.T) {
	t.Parallel()
	var s *checkpoint.Store
	if err := s.Close(); err != nil {
		t.Fatalf("nil-Store.Close should be nil; got %v", err)
	}
}

// NewStore on an unreachable path (under a regular file) fails.
func TestCheckpointStoreNewStoreOpenFails(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := checkpoint.NewStore(filepath.Join(blocker, "sub", "x.db"))
	if err == nil {
		t.Fatal("expected error on unreachable path")
	}
}
