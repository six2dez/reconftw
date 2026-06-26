package mcp_test

import (
	"fmt"
	"sync"
	"testing"

	mcp "github.com/six2dez/reconftw/internal/mcp"
)

func TestSessionRegistry(t *testing.T) {
	t.Parallel()

	t.Run("register_and_lookup", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("run-1", "/tmp/run-1", nil)
		entry, ok := reg.Lookup("run-1")
		if !ok {
			t.Fatal("expected entry to be found")
		}
		if entry.RunID != "run-1" {
			t.Errorf("got RunID %q, want %q", entry.RunID, "run-1")
		}
		if entry.Status != mcp.SessionStatusRunning {
			t.Errorf("got Status %q, want %q", entry.Status, mcp.SessionStatusRunning)
		}
	})

	t.Run("lookup_missing", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		_, ok := reg.Lookup("nonexistent")
		if ok {
			t.Fatal("expected not-found for unknown runID")
		}
	})

	t.Run("set_scope_on_registered", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("run-2", "/tmp/run-2", nil)
		scope := mcp.NewSessionScope([]string{"example.com"})
		reg.SetScope("run-2", scope)
		entry, ok := reg.Lookup("run-2")
		if !ok {
			t.Fatal("expected entry to be found")
		}
		if entry.Scope != scope {
			t.Errorf("Scope was not updated")
		}
	})

	t.Run("set_scope_on_missing_no_panic", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		// Must not panic.
		reg.SetScope("unknown-id", mcp.NewSessionScope([]string{"example.com"}))
	})

	t.Run("workdir_returns_correct_value", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("run-3", "/workspace/run-3", nil)
		if got := reg.WorkDir("run-3"); got != "/workspace/run-3" {
			t.Errorf("got WorkDir %q, want %q", got, "/workspace/run-3")
		}
	})

	t.Run("workdir_missing_returns_empty", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		if got := reg.WorkDir("norun"); got != "" {
			t.Errorf("got WorkDir %q, want empty string", got)
		}
	})

	t.Run("mark_complete_sets_status", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		reg.Register("run-4", "/tmp/run-4", nil)
		reg.MarkComplete("run-4")
		entry, ok := reg.Lookup("run-4")
		if !ok {
			t.Fatal("expected entry to be found")
		}
		if entry.Status != mcp.SessionStatusComplete {
			t.Errorf("got Status %q, want %q", entry.Status, mcp.SessionStatusComplete)
		}
	})

	t.Run("mark_complete_missing_no_panic", func(t *testing.T) {
		t.Parallel()
		reg := mcp.NewSessionRegistry()
		// Must not panic.
		reg.MarkComplete("ghost-run")
	})

	t.Run("concurrent", func(t *testing.T) {
		t.Parallel()

		const n = 20
		reg := mcp.NewSessionRegistry()

		// ready channel: closing it releases all goroutines simultaneously.
		ready := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(n)

		for i := range n {
			i := i
			if i < n/2 {
				// Goroutines 0-9: Register unique IDs.
				go func() {
					defer wg.Done()
					<-ready
					reg.Register(fmt.Sprintf("run-%d", i), "/tmp", nil)
				}()
			} else {
				// Goroutines 10-19: Lookup + SetScope on the other half's IDs.
				go func() {
					defer wg.Done()
					<-ready
					id := fmt.Sprintf("run-%d", i-n/2)
					if entry, ok := reg.Lookup(id); ok {
						_ = entry
						reg.SetScope(id, nil)
					}
				}()
			}
		}

		close(ready)
		wg.Wait()

		// After all goroutines complete, all 10 registered IDs must be found.
		for i := range n / 2 {
			id := fmt.Sprintf("run-%d", i)
			if _, ok := reg.Lookup(id); !ok {
				t.Errorf("expected %q to be found after concurrent registration", id)
			}
		}
	})
}

func TestSessionRegistry_PanicOnDuplicate(t *testing.T) {
	t.Parallel()
	reg := mcp.NewSessionRegistry()
	reg.Register("dup", "/tmp", nil)

	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic on duplicate Register, got none")
		}
	}()
	reg.Register("dup", "/tmp", nil) // must panic
}
