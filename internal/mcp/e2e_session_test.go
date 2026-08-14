// e2e_session_test.go — the MCP run lifecycle must tell the truth.
//
// Four defects the registry allowed, all of which reported success:
//   - WorkDir was seeded empty and never filled in, so scan://<runID>/findings
//     returned empty content for every successful scan.
//   - The pipeline error was discarded and MarkComplete called unconditionally,
//     so a failed scan reported complete. SessionStatusFailed was defined but
//     unreachable.
//   - Lookup returned the live pointer after releasing the mutex, racing with
//     the scan goroutine's status writes.
//   - Resources and subscriptions checked only that a runID existed, not that
//     it belonged to the asking session.
package mcp

import (
	"errors"
	"sync"
	"testing"
)

func TestE2ESessionRunLifecycle(t *testing.T) {
	t.Parallel()

	t.Run("workdir is recorded", func(t *testing.T) {
		t.Parallel()
		r := NewSessionRegistry()
		r.RegisterRun("run1", "sessA")
		if got := r.WorkDir("run1"); got != "" {
			t.Fatalf("fresh run should have no workdir, got %q", got)
		}
		r.SetWorkDir("run1", "/tmp/ws/example.com")
		if got := r.WorkDir("run1"); got != "/tmp/ws/example.com" {
			t.Errorf("WorkDir = %q; the findings resource resolves from this and "+
				"returns empty content when it is unset", got)
		}
	})

	t.Run("failure is reachable and recorded", func(t *testing.T) {
		t.Parallel()
		r := NewSessionRegistry()
		r.RegisterRun("run2", "sessA")
		r.MarkFailed("run2", errors.New("boom"))

		entry, ok := r.Lookup("run2")
		if !ok {
			t.Fatal("run2 missing")
		}
		if entry.Status != SessionStatusFailed {
			t.Errorf("Status = %q, want %q — a failed scan must not report complete",
				entry.Status, SessionStatusFailed)
		}
		if entry.Err != "boom" {
			t.Errorf("Err = %q, want the failure reason", entry.Err)
		}
	})

	t.Run("success stays complete", func(t *testing.T) {
		t.Parallel()
		r := NewSessionRegistry()
		r.RegisterRun("run3", "sessA")
		r.MarkComplete("run3")
		entry, _ := r.Lookup("run3")
		if entry.Status != SessionStatusComplete {
			t.Errorf("Status = %q, want complete", entry.Status)
		}
	})
}

// TestE2ESessionOwnership pins the authorisation rule: knowing a runID is not
// permission to read it.
func TestE2ESessionOwnership(t *testing.T) {
	t.Parallel()
	r := NewSessionRegistry()
	r.RegisterRun("runOwned", "sessA")

	if !r.OwnedBy("runOwned", "sessA") {
		t.Error("the launching session must be able to read its own run")
	}
	if r.OwnedBy("runOwned", "sessB") {
		t.Error("another session must NOT be able to read a run it did not launch")
	}
	if r.OwnedBy("nonexistent", "sessA") {
		t.Error("an unknown runID must never be authorised")
	}

	// Session-scope entries carry no owner (their RunID is the session ID) and
	// stay readable — that is the in-memory-transport path where ID() is "".
	r.Register("sessLegacy", "", nil)
	if !r.OwnedBy("sessLegacy", "anyone") {
		t.Error("ownerless entries must stay readable (in-memory transport path)")
	}
}

// TestE2ESessionLookupIsRaceFree runs Lookup against concurrent mutation. With
// Lookup handing out the internal pointer this fails under -race, which is how
// the scan goroutine and resource readers actually interleave in production.
func TestE2ESessionLookupIsRaceFree(t *testing.T) {
	t.Parallel()
	r := NewSessionRegistry()
	r.RegisterRun("runRace", "sessA")

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			r.SetWorkDir("runRace", "/tmp/ws")
			r.MarkComplete("runRace")
		}()
		go func() {
			defer wg.Done()
			if entry, ok := r.Lookup("runRace"); ok {
				_ = entry.Status
				_ = entry.WorkDir
			}
		}()
	}
	wg.Wait()
}
