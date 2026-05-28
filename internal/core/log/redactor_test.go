// Tests for the Redactor (Layer 2 of two-layer redaction defense).
// Source: ADR 0002 §10.2 lines 2429-2464 (canonical: skip ≤4 chars, dedup, RWMutex).
//
// External test package.
package log_test

import (
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/six2dez/reconftw/internal/core/log"
)

// --- Test 5: Values with length ≤ 4 are silently ignored ---

func TestRedactor_RegisterSkipsShortValues(t *testing.T) {
	t.Parallel()
	r := &log.Redactor{}
	for _, short := range []string{"", "a", "ab", "abc", "abcd"} {
		r.Register(short)
	}
	// None of those should affect Redact output.
	const input = "abcd abc ab a"
	if got := r.Redact(input); got != input {
		t.Errorf("Redact(%q) = %q; want %q (short values must be ignored)", input, got, input)
	}
}

// --- Test 6: Long value registers + Redact substring-replaces ---

func TestRedactor_RegisterAndRedact(t *testing.T) {
	t.Parallel()
	r := &log.Redactor{}
	r.Register("supersecret-token-abc-12345")
	input := "my supersecret-token-abc-12345 leaked"
	want := "my *** leaked"
	if got := r.Redact(input); got != want {
		t.Errorf("Redact(%q) = %q; want %q", input, got, want)
	}
}

// Multiple registered secrets all redact in the same string.
func TestRedactor_MultipleSecretsRedacted(t *testing.T) {
	t.Parallel()
	r := &log.Redactor{}
	r.Register("first-secret-value-aaa")
	r.Register("second-secret-value-bbb")
	input := "first-secret-value-aaa and second-secret-value-bbb"
	want := "*** and ***"
	if got := r.Redact(input); got != want {
		t.Errorf("Redact() = %q; want %q", got, want)
	}
}

// --- Test 7: Concurrent Register + Redact is race-clean ---
//
// Runs under -race and must finish well under 1 second per ADR §10.2 contract.
func TestRedactor_ConcurrentRegisterAndRedactRaceFree(t *testing.T) {
	t.Parallel()
	r := &log.Redactor{}

	deadline := time.NewTimer(900 * time.Millisecond)
	defer deadline.Stop()
	done := make(chan struct{})

	go func() {
		defer close(done)
		var wg sync.WaitGroup
		// 10 writers register distinct long values.
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					r.Register(strings.Repeat("x", 5) + string(rune('a'+i)) + string(rune('A'+j%26)))
				}
			}(i)
		}
		// 10 readers issue Redact concurrently.
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := 0; j < 50; j++ {
					_ = r.Redact("some line with xxxxxa and xxxxxbA and other content")
				}
			}()
		}
		wg.Wait()
	}()

	select {
	case <-done:
		// pass
	case <-deadline.C:
		t.Fatalf("concurrent Register/Redact did not complete within 900ms; possible deadlock")
	}
}

// --- Test 8: Register dedup — registering the same long value twice is a no-op ---
//
// Hard to assert "only one entry" via public API; the proof is that Redact
// output remains a single replacement, no double-replace.
func TestRedactor_RegisterDedup(t *testing.T) {
	t.Parallel()
	r := &log.Redactor{}
	r.Register("repeated-value")
	r.Register("repeated-value")
	r.Register("repeated-value")

	got := r.Redact("repeated-value")
	if got != "***" {
		t.Errorf("Redact(%q) = %q; want %q (one replacement)", "repeated-value", got, "***")
	}
	// And the dedup does not break subsequent unique-value redaction.
	r.Register("unique-other-secret")
	got = r.Redact("repeated-value and unique-other-secret")
	want := "*** and ***"
	if got != want {
		t.Errorf("Redact() after dedup = %q; want %q", got, want)
	}
}
