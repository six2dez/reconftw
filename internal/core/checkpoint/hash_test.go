// Source: .planning/phases/03-foundation-kernel/03-03-PLAN.md Task 3 (hash.go).
// Validates the input_hash formula per ADR §3.4 line 1319:
//
//	input_hash = SHA-256(task_name + target + config_slice_json + wordlists.lock_content)
//
// Plus determinism + change-detection (one-byte diff produces a different
// hash).
package checkpoint_test

import (
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/checkpoint"
)

// Test 9: InputHash is deterministic — same inputs → same output.
func TestInputHashDeterministic(t *testing.T) {
	t.Parallel()
	cfg := []byte(`{"max_jobs":4}`)
	wl := []byte("hash:abc\n")
	h1 := checkpoint.InputHash("subdomains.passive", "example.com", cfg, wl)
	h2 := checkpoint.InputHash("subdomains.passive", "example.com", cfg, wl)
	if h1 != h2 {
		t.Fatalf("non-deterministic: %s != %s", h1, h2)
	}
	if len(h1) != 64 {
		t.Fatalf("expected 64-char hex; got %d chars", len(h1))
	}
	for _, c := range h1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("non-hex byte %q in hash", c)
		}
	}
}

// Test 10: One-byte difference in any input produces a different hash.
func TestInputHashChangeDetection(t *testing.T) {
	t.Parallel()
	cfg := []byte(`{"max_jobs":4}`)
	wl := []byte("hash:abc\n")
	base := checkpoint.InputHash("t.x", "tgt", cfg, wl)

	cases := []struct {
		name string
		got  string
	}{
		{"task changed", checkpoint.InputHash("t.x.2", "tgt", cfg, wl)},
		{"target changed", checkpoint.InputHash("t.x", "tgt2", cfg, wl)},
		{"cfg byte diff", checkpoint.InputHash("t.x", "tgt", []byte(`{"max_jobs":5}`), wl)},
		{"wordlist byte diff", checkpoint.InputHash("t.x", "tgt", cfg, []byte("hash:abd\n"))},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if tc.got == base {
				t.Fatalf("expected hash change for %s; both %s", tc.name, base)
			}
		})
	}
}

// Null-byte separator must prevent prefix collision attacks: changing
// where boundaries fall between fields must not collide. e.g.
// task="a" target="b" must NOT equal task="ab" target="" (or analogous).
func TestInputHashPrefixCollisionSafe(t *testing.T) {
	t.Parallel()
	cfg := []byte("c")
	wl := []byte("w")
	// task="ab" target="" vs task="a" target="b" — without null separators,
	// these would concat to the same byte string in some hash schemes.
	h1 := checkpoint.InputHash("ab", "", cfg, wl)
	h2 := checkpoint.InputHash("a", "b", cfg, wl)
	if h1 == h2 {
		t.Fatal("prefix collision: implementation lacks null separators")
	}
}

// Empty inputs are accepted and produce a deterministic non-empty hash.
func TestInputHashEmptyInputs(t *testing.T) {
	t.Parallel()
	h := checkpoint.InputHash("", "", nil, nil)
	if h == "" {
		t.Fatal("empty inputs should still produce a hash")
	}
	if !strings.HasPrefix(h, "") || len(h) != 64 {
		t.Fatalf("expected 64-char hex; got %d", len(h))
	}
}
