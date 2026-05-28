// Source: .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 1.
//
// MockOutputTree test suite (Tests 16-18).
package testutil_test

import (
	"strings"
	"sync"
	"testing"

	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/testutil"
)

// Test 16 (interface satisfaction): MockOutputTree satisfies output.Interface.
var _ output.Interface = (*testutil.MockOutputTree)(nil)

// Test 17: Append + Lines round-trip.
func TestMockOutputTree_AppendAndLines(t *testing.T) {
	t.Parallel()
	mt := testutil.NewMockOutputTree()
	if err := mt.Append("subdomains", [][]byte{
		[]byte(`{"subdomain":"api.example.com"}`),
		[]byte(`{"subdomain":"www.example.com"}`),
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	got := mt.Lines("subdomains")
	if len(got) != 2 {
		t.Fatalf("expected 2 appended lines, got %d", len(got))
	}
	if !strings.Contains(got[0], "api.example.com") {
		t.Errorf("first line missing api.example.com: %q", got[0])
	}
}

// Test 18: Reset clears all artefacts.
func TestMockOutputTree_Reset(t *testing.T) {
	t.Parallel()
	mt := testutil.NewMockOutputTree()
	_ = mt.Append("demo", [][]byte{[]byte(`{"k":"v"}`)})
	if len(mt.Lines("demo")) != 1 {
		t.Fatal("Append failed")
	}
	mt.Reset()
	if len(mt.Lines("demo")) != 0 {
		t.Errorf("Reset failed; got %d lines", len(mt.Lines("demo")))
	}
}

// Race-clean — concurrent Append + Lines.
func TestMockOutputTree_RaceClean(t *testing.T) {
	t.Parallel()
	mt := testutil.NewMockOutputTree()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mt.Append("subdomains", [][]byte{[]byte(`{"k":"v"}`)})
		}()
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mt.Lines("subdomains")
		}()
	}
	wg.Wait()
}

// Bonus: Append deep-copies the input bytes (mutating the caller's slice
// must not affect the stored Lines).
func TestMockOutputTree_AppendDeepCopies(t *testing.T) {
	t.Parallel()
	mt := testutil.NewMockOutputTree()
	original := []byte(`{"subdomain":"api.example.com"}`)
	_ = mt.Append("subdomains", [][]byte{original})
	// Mutate the original.
	for i := range original {
		original[i] = 'X'
	}
	got := mt.Lines("subdomains")
	if !strings.Contains(got[0], "api.example.com") {
		t.Errorf("Append did not deep-copy; mutation leaked: %q", got[0])
	}
}
