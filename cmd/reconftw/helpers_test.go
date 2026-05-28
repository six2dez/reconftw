// helpers_test.go — shared test helpers for cmd/reconftw tests.
package main

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// readCmdReconftwSource reads a source file from the cmd/reconftw/ package
// directory. Used by tests that grep source content for required citations
// or invariants (e.g. kernel_demo.go must cite W16 / D-07 in its header).
func readCmdReconftwSource(t *testing.T, basename string) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	body, err := os.ReadFile(filepath.Join(dir, basename))
	if err != nil {
		t.Fatalf("read %s: %v", basename, err)
	}
	return string(body)
}
