// Package batsmap holds the XCUT-03 drift guard for the v1-bats -> v2-test
// parity map (docs/14-BATS-PARITY-MAP.md).
//
// The guard is deliberately test-only and stdlib-only: it re-derives the live
// `@test` inventory from tests/**/*.bats and asserts the checked-in map has
// exactly one row per scenario — both in total AND per bats file — so the map
// can never silently drift from the suite. There is no production code here.
package batsmap

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

// repoRoot resolves the repository root from this test file's compile-time path
// (internal/batsmap/parity_map_test.go -> ../..), independent of the test CWD.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed to resolve this file's path")
	}
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	// sanity: the tests/ dir and the map must both exist under the resolved root
	for _, p := range []string{"tests", filepath.Join("docs", "14-BATS-PARITY-MAP.md")} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			t.Fatalf("resolved repo root %q missing %q: %v", root, p, err)
		}
	}
	return root
}

// batsScenarioCounts walks tests/**/*.bats and counts, per file basename, the
// number of lines containing "@test". This mirrors `grep -rc '@test' tests/`
// (line-based), which is the canonical XCUT-03 count.
func batsScenarioCounts(t *testing.T, root string) map[string]int {
	t.Helper()
	counts := make(map[string]int)
	testsDir := filepath.Join(root, "tests")
	err := filepath.WalkDir(testsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".bats") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck
		base := filepath.Base(path)
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if strings.Contains(sc.Text(), "@test") {
				counts[base]++
			}
		}
		return sc.Err()
	})
	if err != nil {
		t.Fatalf("walking %s: %v", testsDir, err)
	}
	if len(counts) == 0 {
		t.Fatalf("found no .bats files under %s", testsDir)
	}
	return counts
}

// validDisposition reports whether a disposition cell is in the allowed set:
// covered-by:<ref>, superseded, or not-applicable.
func validDisposition(d string) bool {
	return d == "superseded" || d == "not-applicable" || strings.HasPrefix(d, "covered-by:")
}

// mapRowCounts parses docs/14-BATS-PARITY-MAP.md and counts, per bats basename,
// the scenario rows. A scenario row is a markdown table line where the first
// cell ends in ".bats" AND the disposition cell (3rd column) is a valid
// disposition. This uniquely excludes the summary/per-file-count tables (whose
// 3rd column is a number or empty) and the legend (backtick-wrapped cells).
func mapRowCounts(t *testing.T, root string) map[string]int {
	t.Helper()
	path := filepath.Join(root, "docs", "14-BATS-PARITY-MAP.md")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close() //nolint:errcheck

	counts := make(map[string]int)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(strings.TrimSpace(line), "|") {
			continue
		}
		parts := strings.Split(line, "|")
		// "| a | b | c | d |" -> ["", " a ", " b ", " c ", " d ", ""]
		if len(parts) < 6 {
			continue
		}
		batsFile := strings.TrimSpace(parts[1])
		disposition := strings.TrimSpace(parts[3])
		if !strings.HasSuffix(batsFile, ".bats") {
			continue
		}
		if !validDisposition(disposition) {
			continue
		}
		counts[batsFile]++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanning %s: %v", path, err)
	}
	return counts
}

func sum(m map[string]int) int {
	total := 0
	for _, v := range m {
		total += v
	}
	return total
}

// TestBatsParityMapMatchesSuite is the drift guard: the parity map must have
// exactly one scenario row per v1 @test, both in total and per bats file. If a
// bats test is added/removed without updating the map (or a map row is removed),
// the counts diverge and this test fails.
func TestBatsParityMapMatchesSuite(t *testing.T) {
	root := repoRoot(t)
	bats := batsScenarioCounts(t, root)
	doc := mapRowCounts(t, root)

	batsTotal := sum(bats)
	docTotal := sum(doc)

	if docTotal != batsTotal {
		t.Errorf("parity map row count (%d) != live @test count (%d) — the map has drifted from tests/**/*.bats",
			docTotal, batsTotal)
	}

	// Per-file equality is the stronger guard: catches a row filed under the
	// wrong bats file even when the total happens to match.
	files := make(map[string]struct{})
	for k := range bats {
		files[k] = struct{}{}
	}
	for k := range doc {
		files[k] = struct{}{}
	}
	names := make([]string, 0, len(files))
	for k := range files {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		if bats[name] != doc[name] {
			t.Errorf("bats file %s: live @test=%d but map rows=%d", name, bats[name], doc[name])
		}
	}

	t.Logf("parity map in sync: %d scenarios across %d bats files", docTotal, len(bats))
}

// TestBatsParityMapBaselineCount is a baseline sentinel documenting the expected
// XCUT-03 scenario count (348). It is intentionally separate from the drift
// guard: if the bats suite legitimately changes, TestBatsParityMapMatchesSuite
// still enforces that the map tracks it, while THIS test forces a conscious,
// reviewed bump of the baseline constant.
func TestBatsParityMapBaselineCount(t *testing.T) {
	const wantBaseline = 348
	root := repoRoot(t)

	if got := sum(batsScenarioCounts(t, root)); got != wantBaseline {
		t.Errorf("live @test count = %d, baseline = %d — if the bats suite changed intentionally, "+
			"update docs/14-BATS-PARITY-MAP.md AND bump wantBaseline", got, wantBaseline)
	}
	if got := sum(mapRowCounts(t, root)); got != wantBaseline {
		t.Errorf("parity map row count = %d, baseline = %d — update the map to one row per scenario",
			got, wantBaseline)
	}
}
