package config

// Drift guard for MIGRATION.md (Phase 14 D-06, CUT-07 / XCUT-05).
//
// MIGRATION.md's §2.3 config-rename table is authored FROM legacyAliasMap so it
// can never silently drift from the code: this test iterates the actual map and
// fails if any v1->v2 rename row is missing from the doc. Removing (or mistyping)
// a row makes CI fail — which is exactly the "zero silent breakages" guarantee.
//
// The doc lives at the repo root; `go test` runs with the package directory as
// the working directory, so the doc is three levels up from internal/core/config.

import (
	"os"
	"sort"
	"strings"
	"testing"
)

const migrationDocPath = "../../../MIGRATION.md"

// renameRow renders one config-rename table row EXACTLY as MIGRATION.md must
// contain it. The doc's generated table and this guard share this one format, so
// they cannot disagree about what a "present" row looks like.
func renameRow(v1Key, v2Path string) string {
	return "| `" + v1Key + "` | `" + v2Path + "` |"
}

func readMigrationDoc(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(migrationDocPath)
	if err != nil {
		t.Fatalf("read %s: %v (MIGRATION.md must exist at the repo root)", migrationDocPath, err)
	}
	return string(data)
}

// TestMigrationDocRenameTableCoversLegacyAliasMap asserts every legacyAliasMap
// entry appears as a rename row in MIGRATION.md. This is the CUT-07/XCUT-05
// drift guard: a config rename cannot ship without its MIGRATION.md before/after.
func TestMigrationDocRenameTableCoversLegacyAliasMap(t *testing.T) {
	doc := readMigrationDoc(t)

	var missing []string
	for v1Key, v2Path := range legacyAliasMap {
		if !strings.Contains(doc, renameRow(v1Key, v2Path)) {
			missing = append(missing, renameRow(v1Key, v2Path))
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("MIGRATION.md §2.3 is missing %d legacyAliasMap rename row(s) — the "+
			"config-rename table has drifted from the code. Add these rows:\n%s",
			len(missing), strings.Join(missing, "\n"))
	}
}

// TestMigrationDocHasBreakingChangeSections asserts the four breaking-change
// categories plus the rollback procedure and the two-clock deprecation timeline
// are all present, so the doc cannot lose a whole section undetected.
func TestMigrationDocHasBreakingChangeSections(t *testing.T) {
	doc := strings.ToLower(readMigrationDoc(t))

	required := []string{
		"cli flag",          // §2.1 CLI-flag category
		"output tree",       // §2.2 output-tree category
		"config key rename", // §2.3 config-rename category
		"default-behavior",  // §2.4 default-change category
		"rollback",          // §3 CUT-15
		"6-month",           // §4 compat-window clock
		"12-month",          // §4 v1-freeze clock
	}
	for _, anchor := range required {
		if !strings.Contains(doc, anchor) {
			t.Errorf("MIGRATION.md is missing required anchor %q", anchor)
		}
	}
}
