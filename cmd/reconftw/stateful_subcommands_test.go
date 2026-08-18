// stateful_subcommands_test.go — F14 regression suite for the three stateful
// utility subcommands (gen-resolvers, refresh-cache, quick-rescan).
//
// The defects these tests pin down (15-12):
//
//	T-15-12-02  --dry-run was read AFTER the mutation it was supposed to gate:
//	            refresh-cache deleted cache files first, quick-rescan inserted a
//	            scan row first, gen-resolvers never read the flag at all.
//	T-15-12-04  the dry-run preview must be produced by the same function that
//	            performs the deletion, or it eventually lies.
//	T-15-12-05  -o/--output must beat paths.data_dir BEFORE any path is computed.
//
// Every assertion here is made against a seeded workspace / store on disk, never
// by reading the implementation — except TestStatefulDryRunReadPrecedesMutation,
// which is deliberately a source-order guard because ordering is the whole bug.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/spf13/cobra"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// dryRunPathPrefix is the stable per-path prefix printed by
// printCacheInvalidationPlan / printGenResolversDryRun.
const dryRunPathPrefix = "[dry-run]   "

// --- harness -----------------------------------------------------------------

// statefulTestEnv isolates everything config.Load auto-discovers so a
// developer's real ~/.config/reconftw/config.toml (or a reconftw.toml in the
// repo root) cannot steer these tests.
//
// It matters more than usual here: parseEarlyFlags reads os.Args, not the cobra
// arg slice, so a test CANNOT pass --config. Environment isolation is the only
// lever, which is why every path these commands touch is pinned through
// XDG_CONFIG_HOME, HOME and an explicit -o.
func statefulTestEnv(t *testing.T) (home string) {
	t.Helper()

	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	// A temp cwd removes the "reconftw.toml" project layer.
	t.Chdir(t.TempDir())

	// newRootCmd's PersistentPreRunE writes these package globals.
	prevOutputDir, prevLogLevel := cliOutputDir, cliLogLevel
	t.Cleanup(func() { cliOutputDir, cliLogLevel = prevOutputDir, prevLogLevel })
	cliOutputDir, cliLogLevel = "", ""

	return home
}

// writeUserConfig plants a config.toml on the XDG user layer. Used to prove
// -o/--output overrides a CONFIGURED data_dir rather than merely a default.
func writeUserConfig(t *testing.T, home, body string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "reconftw")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir user config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatalf("write user config: %v", err)
	}
}

// runStatefulCmd executes a subcommand through the REAL root command, so the
// persistent --dry-run / -o flags and PersistentPreRunE behave exactly as they
// do for an operator.
func runStatefulCmd(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	root := newRootCmd(nil, config.Defaults())
	var outBuf, errBuf strings.Builder
	root.SetOut(&outBuf)
	root.SetErr(&errBuf)
	root.SetArgs(args)
	err = root.Execute()
	return outBuf.String(), errBuf.String(), err
}

// seedWorkspace creates the canonical workspace for target under dataDir (via
// the real output.WorkspaceInit, so the directory name is the real slug) and
// writes files into it. rel paths are relative to the workspace root.
func seedWorkspace(t *testing.T, dataDir, target string, files map[string]string) string {
	t.Helper()
	workspace, err := output.WorkspaceInit(dataDir, target)
	if err != nil {
		t.Fatalf("WorkspaceInit(%q, %q): %v", dataDir, target, err)
	}
	for rel, content := range files {
		p := filepath.Join(workspace, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(p), err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return workspace
}

// cacheFileFixture is the seed set every refresh-cache test uses: three files
// the command SHOULD treat as cache, and one artefact it must never touch.
func cacheFileFixture(marker string) map[string]string {
	return map[string]string{
		"inputs/geo.example.txt":   "geo " + marker,
		"inputs/asn.jsonl":         "asn " + marker,
		"inputs/resolvers.txt":     "resolvers " + marker,
		"artefacts/findings.jsonl": "findings " + marker,
	}
}

// snapshotTree maps every regular file under root to the hex SHA-256 of its
// contents, keyed by the path relative to root.
func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := make(map[string]string)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		b, readErr := os.ReadFile(p) //nolint:gosec // test-local temp tree
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		sum := sha256.Sum256(b)
		out[rel] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatalf("snapshotTree(%s): %v", root, err)
	}
	return out
}

// assertNoneRemovedOrModified fails when any file present in before is missing
// from after, or present with different content. New files are tolerated: boot
// legitimately creates checkpoints.db and the identity marker, and dry-run
// purity for THOSE is plan 15-05's surface, not this one.
func assertNoneRemovedOrModified(t *testing.T, before, after map[string]string, what string) {
	t.Helper()
	for rel, sum := range before {
		got, ok := after[rel]
		if !ok {
			t.Errorf("%s: %s was DELETED by a dry run", what, rel)
			continue
		}
		if got != sum {
			t.Errorf("%s: %s was MODIFIED by a dry run (%s -> %s)", what, rel, sum, got)
		}
	}
}

// parseDryRunPaths extracts the per-path preview lines from command output.
func parseDryRunPaths(stdout string) []string {
	var paths []string
	for _, line := range strings.Split(stdout, "\n") {
		if !strings.HasPrefix(line, dryRunPathPrefix) {
			continue
		}
		p := strings.TrimSpace(strings.TrimPrefix(line, dryRunPathPrefix))
		if p == "" || strings.HasPrefix(p, "would write") || strings.HasPrefix(p, "source:") ||
			strings.HasPrefix(p, "trusted source:") {
			continue
		}
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths
}

// --- store helpers -----------------------------------------------------------

func storePath(dataDir string) string {
	return filepath.Join(dataDir, "store.db")
}

func openStore(t *testing.T, dataDir string) *sql.DB {
	t.Helper()
	dsn := storePath(dataDir) + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return db
}

// seedStore creates store.db with the real schema and one pre-existing scan row,
// so "no row inserted" is asserted against a live store rather than an absence
// of the file.
func seedStore(t *testing.T, dataDir, target string) {
	t.Helper()
	db := openStore(t, dataDir)
	defer db.Close() //nolint:errcheck // test cleanup

	ctx := context.Background()
	if err := sqlcgen.EnsureSchema(ctx, db); err != nil {
		t.Fatalf("EnsureSchema: %v", err)
	}
	q := sqlcgen.New(db)
	if _, err := q.CreateScan(ctx, sqlcgen.CreateScanParams{
		ID:                  uuid.New().String(),
		TargetID:            target,
		Mode:                "recon",
		Status:              "completed",
		StartedAt:           time.Now().Unix(),
		RawArgsJson:         "{}",
		ConfigOverridesJson: "{}",
		OutputDir:           dataDir,
	}); err != nil {
		t.Fatalf("seed CreateScan: %v", err)
	}
}

func countScans(t *testing.T, dataDir, whereStatus string) int {
	t.Helper()
	db := openStore(t, dataDir)
	defer db.Close() //nolint:errcheck // test cleanup

	query := "SELECT count(*) FROM scans"
	args := []any{}
	if whereStatus != "" {
		query += " WHERE status = ?"
		args = append(args, whereStatus)
	}
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("count scans: %v", err)
	}
	return n
}

// --- refresh-cache -----------------------------------------------------------

// TestRefreshCacheDryRunDeletesNothing is the T-15-12-02 regression: before the
// fix, invalidateCacheFiles ran at the top of runRefreshCacheCmd and the
// dry-run flag was only read afterwards, so --dry-run deleted the cache.
func TestRefreshCacheDryRunDeletesNothing(t *testing.T) {
	statefulTestEnv(t)
	dataDir := t.TempDir()
	const target = "example.com"

	seedWorkspace(t, dataDir, target, cacheFileFixture("keep"))
	before := snapshotTree(t, dataDir)
	if len(before) == 0 {
		t.Fatal("precondition: seeded workspace snapshot is empty")
	}

	if _, stderr, err := runStatefulCmd(t,
		"refresh-cache", "--target", target, "-o", dataDir, "--dry-run"); err != nil {
		t.Fatalf("refresh-cache --dry-run: %v\nstderr:\n%s", err, stderr)
	}

	assertNoneRemovedOrModified(t, before, snapshotTree(t, dataDir), "refresh-cache --dry-run")
}

// TestRefreshCacheDryRunPreviewMatchesDeletion is the T-15-12-04 drift guard:
// the set of paths the preview names must be exactly the set a real
// invalidation removes. Both come from planCacheInvalidation, and this test is
// what keeps them that way.
func TestRefreshCacheDryRunPreviewMatchesDeletion(t *testing.T) {
	statefulTestEnv(t)
	dataDir := t.TempDir()
	const target = "example.com"

	seedWorkspace(t, dataDir, target, cacheFileFixture("drift"))

	stdout, stderr, err := runStatefulCmd(t,
		"refresh-cache", "--target", target, "-o", dataDir, "--dry-run")
	if err != nil {
		t.Fatalf("refresh-cache --dry-run: %v\nstderr:\n%s", err, stderr)
	}
	previewed := parseDryRunPaths(stdout)
	if len(previewed) == 0 {
		t.Fatalf("dry-run preview listed no paths; stdout:\n%s", stdout)
	}

	// Now perform the real invalidation and diff the tree.
	before := snapshotTree(t, dataDir)
	cfg := config.Defaults()
	cfg.Paths.DataDir = dataDir
	if invErr := invalidateCacheFiles(cfg, target); invErr != nil {
		t.Fatalf("invalidateCacheFiles: %v", invErr)
	}
	after := snapshotTree(t, dataDir)

	var disappeared []string
	for rel := range before {
		if _, ok := after[rel]; !ok {
			disappeared = append(disappeared, filepath.Join(dataDir, rel))
		}
	}
	sort.Strings(disappeared)

	if strings.Join(previewed, "\n") != strings.Join(disappeared, "\n") {
		t.Errorf("dry-run preview drifted from the real deletion set\npreviewed:\n  %s\ndeleted:\n  %s",
			strings.Join(previewed, "\n  "), strings.Join(disappeared, "\n  "))
	}
}

// TestRefreshCacheHonoursOutputDirOverConfig is the T-15-12-05 regression:
// -o/--output must be applied before the cache path is computed, otherwise the
// command services the configured data_dir instead of the one the operator named.
func TestRefreshCacheHonoursOutputDirOverConfig(t *testing.T) {
	home := statefulTestEnv(t)
	configuredDir := t.TempDir()
	flagDir := t.TempDir()
	const target = "example.com"

	writeUserConfig(t, home, "[paths]\ndata_dir = "+strconvQuote(configuredDir)+"\n")

	seedWorkspace(t, configuredDir, target, cacheFileFixture("configured"))
	seedWorkspace(t, flagDir, target, cacheFileFixture("flag"))

	stdout, stderr, err := runStatefulCmd(t,
		"refresh-cache", "--target", target, "-o", flagDir, "--dry-run")
	if err != nil {
		t.Fatalf("refresh-cache --dry-run: %v\nstderr:\n%s", err, stderr)
	}

	previewed := parseDryRunPaths(stdout)
	if len(previewed) == 0 {
		t.Fatalf("dry-run preview listed no paths; stdout:\n%s", stdout)
	}
	for _, p := range previewed {
		if !strings.HasPrefix(p, flagDir) {
			t.Errorf("refresh-cache previewed %q, which is outside the -o dir %q — "+
				"the configured data_dir won over the flag", p, flagDir)
		}
	}
}

// --- quick-rescan ------------------------------------------------------------

// TestQuickRescanDryRunInsertsNoScanRow is the T-15-12-02 regression for the DB
// side: recordQuickRescanBaseline used to run before the dry-run flag was read,
// leaving a permanent scan row behind for a command that promised a preview.
func TestQuickRescanDryRunInsertsNoScanRow(t *testing.T) {
	statefulTestEnv(t)
	dataDir := t.TempDir()
	const target = "example.com"

	seedStore(t, dataDir, target)
	seedWorkspace(t, dataDir, target, nil)

	beforeCount := countScans(t, dataDir, "")
	if beforeCount != 1 {
		t.Fatalf("precondition: seeded store has %d scans, want 1", beforeCount)
	}

	if _, stderr, err := runStatefulCmd(t,
		"quick-rescan", "--target", target, "-o", dataDir, "--dry-run"); err != nil {
		t.Fatalf("quick-rescan --dry-run: %v\nstderr:\n%s", err, stderr)
	}

	if got := countScans(t, dataDir, ""); got != beforeCount {
		t.Errorf("quick-rescan --dry-run inserted %d scan row(s) (count %d -> %d)",
			got-beforeCount, beforeCount, got)
	}
	if got := countScans(t, dataDir, "running"); got != 0 {
		t.Errorf("quick-rescan --dry-run left %d scan row(s) in status 'running', want 0", got)
	}
}

// TestQuickRescanDryRunCreatesNoStore proves the dry run does not even bring
// store.db into existence. sql.Open against a missing SQLite file CREATES it,
// so "no row inserted" alone would have missed this.
func TestQuickRescanDryRunCreatesNoStore(t *testing.T) {
	statefulTestEnv(t)
	dataDir := t.TempDir()
	const target = "example.com"

	if _, stderr, err := runStatefulCmd(t,
		"quick-rescan", "--target", target, "-o", dataDir, "--dry-run"); err != nil {
		t.Fatalf("quick-rescan --dry-run: %v\nstderr:\n%s", err, stderr)
	}

	if _, err := os.Stat(storePath(dataDir)); err == nil {
		t.Errorf("quick-rescan --dry-run created %s", storePath(dataDir))
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat store.db: %v", err)
	}
}

// TestQuickRescanDryRunLeavesWorkspaceFilesIntact asserts the dry run neither
// deletes nor rewrites anything already in the workspace.
func TestQuickRescanDryRunLeavesWorkspaceFilesIntact(t *testing.T) {
	statefulTestEnv(t)
	dataDir := t.TempDir()
	const target = "example.com"

	seedWorkspace(t, dataDir, target, cacheFileFixture("quick"))
	before := snapshotTree(t, dataDir)

	if _, stderr, err := runStatefulCmd(t,
		"quick-rescan", "--target", target, "-o", dataDir, "--dry-run"); err != nil {
		t.Fatalf("quick-rescan --dry-run: %v\nstderr:\n%s", err, stderr)
	}

	assertNoneRemovedOrModified(t, before, snapshotTree(t, dataDir), "quick-rescan --dry-run")
}

// --- gen-resolvers -----------------------------------------------------------

// TestGenResolversDryRunWritesNothing is the T-15-12-02 regression for the
// command that never read the flag at all: RunGenResolvers MkdirAlls the
// resolver directory and writes (or downloads into) the resolver file.
func TestGenResolversDryRunWritesNothing(t *testing.T) {
	home := statefulTestEnv(t)

	before := snapshotTree(t, home)

	stdout, stderr, err := runStatefulCmd(t, "gen-resolvers", "--dry-run")
	if err != nil {
		t.Fatalf("gen-resolvers --dry-run: %v\nstderr:\n%s", err, stderr)
	}

	// The default resolver path lives under the isolated HOME.
	resolversPath := filepath.Join(home, ".config", "reconftw", "resolvers.txt")
	if _, statErr := os.Stat(resolversPath); statErr == nil {
		t.Errorf("gen-resolvers --dry-run wrote %s", resolversPath)
	} else if !os.IsNotExist(statErr) {
		t.Fatalf("stat resolvers.txt: %v", statErr)
	}

	after := snapshotTree(t, home)
	assertNoneRemovedOrModified(t, before, after, "gen-resolvers --dry-run")
	for rel := range after {
		if _, existed := before[rel]; !existed {
			t.Errorf("gen-resolvers --dry-run created %s", rel)
		}
	}

	if !strings.Contains(stdout, "would write") {
		t.Errorf("gen-resolvers --dry-run did not report the file it would write; stdout:\n%s", stdout)
	}
	if !strings.Contains(stdout, "source:") {
		t.Errorf("gen-resolvers --dry-run did not report its source; stdout:\n%s", stdout)
	}
}

// --- source-order guard ------------------------------------------------------

// TestStatefulDryRunReadPrecedesMutation automates the grep acceptance criterion
// from 15-12: in every one of the three RunE bodies the dry-run read must appear
// at a LOWER line number than the first mutation. Ordering IS the defect class
// here, so a source-order assertion is the honest form of this check — a
// behavioural test can only catch the orderings someone thought to exercise.
func TestStatefulDryRunReadPrecedesMutation(t *testing.T) {
	src, err := os.ReadFile("stateful_subcommands.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}

	cases := []struct {
		fn        string
		mutations []string
	}{
		{"runGenResolversCmd", []string{"resolvers.RunGenResolvers(", "handlers.RunCompositeAsync("}},
		{"runRefreshCacheCmd", []string{"invalidateCacheFiles(", "handlers.RunCompositeAsync("}},
		{"runQuickRescanCmd", []string{"recordQuickRescanBaseline(", "handlers.RunCompositeAsync("}},
	}

	for _, tc := range cases {
		body, ok := funcBody(string(src), tc.fn)
		if !ok {
			t.Errorf("%s: function body not found", tc.fn)
			continue
		}
		readIdx := strings.Index(body, "resolveDryRun(cmd)")
		if readIdx < 0 {
			t.Errorf("%s: does not read the dry-run flag at all", tc.fn)
			continue
		}
		for _, mutation := range tc.mutations {
			mutIdx := strings.Index(body, mutation)
			if mutIdx < 0 {
				continue // that mutation is not present in this function
			}
			if mutIdx < readIdx {
				t.Errorf("%s: %s appears BEFORE the dry-run read — a dry run would mutate",
					tc.fn, mutation)
			}
		}
	}
}

// funcBody returns the source text of the named top-level function, from its
// "func name(" header to the first line consisting of a single closing brace.
func funcBody(src, name string) (string, bool) {
	start := strings.Index(src, "\nfunc "+name+"(")
	if start < 0 {
		return "", false
	}
	rest := src[start+1:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		return rest, true
	}
	return rest[:end], true
}

// strconvQuote renders s as a TOML basic string. Written out rather than pulled
// from strconv so the escaping intent is explicit for a config-file literal.
func strconvQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// compile-time assertion that the helpers above are wired to the real cobra type.
var _ = func(cmd *cobra.Command) bool { return resolveDryRun(cmd) }
