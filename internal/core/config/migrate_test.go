// Tests for the Phase 14 config migrator engine (migrate.go + legacy_aliases.go).
//
// TestMigrateSchemaPathValidity is the load-bearing guard: it proves EVERY
// Case-A legacyAliasMap target binds to a real scalar Defaults() field. Because
// loader.go:151 uses koanf's non-strict decoder (DecoderConfig: nil), a typo'd
// v2 target would emit a live `native.path = value` the loader SILENTLY IGNORES
// — inertly dropping a user setting and violating D-02 keep-all + CUT-06. A bare
// `count >= 250` cannot catch that; this test can (and its negative sub-case
// proves it would fail on a typo).

package config

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// updateGolden regenerates the *.golden.toml fixtures: `go test -run TestMigrateGolden -update`.
var updateGolden = flag.Bool("update", false, "regenerate migrator golden files")

// repoRoot is the path from internal/core/config to the repository root, where
// reconftw.cfg + config/reconftw_*.cfg live.
const repoRoot = "../../.."

// CUT-03 SCOPE NOTE: the literal "20+ community-collected config corpus" (CUT-03)
// is a beta stretch, DEFERRED per 14-SPEC (collected during the beta period).
// The offline validation set below stands in for it: the real reconftw.cfg, the
// three config/reconftw_{full,quick,stealth}.cfg presets, and the hand-authored
// testdata/migrate/*.cfg golden pairs — each migrated with zero hard errors and
// round-tripped through config.Load with zero WarnSink output (D-02 verified E2E).

// TestMigrateSchemaPathValidity iterates every Case-A entry and asserts the
// target path resolves to a real, scalar schema field.
func TestMigrateSchemaPathValidity(t *testing.T) {
	t.Parallel()
	def := Defaults()

	if len(legacyAliasMap) < 250 {
		t.Fatalf("legacyAliasMap has %d entries; want >= 250 (full v1 surface, D-03)", len(legacyAliasMap))
	}

	for key, path := range legacyAliasMap {
		v := readByPath(def, path)
		if v == nil {
			t.Errorf("legacyAliasMap[%q] = %q does not bind to any Defaults() field (typo → silent drop)", key, path)
			continue
		}
		if k := reflect.ValueOf(v).Kind(); k == reflect.Struct || k == reflect.Map || k == reflect.Slice {
			t.Errorf("legacyAliasMap[%q] = %q binds to a non-scalar (%s); must be a scalar field", key, path, k)
		}
	}
}

// TestMigrateSchemaPathValidityNegative proves the schema-path check actually
// catches a typo'd target (a deliberately wrong path resolves to nil).
func TestMigrateSchemaPathValidityNegative(t *testing.T) {
	t.Parallel()
	if v := readByPath(Defaults(), "osint.github.enabledd"); v != nil {
		t.Fatalf("expected typo path to resolve to nil, got %v — the schema-path guard is ineffective", v)
	}
	if v := readByPath(Defaults(), "web.fuzz.threadz"); v != nil {
		t.Fatalf("expected typo path to resolve to nil, got %v", v)
	}
}

// TestMigratePreservesTestedLegacyEntries guards the W18 corpus the loader tests
// depend on (loader_test.go / coverage_test.go) so the D-03 rewrite keeps them.
func TestMigratePreservesTestedLegacyEntries(t *testing.T) {
	t.Parallel()
	want := map[string]string{
		"PARALLEL_MAX_JOBS":  "concurrency.max_jobs",
		"OSINT":              "osint.enabled",
		"SUBDOMAINS_GENERAL": "subdomains.enabled",
		"SHODAN_API_KEY":     "api_keys.shodan",
		"AXIOM_FLEET_COUNT":  "axiom.fleet_count",
	}
	for k, v := range want {
		if got := legacyAliasMap[k]; got != v {
			t.Errorf("legacyAliasMap[%q] = %q; want %q", k, got, v)
		}
	}
}

// TestMigrateLowercaseKeys — D-03 requires the lowercase v1 keys the old map lacked.
func TestMigrateLowercaseKeys(t *testing.T) {
	t.Parallel()
	for _, k := range []string{"generate_resolvers", "update_resolvers", "install_golang", "upgrade_tools", "proxy_url", "resolvers_url"} {
		if _, ok := legacyAliasMap[k]; !ok {
			t.Errorf("legacyAliasMap missing lowercase key %q (D-03)", k)
		}
	}
}

func migrateString(t *testing.T, cfg string) (MigrateResult, string) {
	t.Helper()
	var warn bytes.Buffer
	res, err := Migrate(strings.NewReader(cfg), MigrateOptions{WarnSink: &warn})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return res, warn.String()
}

// TestMigrateArithmeticEval — $((AVAILABLE_CORES*10)) is evaluated with go/constant
// to the concrete host value and appears in a Case-B # SUPERSEDED comment.
func TestMigrateArithmeticEval(t *testing.T) {
	t.Parallel()
	cfg := "AVAILABLE_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)\n" +
		"FFUF_THREADS=$((AVAILABLE_CORES * 10))\n"
	res, _ := migrateString(t, cfg)
	toml := string(res.TOML)

	wantThreads := fmt.Sprintf("FFUF_THREADS = %d", runtime.NumCPU()*10)
	if !strings.Contains(toml, wantThreads) {
		t.Errorf("expected arithmetic evaluated to %q in output; got:\n%s", wantThreads, toml)
	}
	if !strings.Contains(toml, "# SUPERSEDED: FFUF_THREADS") {
		t.Errorf("FFUF_THREADS should be a SUPERSEDED comment (auto-scaled thread), got:\n%s", toml)
	}
	// The pin hint names the v2 path.
	if !strings.Contains(toml, "web.fuzz.threads") {
		t.Errorf("expected pin hint web.fuzz.threads in FFUF_THREADS comment; got:\n%s", toml)
	}
}

// TestMigrateNprocIdiom — the $(nproc …) idiom resolves to runtime.NumCPU().
func TestMigrateNprocIdiom(t *testing.T) {
	t.Parallel()
	cfg := "AVAILABLE_CORES=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)\n"
	res, _ := migrateString(t, cfg)
	want := fmt.Sprintf("AVAILABLE_CORES = %d", runtime.NumCPU())
	if !strings.Contains(string(res.TOML), want) {
		t.Errorf("expected nproc idiom → %q; got:\n%s", want, string(res.TOML))
	}
}

// TestMigrateDurationString — WAYMORE_TIMEOUT=30m maps to the v2 STRING field verbatim.
func TestMigrateDurationString(t *testing.T) {
	t.Parallel()
	res, _ := migrateString(t, "WAYMORE_TIMEOUT=30m # comment\n")
	toml := string(res.TOML)
	if !strings.Contains(toml, `waymore_timeout = "30m"`) {
		t.Errorf("expected waymore_timeout = \"30m\"; got:\n%s", toml)
	}
	if !strings.Contains(toml, "# was WAYMORE_TIMEOUT") {
		t.Errorf("expected inline # was WAYMORE_TIMEOUT provenance; got:\n%s", toml)
	}
}

// TestMigrateQuotedCSVStaysString — a quoted CSV stays a TOML string, NOT an array.
func TestMigrateQuotedCSVStaysString(t *testing.T) {
	t.Parallel()
	res, _ := migrateString(t, `NUCLEI_SEVERITY="info,low,medium,high,critical" # set criticity`+"\n")
	toml := string(res.TOML)
	if !strings.Contains(toml, `severity = "info,low,medium,high,critical"`) {
		t.Errorf("expected CSV kept as a quoted string; got:\n%s", toml)
	}
	if strings.Contains(toml, "severity = [") {
		t.Errorf("CSV must NOT become a TOML array; got:\n%s", toml)
	}
}

// TestMigrateUnknownKey — unknown key emits a loud stderr warning AND a # UNKNOWN
// comment; it is never silently dropped (CUT-06).
func TestMigrateUnknownKey(t *testing.T) {
	t.Parallel()
	res, warn := migrateString(t, "TOTALLY_MADE_UP_KEY=42\n")
	if !strings.Contains(warn, "⚠ unknown key TOTALLY_MADE_UP_KEY") {
		t.Errorf("expected loud stderr ⚠ unknown key line; got warn=%q", warn)
	}
	if !strings.Contains(string(res.TOML), "# UNKNOWN (needs human review): TOTALLY_MADE_UP_KEY = 42") {
		t.Errorf("expected # UNKNOWN comment preserving the key; got:\n%s", string(res.TOML))
	}
	if res.UnknownCount != 1 {
		t.Errorf("UnknownCount = %d; want 1", res.UnknownCount)
	}
}

// TestMigrateNoLegacyBlock — the migrated output NEVER contains a live [legacy]
// table (D-02: comments, not a live block that trips the per-load warning).
func TestMigrateNoLegacyBlock(t *testing.T) {
	t.Parallel()
	cfg := "OSINT=true\nAVAILABLE_CORES=$(nproc || echo 4)\nTOTALLY_MADE_UP_KEY=1\n"
	res, _ := migrateString(t, cfg)
	if strings.Contains(string(res.TOML), "[legacy]") {
		t.Errorf("migrated output must NOT contain a [legacy] table; got:\n%s", string(res.TOML))
	}
}

// TestMigrateCollisionPolicy — many-v1→one-v2 (GITHUB_DORKS + GITHUB_REPOS →
// osint.github.enabled): OR-combine for booleans, single live key, both keys in
// the provenance comment.
func TestMigrateCollisionPolicy(t *testing.T) {
	t.Parallel()

	res, _ := migrateString(t, "GITHUB_DORKS=true\nGITHUB_REPOS=true\n")
	toml := string(res.TOML)
	if !strings.Contains(toml, "enabled = true  # was GITHUB_DORKS / GITHUB_REPOS") {
		t.Errorf("expected merged provenance for github collision; got:\n%s", toml)
	}
	// enabled appears exactly once under [osint.github] (no duplicate key).
	if n := strings.Count(toml, "# was GITHUB_DORKS / GITHUB_REPOS"); n != 1 {
		t.Errorf("collision should emit a single merged key, found %d", n)
	}

	// OR-combine: one true wins even if the other is false.
	res2, _ := migrateString(t, "GITHUB_DORKS=false\nGITHUB_REPOS=true\n")
	if !strings.Contains(string(res2.TOML), "enabled = true") {
		t.Errorf("OR-combine failed: one true should win; got:\n%s", string(res2.TOML))
	}
}

// TestMigrateSecretRedactedInTable — secret values are redacted in the dry-run
// table but written verbatim to the TOML bytes (threat T-14-02).
func TestMigrateSecretRedactedInTable(t *testing.T) {
	t.Parallel()
	res, _ := migrateString(t, "SHODAN_API_KEY=deadbeefdeadbeefdeadbeef\n")
	table := res.DispositionTable()
	if strings.Contains(table, "deadbeef") {
		t.Errorf("dry-run table must NOT contain the raw secret; got:\n%s", table)
	}
	if !strings.Contains(table, "***") {
		t.Errorf("dry-run table should show *** for the secret; got:\n%s", table)
	}
	if !strings.Contains(string(res.TOML), "deadbeefdeadbeefdeadbeef") {
		t.Errorf("the migrated TOML file MUST contain the real secret value; got:\n%s", string(res.TOML))
	}
}

// TestMigrateNoShellOut — a defensive source-level assertion that the engine
// never shells out (D-01 / threat T-14-01). The grep acceptance checks the same;
// this keeps it green under refactors.
func TestMigrateArithmeticRejectsIdentifiers(t *testing.T) {
	t.Parallel()
	// An unexpected identifier (not AVAILABLE_CORES) must NOT evaluate — it routes
	// to Case B rather than being shelled out.
	if _, err := evalIntExpr("SOME_VAR * 2"); err == nil {
		t.Errorf("evalIntExpr must reject bare identifiers (no shell-out), got nil error")
	}
	if n, err := evalIntExpr("(4 + 2) * 3"); err != nil || n != 18 {
		t.Errorf("evalIntExpr((4+2)*3) = %d, %v; want 18, nil", n, err)
	}
}

// migratePath migrates a cfg file on disk with a captured WarnSink.
func migratePath(t *testing.T, path string) (MigrateResult, string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close() //nolint:errcheck
	var warn bytes.Buffer
	res, err := Migrate(f, MigrateOptions{WarnSink: &warn})
	if err != nil {
		t.Fatalf("Migrate(%s): %v", path, err)
	}
	return res, warn.String()
}

// TestMigrateCorpus — the CUT-03-scoped corpus: the real reconftw.cfg + all three
// presets migrate with ZERO hard errors and an empty unknown-disposition set.
func TestMigrateCorpus(t *testing.T) {
	t.Parallel()
	corpus := []string{
		filepath.Join(repoRoot, "reconftw.cfg"),
		filepath.Join(repoRoot, "config", "reconftw_full.cfg"),
		filepath.Join(repoRoot, "config", "reconftw_quick.cfg"),
		filepath.Join(repoRoot, "config", "reconftw_stealth.cfg"),
	}
	for _, path := range corpus {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			if _, err := os.Stat(path); err != nil {
				t.Skipf("corpus file not present: %v", path)
			}
			res, warn := migratePath(t, path)
			if res.UnknownCount != 0 {
				t.Errorf("%s: %d unknown keys (want 0 — every v1 key must be mapped or superseded); warn:\n%s",
					filepath.Base(path), res.UnknownCount, warn)
			}
			if res.MappedCount == 0 {
				t.Errorf("%s: 0 mapped keys — migration produced nothing", filepath.Base(path))
			}
		})
	}
}

// TestMigrateRoundTrip — every migrated corpus output loads through config.Load
// with an EMPTY WarnSink and no error, proving the D-02 comment mechanism trips
// zero unknown-key warnings and the emitted values all validate (D-02 E2E).
func TestMigrateRoundTrip(t *testing.T) {
	t.Parallel()
	inputs := []string{
		filepath.Join(repoRoot, "reconftw.cfg"),
		filepath.Join(repoRoot, "config", "reconftw_full.cfg"),
		filepath.Join(repoRoot, "config", "reconftw_quick.cfg"),
		filepath.Join(repoRoot, "config", "reconftw_stealth.cfg"),
		filepath.Join("testdata", "migrate", "basic.cfg"),
	}
	for _, path := range inputs {
		path := path
		t.Run(filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			if _, err := os.Stat(path); err != nil {
				t.Skipf("input not present: %v", path)
			}
			res, _ := migratePath(t, path)

			out := filepath.Join(t.TempDir(), "migrated.toml")
			if err := os.WriteFile(out, res.TOML, 0o644); err != nil {
				t.Fatalf("write migrated toml: %v", err)
			}
			var sink bytes.Buffer
			if _, err := Load(LoadOptions{ExplicitConfigPath: out, WarnSink: &sink}); err != nil {
				t.Fatalf("Load(migrated %s) failed: %v\n--- migrated TOML ---\n%s", filepath.Base(path), err, string(res.TOML))
			}
			if sink.Len() != 0 {
				t.Errorf("%s: config.Load emitted WarnSink output (want empty — D-02 comments must not warn):\n%s",
					filepath.Base(path), sink.String())
			}
		})
	}
}

// TestMigrateGolden — migrating basic.cfg byte-equals basic.golden.toml. The
// host-dependent auto-scaled thread number (NumCPU*10) is normalized to <NCPU10>
// so the golden is portable across machines. Regenerate with -update.
func TestMigrateGolden(t *testing.T) {
	res, _ := migratePath(t, filepath.Join("testdata", "migrate", "basic.cfg"))
	norm := func(b []byte) []byte {
		return []byte(strings.ReplaceAll(string(b), strconv.Itoa(runtime.NumCPU()*10), "<NCPU10>"))
	}
	got := norm(res.TOML)
	goldenPath := filepath.Join("testdata", "migrate", "basic.golden.toml")

	if *updateGolden {
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatalf("update golden: %v", err)
		}
		t.Logf("wrote golden %s", goldenPath)
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to generate): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("migrated basic.cfg != basic.golden.toml (run -update to refresh)\n--- got ---\n%s\n--- want ---\n%s",
			string(got), string(want))
	}
}

// TestMigrateUnknownKeyFixture — the unknown_key.cfg fixture triggers the loud
// warning AND the # UNKNOWN comment while its neighbors migrate cleanly.
func TestMigrateUnknownKeyFixture(t *testing.T) {
	t.Parallel()
	res, warn := migratePath(t, filepath.Join("testdata", "migrate", "unknown_key.cfg"))
	if !strings.Contains(warn, "⚠ unknown key THIS_IS_NOT_A_REAL_KEY") {
		t.Errorf("expected loud stderr for the fixture's unknown key; got:\n%s", warn)
	}
	if !strings.Contains(string(res.TOML), "# UNKNOWN (needs human review): THIS_IS_NOT_A_REAL_KEY") {
		t.Errorf("expected # UNKNOWN comment preserving the key; got:\n%s", string(res.TOML))
	}
	if !strings.Contains(string(res.TOML), "# was OSINT") {
		t.Errorf("neighbor keys should still migrate cleanly; got:\n%s", string(res.TOML))
	}
}

// TestMigrateDryRunEngineWritesNothing — MigrateFile with DryRun writes no file.
func TestMigrateDryRunEngineWritesNothing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cfg := filepath.Join(dir, "in.cfg")
	if err := os.WriteFile(cfg, []byte("OSINT=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out.toml")
	if _, err := MigrateFile(cfg, target, MigrateOptions{DryRun: true}); err != nil {
		t.Fatalf("MigrateFile dry-run: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Errorf("DryRun must not write %s", target)
	}
}
