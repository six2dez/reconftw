// toolsroot_test.go — paths.tools_dir and Config.ToolsRoot() (18-02 / RS-B).
//
// The tools root is the directory install.sh clones repo-based tools into —
// v1's ${tools}. It is a SEPARATE key from paths.data_dir on purpose: data_dir
// already means two different things in v2 (workspace root, and — via three
// module-local resolvers — tools root), and 17-06 recorded that guessing a third
// meaning "would put an unpredictable path on a command line".
package config_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// TestPathsToolsRootDefaultsToHomeTools: with the key unset, the resolver
// returns $HOME/Tools — the v1 default install.sh clones into.
func TestPathsToolsRootDefaultsToHomeTools(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory on this box: %v", err)
	}
	cfg := config.Defaults()
	if got, want := cfg.ToolsRoot(), filepath.Join(home, "Tools"); got != want {
		t.Errorf("ToolsRoot() = %q, want %q", got, want)
	}
	// The DEFAULT must not be baked into Defaults() itself: that struct is a
	// pure, host-independent snapshot compared byte-for-byte by the dry-run and
	// snapshot gates, and it is also what makes "the operator set it" and "we
	// guessed" distinguishable.
	if cfg.Paths.ToolsDir != "" {
		t.Errorf("Defaults().Paths.ToolsDir = %q, want \"\" — the $HOME default belongs in "+
			"ToolsRoot(), not in the host-independent defaults snapshot", cfg.Paths.ToolsDir)
	}
}

// TestPathsToolsRootHonoursConfiguredValue: an explicit key wins over the
// default, and is cleaned.
func TestPathsToolsRootHonoursConfiguredValue(t *testing.T) {
	cfg := config.Defaults()
	cfg.Paths.ToolsDir = "/opt/recon/tools/"
	if got, want := cfg.ToolsRoot(), "/opt/recon/tools"; got != want {
		t.Errorf("ToolsRoot() = %q, want %q", got, want)
	}
	cfg.Paths.ToolsDir = "   "
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home directory on this box: %v", err)
	}
	if got, want := cfg.ToolsRoot(), filepath.Join(home, "Tools"); got != want {
		t.Errorf("ToolsRoot() with a whitespace-only key = %q, want the default %q", got, want)
	}
}

// TestPathsToolsDirRejectsTraversal: the key carries the SAME nopath_traversal
// validator data_dir does (T-18-02-03). Without it, an operator-editable config
// value becomes a filesystem root that executables are resolved under.
func TestPathsToolsDirRejectsTraversal(t *testing.T) {
	cfg := config.Defaults()
	cfg.Paths.ToolsDir = "../../../../usr/bin"
	err := config.Validate(cfg)
	if err == nil {
		t.Fatalf("Validate(paths.tools_dir=%q) err = nil; want a traversal rejection — "+
			"this key becomes the root that executables are resolved under", cfg.Paths.ToolsDir)
	}
	if !strings.Contains(strings.ToLower(err.Error()), "tools_dir") &&
		!strings.Contains(err.Error(), "ToolsDir") {
		t.Errorf("Validate error does not name the offending key: %v", err)
	}

	cfg.Paths.ToolsDir = "/home/op/Tools"
	if err := config.Validate(cfg); err != nil {
		t.Errorf("Validate(paths.tools_dir=%q) err = %v; want nil", cfg.Paths.ToolsDir, err)
	}
}

// ---------------------------------------------------------------------------
// 18-06: the "exactly one tools-root resolver survives" assertion
// ---------------------------------------------------------------------------

// toolsRootProductionAllowlist names every PRODUCTION file permitted to compute
// a tools root of its own, with the reason it is allowed to.
//
// The list is exact: an entry that is not here fails, and an entry here that no
// longer matches also fails. 18-03 established that a one-directional list rots
// (a stale entry quietly excuses the next genuine one), so both directions bite.
var toolsRootProductionAllowlist = map[string]string{
	"internal/core/config/defaults.go": "Config.ToolsRoot() itself — THE resolver. Every other consumer " +
		"comes through it.",

	// DECLARED, NOT FIXED. 18-06 found this while asserting the residue and is
	// recording it rather than papering over it or silently fixing it.
	//
	// installer.toolsRepoDir() computes $HOME/Tools with NO reference to
	// paths.tools_dir. An operator who sets paths.tools_dir therefore has clones
	// INSTALLED into $HOME/Tools while ToolRegistry.Discover LOOKS in the
	// configured root — the two disagree and the tool reports absent while
	// sitting on disk, which is the precise defect 18-02 existed to remove, one
	// component over.
	//
	// It is not fixed here because it is not a module-local resolver and the fix
	// is an INTERFACE change: Installer.Install(ctx, *backend.Tool) carries no
	// *config.Config, and clone_tool.go imports only core/backend. Threading
	// config through the installer interface is a Rule-4 architectural change,
	// and this plan's files_modified claims no installer file.
	//
	// FLIP CONDITION: when the installer interface gains the loaded *config.Config
	// (or a ToolsRoot string), toolsRepoDir() collapses onto Config.ToolsRoot()
	// and this entry is DELETED — at which point the stale direction below fails
	// until it is, which is the forcing function.
	"internal/installer/clone_tool.go": "installer.toolsRepoDir() — the INSTALL-side root. Declared, not " +
		"justified: it ignores paths.tools_dir. See the flip condition above.",
}

// toolsRootTestOccurrences pins the TEST files that name a tools root.
//
// These are realtools fixtures that deliberately point at the operator's real
// $HOME/Tools, which is legitimate — a real-tool test has to reach the real
// clones. They are pinned rather than ignored so a new one is a visible diff:
// an unpinned test-side resolver is how the production-side ones got written in
// the first place.
var toolsRootTestOccurrences = map[string]string{
	"internal/core/config/toolsroot_test.go":                 "asserts ToolsRoot()'s own $HOME/Tools default",
	"internal/core/backend/registry_seed_test.go":            "points a probe registry at the real clones",
	"internal/core/backend/registry_clone_realtools_test.go": "-tags realtools: drives the real regulator clone",
	"internal/modules/web/nomore403_realtools_test.go":       "-tags realtools: drives the real nomore403 clone",
}

// TestToolsRootHasNoModuleLocalRivals asserts that nothing outside the
// allowlist computes a tools root.
//
// # WHY THIS TEST EXISTS
//
// ToolsRoot()'s doc comment used to state, as settled fact, that three
// module-local copies "still exist" and that a later plan would collapse them.
// 18-05 deleted all three; the comment kept saying otherwise for a full plan,
// because a comment is checked by nobody. 18-06 corrected the prose AND wrote
// this, so the corrected version cannot rot the same way: the sentence "every
// consumer comes through this method" is now a failing test when it stops being
// true.
//
// # WHAT IT LOOKS FOR, AND WHY THAT SIGNAL
//
// The literal "Tools" — v1's ${tools} directory name, capital T. It is the one
// token every hand-rolled resolver in this tree has contained, and it is rare
// enough elsewhere to keep the signal clean. Comments are stripped first, for
// the reason 18-03 established: vulns/second_order.go carries the deleted join
// verbatim in a comment explaining why it was deleted, and a naive grep would
// report the removed code as still present.
func TestToolsRootHasNoModuleLocalRivals(t *testing.T) {
	root := repoRootForToolsRootScan(t)

	foundProd := map[string][]int{}
	foundTest := map[string][]int{}

	for _, dir := range []string{"internal", "cmd"} {
		walkGoFiles(t, filepath.Join(root, dir), func(rel string, lines []string) {
			for i, line := range lines {
				code := stripLineComment(line)
				if !isToolsRootExpression(code) {
					continue
				}
				if strings.HasSuffix(rel, "_test.go") {
					foundTest[rel] = append(foundTest[rel], i+1)
				} else {
					foundProd[rel] = append(foundProd[rel], i+1)
				}
			}
		})
	}

	t.Logf("TOOLSROOT_RESOLVERS production=%d test=%d", len(foundProd), len(foundTest))

	// Forward: an undeclared production resolver.
	for file, lines := range foundProd {
		if _, ok := toolsRootProductionAllowlist[file]; !ok {
			t.Errorf("%s (lines %v) computes a tools root of its own and is NOT on the allowlist.\n"+
				"  Config.ToolsRoot() is the single resolver; a second opinion about where the tools\n"+
				"  live means an operator who sets paths.tools_dir has one component looking in the\n"+
				"  configured root and another in $HOME/Tools. Route it through cfg.ToolsRoot(), or add\n"+
				"  it here WITH the reason and the condition that would remove it.", file, lines)
		}
	}
	// Stale: a declared resolver that is gone. The direction 18-03 proved matters.
	for file, why := range toolsRootProductionAllowlist {
		if _, ok := foundProd[file]; !ok {
			t.Errorf("%s is on the tools-root allowlist (%q) but no longer computes one.\n"+
				"  Delete the entry. A list that outlives its reason quietly excuses the next genuine\n"+
				"  rival — which is exactly how ToolsRoot()'s own doc comment stayed wrong for a plan.",
				file, why)
		}
	}

	// The module tree specifically must be EMPTY. 18-05 took it to zero and the
	// number this pins is zero, not "at most one": web.resolveToolsDir,
	// vulns.resolveToolsDirVulns and second_order.go's inline join are all gone.
	for file := range foundProd {
		if strings.HasPrefix(file, "internal/modules/") {
			t.Errorf("%s is a MODULE-LOCAL tools-root resolver. 18-05 deleted the last three and the "+
				"count is pinned at zero.", file)
		}
	}

	// Test-side occurrences are pinned, not forbidden.
	for file := range foundTest {
		if _, ok := toolsRootTestOccurrences[file]; !ok {
			t.Errorf("%s names a tools root and is not pinned in toolsRootTestOccurrences.\n"+
				"  Test-side roots are allowed (a real-tool test must reach the real clones) but they\n"+
				"  are PINNED, because an unpinned test resolver is how the production ones started.",
				file)
		}
	}
	for file, why := range toolsRootTestOccurrences {
		if _, ok := foundTest[file]; !ok {
			t.Errorf("%s is pinned as a test-side tools root (%q) but no longer names one — delete "+
				"the entry.", file, why)
		}
	}
}

// repoRootForToolsRootScan walks up from the package directory to the module
// root (the directory holding go.mod).
func repoRootForToolsRootScan(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate the module root (no go.mod found walking up from the test's cwd)")
	return ""
}

// walkGoFiles calls fn for every .go file under dir, with the path relative to
// the module root and the file split into lines.
func walkGoFiles(t *testing.T, dir string, fn func(rel string, lines []string)) {
	t.Helper()
	root := repoRootForToolsRootScan(t)
	seen := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		data, readErr := os.ReadFile(path) //nolint:gosec // repo-relative source scan
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			rel = path
		}
		seen++
		fn(filepath.ToSlash(rel), strings.Split(string(data), "\n"))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", dir, err)
	}
	if seen == 0 {
		t.Fatalf("walked %s and found ZERO .go files — a scan that reads nothing reports a clean "+
			"tree, which is the false green this guard exists to avoid", dir)
	}
}

// isToolsRootExpression reports whether a comment-stripped line of Go source
// computes a path whose element is v1's "Tools" directory.
//
// # WHY THE SECOND CONDITION
//
// The first version of this guard matched the bare literal `"Tools"` and it
// reported FOUR false positives on its very first run — which is why it was run
// before being trusted rather than reasoned about:
//
//	internal/core/appctx/appctx_test.go:65        "Tools" in a reflect field-name list
//	internal/modules/silent_success_test.go:822   inner.Sel.Name == "Tools"  (AST match on app.Tools)
//	internal/modules/stream_contract_test.go:524  the same
//
// In all three, "Tools" is an IDENTIFIER — the AppContext field every module
// dispatches through — not a path element. A guard that fires on the correct
// pattern is worse than no guard, because it gets weakened until it stops
// firing at all. Requiring a path join or a home lookup on the same line keeps
// every real resolver (all six on this tree carry filepath.Join) and drops all
// three identifier cases.
func isToolsRootExpression(code string) bool {
	if !strings.Contains(code, `"Tools"`) {
		return false
	}
	return strings.Contains(code, "Join(") ||
		strings.Contains(code, "HOME") ||
		strings.Contains(code, "UserHomeDir")
}

// stripLineComment removes a trailing // comment, respecting string literals so
// a `"http://x"` inside code is not mistaken for the start of one.
func stripLineComment(line string) string {
	inStr := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		if inStr {
			if c == '\\' {
				i++
				continue
			}
			if c == quote {
				inStr = false
			}
			continue
		}
		switch c {
		case '"', '`', '\'':
			inStr = true
			quote = c
		case '/':
			if i+1 < len(line) && line[i+1] == '/' {
				return line[:i]
			}
		}
	}
	return line
}
