// SPDX-License-Identifier: MIT
//
// bypasses_test.go — the corroboration engine for the FOUND-10 bypass manifest
// (plan 18-03, RS-C).
//
// The manifest DATA lives in bypasses.go (package lint). The PREDICATES and the
// gate live here, in the external test package, so that walking syntax trees
// with golang.org/x/tools/go/packages stays a test-only dependency and the
// production build graph is unchanged.
//
// Each Reason in lint's closed vocabulary has exactly one predicate below. A
// predicate returns the SET OF SCOPES (top-level declarations) in the declared
// file whose dispatch sites that reason explains — not a bare bool — because a
// file with two dispatch shapes must declare both, and a set lets the gate check
// that the declared reasons COVER EVERY SITE rather than merely being evidenced
// somewhere in the file.
//
// FOUR FAILURE MODES, each proven to fire against testdata/ fixtures:
//
//  1. unlisted     — a file with >=1 dispatch site and no manifest entry.
//  2. stale        — a manifest entry naming a file with ZERO sites.
//  3. count drift  — Sites != the walker's count, checked in BOTH directions.
//  4. bad reason   — a declared reason with no evidence, an unknown reason, or a
//     declared reason set that leaves some site unexplained.
package lint_test

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	tomlv2 "github.com/pelletier/go-toml/v2"
	"golang.org/x/tools/go/packages"

	"github.com/six2dez/reconftw/internal/core/backend/lint"
)

// -----------------------------------------------------------------------------
// The census, pinned.
// -----------------------------------------------------------------------------

// BYPASS_CENSUS pins. Same rule the arg-vector census states: A CHANGE TO EITHER
// CONSTANT MUST BE A VISIBLE DIFF WITH A WRITTEN REASON. Plans 18-04 and 18-05
// LOWER them in the same change that routes a file back onto backend.Runner;
// nothing may raise them without a new, corroborated manifest entry.
//
// Derived from the walker on 2026-08-26, not from a table:
//
//	12 module files (27 sites) + 2 installer files (3 sites) = 14 files, 30 sites.
//
// 18-04 LOWERED both, one file at a time, each with its reason:
//
//	14 -> 13 files, 30 -> 28 sites  internal/modules/web/gxss.go came home. Its
//	  only reason was `stdin`, and 18-01's ExecOptions.Stdin serves it directly.
//	  Two sites went (exec.CommandContext@GxssTask.Run + (*exec.Cmd).Run@GxssTask.Run).
//	13 -> 12 files, 28 -> 26 sites  internal/modules/web/hakoriginfinder.go — same
//	  `stdin`-only reason, same seam, two sites.
//	12 -> 11 files, 26 -> 24 sites  internal/modules/web/mantra.go — likewise.
//	11 -> 10 files, 24 -> 21 sites  internal/modules/vulns/xss.go — THREE sites,
//	  both of its shapes. dalfox pipe mode moved to StreamOpts (it exits non-zero
//	  when it HAS findings, so the buffered path would discard them); the Gxss
//	  reflection pre-pass moved to RunOpts. Note the pre-pass dispatched via
//	  gxssCmd.Output(), which the walker does NOT count — so of the three sites
//	  the census tracked, only two belonged to the two constructors and one to
//	  cmd.Start(). Moving it lowers the count by three regardless, because all
//	  three forbidden-pattern calls are gone from the file.
//	10 -> 9 files, 21 -> 19 sites   internal/modules/vulns/spray.go — brutus, the
//	  only site in the phase whose stdin is an open FILE, now ExecOptions.StdinPath.
//	  Its tools.lock deadline was reconciled in the same change (0 -> 1800).
//	9 -> 8 files, 19 -> 17 sites    internal/modules/web/shortscan.go — the one
//	  file in the manifest with NO technical reason at all. It carried
//	  `pending_removal` with HomeBy "18-04"; that entry is now gone, which is the
//	  expiry doing its job rather than a temporary exemption quietly becoming
//	  permanent. Two sites.
//
// TOTAL FOR 18-04: 14 -> 8 files, 30 -> 17 sites. Six files, THIRTEEN sites — not
// the "seven" the plan's prose table said, because the walker counts a chained
// `cmd := exec.CommandContext(...)` plus `cmd.Run()` as two. The walker wins over
// any table, including its own plan's; that rule is 18-03's and it held here.
// 18-05 lowers it again. Each line below is one file routed onto backend.Runner,
// with the count movement it caused. The rule is unchanged: remove the entry and
// lower BOTH pins in the SAME change, with the reason written down.
//
//	8 -> 7 files, 17 -> 15 sites  internal/modules/web/nomore403.go — the plan's
//	  tracer, and the only file in the phase that needed all THREE capabilities at
//	  once: an executable resolved from a repo clone (18-02 clone_dir/clone_entry),
//	  that clone as the working directory (18-02 clone_workdir -> Tool.WorkDir),
//	  and its 4xx candidates on standard input (18-01 ExecOptions.Stdin). Two sites.
//	7 -> 6 files, 15 -> 13 sites  internal/modules/vulns/bypass4xx.go — the SAME
//	  tool and the same two capabilities, moved in the same change on purpose so
//	  the two call sites stop resolving nomore403 independently.
//	6 -> 5 files, 13 -> 11 sites  internal/modules/web/jsa.go — the
//	  interpreter-plus-script shape, served by 18-02's clone_interpreter +
//	  clone_entry through Tool.ArgvPrefix.
//	5 files, 11 -> 9 sites        internal/modules/web/wordlistgen.go — THE FILE
//	  COUNT DOES NOT MOVE HERE, and that is the two-shape check working rather
//	  than a partial job. Its roboxtractor leg (stdin, 2 sites) came home; its
//	  getjswords leg (clone_path, 2 sites) is an ADJUDICATED surviving bypass — the
//	  interpreter is operator-configurable and the registry can only take one from
//	  the manifest, so declaring coordinates would silently override the operator.
//	  The entry's Reasons set shrank from [stdin clone_path] to [clone_path] in the
//	  same change; leaving `stdin` behind would have been the stale claim
//	  TestBypassReasonsAreCorroborated refuses.
//
//	5 -> 4 files, 9 -> 7 sites   internal/modules/vulns/ssrf.go — THE ADJUDICATION,
//	  and the one entry this phase inherited as "not obsolete". 18-03 recorded
//	  process_lifecycle as the reason 18-01 had NOT served. 18-05 tested that
//	  instead of inheriting it and it did not hold: Runner.StreamOpts +
//	  LocalBackend's Setpgid / group-SIGTERM / group-SIGKILL escalation serve the
//	  long-lived OOB session exactly. Proven by a real process with a
//	  SIGTERM-immune grandchild, and by MUTATION 5, which PASSED against the first
//	  fixture and forced it to be strengthened before the verdict was trusted.
//	4 -> 3 files, 7 -> 5 sites   internal/modules/osint/github_repos.go — THE OTHER
//	  ADJUDICATION. Its premise (git absent from tools.lock) was true; its
//	  rationale was not, because tools.lock already carries seven kind="system"
//	  base-system rows. git is registered and the clone of an untrusted repo is
//	  recorded with its RCE hardening visible.
//
// TOTAL FOR 18-05: 8 -> 3 files, 17 -> 5 sites. Five files, twelve sites.
//
// WHAT REMAINS, and it is the phase-end state 18-06 reconciles:
//
//	internal/modules/web/wordlistgen.go   clone_path          2 sites  (adjudicated)
//	internal/installer/installer.go       installer_toolchain 2 sites  (never expires)
//	internal/installer/probe.go           installer_toolchain 1 site   (never expires)
//
// THREE files, and only ONE of them is a module. No entry carries
// pending_removal. The two installer entries are the irreducible floor this
// census was deliberately designed to have (see infrastructureAllowlist's note
// on why the SEAM itself is not in the manifest), so "one module file left, and
// it is adjudicated with a flip condition" is what done looks like here.
const (
	bypassCensusFiles = 3
	bypassCensusSites = 5
)

// -----------------------------------------------------------------------------
// The infrastructure allowlist — DELIBERATELY SEPARATE from the manifest.
// -----------------------------------------------------------------------------

// infrastructureAllowlist holds the files that ARE the Runner seam and its own
// tests, as opposed to files that bypass it.
//
// WHY A SEPARATE LIST RATHER THAN MANIFEST ENTRIES (the choice the plan asked to
// be stated): the manifest's whole purpose is to be a shrinking census of work
// still owed. local.go's four dispatch sites are the seam's implementation and
// will never "come home" — folding them in would put 4 permanent sites into a
// number that 18-04/18-05/18-06 are supposed to drive toward zero, and a census
// with an irreducible floor cannot express "done". They are also not subject to
// corroboration: there is no reason to state, because they are not exceptions.
//
// Suffix-match for `.go` entries (exact file); prefix-match for entries ending
// in `/` (directory tree). Matched against the repo-relative path.
var infrastructureAllowlist = []string{
	"internal/core/backend/local.go",            // THE Backend.ExecOpts / StreamOpts call site
	"internal/core/backend/local_test.go",       // exercises LocalBackend
	"internal/core/backend/local_smoke_test.go", // FOUND-09 kill-tree smoke test
	"internal/core/backend/registry.go",         // exec.LookPath (Discover path resolution)
	"internal/core/backend/registry_test.go",    // exercises Discover
	"internal/core/testutil/",                   // mock backends + test fixtures
	"internal/core/backend/lint/testdata/",      // fixtures used to validate the scanner
}

func isInfrastructure(repoRelPath string) bool {
	for _, entry := range infrastructureAllowlist {
		if strings.HasSuffix(entry, "/") {
			if strings.HasPrefix(repoRelPath, entry) {
				return true
			}
		} else if repoRelPath == entry || strings.HasSuffix(repoRelPath, "/"+entry) {
			return true
		}
	}
	return false
}

// isAllowed is the FOUND-10 walker's gate (no_raw_subprocess_test.go). A file is
// permitted to dispatch directly when it is infrastructure OR when it carries a
// manifest entry. Unlike the string allowlist it replaced, a manifest entry is
// not self-certifying: TestBypassManifestGate independently checks that the
// entry's reasons are corroborated and its site count is exact.
func isAllowed(repoRelPath string) bool {
	if isInfrastructure(repoRelPath) {
		return true
	}
	for _, b := range lint.Bypasses {
		if b.File == repoRelPath {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------------
// The walker: dispatch sites, scoped to their enclosing top-level declaration.
// -----------------------------------------------------------------------------

// dispatchSite is one direct subprocess dispatch found by the AST walker. It
// carries the enclosing TOP-LEVEL DECLARATION name ("scope") so a reason can be
// attributed to the shape it actually explains. A package-level
// `var fooRunner = func(...)` is its own scope, which is exactly the granularity
// the module tree uses for its overridable runner seams.
type dispatchSite struct {
	Rel   string
	Line  int
	Col   int
	Call  string
	Scope string
}

// bypassFile is one loaded Go file plus the dispatch sites found inside it.
type bypassFile struct {
	Rel   string
	Pkg   *packages.Package
	Syn   *ast.File
	Sites []dispatchSite
}

// scopesWithSites returns the set of scopes in this file that contain at least
// one dispatch site.
func (f *bypassFile) scopesWithSites() scopeSet {
	out := scopeSet{}
	for _, s := range f.Sites {
		out[s.Scope] = true
	}
	return out
}

// declScopeName returns a stable name for a top-level declaration, used as the
// attribution unit for reasons.
func declScopeName(d ast.Decl) string {
	switch decl := d.(type) {
	case *ast.FuncDecl:
		if decl.Recv != nil && len(decl.Recv.List) > 0 {
			return recvTypeName(decl.Recv.List[0].Type) + "." + decl.Name.Name
		}
		return decl.Name.Name
	case *ast.GenDecl:
		for _, spec := range decl.Specs {
			if vs, ok := spec.(*ast.ValueSpec); ok && len(vs.Names) > 0 {
				return vs.Names[0].Name
			}
		}
	}
	return "<decl>"
}

func recvTypeName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		return recvTypeName(t.X)
	case *ast.Ident:
		return t.Name
	}
	return "?"
}

// isCmdTyped reports whether expr's resolved type is *os/exec.Cmd.
//
// This resolves the TYPE through pkg.TypesInfo. It deliberately does NOT match
// on an identifier spelled "cmd": an identifier match would pass on any variable
// a developer happened to name `cmd` and would MISS the real receiver at
// vulns/xss.go:291, which is named `gxssCmd`.
func isCmdTyped(pkg *packages.Package, expr ast.Expr) bool {
	if pkg.TypesInfo == nil {
		return false
	}
	tv, ok := pkg.TypesInfo.Types[expr]
	if !ok || tv.Type == nil {
		return false
	}
	t := tv.Type
	if ptr, ok := t.(*types.Pointer); ok {
		t = ptr.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok {
		return false
	}
	obj := named.Obj()
	return obj != nil && obj.Pkg() != nil &&
		obj.Pkg().Path() == "os/exec" && obj.Name() == "Cmd"
}

// isExecConstructor reports whether call is exec.Command / exec.CommandContext.
func isExecConstructor(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	ident, ok := sel.X.(*ast.Ident)
	if !ok || ident.Name != "exec" {
		return "", false
	}
	if sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext" {
		return "exec." + sel.Sel.Name, true
	}
	return "", false
}

// execProgramAndArgs splits an exec.Command / exec.CommandContext call into the
// program expression and the argument expressions, accounting for the leading
// context argument of CommandContext.
func execProgramAndArgs(call *ast.CallExpr, name string) (ast.Expr, []ast.Expr) {
	args := call.Args
	if name == "exec.CommandContext" {
		if len(args) < 2 {
			return nil, nil
		}
		return args[1], args[2:]
	}
	if len(args) < 1 {
		return nil, nil
	}
	return args[0], args[1:]
}

// collectDispatchSites walks every loaded package and returns the loaded files
// keyed by repo-relative path, each carrying its dispatch sites.
//
// The forbidden patterns are IDENTICAL to the FOUND-10 walker in
// no_raw_subprocess_test.go: exec.Command, exec.CommandContext,
// (*exec.Cmd).Run, (*exec.Cmd).Start.
func collectDispatchSites(pkgs []*packages.Package, repoRoot string) map[string]*bypassFile {
	out := map[string]*bypassFile{}
	for _, pkg := range pkgs {
		for i, syn := range pkg.Syntax {
			if i >= len(pkg.GoFiles) {
				continue
			}
			rel, err := filepath.Rel(repoRoot, pkg.GoFiles[i])
			if err != nil {
				rel = pkg.GoFiles[i]
			}
			rel = filepath.ToSlash(rel)

			bf := &bypassFile{Rel: rel, Pkg: pkg, Syn: syn}
			for _, decl := range syn.Decls {
				scope := declScopeName(decl)
				ast.Inspect(decl, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if name, ok := isExecConstructor(call); ok {
						pos := pkg.Fset.Position(call.Pos())
						bf.Sites = append(bf.Sites, dispatchSite{
							Rel: rel, Line: pos.Line, Col: pos.Column,
							Call: name, Scope: scope,
						})
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if sel.Sel.Name != "Run" && sel.Sel.Name != "Start" {
						return true
					}
					if !isCmdTyped(pkg, sel.X) {
						return true
					}
					pos := pkg.Fset.Position(call.Pos())
					bf.Sites = append(bf.Sites, dispatchSite{
						Rel: rel, Line: pos.Line, Col: pos.Column,
						Call: "(*exec.Cmd)." + sel.Sel.Name, Scope: scope,
					})
					return true
				})
			}
			sort.Slice(bf.Sites, func(a, b int) bool { return bf.Sites[a].Line < bf.Sites[b].Line })
			out[rel] = bf
		}
	}
	return out
}

// loadInternalPackages loads ./internal/... with types, exactly as the FOUND-10
// gate does.
func loadInternalPackages(t *testing.T, repoRoot string) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:   repoRoot,
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, "./internal/...")
	if err != nil {
		t.Fatalf("packages.Load: %v", err)
	}
	return pkgs
}

// -----------------------------------------------------------------------------
// Intra-file origin tracing (used by clone_path and non_recon_binary).
// -----------------------------------------------------------------------------

const originMaxDepth = 6

// assignedRHS finds, within decl, the right-hand expression bound to an
// identifier named name. For a multi-value assignment from a single call
// (`bin, err := exec.LookPath("git")`) it returns that call — the caller is
// interested in the call's identity, not its result index.
func assignedRHS(decl ast.Decl, name string) []ast.Expr {
	var out []ast.Expr
	if decl == nil {
		return out
	}
	ast.Inspect(decl, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || ident.Name != name {
				continue
			}
			if len(assign.Rhs) == len(assign.Lhs) {
				out = append(out, assign.Rhs[i])
			} else if len(assign.Rhs) == 1 {
				out = append(out, assign.Rhs[0])
			}
		}
		return true
	})
	return out
}

// paramIndex returns the positional index of a parameter named name in decl, or
// -1. Grouped parameters (`a, b string`) are flattened.
func paramIndex(decl ast.Decl, name string) int {
	fn, ok := decl.(*ast.FuncDecl)
	if !ok || fn.Type.Params == nil {
		return -1
	}
	idx := 0
	for _, field := range fn.Type.Params.List {
		if len(field.Names) == 0 {
			idx++
			continue
		}
		for _, n := range field.Names {
			if n.Name == name {
				return idx
			}
			idx++
		}
	}
	return -1
}

// callBindings returns, for every call to the function named fnName anywhere in
// the file, the argument expression at position idx paired with the top-level
// declaration that call appears in.
func callBindings(f *bypassFile, fnName string, idx int) []struct {
	Expr ast.Expr
	Decl ast.Decl
} {
	var out []struct {
		Expr ast.Expr
		Decl ast.Decl
	}
	for _, decl := range f.Syn.Decls {
		d := decl
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			ident, ok := call.Fun.(*ast.Ident)
			if !ok || ident.Name != fnName {
				return true
			}
			if idx < len(call.Args) {
				out = append(out, struct {
					Expr ast.Expr
					Decl ast.Decl
				}{call.Args[idx], d})
			}
			return true
		})
	}
	return out
}

// tracesToFilepathJoin reports whether expr's value originates from a
// filepath.Join call, following (a) local assignments in decl and (b) the
// bindings of decl's parameters at every call site of decl in the same file.
//
// (b) is what makes shortscan.go FAIL this predicate and jsa.go PASS it: both
// dispatch a path held in a function parameter, but shortscan's parameter is
// bound from exec.LookPath in Run and jsa's is bound from filepath.Join.
func tracesToFilepathJoin(f *bypassFile, expr ast.Expr, decl ast.Decl, depth int) bool {
	if expr == nil || depth > originMaxDepth {
		return false
	}
	switch e := expr.(type) {
	case *ast.CallExpr:
		if sel, ok := e.Fun.(*ast.SelectorExpr); ok {
			if x, ok := sel.X.(*ast.Ident); ok && x.Name == "filepath" && sel.Sel.Name == "Join" {
				return true
			}
		}
		return false
	case *ast.Ident:
		for _, rhs := range assignedRHS(decl, e.Name) {
			if tracesToFilepathJoin(f, rhs, decl, depth+1) {
				return true
			}
		}
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if idx := paramIndex(decl, e.Name); idx >= 0 {
				for _, b := range callBindings(f, fn.Name.Name, idx) {
					if tracesToFilepathJoin(f, b.Expr, b.Decl, depth+1) {
						return true
					}
				}
			}
		}
		return false
	}
	return false
}

// resolveProgramName resolves an exec program expression to the literal tool
// name it will dispatch, following string literals, exec.LookPath arguments,
// local assignments and parameter bindings. Returns "" when it cannot resolve.
func resolveProgramName(f *bypassFile, expr ast.Expr, decl ast.Decl, depth int) string {
	if expr == nil || depth > originMaxDepth {
		return ""
	}
	switch e := expr.(type) {
	case *ast.BasicLit:
		if s, err := strconv.Unquote(e.Value); err == nil {
			return s
		}
		return ""
	case *ast.CallExpr:
		sel, ok := e.Fun.(*ast.SelectorExpr)
		if !ok {
			return ""
		}
		x, ok := sel.X.(*ast.Ident)
		if !ok {
			return ""
		}
		// exec.LookPath("git") — the argument IS the tool name.
		if x.Name == "exec" && sel.Sel.Name == "LookPath" && len(e.Args) == 1 {
			return resolveProgramName(f, e.Args[0], decl, depth+1)
		}
		// filepath.Join(..., "getjswords.py") — the last element is the leaf.
		if x.Name == "filepath" && sel.Sel.Name == "Join" && len(e.Args) > 0 {
			return resolveProgramName(f, e.Args[len(e.Args)-1], decl, depth+1)
		}
		return ""
	case *ast.Ident:
		for _, rhs := range assignedRHS(decl, e.Name) {
			if n := resolveProgramName(f, rhs, decl, depth+1); n != "" {
				return n
			}
		}
		if fn, ok := decl.(*ast.FuncDecl); ok {
			if idx := paramIndex(decl, e.Name); idx >= 0 {
				for _, b := range callBindings(f, fn.Name.Name, idx) {
					if n := resolveProgramName(f, b.Expr, b.Decl, depth+1); n != "" {
						return n
					}
				}
			}
		}
		return ""
	}
	return ""
}

// -----------------------------------------------------------------------------
// Corroboration predicates.
// -----------------------------------------------------------------------------

// scopeSet is a set of top-level declaration names.
type scopeSet map[string]bool

// corrobEnv carries facts the predicates need that do not come from the file
// itself. Today: the tools.lock inventory.
type corrobEnv struct {
	ToolNames map[string]bool
}

// predicate evaluates one Reason against a declared file's own syntax tree and
// returns the scopes whose dispatch sites that reason explains. An empty result
// means the reason is NOT corroborated.
type predicate func(b lint.Bypass, f *bypassFile, env *corrobEnv) scopeSet

// cmdFieldAssignScopes returns the scopes containing an assignment to `field` on
// a value whose type resolves to *os/exec.Cmd.
func cmdFieldAssignScopes(f *bypassFile, field string) scopeSet {
	found := scopeSet{}
	for _, decl := range f.Syn.Decls {
		scope := declScopeName(decl)
		ast.Inspect(decl, func(n ast.Node) bool {
			assign, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range assign.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != field {
					continue
				}
				if isCmdTyped(f.Pkg, sel.X) {
					found[scope] = true
				}
			}
			return true
		})
	}
	return found
}

// negativePIDSignalScopes finds scopes that signal a process GROUP — a signal
// delivered to a negated pid, e.g. syscall.Kill(-pgid, syscall.SIGTERM).
func negativePIDSignalScopes(f *bypassFile) scopeSet {
	found := scopeSet{}
	for _, decl := range f.Syn.Decls {
		scope := declScopeName(decl)
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if sel.Sel.Name != "Kill" && sel.Sel.Name != "Signal" {
				return true
			}
			for _, a := range call.Args {
				if unary, ok := a.(*ast.UnaryExpr); ok && unary.Op.String() == "-" {
					found[scope] = true
				}
			}
			return true
		})
	}
	return found
}

// execCallScopes walks every exec.Command/CommandContext call in the file and
// invokes match with the program expression, the remaining argument expressions
// and the enclosing declaration. Scopes where match returns true are collected.
func execCallScopes(f *bypassFile, match func(prog ast.Expr, args []ast.Expr, decl ast.Decl) bool) scopeSet {
	found := scopeSet{}
	for _, decl := range f.Syn.Decls {
		d := decl
		scope := declScopeName(decl)
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := isExecConstructor(call)
			if !ok {
				return true
			}
			prog, args := execProgramAndArgs(call, name)
			if match(prog, args, d) {
				found[scope] = true
			}
			return true
		})
	}
	return found
}

// reasonPredicates is the corroboration table. A Reason with NO entry here fails
// the gate — the vocabulary is closed, and a reason that corroborates nothing is
// a hole with a name.
var reasonPredicates = map[lint.Reason]predicate{
	// stdin — an assignment to the Stdin field of an *os/exec.Cmd.
	lint.ReasonStdin: func(_ lint.Bypass, f *bypassFile, _ *corrobEnv) scopeSet {
		return cmdFieldAssignScopes(f, "Stdin")
	},

	// work_dir — the same, for the Dir field.
	lint.ReasonWorkDir: func(_ lint.Bypass, f *bypassFile, _ *corrobEnv) scopeSet {
		return cmdFieldAssignScopes(f, "Dir")
	},

	// clone_path — the dispatched executable, or its leading script argument, is
	// a path built with filepath.Join rather than a bare tool name.
	lint.ReasonClonePath: func(_ lint.Bypass, f *bypassFile, _ *corrobEnv) scopeSet {
		return execCallScopes(f, func(prog ast.Expr, args []ast.Expr, decl ast.Decl) bool {
			if tracesToFilepathJoin(f, prog, decl, 0) {
				return true
			}
			// Interpreter-plus-script argv: the program is an interpreter and the
			// FIRST argument is the constructed script path.
			if len(args) > 0 && tracesToFilepathJoin(f, args[0], decl, 0) {
				return true
			}
			return false
		})
	},

	// process_lifecycle — the file manages the child's lifetime itself.
	lint.ReasonProcessLifecycle: func(_ lint.Bypass, f *bypassFile, _ *corrobEnv) scopeSet {
		out := cmdFieldAssignScopes(f, "SysProcAttr")
		for s := range negativePIDSignalScopes(f) {
			out[s] = true
		}
		return out
	},

	// non_recon_binary — the dispatched name is not a tools.lock entry. Checked
	// against the manifest itself, never against a hand-written list.
	lint.ReasonNonReconBinary: func(_ lint.Bypass, f *bypassFile, env *corrobEnv) scopeSet {
		return execCallScopes(f, func(prog ast.Expr, _ []ast.Expr, decl ast.Decl) bool {
			name := resolveProgramName(f, prog, decl, 0)
			if name == "" {
				return false // unresolved is NOT corroboration
			}
			return !env.ToolNames[name]
		})
	},

	// installer_toolchain — the file is under internal/installer/.
	lint.ReasonInstallerToolchain: func(_ lint.Bypass, f *bypassFile, _ *corrobEnv) scopeSet {
		if !strings.HasPrefix(f.Rel, "internal/installer/") {
			return scopeSet{}
		}
		return f.scopesWithSites()
	},

	// pending_removal — an exemption WITH AN EXPIRY. Corroborated only by a
	// non-empty HomeBy naming the owning plan; see
	// TestNoPendingRemovalOutlivesItsPlan.
	lint.ReasonPendingRemoval: func(b lint.Bypass, f *bypassFile, _ *corrobEnv) scopeSet {
		if strings.TrimSpace(b.HomeBy) == "" {
			return scopeSet{}
		}
		return f.scopesWithSites()
	},
}

// -----------------------------------------------------------------------------
// tools.lock — the inventory the non_recon_binary predicate checks against.
// -----------------------------------------------------------------------------

// loadToolNames parses internal/core/backend/tools.lock. Parsed from disk rather
// than read off backend.Default because that package's Blocker-7 audit gate
// forbids *_test.go references to the singleton (same reasoning as
// argvector_coverage_test.go's censusToolRegistry).
func loadToolNames(t *testing.T, repoRoot string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repoRoot, "internal", "core", "backend", "tools.lock"))
	if err != nil {
		t.Fatalf("read tools.lock: %v", err)
	}
	var lock struct {
		Tools []struct {
			Name string `toml:"name"`
		} `toml:"tools"`
	}
	if err := tomlv2.Unmarshal(data, &lock); err != nil {
		t.Fatalf("parse tools.lock: %v", err)
	}
	if len(lock.Tools) == 0 {
		t.Fatalf("tools.lock parsed to ZERO tools — the non_recon_binary predicate would call every binary non-recon")
	}
	out := map[string]bool{}
	for _, tl := range lock.Tools {
		out[tl.Name] = true
	}
	return out
}

// -----------------------------------------------------------------------------
// The four checks, as one pure function over (manifest, files).
// -----------------------------------------------------------------------------

// checkManifest applies all four failure modes and returns one string per
// problem found. It is a pure function of its inputs so the SAME code runs
// against the real tree (TestBypassManifestGate) and against deliberately-broken
// testdata fixtures (the four fire-proof tests below).
func checkManifest(
	manifest []lint.Bypass,
	files map[string]*bypassFile,
	infra func(string) bool,
	env *corrobEnv,
) []string {
	var problems []string

	declared := map[string]lint.Bypass{}
	for _, b := range manifest {
		if _, dup := declared[b.File]; dup {
			problems = append(problems, fmt.Sprintf("DUPLICATE: %s declared twice", b.File))
		}
		declared[b.File] = b
	}

	// 1. UNLISTED — a file with dispatch sites and no manifest entry. This is
	//    the one thing the old string allowlist did right; preserved exactly.
	var rels []string
	for rel := range files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	for _, rel := range rels {
		f := files[rel]
		if len(f.Sites) == 0 || infra(rel) {
			continue
		}
		if _, ok := declared[rel]; !ok {
			problems = append(problems, fmt.Sprintf(
				"UNLISTED: %s has %d direct dispatch site(s) and NO manifest entry — route it through backend.Runner (RunOpts/StreamOpts) or declare a corroborated bypass",
				rel, len(f.Sites)))
		}
	}

	// Deterministic order over the manifest.
	sorted := append([]lint.Bypass(nil), manifest...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].File < sorted[j].File })

	for _, b := range sorted {
		f, ok := files[b.File]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"STALE: %s is declared but was not loaded — the file is gone or moved; delete the entry",
				b.File))
			continue
		}

		// 2. STALE — declared, but the file dispatches nothing any more.
		if len(f.Sites) == 0 {
			problems = append(problems, fmt.Sprintf(
				"STALE: %s is declared as a bypass but has ZERO direct dispatch sites — the justification outlived the code it justified; delete the entry",
				b.File))
			continue
		}

		// 3. SITE-COUNT DRIFT — exact match, not a floor.
		if b.Sites != len(f.Sites) {
			problems = append(problems, fmt.Sprintf(
				"SITE DRIFT: %s declares Sites=%d, walker found %d (%s) — an exact count is what makes a SECOND dispatch added to an already-forgiven file a failing diff",
				b.File, b.Sites, len(f.Sites), siteSummary(f.Sites)))
		}

		// 4. REASONS — declared, known, and corroborated.
		if len(b.Reasons) == 0 {
			problems = append(problems, fmt.Sprintf("NO REASON: %s declares no reasons", b.File))
			continue
		}
		covered := scopeSet{}
		for _, r := range b.Reasons {
			pred, ok := reasonPredicates[r]
			if !ok {
				problems = append(problems, fmt.Sprintf(
					"UNKNOWN REASON: %s declares %q, which has NO corroboration predicate — the vocabulary is closed; a reason that corroborates nothing is a hole with a name",
					b.File, r))
				continue
			}
			explained := pred(b, f, env)
			if len(explained) == 0 {
				problems = append(problems, fmt.Sprintf(
					"UNCORROBORATED: %s declares reason %q but that file's syntax tree shows no evidence for it",
					b.File, r))
			}
			for scope := range explained {
				covered[scope] = true
			}
		}

		// 4b. COVERAGE — the declared reason set must explain EVERY dispatch
		//     site, not merely be evidenced somewhere in the file.
		//
		//     This check exists because of a measured miss, not a hunch. With
		//     only "each declared reason is evidenced somewhere" (the form this
		//     gate shipped in first), dropping `clone_path` from
		//     web/wordlistgen.go left its two getjswords sites unexplained and
		//     the gate stayed GREEN: `stdin` was still evidenced, in the OTHER
		//     runner in the same file. A two-shape file could hide its second
		//     shape behind its first shape's reason — which is precisely the
		//     "already-forgiven file absorbs a new bypass" hole that the exact
		//     site count closes for COUNT and this closes for KIND.
		var uncovered []string
		for scope := range f.scopesWithSites() {
			if !covered[scope] {
				uncovered = append(uncovered, scope)
			}
		}
		if len(uncovered) > 0 {
			sort.Strings(uncovered)
			problems = append(problems, fmt.Sprintf(
				"UNEXPLAINED SITES: %s has dispatch sites in %v that NONE of its declared reasons %v accounts for — every site needs a reason, or a file with two shapes hides the second behind the first",
				b.File, uncovered, b.Reasons))
		}
	}
	return problems
}

func siteSummary(sites []dispatchSite) string {
	var parts []string
	for _, s := range sites {
		parts = append(parts, s.Call+"@"+s.Scope+":"+strconv.Itoa(s.Line))
	}
	return strings.Join(parts, " ")
}

// -----------------------------------------------------------------------------
// The real-tree gates.
// -----------------------------------------------------------------------------

// TestBypassManifestGate is THE manifest gate. It applies all four checks to the
// real tree and pins the census.
func TestBypassManifestGate(t *testing.T) {
	repoRoot := findRepoRoot(t)
	pkgs := loadInternalPackages(t, repoRoot)
	files := collectDispatchSites(pkgs, repoRoot)
	env := &corrobEnv{ToolNames: loadToolNames(t, repoRoot)}

	problems := checkManifest(lint.Bypasses, files, isInfrastructure, env)
	for _, p := range problems {
		t.Errorf("FOUND-10 bypass manifest: %s", p)
	}

	totalSites := 0
	for _, b := range lint.Bypasses {
		if f, ok := files[b.File]; ok {
			totalSites += len(f.Sites)
		}
	}
	t.Logf("BYPASS_CENSUS files=%d sites=%d", len(lint.Bypasses), totalSites)

	if len(lint.Bypasses) != bypassCensusFiles || totalSites != bypassCensusSites {
		t.Errorf("BYPASS_CENSUS drift: files=%d sites=%d, pinned files=%d sites=%d — "+
			"lowering these is the POINT (18-04/18-05 route files home); raising them requires a new corroborated entry. Either way it must be a visible diff with a written reason.",
			len(lint.Bypasses), totalSites, bypassCensusFiles, bypassCensusSites)
	}
}

// TestBypassReasonsAreCorroborated asserts that every reason declared in the
// manifest is evidenced by the declared file's OWN syntax tree, and logs the
// walker's per-file site census so manifest Sites values are read from the
// walker and never from a table.
//
// This is the check the string allowlist could never make. The 18-03 experiment
// showed that appending a path with a KNOWN-FALSE prose reason turned the old
// gate green; here a false reason has nothing to point at and fails.
func TestBypassReasonsAreCorroborated(t *testing.T) {
	repoRoot := findRepoRoot(t)
	pkgs := loadInternalPackages(t, repoRoot)
	files := collectDispatchSites(pkgs, repoRoot)
	env := &corrobEnv{ToolNames: loadToolNames(t, repoRoot)}

	var withSites []string
	for rel, bf := range files {
		if len(bf.Sites) > 0 {
			withSites = append(withSites, rel)
		}
	}
	sort.Strings(withSites)
	for _, rel := range withSites {
		t.Logf("WALKER_SITES %s sites=%d [%s]", rel, len(files[rel].Sites), siteSummary(files[rel].Sites))
	}

	for _, b := range lint.Bypasses {
		f, ok := files[b.File]
		if !ok {
			t.Errorf("manifest entry %s: file not found in ./internal/... load", b.File)
			continue
		}
		for _, r := range b.Reasons {
			pred, ok := reasonPredicates[r]
			if !ok {
				t.Errorf("manifest entry %s: reason %q has NO corroboration predicate", b.File, r)
				continue
			}
			if len(pred(b, f, env)) == 0 {
				t.Errorf("manifest entry %s: reason %q is NOT CORROBORATED by that file's syntax tree — no evidence found (declared reasons: %v)",
					b.File, r, b.Reasons)
			}
		}
	}
}

// TestNoPendingRemovalOutlivesItsPlan — a temporary exemption with no expiry is
// a permanent one. Every pending_removal entry must name the plan that routes it
// home. 18-06 asserts the COUNT of such entries is zero at phase end.
func TestNoPendingRemovalOutlivesItsPlan(t *testing.T) {
	for _, b := range lint.Bypasses {
		pending := false
		for _, r := range b.Reasons {
			if r == lint.ReasonPendingRemoval {
				pending = true
			}
		}
		if !pending {
			continue
		}
		if strings.TrimSpace(b.HomeBy) == "" {
			t.Errorf("%s declares pending_removal with an EMPTY HomeBy — name the owning plan or find a real reason", b.File)
			continue
		}
		t.Logf("PENDING_REMOVAL %s -> owned by plan %s", b.File, b.HomeBy)
	}
}

// TestNoPendingRemovalRemains asserts the COUNT of pending_removal entries is
// exactly ZERO at the end of phase 18 (18-06 / RS-E).
//
// # WHY THIS IS NOT A DUPLICATE OF TestNoPendingRemovalOutlivesItsPlan
//
// That test asserts every pending_removal entry NAMES an owning plan. It is
// satisfied by a manifest full of pending entries as long as each is attributed,
// which is the correct rule mid-phase — 18-03 wrote it while shortscan.go was
// still pending and 18-04 owned it.
//
// This test asserts there are NONE. It is the END-OF-PHASE assertion, and it can
// only be made once, at the point the phase claims the work is finished. The two
// answer different questions: "is every deferral accounted for?" and "is
// anything still deferred?". A phase that closes with the first green and the
// second red has not closed.
//
// # WHY A COUNT AND NOT A LOOP OVER lint.Bypasses
//
// Both. The loop names the offender; the count is what makes the assertion a
// PIN. Without the explicit zero, deleting the loop body would leave this green,
// and a guard that passes when its body is removed is not a guard.
func TestNoPendingRemovalRemains(t *testing.T) {
	pending := 0
	for _, b := range lint.Bypasses {
		for _, r := range b.Reasons {
			if r != lint.ReasonPendingRemoval {
				continue
			}
			pending++
			t.Errorf("%s STILL declares pending_removal (owned by plan %q) at the end of phase 18.\n"+
				"  pending_removal is a dated IOU: it says a file dispatches around backend.Runner and a\n"+
				"  NAMED plan will fix it. Phase 18 is that plan set, so an entry surviving it is an IOU\n"+
				"  with nobody left to pay it — which is how the blanket allowlist this manifest replaced\n"+
				"  came to hold six undocumented bypasses.\n"+
				"  Either route it onto the Runner, or give it a reason that is TRUE and PERMANENT and\n"+
				"  corroborated by its own syntax tree.", b.File, b.HomeBy)
		}
	}
	if pending != 0 {
		t.Errorf("PENDING_REMOVAL_COUNT %d, want 0 at the end of phase 18.", pending)
	}
	t.Logf("PENDING_REMOVAL_COUNT %d (manifest holds %d file(s))", pending, len(lint.Bypasses))
}

// -----------------------------------------------------------------------------
// Fire-proofs: each of the four checks made to FAIL on a testdata fixture.
// -----------------------------------------------------------------------------

const (
	fixtureShapes = "internal/core/backend/lint/testdata/bypass_shapes.go"
	fixtureBasic  = "internal/core/backend/lint/testdata/violating.go"
)

// loadFixtureFiles loads testdata/ with the fixture build tag AND full type
// information, so the corroboration predicates run against it exactly as they do
// against the real tree.
func loadFixtureFiles(t *testing.T) map[string]*bypassFile {
	t.Helper()
	repoRoot := findRepoRoot(t)
	fixtureDir := filepath.Join(repoRoot, "internal", "core", "backend", "lint", "testdata")
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedCompiledGoFiles |
			packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo,
		Dir:        fixtureDir,
		BuildFlags: []string{"-tags=ignore_in_normal_build"},
		Tests:      false,
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("packages.Load(testdata): %v", err)
	}
	files := collectDispatchSites(pkgs, repoRoot)
	if len(files[fixtureShapes].Sites) != 4 {
		t.Fatalf("fixture precondition: %s should have 4 dispatch sites, walker found %d — the fire-proofs below would be testing nothing",
			fixtureShapes, len(files[fixtureShapes].Sites))
	}
	return files
}

// noInfra is the infrastructure predicate used by the fire-proofs: testdata IS
// on the real infrastructure allowlist, so the fixtures must be scanned with it
// switched off or every check below would silently pass.
func noInfra(string) bool { return false }

func fixtureEnv(t *testing.T) *corrobEnv {
	t.Helper()
	return &corrobEnv{ToolNames: loadToolNames(t, findRepoRoot(t))}
}

func hasProblem(problems []string, substr string) bool {
	for _, p := range problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

// TestUnlistedDirectDispatchFails — failure mode 1.
func TestUnlistedDirectDispatchFails(t *testing.T) {
	files := loadFixtureFiles(t)
	// Empty manifest: BOTH fixture files dispatch and neither is declared.
	problems := checkManifest(nil, files, noInfra, fixtureEnv(t))
	if !hasProblem(problems, "UNLISTED: "+fixtureShapes) {
		t.Errorf("check 1 did not fire: an undeclared file with 4 dispatch sites was accepted.\nproblems: %v", problems)
	}
	if !hasProblem(problems, "UNLISTED: "+fixtureBasic) {
		t.Errorf("check 1 did not fire for %s.\nproblems: %v", fixtureBasic, problems)
	}
	t.Logf("FIRED: %v", problems)
}

// TestStaleBypassEntryFails — failure mode 2. A declared file with ZERO dispatch
// sites. This is verbatim the shape the arg-vector census currently carries for
// web.screenshot, which is asserted to bypass the Runner at web/screenshot.go —
// a file that has no direct dispatch at all and calls app.Tools.Stream.
func TestStaleBypassEntryFails(t *testing.T) {
	files := loadFixtureFiles(t)
	// A file that exists in the load but dispatches nothing: synthesise one from
	// the fixture package by declaring a path with its sites stripped.
	const cleanRel = "internal/core/backend/lint/testdata/clean_fixture.go"
	files[cleanRel] = &bypassFile{
		Rel: cleanRel,
		Pkg: files[fixtureShapes].Pkg,
		Syn: files[fixtureShapes].Syn,
		// Sites deliberately empty — the file no longer dispatches.
	}
	manifest := []lint.Bypass{{
		File:    cleanRel,
		Reasons: []lint.Reason{lint.ReasonStdin},
		Sites:   1,
		Tool:    "gone",
		Why:     "fixture: a justification that outlived its code",
	}}
	problems := checkManifest(manifest, files, noInfra, fixtureEnv(t))
	if !hasProblem(problems, "STALE: "+cleanRel) {
		t.Errorf("check 2 did not fire: a manifest entry for a file with zero dispatch sites was accepted.\nproblems: %v", problems)
	}
	t.Logf("FIRED: %v", problems)
}

// TestBypassSiteCountIsExact — failure mode 3, proven in BOTH directions. A
// check that only catches one direction is half a guard.
func TestBypassSiteCountIsExact(t *testing.T) {
	files := loadFixtureFiles(t)
	env := fixtureEnv(t)
	base := lint.Bypass{
		File:    fixtureShapes,
		Reasons: []lint.Reason{lint.ReasonStdin},
		Sites:   4,
		Tool:    "fixture-stdin-tool",
		Why:     "fixture",
	}

	// Truthful count: no SITE DRIFT problem.
	if p := checkManifest([]lint.Bypass{base}, files, noInfra, env); hasProblem(p, "SITE DRIFT") {
		t.Fatalf("control failed: the TRUE site count was reported as drift.\nproblems: %v", p)
	}

	over := base
	over.Sites = 5
	if p := checkManifest([]lint.Bypass{over}, files, noInfra, env); !hasProblem(p, "SITE DRIFT") {
		t.Errorf("check 3 did not fire on Sites=+1 (declared 5, actual 4).\nproblems: %v", p)
	} else {
		t.Logf("FIRED (+1): %v", p)
	}

	under := base
	under.Sites = 3
	if p := checkManifest([]lint.Bypass{under}, files, noInfra, env); !hasProblem(p, "SITE DRIFT") {
		t.Errorf("check 3 did not fire on Sites=-1 (declared 3, actual 4) — a >= check would wave this through, which is exactly how a second undocumented dispatch lands in an already-forgiven file.\nproblems: %v", p)
	} else {
		t.Logf("FIRED (-1): %v", p)
	}
}

// TestUnknownReasonFails — failure mode 4, in both of its shapes: a reason with
// no predicate, and a known reason with no evidence.
func TestUnknownReasonFails(t *testing.T) {
	files := loadFixtureFiles(t)
	env := fixtureEnv(t)

	unknown := []lint.Bypass{{
		File:    fixtureShapes,
		Reasons: []lint.Reason{lint.Reason("legacy_pattern")},
		Sites:   4,
		Tool:    "fixture-stdin-tool",
		Why:     "fixture",
	}}
	if p := checkManifest(unknown, files, noInfra, env); !hasProblem(p, "UNKNOWN REASON") {
		t.Errorf("check 4a did not fire: a reason outside the vocabulary was accepted, so the vocabulary is not closed.\nproblems: %v", p)
	} else {
		t.Logf("FIRED (unknown reason): %v", p)
	}

	// work_dir is a KNOWN reason, but the fixture assigns no Dir field anywhere.
	uncorroborated := []lint.Bypass{{
		File:    fixtureShapes,
		Reasons: []lint.Reason{lint.ReasonWorkDir},
		Sites:   4,
		Tool:    "fixture-stdin-tool",
		Why:     "fixture",
	}}
	if p := checkManifest(uncorroborated, files, noInfra, env); !hasProblem(p, "UNCORROBORATED") {
		t.Errorf("check 4b did not fire: a known reason with no evidence in the file was accepted.\nproblems: %v", p)
	} else {
		t.Logf("FIRED (uncorroborated): %v", p)
	}

	// Control: the reason the fixture DOES evidence must pass, or 4b proves
	// nothing but that the predicate always returns empty.
	corroborated := []lint.Bypass{{
		File:    fixtureShapes,
		Reasons: []lint.Reason{lint.ReasonStdin},
		Sites:   4,
		Tool:    "fixture-stdin-tool",
		Why:     "fixture",
	}}
	if p := checkManifest(corroborated, files, noInfra, env); hasProblem(p, "UNCORROBORATED") {
		t.Errorf("control failed: the fixture DOES assign cmd.Stdin, so `stdin` must corroborate.\nproblems: %v", p)
	}
}

// TestDeclaredReasonsMustCoverEverySite — failure mode 4c, on a controlled
// fixture rather than only on a live mutation.
//
// bypass_shapes.go carries TWO scopes on purpose: fixtureStdinShape assigns
// cmd.Stdin, fixtureBareShape assigns nothing. Declaring `stdin` alone is
// therefore a reason that IS corroborated (so checks 4a/4b are both silent) and
// still leaves half the file's dispatch sites unexplained. That combination is
// exactly what let MUTATION 6 pass against web/wordlistgen.go before this check
// existed.
func TestDeclaredReasonsMustCoverEverySite(t *testing.T) {
	files := loadFixtureFiles(t)
	env := fixtureEnv(t)

	partial := []lint.Bypass{{
		File:    fixtureShapes,
		Reasons: []lint.Reason{lint.ReasonStdin},
		Sites:   4,
		Tool:    "fixture-stdin-tool + fixture-bare-tool",
		Why:     "fixture: one reason, two shapes",
	}}
	p := checkManifest(partial, files, noInfra, env)
	if hasProblem(p, "UNCORROBORATED") {
		t.Fatalf("control failed: `stdin` IS evidenced in this fixture, so 4b must stay silent — otherwise this test proves nothing about coverage.\nproblems: %v", p)
	}
	if !hasProblem(p, "UNEXPLAINED SITES: "+fixtureShapes) {
		t.Errorf("check 4c did not fire: a corroborated reason covering only ONE of two dispatch shapes was accepted, so a two-shape file can still hide its second shape.\nproblems: %v", p)
	} else {
		t.Logf("FIRED (uncovered sites): %v", p)
	}
}
