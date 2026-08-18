// staging_contract_test.go — the repo-wide STAGING-GLOB-TRIGGERED guard that
// every producer's staging write goes through output.StageJSONL /
// output.StageLines.
//
// ORIGIN: phase 15, audit finding F3 ("results from previous runs persist into
// later ones"). Workspaces are stable across runs by design, so a producer that
// wrote its staging file only when it had data left the PREVIOUS run's file on
// disk, and the next merge republished it. output.StageJSONL / StageLines
// (plan 15-03 Task 1) write-or-REMOVE; every producer must route its staging
// write through them.
//
// stagingContractAllowlist IS PERMANENTLY EMPTY — THE RATCHET IS CLOSED. Plan
// 15-13 migrated the web + subdomains share, plan 15-14 the vulns + osint share,
// and plan 15-17 closed it: stagingContractAllowlistSize is asserted to be
// exactly 0 by TestStagingContractRatchetIsClosed and the map literal is
// asserted to be empty. A NON-EMPTY ALLOWLIST IS NOW A REGRESSION, not a
// migration state — there is no remaining migration.
//
// The empty map literal is deliberately KEPT rather than deleted. An empty map
// plus a zero assertion is a stronger guard than removing the mechanism: a
// contributor who adds a raw merger-globbed staging write gets a NAMED failure
// naming the file and function, rather than a silent pass. NO NEW ENTRY MAY
// EVER BE ADDED. A new producer writes its staging through the helpers from the
// start; if this test fails on code you just wrote, migrate the write — do not
// append to the list.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE RULE IS STAGING-GLOB-TRIGGERED.
//
// A write into inputs/ is IN SCOPE only when its resolved path matches a
// pattern that a merger actually globs. It is NOT path-triggered ("builds an
// inputs path") and NOT write-triggered ("writes anything into inputs/").
// Both weaker rules are unsatisfiable and would pressure this guard into being
// weakened rather than emptied:
//
//   - Path-triggered: ~15 non-test files under internal/modules/ build an
//     inputs path only to READ it (web/merge.go, web/ffuf.go,
//     web/hakoriginfinder.go, subdomains/geo.go, subdomains/buckets.go,
//     vulns/merge.go, osint/merge.go, osint/{metadata,xnldorker,swagger,
//     github_dorks,cmseek,github_leaks,postman,gqlspection}.go). A reader has
//     nothing to stage.
//   - Write-triggered: ~35 functions write a NON-staging file into inputs/ — a
//     tool-input list, a scratch file, or a file under an inputs/
//     subdirectory — and ~21 of them do it in the SAME function as a genuine
//     staging write, so they cannot be excluded by file or by function.
//     web/katana.go writes inputs/katana_targets.txt in the same function as
//     the urls.katana.jsonl staging; web/wafw00f.go writes
//     inputs/wafw00f.hosts.txt beside waf.wafw00f.jsonl; vulns/sqli.go writes
//     inputs/tmp_sqli.txt as sqlmap's -m file; subdomains/csprecon.go writes
//     inputs/csprecon.hosts.txt, a scratch file no merger reads, in a
//     PolicyFailFast module. Routing any of them through a remove-on-empty
//     helper would change the contract of a file handed to an external binary.
//
// Under the staging-glob rule those three categories fall out BY CONSTRUCTION,
// not by allowlist, which is what makes `== 0` reachable.
//
// THE FIVE MERGERS whose globs define the stage sets below:
//
//	webStagingPrefixes        internal/modules/web/merge.go        inputs/<stage>.*.jsonl
//	vulnsStagingPrefixes      internal/modules/vulns/merge.go      inputs/findings.*.jsonl
//	osintStagingPrefixes      internal/modules/osint/merge.go      inputs/findings.*.jsonl
//	subdomainStagingPrefixes  internal/modules/subdomains/merge.go inputs/<stage>.*.txt
//	mergeTakeoverFindings     internal/mcp/handlers/common.go      inputs/takeover.{subzy,dnstake}.jsonl
//
// The fifth lives OUTSIDE internal/modules/ and "takeover" appears in no
// *StagingPrefixes slice — its own comment says "no merger has to know that
// takeover exists". Miss it and subdomains/takeover.go silently leaves the
// guard.
//
// ─────────────────────────────────────────────────────────────────────────────
// derivedOutputExemptions IS A DIFFERENT MAP WITH A DIFFERENT CONTRACT.
//
// It is NOT part of the ratchet. It holds exactly ONE entry and stays at one:
// plans 15-13, 15-14 and 15-17 must not change it. Its size is pinned by a test
// so growing it is a visible diff.
//
// GROWING THIS MAP IS HOW A FUTURE CONTRIBUTOR WOULD SMUGGLE AN UNMIGRATED RAW
// STAGING WRITE PAST A ZERO-LENGTH ALLOWLIST. A closed allowlist beside an
// unbounded exemption map is a green gate protecting nothing: every entry moved
// in here is a producer whose staging file is no longer removed on a zero-result
// run, which is exactly the F3 defect the allowlist was built to eliminate.
// derivedOutputExemptionsSize is therefore asserted at 1 permanently, and the
// single key is named in the assertion so a swap is as visible as a growth.
//
// An entry qualifies only if BOTH hold:
//
//	(a) the file is a DERIVED intermediate regenerated by its owner on every
//	    run, not producer staging; and
//	(b) downstream consumers open it as a file, so remove-on-empty would break
//	    them.
//
// The single entry — subdomains/merge.go MergeStage → inputs/<stage>.merged.txt
// — needs the exemption precisely BECAUSE <stage>.merged.txt matches the
// subdomains merger glob <stage>.*.txt. That is the same reason
// MergeAllSubdomains has to skip *.merged.txt by hand when collecting sources.
//
// vulns/gf.go is deliberately NOT here and must not be added. Its buckets are
// inputs/gf/<class>.txt — a SUBDIRECTORY — and filepath.Glob's `*` does not
// cross `/`, so no merger glob can reach them and they fall out of the
// detector's scope by construction. gf's F3 correctness (every bucket rewritten
// unconditionally, empty file on both the tool-failure and zero-match paths) is
// hand-verified in plan 15-14 Task 1, justified there as "outside the
// detector's scope, therefore hand-verified" rather than "exempted".
package modules_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// ─── stage sets ─────────────────────────────────────────────────────────────

// jsonlStagingStages are the stage prefixes some merger globs as
// inputs/<stage>.*.jsonl.
//
//	hosts, fuzz, waf, origins, urls, findings  — webStagingPrefixes,
//	                                             internal/modules/web/merge.go
//	findings                                   — vulnsStagingPrefixes (vulns/merge.go),
//	                                             osintStagingPrefixes (osint/merge.go)
//	takeover                                   — mergeTakeoverFindings,
//	                                             internal/mcp/handlers/common.go
var jsonlStagingStages = map[string]bool{
	"hosts":    true,
	"fuzz":     true,
	"waf":      true,
	"origins":  true,
	"urls":     true,
	"findings": true,
	"takeover": true,
}

// txtStagingStages are the stage prefixes the subdomains merger globs as
// inputs/<stage>.*.txt — subdomainStagingPrefixes,
// internal/modules/subdomains/merge.go.
var txtStagingStages = map[string]bool{
	"passive":   true,
	"resolved":  true,
	"permut":    true,
	"recursive": true,
}

// ─── the ratchet ────────────────────────────────────────────────────────────

// stagingContractAllowlist maps a repo-relative file path to the functions in
// it that still perform a raw, merger-globbed staging write. Seeded by running
// checkStagingContract with an EMPTY allowlist (the single derivedOutputExemptions
// entry in place) and copying the reported set verbatim.
//
// MUST REACH ZERO. NO NEW ENTRY MAY EVER BE ADDED.
var stagingContractAllowlist = map[string][]string{
	// EMPTY — THE RATCHET IS CLOSED. Every producer in internal/modules/ now
	// stages through output.StageJSONL / output.StageLines.
	//
	//	web         0 — all 16 migrated by plan 15-13 Task 1
	//	subdomains  0 — all  6 migrated by plan 15-13 Task 1
	//	vulns       0 — all 15 migrated by plan 15-14 Task 1
	//	osint       0 — the single writeOSINTStaging writer, which fronts 23 call
	//	                sites across 20 files, migrated by plan 15-14 Task 1
	//
	// NO ENTRY MAY EVER BE ADDED BACK. If TestStagingContract fails on code you
	// just wrote, migrate the write.
}

// stagingContractAllowlistSize is the FLATTENED entry count of
// stagingContractAllowlist. Asserted by TestStagingContractAllowlistShrinks so
// lowering one without the other fails, and pinned at exactly 0 by
// TestStagingContractRatchetIsClosed so neither can be raised.
//
// 15-03 seed: 38 (web 16, vulns 15, subdomains 6, osint 1).
// 15-13 lowered it to 16 by removing all 22 web + subdomains entries (web 16,
//
//	subdomains 6). Remaining: vulns 15 + osint 1.
//
// 15-14 drove it to 0 by removing all 16 remaining entries (vulns 15, osint 1).
// 15-17 CLOSED it: this constant is now a permanent 0 and may never be raised.
const stagingContractAllowlistSize = 0

// derivedOutputExemptions maps file → function → the path literal whose write is
// exempt. See the file header for the two-part justification test. NOT part of
// the ratchet; stays at exactly one entry.
var derivedOutputExemptions = map[string]map[string]string{
	"internal/modules/subdomains/merge.go": {"MergeStage": ".merged.txt"},
}

// derivedOutputExemptionsSize pins the exemption map so growing it is a visible
// diff. Plans 15-13, 15-14 and 15-17 must not change it.
const derivedOutputExemptionsSize = 1

// ─── detector ───────────────────────────────────────────────────────────────

const (
	// unknownComp is a path component that could not be resolved to a literal.
	unknownComp = "\x00?"
	// paramPrefix marks a path component derived from one of the enclosing
	// function's own string parameters, pending argument propagation.
	paramPrefix = "\x00p:"
	// maxCandidates bounds the cross-product when a component has several
	// possible literal values.
	maxCandidates = 64
)

// pathChain is a resolved filepath component list, outermost first.
type pathChain []string

// writeFuncs are the direct write calls the detector recognises, as
// "<pkg>.<Func>" for qualified calls and "<Func>" for package-local ones.
var writeFuncs = map[string]bool{
	"output.WriteJSONL": true,
	"output.WriteFile":  true,
	"os.WriteFile":      true,
	"os.Create":         true,
	"os.OpenFile":       true,
	"atomicWriteLines":  true,
}

// stagingHelperCalls are the migrated staging helpers. A function containing one
// of these AND no remaining glob-matching raw write satisfies the contract.
var stagingHelperCalls = map[string]bool{
	"output.StageJSONL": true,
	"output.StageLines": true,
}

type fileUnit struct {
	key  string // repo-relative path, slash-separated
	file *ast.File
}

type pkgUnit struct {
	files []fileUnit
	// helperParams maps a package-local function name to the names of its own
	// string parameters that feed a write path.
	helperParams map[string]map[string]bool
	// helperArgs maps function name → param name → candidate chains collected
	// from call sites in this package.
	helperArgs map[string]map[string][]pathChain
	// helperCallerMatched records a helper whose param was fed a chain that
	// ALREADY matches a merger glob at the call site. The CALLER owns that
	// violation, so the helper is not separately reported.
	helperCallerMatched map[string]bool
	// paramIndex maps function name → param name → argument index.
	paramIndex map[string]map[string]int
}

// checkStagingContract walks root, and reports every function that performs a
// raw write to a path matching a merger's staging glob without going through
// output.StageJSONL / output.StageLines.
//
// It is a pure function with no *testing.T so the fixture test can drive it
// directly.
//
//   - violations: "<file>\t<func>\t<resolved path>" for each unmigrated,
//     non-allowlisted, non-exempt staging write.
//   - stale: allowlist entries whose file no longer contains that function, or
//     whose function is no longer in scope, or which now satisfies the contract.
func checkStagingContract(root string, allow map[string][]string, exempt map[string]map[string]string) (violations, stale []string) {
	base := moduleRelBase(root)
	byDir := map[string][]fileUnit{}

	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// testdata holds compiled-out fixtures; never scan it as real code.
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		af, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
		if perr != nil {
			return fmt.Errorf("parse %s: %w", p, perr)
		}
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			return rerr
		}
		key := path.Join(base, filepath.ToSlash(rel))
		dir := filepath.Dir(p)
		byDir[dir] = append(byDir[dir], fileUnit{key: key, file: af})
		return nil
	})
	if err != nil {
		return []string{fmt.Sprintf("detector error: %v", err)}, nil
	}

	// satisfied/inScope are keyed "file\tfunc".
	inScope := map[string]bool{}
	satisfied := map[string]bool{}
	declared := map[string]bool{}

	dirs := make([]string, 0, len(byDir))
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)

	for _, d := range dirs {
		pu := newPkgUnit(byDir[d])
		for _, fu := range pu.files {
			for _, decl := range fu.file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				name := funcName(fn)
				k := fu.key + "\t" + name
				declared[k] = true

				fc := newFuncCtx(fn, pu.helperArgs[name])
				resolveIdents(fn, fc)

				matched, hasStaging := scanFunc(fn, fc, pu)
				if hasStaging {
					satisfied[k] = true
				}
				if len(matched) == 0 {
					continue
				}
				// A helper whose only route to a matching path is a caller that
				// ALREADY resolves the full staging path is not the reported
				// site — the caller is.
				if pu.helperCallerMatched[name] && !selfMatched(fn, fc, pu) {
					continue
				}

				var reported []string
				for _, m := range matched {
					if lit, ok := exempt[fu.key][name]; ok && strings.Contains(m, lit) {
						continue // derived-output exemption, scoped to its literal
					}
					reported = append(reported, m)
				}
				if len(reported) == 0 {
					continue
				}
				inScope[k] = true
				satisfied[k] = false
				if allowed(allow, fu.key, name) {
					continue
				}
				sort.Strings(reported)
				violations = append(violations,
					fmt.Sprintf("%s\t%s\t%s", fu.key, name, strings.Join(reported, ", ")))
			}
		}
	}

	// Stale allowlist entries.
	for file, fns := range allow {
		for _, fn := range fns {
			k := file + "\t" + fn
			switch {
			case !declared[k]:
				stale = append(stale, fmt.Sprintf("%s\t%s\tno such function in that file", file, fn))
			case !inScope[k]:
				stale = append(stale, fmt.Sprintf("%s\t%s\tno longer performs a merger-globbed staging write", file, fn))
			case satisfied[k]:
				stale = append(stale, fmt.Sprintf("%s\t%s\tnow satisfies the staging contract", file, fn))
			}
		}
	}

	sort.Strings(violations)
	sort.Strings(stale)
	return violations, stale
}

func allowed(allow map[string][]string, file, fn string) bool {
	for _, name := range allow[file] {
		if name == fn {
			return true
		}
	}
	return false
}

// newPkgUnit runs the two pre-passes: helper discovery, then argument
// propagation from call sites in the same package.
func newPkgUnit(files []fileUnit) *pkgUnit {
	pu := &pkgUnit{
		files:               files,
		helperParams:        map[string]map[string]bool{},
		helperArgs:          map[string]map[string][]pathChain{},
		helperCallerMatched: map[string]bool{},
		paramIndex:          map[string]map[string]int{},
	}

	// Pass A — a package-local function is a path-writer helper when a write
	// call in its body targets a path built from one of its own string params.
	for _, fu := range files {
		for _, decl := range fu.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := funcName(fn)
			pu.paramIndex[name] = paramIndexes(fn)
			fc := newFuncCtx(fn, nil)
			resolveIdents(fn, fc)
			params := map[string]bool{}
			for _, ch := range writeTargets(fn, fc, nil) {
				for _, comp := range ch {
					if p, ok := paramOf(comp); ok {
						params[p] = true
					}
				}
			}
			if len(params) > 0 {
				pu.helperParams[name] = params
			}
		}
	}

	// Pass B — collect the chains callers pass into each helper param.
	for _, fu := range files {
		for _, decl := range fu.file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			fc := newFuncCtx(fn, nil)
			resolveIdents(fn, fc)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				params, ok := pu.helperParams[id.Name]
				if !ok {
					return true
				}
				for p := range params {
					idx, ok := pu.paramIndex[id.Name][p]
					if !ok || idx >= len(call.Args) {
						continue
					}
					chains := resolveExpr(call.Args[idx], fc)
					if pu.helperArgs[id.Name] == nil {
						pu.helperArgs[id.Name] = map[string][]pathChain{}
					}
					pu.helperArgs[id.Name][p] = append(pu.helperArgs[id.Name][p], chains...)
					for _, ch := range chains {
						if _, ok := matchMergerGlob(ch); ok {
							// The caller already holds the full staging path, so
							// the caller is the reported site, not the helper.
							pu.helperCallerMatched[id.Name] = true
						}
					}
				}
				return true
			})
		}
	}
	return pu
}

// scanFunc returns the glob-matching write paths in fn and whether fn calls a
// migrated staging helper.
func scanFunc(fn *ast.FuncDecl, fc *funcCtx, pu *pkgUnit) (matched []string, hasStaging bool) {
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if stagingHelperCalls[callName(call)] {
			hasStaging = true
		}
		return true
	})
	seen := map[string]bool{}
	for _, ch := range writeTargets(fn, fc, pu) {
		if rendered, ok := matchMergerGlob(ch); ok && !seen[rendered] {
			seen[rendered] = true
			matched = append(matched, rendered)
		}
	}
	return matched, hasStaging
}

// selfMatched reports whether fn matches a merger glob WITHOUT any argument
// propagation — i.e. the function resolves the staging path itself.
func selfMatched(fn *ast.FuncDecl, _ *funcCtx, pu *pkgUnit) bool {
	bare := newFuncCtx(fn, nil)
	resolveIdents(fn, bare)
	for _, ch := range writeTargets(fn, bare, pu) {
		if _, ok := matchMergerGlob(ch); ok {
			return true
		}
	}
	return false
}

// writeTargets returns the resolved path chains of every write in fn: the direct
// write calls in writeFuncs, plus calls to package-local path-writer helpers
// (pu may be nil during pass A, which disables the helper-call arm).
func writeTargets(fn *ast.FuncDecl, fc *funcCtx, pu *pkgUnit) []pathChain {
	var out []pathChain
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name := callName(call)
		isWrite := writeFuncs[name]
		if !isWrite && pu != nil {
			if id, ok := call.Fun.(*ast.Ident); ok {
				if _, isHelper := pu.helperParams[id.Name]; isHelper && id.Name != funcName(fn) {
					isWrite = true
				}
			}
		}
		if !isWrite {
			return true
		}
		out = append(out, resolveExpr(call.Args[0], fc)...)
		return true
	})
	return out
}

// ─── expression resolution ──────────────────────────────────────────────────

type funcCtx struct {
	idents map[string]pathChain   // ident → resolved chain
	consts map[string]string      // ident → literal string value
	params map[string]bool        // string parameter names
	sub    map[string][]pathChain // param name → caller-supplied chains
	depth  int
}

func newFuncCtx(fn *ast.FuncDecl, sub map[string][]pathChain) *funcCtx {
	fc := &funcCtx{
		idents: map[string]pathChain{},
		consts: map[string]string{},
		params: map[string]bool{},
		sub:    sub,
	}
	if fn.Type.Params != nil {
		for _, f := range fn.Type.Params.List {
			if id, ok := f.Type.(*ast.Ident); !ok || id.Name != "string" {
				continue
			}
			for _, n := range f.Names {
				fc.params[n.Name] = true
			}
		}
	}
	return fc
}

// paramIndexes maps each string parameter name to its argument index.
func paramIndexes(fn *ast.FuncDecl) map[string]int {
	out := map[string]int{}
	if fn.Type.Params == nil {
		return out
	}
	idx := 0
	for _, f := range fn.Type.Params.List {
		isString := false
		if id, ok := f.Type.(*ast.Ident); ok && id.Name == "string" {
			isString = true
		}
		if len(f.Names) == 0 {
			idx++
			continue
		}
		for _, n := range f.Names {
			if isString {
				out[n.Name] = idx
			}
			idx++
		}
	}
	return out
}

// resolveIdents records every string constant and every filepath.Join-derived
// identifier in fn, iterating to a fixed point so a two-level chain
// (gfDir := Join(WorkDir,"inputs","gf"); bucketFile := Join(gfDir, class+".txt"))
// resolves fully. One level is not enough.
func resolveIdents(fn *ast.FuncDecl, fc *funcCtx) {
	// String constants and literal assignments first — helper call sites pass
	// in-function `const stagingName = "takeover.subzy.jsonl"`.
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) {
						if s, ok := stringLit(vs.Values[i]); ok {
							fc.consts[name.Name] = s
						}
					}
				}
			}
		case *ast.AssignStmt:
			for i, lhs := range d.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || i >= len(d.Rhs) {
					continue
				}
				if s, ok := stringLit(d.Rhs[i]); ok {
					fc.consts[id.Name] = s
				}
			}
		}
		return true
	})

	// filepath.Join-derived identifiers, to a fixed point.
	for pass := 0; pass < 6; pass++ {
		changed := false
		record := func(name string, rhs ast.Expr) {
			call, ok := rhs.(*ast.CallExpr)
			if !ok || callName(call) != "filepath.Join" {
				return
			}
			chains := resolveExpr(call, fc)
			if len(chains) == 0 {
				return
			}
			prev, had := fc.idents[name]
			if !had || !equalChain(prev, chains[0]) {
				fc.idents[name] = chains[0]
				changed = true
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.AssignStmt:
				for i, lhs := range d.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && i < len(d.Rhs) {
						record(id.Name, d.Rhs[i])
					}
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					if vs, ok := spec.(*ast.ValueSpec); ok {
						for i, name := range vs.Names {
							if i < len(vs.Values) {
								record(name.Name, vs.Values[i])
							}
						}
					}
				}
			}
			return true
		})
		if !changed {
			break
		}
	}
}

// resolveExpr resolves a path or string expression to its candidate component
// chains. An unresolvable component becomes unknownComp; a component derived
// from one of the enclosing function's own string parameters becomes a
// paramPrefix marker (or the caller-supplied chains, when propagation applies).
func resolveExpr(e ast.Expr, fc *funcCtx) []pathChain {
	if fc.depth > 8 {
		return []pathChain{{unknownComp}}
	}
	fc.depth++
	defer func() { fc.depth-- }()

	switch v := e.(type) {
	case *ast.BasicLit:
		if s, ok := stringLit(v); ok {
			return []pathChain{{s}}
		}
		return []pathChain{{unknownComp}}

	case *ast.Ident:
		if s, ok := fc.consts[v.Name]; ok {
			return []pathChain{{s}}
		}
		if ch, ok := fc.idents[v.Name]; ok {
			return []pathChain{append(pathChain{}, ch...)}
		}
		if fc.params[v.Name] {
			if subs, ok := fc.sub[v.Name]; ok && len(subs) > 0 {
				return dedupChains(subs)
			}
			return []pathChain{{paramPrefix + v.Name}}
		}
		return []pathChain{{unknownComp}}

	case *ast.BinaryExpr:
		if v.Op.String() != "+" {
			return []pathChain{{unknownComp}}
		}
		left := resolveExpr(v.X, fc)
		right := resolveExpr(v.Y, fc)
		var out []pathChain
		for _, l := range left {
			for _, r := range right {
				if len(out) >= maxCandidates {
					return out
				}
				out = append(out, pathChain{flatten(l) + flatten(r)})
			}
		}
		if len(out) == 0 {
			return []pathChain{{unknownComp}}
		}
		return out

	case *ast.CallExpr:
		if callName(v) != "filepath.Join" {
			return []pathChain{{unknownComp}}
		}
		out := []pathChain{{}}
		for _, arg := range v.Args {
			parts := resolveExpr(arg, fc)
			var next []pathChain
			for _, base := range out {
				for _, p := range parts {
					if len(next) >= maxCandidates {
						break
					}
					next = append(next, append(append(pathChain{}, base...), p...))
				}
			}
			out = next
		}
		if len(out) == 0 {
			return []pathChain{{unknownComp}}
		}
		return out

	case *ast.ParenExpr:
		return resolveExpr(v.X, fc)
	}
	return []pathChain{{unknownComp}}
}

// matchMergerGlob reports whether chain resolves to a path some merger globs,
// and returns the rendered path for the failure message.
//
// ALL of the following must hold:
//   - the chain contains the literal component "inputs";
//   - EXACTLY ONE component follows it — a second means a subdirectory, and
//     filepath.Glob's `*` does not cross `/`, so no merger glob can match it
//     (this is what puts inputs/gf/<class>.txt out of scope);
//   - splitting that final component on "." yields at least THREE parts and the
//     last is "jsonl" or "txt";
//   - part[0] is a member of the matching stage set, OR is not a literal — an
//     unknown stage could be a real one, so it matches CONSERVATIVELY.
func matchMergerGlob(ch pathChain) (string, bool) {
	idx := -1
	for i, c := range ch {
		if c == "inputs" {
			idx = i
		}
	}
	if idx < 0 || len(ch) != idx+2 {
		return "", false
	}
	final := ch[idx+1]
	parts := strings.Split(final, ".")
	if len(parts) < 3 {
		return "", false
	}
	ext := parts[len(parts)-1]
	set, ok := map[string]map[string]bool{"jsonl": jsonlStagingStages, "txt": txtStagingStages}[ext]
	if !ok {
		return "", false
	}
	stage := parts[0]
	if isLiteral(stage) && !set[stage] {
		return "", false
	}
	return "inputs/" + render(final), true
}

// ─── small helpers ──────────────────────────────────────────────────────────

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

func callName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		if x, ok := f.X.(*ast.Ident); ok {
			return x.Name + "." + f.Sel.Name
		}
	}
	return ""
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv != nil && len(fn.Recv.List) > 0 {
		return fn.Name.Name
	}
	return fn.Name.Name
}

func paramOf(comp string) (string, bool) {
	i := strings.Index(comp, paramPrefix)
	if i < 0 {
		return "", false
	}
	rest := comp[i+len(paramPrefix):]
	if j := strings.IndexAny(rest, "\x00."); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		return "", false
	}
	return rest, true
}

func isLiteral(s string) bool { return !strings.Contains(s, "\x00") }

func flatten(ch pathChain) string { return strings.Join(ch, "/") }

func render(s string) string {
	s = strings.ReplaceAll(s, unknownComp, "*")
	for {
		i := strings.Index(s, paramPrefix)
		if i < 0 {
			break
		}
		rest := s[i+len(paramPrefix):]
		j := strings.IndexAny(rest, "\x00.")
		if j < 0 {
			j = len(rest)
		}
		s = s[:i] + "<" + rest[:j] + ">" + rest[j:]
	}
	return s
}

func equalChain(a, b pathChain) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func dedupChains(in []pathChain) []pathChain {
	seen := map[string]bool{}
	var out []pathChain
	for _, ch := range in {
		k := flatten(ch)
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, ch)
	}
	return out
}

// moduleRelBase returns root's path relative to the enclosing Go module root, so
// detector keys are repo-relative regardless of the test's working directory.
func moduleRelBase(root string) string {
	abs, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	dir := abs
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			rel, rerr := filepath.Rel(dir, abs)
			if rerr != nil || rel == "." {
				return ""
			}
			return filepath.ToSlash(rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func formatRows(rows []string) string {
	var b strings.Builder
	for _, r := range rows {
		f := strings.Split(r, "\t")
		for len(f) < 3 {
			f = append(f, "")
		}
		fmt.Fprintf(&b, "\n  %s  %s()  %s", f[0], f[1], f[2])
	}
	return b.String()
}

// violationFunc extracts the function name from a detector row.
func violationFunc(row string) string {
	f := strings.Split(row, "\t")
	if len(f) < 2 {
		return row
	}
	return f[1]
}

// violationFile extracts the file path from a detector row.
func violationFile(row string) string {
	f := strings.Split(row, "\t")
	if len(f) < 1 {
		return row
	}
	return f[0]
}

// ─── tests ──────────────────────────────────────────────────────────────────

func TestStagingContract(t *testing.T) {
	violations, stale := checkStagingContract(".", stagingContractAllowlist, derivedOutputExemptions)
	if len(violations) > 0 {
		t.Errorf("raw staging writes that must go through output.StageJSONL/StageLines (F3):%s\n\n"+
			"Migrate the write — DO NOT add it to stagingContractAllowlist. The allowlist "+
			"must reach zero before cutover.", formatRows(violations))
	}
	if len(stale) > 0 {
		t.Errorf("stale stagingContractAllowlist entries — DELETE them and decrement "+
			"stagingContractAllowlistSize:%s", formatRows(stale))
	}
}

func TestStagingContractAllowlistShrinks(t *testing.T) {
	n := 0
	for _, fns := range stagingContractAllowlist {
		n += len(fns)
	}
	if n != stagingContractAllowlistSize {
		t.Fatalf("flattened stagingContractAllowlist has %d entries but "+
			"stagingContractAllowlistSize is %d — lower BOTH together (the ratchet must "+
			"reach 0 before cutover)", n, stagingContractAllowlistSize)
	}
}

func TestDerivedOutputExemptionsPinned(t *testing.T) {
	n := 0
	for _, fns := range derivedOutputExemptions {
		n += len(fns)
	}
	if n != derivedOutputExemptionsSize {
		t.Fatalf("derivedOutputExemptions has %d entries, want %d — this map is NOT part of "+
			"the ratchet and must stay at exactly one entry", n, derivedOutputExemptionsSize)
	}
	// The CONSTANT itself, not merely map-vs-constant agreement. Raising both
	// together satisfies the check above; this one does not move.
	if derivedOutputExemptionsSize != 1 {
		t.Fatalf("derivedOutputExemptionsSize is %d, want 1.\n"+
			"  Growing this map is how an unmigrated raw staging write gets past a "+
			"zero-length allowlist:\n"+
			"  the allowlist stays at 0, the gate stays green, and a producer stops "+
			"clearing its staging on a\n"+
			"  zero-result run — the exact F3 defect. There is one legitimate derived "+
			"intermediate and it is\n"+
			"  already here.", derivedOutputExemptionsSize)
	}
	if len(derivedOutputExemptions) != 1 {
		t.Fatalf("derivedOutputExemptions must have exactly ONE file key, got %d: %v",
			len(derivedOutputExemptions), derivedOutputExemptions)
	}
	got, ok := derivedOutputExemptions["internal/modules/subdomains/merge.go"]
	if !ok || got["MergeStage"] != ".merged.txt" {
		t.Fatalf("the one exemption must be subdomains/merge.go MergeStage -> .merged.txt, got %v",
			derivedOutputExemptions)
	}
	if len(got) != 1 {
		t.Fatalf("the subdomains/merge.go exemption must name exactly ONE function, got %v", got)
	}
}

// TestStagingContractRatchetIsClosed is phase 15 plan 17's permanent closure of
// the F3 migration ratchet.
//
// TestStagingContractAllowlistShrinks only pins the map AGAINST the constant, so
// raising BOTH together would satisfy it. This test pins the CONSTANT, so the
// only way to re-open the ratchet is to edit an assertion whose failure message
// says that editing it is the regression.
//
// It also re-asserts, with an EMPTY allowlist and the one exemption in place,
// that the detector reports ZERO violations across internal/modules/. That is
// the substantive claim: "the allowlist is empty" is worthless if the detector
// would report violations were it consulted.
func TestStagingContractRatchetIsClosed(t *testing.T) {
	if stagingContractAllowlistSize != 0 {
		t.Errorf("stagingContractAllowlistSize is %d, want 0.\n"+
			"  The F3 staging-contract ratchet was CLOSED by phase 15 plan 17. Every "+
			"producer under\n"+
			"  internal/modules/ stages through output.StageJSONL / output.StageLines. "+
			"If a new write fails\n"+
			"  TestStagingContract, migrate the write — do NOT raise this constant.",
			stagingContractAllowlistSize)
	}
	if n := len(stagingContractAllowlist); n != 0 {
		var files []string
		for f := range stagingContractAllowlist {
			files = append(files, f)
		}
		sort.Strings(files)
		t.Errorf("stagingContractAllowlist has %d file(s) — %v — but the ratchet is closed.\n"+
			"  The empty map literal is kept ON PURPOSE so a new raw staging write still "+
			"gets a named\n"+
			"  failure; it is not a place to park one.", n, files)
	}

	violations, stale := checkStagingContract(".", nil, derivedOutputExemptions)
	if len(violations) > 0 {
		t.Errorf("with an EMPTY allowlist the detector still reports %d violation(s) — the "+
			"zero-length allowlist\n"+
			"  is therefore not evidence of anything:%s", len(violations), formatRows(violations))
	}
	if len(stale) > 0 {
		t.Errorf("an empty allowlist cannot produce stale entries; got:%s", formatRows(stale))
	}
}

// TestStagingContractMergersAndGfClassification asserts the three structural
// claims the guard's reachability depends on.
func TestStagingContractMergersAndGfClassification(t *testing.T) {
	violations, _ := checkStagingContract(".", nil, derivedOutputExemptions)
	reported := map[string]bool{}
	for _, v := range violations {
		reported[violationFile(v)] = true
	}

	// web/vulns/osint mergers only READ inputs/ — neither reported nor allowlisted.
	for _, f := range []string{
		"internal/modules/web/merge.go",
		"internal/modules/vulns/merge.go",
		"internal/modules/osint/merge.go",
	} {
		if reported[f] {
			t.Errorf("%s is a READER of inputs/ and must not be reported", f)
		}
		if _, ok := stagingContractAllowlist[f]; ok {
			t.Errorf("%s must not appear in stagingContractAllowlist", f)
		}
	}

	// subdomains/merge.go is exempted, never allowlisted.
	if reported["internal/modules/subdomains/merge.go"] {
		t.Error("subdomains/merge.go must be covered by derivedOutputExemptions, not reported")
	}
	if _, ok := stagingContractAllowlist["internal/modules/subdomains/merge.go"]; ok {
		t.Error("subdomains/merge.go must NOT be in stagingContractAllowlist — it is exempted")
	}
	if _, ok := derivedOutputExemptions["internal/modules/subdomains/merge.go"]; !ok {
		t.Error("subdomains/merge.go must be in derivedOutputExemptions")
	}

	// vulns/gf.go writes inputs/gf/<class>.txt — a SUBDIRECTORY. Out of scope by
	// construction: in NEITHER the violation set, NOR the allowlist, NOR the
	// exemptions. The previous plan revision wrongly exempted it; re-adding the
	// exemption is the most likely regression here.
	const gf = "internal/modules/vulns/gf.go"
	if reported[gf] {
		t.Error("vulns/gf.go writes a SUBDIRECTORY (inputs/gf/) that no merger glob can " +
			"reach — it must not be reported")
	}
	if _, ok := stagingContractAllowlist[gf]; ok {
		t.Error("vulns/gf.go must NOT be in stagingContractAllowlist")
	}
	if _, ok := derivedOutputExemptions[gf]; ok {
		t.Error("vulns/gf.go must NOT be in derivedOutputExemptions — it is out of scope by " +
			"subdirectory and is hand-verified in plan 15-14 Task 1 instead")
	}
}

// TestStagingContractReaderOnlyFilesPass asserts the ~15 reader-only files are
// never reported, with an EMPTY allowlist.
func TestStagingContractReaderOnlyFilesPass(t *testing.T) {
	readers := []string{
		"internal/modules/web/merge.go",
		"internal/modules/web/ffuf.go",
		"internal/modules/web/hakoriginfinder.go",
		"internal/modules/subdomains/geo.go",
		"internal/modules/subdomains/buckets.go",
		"internal/modules/vulns/merge.go",
		"internal/modules/osint/merge.go",
		"internal/modules/osint/metadata.go",
		"internal/modules/osint/xnldorker.go",
		"internal/modules/osint/swagger.go",
		"internal/modules/osint/github_dorks.go",
		"internal/modules/osint/cmseek.go",
		"internal/modules/osint/github_leaks.go",
		"internal/modules/osint/postman.go",
		"internal/modules/osint/gqlspection.go",
	}
	violations, _ := checkStagingContract(".", nil, derivedOutputExemptions)
	reported := map[string]bool{}
	for _, v := range violations {
		reported[violationFile(v)] = true
	}
	for _, f := range readers {
		if reported[f] {
			t.Errorf("reader-only file %s was reported — a reader has nothing to stage, and a "+
				"path-triggered rule like that can never reach zero", f)
		}
	}
}

// TestStagingContractToolInputWritesOutOfScope is THE criterion that makes `== 0`
// reachable. ~35 functions write a tool-input, scratch or subdirectory file into
// inputs/; none may be reported for that write.
//
// Each site below still writes its tool-input/scratch file. The assertion has
// two flavours:
//
//   - staging != "" — the file ALSO contains an unmigrated staging write, so it
//     DOES appear, but the reported path must be the STAGING path and never the
//     tool-input path.
//   - staging == "" — the file must be ABSENT from the violation set entirely,
//     because its only remaining inputs/ writes are tool-input or scratch files
//     that no merger globs. That is the stronger direction: a write-triggered
//     rule would report every one of them.
//
// Plan 15-13 migrated katana.go and wafw00f.go, so both moved from the first
// flavour to the second: their staging now goes through output.StageJSONL while
// inputs/katana_targets.txt and inputs/wafw00f.hosts.txt are still written
// unconditionally as tool input. Their absence here is what proves the rule
// stayed staging-glob-triggered rather than being loosened during the sweep.
// vulns/sqli.go keeps the first flavour until plan 15-14 migrates it.
func TestStagingContractToolInputWritesOutOfScope(t *testing.T) {
	violations, _ := checkStagingContract(".", nil, derivedOutputExemptions)
	byFile := map[string][]string{}
	for _, v := range violations {
		byFile[violationFile(v)] = append(byFile[violationFile(v)], v)
	}

	cases := []struct {
		file      string
		toolInput string // must NEVER appear in a reported path
		staging   string // "" ⇒ the file must be absent from the set entirely
		why       string // why it must be absent (staging == "" only)
	}{
		{
			file: "internal/modules/web/katana.go", toolInput: "katana_targets.txt",
			why: "its urls.katana.jsonl staging was migrated to output.StageJSONL by plan 15-13; " +
				"only the tool-input write remains",
		},
		{
			file: "internal/modules/web/wafw00f.go", toolInput: "wafw00f.hosts.txt",
			why: "its waf.wafw00f.jsonl staging was migrated to output.StageJSONL by plan 15-13; " +
				"only the tool-input write remains",
		},
		{
			file: "internal/modules/vulns/sqli.go", toolInput: "tmp_sqli.txt",
			why: "its findings.sqli.jsonl staging was migrated to output.StageJSONL by plan 15-14; " +
				"only the -m tool-input write remains, and sqli.go Run legitimately " +
				"contains BOTH shapes",
		},
		{
			file: "internal/modules/subdomains/csprecon.go", toolInput: "csprecon.hosts.txt",
			why: "it writes only a scratch file that no merger globs",
		},
	}
	for _, c := range cases {
		rows := byFile[c.file]
		if c.staging == "" {
			if len(rows) > 0 {
				t.Errorf("%s must be absent from the violation set (%s), yet it was reported — "+
					"the rule must stay staging-glob-triggered, not write-triggered (it still "+
					"writes %s):%s", c.file, c.why, c.toolInput, formatRows(rows))
			}
			continue
		}
		if len(rows) == 0 {
			t.Errorf("%s stages %s and must be reported until migrated", c.file, c.staging)
			continue
		}
		joined := strings.Join(rows, "\n")
		if strings.Contains(joined, c.toolInput) {
			t.Errorf("%s was reported for its TOOL-INPUT write %s — the rule must be "+
				"staging-glob-triggered, not write-triggered:%s", c.file, c.toolInput, formatRows(rows))
		}
		if !strings.Contains(joined, c.staging) {
			t.Errorf("%s must be reported for its STAGING write %s, got:%s",
				c.file, c.staging, formatRows(rows))
		}
	}
}

// TestStagingContractToolInputWritesStayRaw pins four named TOOL-INPUT writes at
// the SOURCE level, in the opposite direction from the detector.
//
// Sixteen of the nineteen tool-input/scratch writes in vulns + osint share a
// function with a genuine staging write, so the plan-15-14 sweep had to be
// surgical: the staging call changes, the tool-input write does not. The
// detector can only prove those writes were not REPORTED. This test proves they
// were not MIGRATED — that nobody "finished the job" by routing a file handed to
// an external binary through a remove-on-empty helper, which would delete
// sqlmap's -m list, commix's -m list, dalfox's stdin corpus or gato's org list
// out from under the tool on a zero-result run.
func TestStagingContractToolInputWritesStayRaw(t *testing.T) {
	cases := []struct {
		file   string
		target string // the tool-input path literal
		tool   string // what consumes it
	}{
		{"internal/modules/vulns/sqli.go", "tmp_sqli.txt", "sqlmap -m"},
		{"internal/modules/vulns/cmdi.go", "tmp_rce.txt", "commix -m"},
		{"internal/modules/vulns/xss.go", "xss_reflected.txt", "dalfox pipe stdin"},
		{"internal/modules/osint/github_actions.go", "gato_orgs.txt", "gato org list"},
	}
	for _, c := range cases {
		// The detector reports repo-relative keys; this test runs with the
		// package dir as cwd, so read through the same relative path.
		onDisk := strings.TrimPrefix(c.file, "internal/modules/")
		src, err := os.ReadFile(onDisk) //nolint:gosec // fixed in-repo path
		if err != nil {
			t.Fatalf("read %s: %v", c.file, err)
		}
		body := string(src)
		if !strings.Contains(body, c.target) {
			t.Errorf("%s no longer writes %s — the %s input list disappeared",
				c.file, c.target, c.tool)
			continue
		}
		// The literal must still be assembled for a RAW write. Every one of the
		// four is written with os.WriteFile in the same function that assembles
		// the path.
		if !strings.Contains(body, "os.WriteFile(") {
			t.Errorf("%s no longer contains a raw os.WriteFile — %s (%s) appears to have "+
				"been routed through a staging helper, which would give a file passed to "+
				"an external binary remove-on-empty semantics",
				c.file, c.target, c.tool)
		}
	}
}

// TestStagingContractArgLiteralPropagation pins the live-tree witnesses for the
// detector's argument-literal propagation — a staging write through a helper
// that assembles the path from its own PARAMETERS rather than from a literal in
// its own body. Without propagation the detector reports ZERO osint violations
// and 20 unmigrated producers pass silently.
//
// BOTH live-tree witnesses are now MIGRATED, so both are asserted in the ABSENT
// direction: subdomains/takeover.go writeTakeoverStagingFile by plan 15-13 and
// osint/domain_info.go writeOSINTStaging by plan 15-14. That means this test no
// longer proves propagation still WORKS — a broken propagator would also report
// nothing. It is not supposed to: the MECHANISM is pinned permanently by the
// helperArgLiteralOK / helperArgLiteralBad fixtures asserted as an exact set by
// TestStagingContractDetector, which is why those fixtures exist. What this test
// pins is the live tree — that neither witness reverts to a raw write. It is
// asserted in that direction rather than deleted, because it is also the only
// producer whose staging is read by the FIFTH merger (mergeTakeoverFindings in
// internal/mcp/handlers/common.go, which appears in no *StagingPrefixes slice) —
// a regression that dropped "takeover" from jsonlStagingStages would silently
// stop reporting it, and this assertion catches that as a still-reported row
// once 15-14 has nothing left to migrate.
//
// The propagation MECHANISM itself is pinned permanently and independently of
// the live tree by the helperArgLiteralOK / helperArgLiteralBad fixtures in
// testdata/stagingcontract/, asserted as an exact set by
// TestStagingContractDetector.
func TestStagingContractArgLiteralPropagation(t *testing.T) {
	violations, _ := checkStagingContract(".", nil, derivedOutputExemptions)
	got := map[string]bool{}
	for _, v := range violations {
		got[violationFile(v)+"\t"+violationFunc(v)] = true
	}

	wantMigrated := map[string]string{
		"internal/modules/subdomains/takeover.go": "writeTakeoverStagingFile",
		"internal/modules/osint/domain_info.go":   "writeOSINTStaging",
	}
	for file, fn := range wantMigrated {
		if got[file+"\t"+fn] {
			t.Errorf("%s %s was migrated to output.StageJSONL (takeover by plan 15-13, "+
				"writeOSINTStaging by plan 15-14) and must no longer be reported — a raw "+
				"staging write has come back", file, fn)
		}
	}
}

// ─── fixture self-test ──────────────────────────────────────────────────────

var fixtureExemptions = map[string]map[string]string{
	"internal/modules/testdata/stagingcontract/fixtures.go": {
		"derivedExemptOK":     ".merged.txt",
		"derivedNotExemptBad": ".merged.txt",
	},
}

func TestStagingContractDetector(t *testing.T) {
	const fixtureRoot = "testdata/stagingcontract"

	violations, stale := checkStagingContract(fixtureRoot, nil, fixtureExemptions)
	if len(stale) > 0 {
		t.Fatalf("empty allowlist must produce no stale entries, got:%s", formatRows(stale))
	}

	got := map[string]bool{}
	for _, v := range violations {
		got[violationFunc(v)] = true
	}
	want := map[string]bool{
		"guardedRawWriteBad":  true,
		"osWriteFileBad":      true,
		"osCreateBad":         true,
		"osOpenFileBad":       true,
		"derivedTxtBad":       true,
		"helperWriteBad":      true,
		"helperArgLiteralBad": true,
		"derivedNotExemptBad": true,
	}

	for fn := range want {
		if !got[fn] {
			t.Errorf("fixture %s must be REPORTED but was not:%s", fn, formatRows(violations))
		}
	}
	for fn := range got {
		if !want[fn] {
			t.Errorf("fixture %s must NOT be reported (it is a passing shape):%s", fn, formatRows(violations))
		}
	}
}

func TestStagingContractDetectorStaleDirection(t *testing.T) {
	const fixtureRoot = "testdata/stagingcontract"
	const fixtureFile = "internal/modules/testdata/stagingcontract/fixtures.go"

	// stageJSONLOK is migrated, so an allowlist entry naming it is STALE.
	allow := map[string][]string{fixtureFile: {"stageJSONLOK"}}
	_, stale := checkStagingContract(fixtureRoot, allow, fixtureExemptions)
	if len(stale) != 1 {
		t.Fatalf("expected exactly 1 stale entry for stageJSONLOK, got %d:%s", len(stale), formatRows(stale))
	}
	if violationFunc(stale[0]) != "stageJSONLOK" {
		t.Fatalf("stale entry names %q, want stageJSONLOK", violationFunc(stale[0]))
	}

	// A function that does not exist is stale too.
	allow = map[string][]string{fixtureFile: {"noSuchFunction"}}
	_, stale = checkStagingContract(fixtureRoot, allow, fixtureExemptions)
	if len(stale) != 1 || violationFunc(stale[0]) != "noSuchFunction" {
		t.Fatalf("expected a stale entry for noSuchFunction, got:%s", formatRows(stale))
	}
}

// TestStagingContractDetectorExemptionIsScopedToLiteral proves the exemption
// keys on file + function + PATH LITERAL, not on the whole function: removing
// the exemption makes derivedExemptOK a violation, and derivedNotExemptBad is
// reported even WITH the exemption in place because its second write does not
// carry the exempt literal.
func TestStagingContractDetectorExemptionIsScopedToLiteral(t *testing.T) {
	const fixtureRoot = "testdata/stagingcontract"

	withExempt, _ := checkStagingContract(fixtureRoot, nil, fixtureExemptions)
	for _, v := range withExempt {
		if violationFunc(v) == "derivedExemptOK" {
			t.Errorf("derivedExemptOK writes only the exempt .merged.txt literal and must pass: %s", v)
		}
		if violationFunc(v) == "derivedNotExemptBad" && !strings.Contains(v, "findings") {
			t.Errorf("derivedNotExemptBad must be reported for its NON-exempt findings write, got %q", v)
		}
	}

	noExempt, _ := checkStagingContract(fixtureRoot, nil, nil)
	found := false
	for _, v := range noExempt {
		if violationFunc(v) == "derivedExemptOK" {
			found = true
		}
	}
	if !found {
		t.Error("without the exemption, derivedExemptOK must be reported — otherwise the " +
			"exemption is decorative rather than load-bearing")
	}
}
