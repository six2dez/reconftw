// SPDX-License-Identifier: MIT
//
// # Stream-contract ratchet
//
// backend.Event.Err reports that a tool RAN and ended badly — it exited non-zero
// or its output was truncated by a scanner overflow. Audit finding F6 established
// that of the 23 stream-consumption loops under internal/modules, ZERO read it: a
// tool could emit half its findings, exit 7, and the task was still reported
// successful while its parser read a truncated — or entirely stale — staging
// file. For a security tool that means a report which understates risk, which is
// the worst failure mode available to us.
//
// This test is the enforcement mechanism. It parses every .go file under
// internal/modules and fails when a function calls app.Tools.Stream without
// consuming the terminal error.
//
// # The allowlist is a temporary migration ratchet
//
// streamContractAllowlist was introduced by phase 15 plan 02 seeded with the 23
// known-unmigrated sites, so this test passes on the tree that introduced it.
// Plans 15-13 and 15-14 migrate those sites and delete their entries; plan 15-17
// asserts the list is empty. It must reach zero before the Phase 14 cutover, and
// no new entry may ever be added — a new Stream call site is expected to consume
// the terminal error on the day it is written.
//
// The ratchet fails in both directions on purpose:
//
//   - A site that consumes nothing and is absent from the allowlist is a
//     violation (the list cannot be dodged).
//   - An allowlist entry whose function is gone, or which now consumes, is stale
//     (the list cannot quietly outlive its migration).
//
// Both directions are asserted permanently by TestStreamContractDetector against
// the fixtures in testdata/streamcontract/, not proven once by hand.
//
// # The four accepted shapes
//
// A migrating executor does not need to read the detector. These four shapes are
// legal, and nothing else is:
//
//  1. backend.Drain(ch) appears in the function body.
//  2. backend.Collect(ch, fn) appears in the function body.
//  3. The function calls a helper defined in the SAME package whose own body
//     contains (1) or (2), and USES that helper's return value — a bare
//     `helper(ch)` statement, or `_ = helper(ch)`, does not count. Only one level
//     of indirection is recognised; a helper calling a helper is not.
//  4. Accumulator: inside the `for ev := range ch` loop, ev.Err is assigned to a
//     variable, AND after the loop an `if` compares that variable against nil.
//     BOTH halves are required — assigning ev.Err and never checking it is still
//     a violation.
//
// Shape 4 is why the detector is AST-based rather than a line scanner: a token
// grep cannot tell "checked after the loop" from "assigned and dropped". It is
// also why a bare mention of ev.Err is NOT sufficient.
//
// What is explicitly NOT consumption: handling the error returned by Stream()
// itself. That is the DISPATCH error — the tool was not registered or is not on
// PATH — and it keeps its existing task.StatusSkipped handling
// (internal/modules/web/arjun.go). Promoting it to task.StatusErrored would
// fail-fast the entire subdomains spine on any host with an incomplete toolchain
// (internal/core/scheduler/policy.go). See the package comment on
// internal/core/backend/stream.go for the full policy boundary.
package modules_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// streamContractAllowlist maps a repo-relative file path to the names of
// functions in it that call app.Tools.Stream without consuming the terminal
// error. Seeded by phase 15 plan 02 with the 23 sites the F6 census found.
//
// Methods are named "<ReceiverType>.<Method>" because a bare "Run" is ambiguous —
// permut.go declares four of them on different task types.
//
// DELETE entries as you migrate. NEVER add one.
var streamContractAllowlist = map[string][]string{
	// internal/modules/web — 0 sites (all 6 migrated by plan 15-13 Task 2)
	// internal/modules/subdomains — 0 sites (all 4 migrated by plan 15-13 Task 2)

	// internal/modules/vulns — 11 sites (sqli.go and ssti.go have two each)
	"internal/modules/vulns/cmdi.go":        {"CMDITask.Run"},
	"internal/modules/vulns/nuclei_dast.go": {"NucleiDASTTask.Run"},
	"internal/modules/vulns/ssrf.go":        {"runSSRFFFUF"},
	"internal/modules/vulns/lfi.go":         {"runLFIFFUF"},
	"internal/modules/vulns/webcache.go":    {"WebCacheTask.Run"},
	"internal/modules/vulns/sqli.go":        {"runSQLMap", "runGhauriPerURL"},
	"internal/modules/vulns/ssti.go":        {"runTInjA", "runSSTImap"},
	"internal/modules/vulns/fuzzparams.go":  {"FuzzparamsTask.Run"},
	"internal/modules/vulns/crlf.go":        {"CRLFTask.Run"},

	// internal/modules/osint — 2 sites
	"internal/modules/osint/cloud_enum.go":   {"CloudEnumTask.Run"},
	"internal/modules/osint/github_leaks.go": {"GitHubLeaksTask.Run"},
}

// streamContractAllowlistSize is the number of flattened allowlist entries.
// TestStreamContractAllowlistShrinks pins it so the list cannot grow by
// accident. Lower it as plans 15-13 and 15-14 migrate sites; plan 15-17 asserts
// it is 0.
//
// 15-02 seed: 23 (web 6, subdomains 4, vulns 11, osint 2).
// 15-13 lowered it to 13 by migrating all 10 web + subdomains sites.
// 15-14 drives it to 0 (vulns 11 + osint 2).
// 15-17 asserts 0.
const streamContractAllowlistSize = 13

// TestStreamContract is the ratchet itself.
func TestStreamContract(t *testing.T) {
	violations, stale := checkStreamContract(".", streamContractAllowlist)

	for _, v := range violations {
		t.Errorf("stream-contract violation: %s calls app.Tools.Stream but never consumes the terminal error.\n"+
			"  A tool that exits non-zero there is indistinguishable from one that succeeded, and the staging\n"+
			"  file it parses may be truncated or left over from a previous run.\n"+
			"  Fix it with one of the four accepted shapes documented at the top of this file — do NOT add an\n"+
			"  allowlist entry; the allowlist only shrinks.", v)
	}

	for _, s := range stale {
		t.Errorf("stale allowlist entry: %s\n"+
			"  Either that function no longer exists, no longer calls app.Tools.Stream, or already consumes the\n"+
			"  terminal error. Delete the entry from streamContractAllowlist and decrement\n"+
			"  streamContractAllowlistSize.", s)
	}
}

// TestStreamContractAllowlistShrinks pins the allowlist size so the ratchet
// cannot be loosened silently.
func TestStreamContractAllowlistShrinks(t *testing.T) {
	got := 0
	for _, fns := range streamContractAllowlist {
		got += len(fns)
	}
	switch {
	case got > streamContractAllowlistSize:
		t.Errorf("the stream-contract allowlist grew to %d entries (constant says %d) — that is never correct.\n"+
			"  A new app.Tools.Stream call site must consume the terminal error on the day it is written;\n"+
			"  the allowlist only shrinks (phase 15 plan 02).", got, streamContractAllowlistSize)
	case got < streamContractAllowlistSize:
		t.Errorf("streamContractAllowlist is down to %d entries but streamContractAllowlistSize still says %d.\n"+
			"  If you migrated a site, lower the constant in the same commit so the ratchet stays tight.",
			got, streamContractAllowlistSize)
	}
}

// TestStreamContractDetector proves the detector itself works, in BOTH
// directions, against the fixtures in testdata/streamcontract/.
//
// Without this, "the guard fails when a site is unmigrated" and "the guard fails
// when an allowlist entry is stale" would be claims backed only by a manual
// mutation someone has to remember to repeat.
func TestStreamContractDetector(t *testing.T) {
	root := filepath.Join("testdata", "streamcontract")
	// Allowlist keys and detector output are both repo-relative (see repoRelPath),
	// so the fixture expectations must be too.
	goodFixture := repoRelPath(filepath.Join(root, "good_shapes.go"))
	badFixture := repoRelPath(filepath.Join(root, "bad_shapes.go"))

	t.Run("violations are exactly the bad shapes", func(t *testing.T) {
		violations, stale := checkStreamContract(root, nil)
		if len(stale) != 0 {
			t.Errorf("stale = %v, want empty (no allowlist was passed)", stale)
		}

		gotNames := funcNamesOf(violations)
		wantNames := []string{
			"accumulatorAssignedNeverChecked",
			"bareRangeBad",
			"streamErrOnlyBad",
		}
		if !equalStrings(gotNames, wantNames) {
			t.Fatalf("violations = %v, want exactly %v\n"+
				"  Extra names mean the detector rejects a shape plans 15-13/15-14 are allowed to use.\n"+
				"  Missing names mean it accepts a shape that drops the terminal error.\n"+
				"  full: %v", gotNames, wantNames, violations)
		}

		// The good shapes must be absent — asserted explicitly so a failure names
		// the shape that broke rather than just showing a set diff.
		for _, good := range []string{"drainOK", "collectOK", "helperOK", "accumulatorOK"} {
			for _, name := range gotNames {
				if name == good {
					t.Errorf("accepted shape %q was reported as a violation", good)
				}
			}
		}

		// Violations must name their file, so the ratchet's failure message is
		// actionable.
		for _, v := range violations {
			if !strings.HasPrefix(v, badFixture+":") {
				t.Errorf("violation %q does not name %s", v, badFixture)
			}
		}
	})

	t.Run("allowlisting a bad shape suppresses it", func(t *testing.T) {
		allow := map[string][]string{badFixture: {"bareRangeBad"}}
		violations, stale := checkStreamContract(root, allow)
		if len(stale) != 0 {
			t.Errorf("stale = %v, want empty — bareRangeBad genuinely violates, so its entry is live", stale)
		}
		if names := funcNamesOf(violations); !equalStrings(names, []string{"accumulatorAssignedNeverChecked", "streamErrOnlyBad"}) {
			t.Errorf("violations = %v, want the two non-allowlisted bad shapes", names)
		}
	})

	t.Run("an allowlisted compliant function is stale", func(t *testing.T) {
		// This is the direction that lets an allowlist quietly outlive its
		// migration: drainOK consumes correctly, so listing it is dead weight
		// that would mask a future regression in that same function.
		allow := map[string][]string{goodFixture: {"drainOK"}}
		_, stale := checkStreamContract(root, allow)
		if names := funcNamesOf(stale); !equalStrings(names, []string{"drainOK"}) {
			t.Fatalf("stale = %v, want [drainOK] — a compliant function left on the allowlist must be reported", names)
		}
	})

	t.Run("an allowlisted missing function is stale", func(t *testing.T) {
		allow := map[string][]string{badFixture: {"noSuchFunction"}}
		_, stale := checkStreamContract(root, allow)
		if names := funcNamesOf(stale); !equalStrings(names, []string{"noSuchFunction"}) {
			t.Fatalf("stale = %v, want [noSuchFunction]", names)
		}
	})

	t.Run("an allowlisted missing file is stale", func(t *testing.T) {
		allow := map[string][]string{"internal/modules/gone.go": {"vanished"}}
		_, stale := checkStreamContract(root, allow)
		if names := funcNamesOf(stale); !equalStrings(names, []string{"vanished"}) {
			t.Fatalf("stale = %v, want [vanished]", names)
		}
	})
}

// TestStreamContractSkipsTestdata asserts the real-tree walk does not pick up the
// fixtures. If it did, the three intentional violations in
// testdata/streamcontract/bad_shapes.go would make TestStreamContract
// permanently red.
func TestStreamContractSkipsTestdata(t *testing.T) {
	violations, _ := checkStreamContract(".", streamContractAllowlist)
	for _, v := range violations {
		if strings.Contains(v, "/testdata/") {
			t.Errorf("the real-tree walk reported a fixture: %s", v)
		}
	}
}

// --- detector ---------------------------------------------------------------

// checkStreamContract parses every .go file under root and reports:
//
//   - violations: "<repo-relative-path>:<func>" for each function that calls
//     app.Tools.Stream (or StreamEnv) without consuming the terminal error and is
//     not named in allow.
//   - stale: "<repo-relative-path>:<func>" for each allow entry whose file is
//     gone, whose function is gone, which no longer calls Stream at all, or which
//     now consumes the terminal error.
//
// Directories named testdata are skipped (unless root itself is one), as are
// dot-directories and vendor. Both slices are sorted for stable output.
func checkStreamContract(root string, allow map[string][]string) (violations []string, stale []string) {
	// index maps "<relpath>:<func>" to what those declarations do with the
	// contract. It holds a slice because a file routinely declares the same method
	// name on several receiver types (permut.go has four Run methods); the
	// receiver-qualified name disambiguates them, and the slice keeps the lookup
	// honest if two declarations ever do collide.
	index := map[string][]*streamFnFacts{}
	// consumingHelpers maps a package directory to the set of function names in
	// it whose own body drains or collects (accepted shape 3).
	consumingHelpers := map[string]map[string]bool{}
	// pending holds every parsed function so shape 3 can be resolved after all
	// files are seen — a helper may be declared in a different file of the same
	// package, or later in the same one.
	var pending []*streamFnFacts

	fset := token.NewFileSet()

	walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}

		file, parseErr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if parseErr != nil {
			return fmt.Errorf("parse %s: %w", path, parseErr)
		}

		rel := repoRelPath(path)
		dir := filepath.Dir(path)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			facts := analyzeStreamFn(fn)
			facts.relPath = rel
			facts.dir = dir

			if facts.drainsDirectly {
				if consumingHelpers[dir] == nil {
					consumingHelpers[dir] = map[string]bool{}
				}
				// Shape-3 helpers are resolved from a plain call expression, so
				// index them under the unqualified name.
				consumingHelpers[dir][fn.Name.Name] = true
			}

			key := rel + ":" + facts.name
			index[key] = append(index[key], facts)
			pending = append(pending, facts)
		}
		return nil
	})
	if walkErr != nil {
		// Surface as a violation rather than panicking: a parse failure must not
		// be able to turn the ratchet green.
		return []string{fmt.Sprintf("<walk error>: %v", walkErr)}, nil
	}

	// Resolve shape 3 now that every package's helpers are known, then classify.
	for _, facts := range pending {
		for name := range facts.usedCallees {
			if consumingHelpers[facts.dir][name] {
				facts.delegatesToHelper = true
				break
			}
		}
		if !facts.hasStreamCall || facts.consumes() {
			continue
		}
		if containsString(allow[facts.relPath], facts.name) {
			continue
		}
		violations = append(violations, facts.relPath+":"+facts.name)
	}

	// An entry is stale when its file is gone, its function is gone, that function
	// no longer calls Stream, or it now consumes — all four collapse to "the index
	// holds no unmigrated declaration by that name".
	for file, fns := range allow {
		for _, name := range fns {
			live := false
			for _, facts := range index[file+":"+name] {
				if facts.hasStreamCall && !facts.consumes() {
					live = true
					break
				}
			}
			if !live {
				stale = append(stale, file+":"+name)
			}
		}
	}

	sort.Strings(violations)
	sort.Strings(stale)
	return violations, stale
}

// streamFnFacts is what the detector learned about one function declaration.
type streamFnFacts struct {
	name    string
	relPath string
	dir     string

	// hasStreamCall is true when the body calls <something>.Tools.Stream or
	// .Tools.StreamEnv.
	hasStreamCall bool
	// drainsDirectly is accepted shape 1 or 2: backend.Drain / backend.Collect
	// appears in the body. It also makes this function a consuming helper for
	// shape 3.
	drainsDirectly bool
	// accumulates is accepted shape 4.
	accumulates bool
	// delegatesToHelper is accepted shape 3, resolved after the whole walk.
	delegatesToHelper bool
	// usedCallees are same-package functions called here whose return value is
	// used (i.e. not a bare expression statement and not assigned only to _).
	usedCallees map[string]bool
}

func (f *streamFnFacts) consumes() bool {
	return f.drainsDirectly || f.accumulates || f.delegatesToHelper
}

// declName renders a declaration's allowlist name. Methods are qualified by
// their receiver type ("SubPermutTask.Run"), because a bare "Run" is ambiguous in
// most module files — permut.go alone declares four of them, and allowlisting the
// wrong one would silently exempt a site that was never migrated.
func declName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	if recv := receiverTypeName(fn.Recv.List[0].Type); recv != "" {
		return recv + "." + fn.Name.Name
	}
	return fn.Name.Name
}

func receiverTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return receiverTypeName(t.X)
	case *ast.IndexExpr: // generic receiver, e.g. Task[T]
		return receiverTypeName(t.X)
	case *ast.IndexListExpr:
		return receiverTypeName(t.X)
	default:
		return ""
	}
}

func analyzeStreamFn(fn *ast.FuncDecl) *streamFnFacts {
	facts := &streamFnFacts{name: declName(fn), usedCallees: map[string]bool{}}

	discarded := discardedCalls(fn.Body)

	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		switch fun := call.Fun.(type) {
		case *ast.SelectorExpr:
			if isToolsStreamCall(fun) {
				facts.hasStreamCall = true
			}
			if isBackendDrainOrCollect(fun) {
				facts.drainsDirectly = true
			}
		case *ast.Ident:
			// A same-package call. Only record it when its result is used;
			// `helper(ch)` as a statement throws the error away.
			if !discarded[call] {
				facts.usedCallees[fun.Name] = true
			}
		}
		return true
	})

	facts.accumulates = accumulatesTerminalErr(fn.Body)
	return facts
}

// isToolsStreamCall matches app.Tools.Stream / app.Tools.StreamEnv, i.e. a
// selector whose receiver is itself a selector ending in "Tools".
func isToolsStreamCall(sel *ast.SelectorExpr) bool {
	if sel.Sel.Name != "Stream" && sel.Sel.Name != "StreamEnv" {
		return false
	}
	inner, ok := sel.X.(*ast.SelectorExpr)
	return ok && inner.Sel.Name == "Tools"
}

// isBackendDrainOrCollect matches backend.Drain / backend.Collect.
func isBackendDrainOrCollect(sel *ast.SelectorExpr) bool {
	if sel.Sel.Name != "Drain" && sel.Sel.Name != "Collect" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "backend"
}

// discardedCalls collects the CallExpr nodes whose result is thrown away: a bare
// expression statement, or an assignment whose left-hand side is entirely blank.
func discardedCalls(body *ast.BlockStmt) map[*ast.CallExpr]bool {
	out := map[*ast.CallExpr]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch st := n.(type) {
		case *ast.ExprStmt:
			if call, ok := st.X.(*ast.CallExpr); ok {
				out[call] = true
			}
		case *ast.AssignStmt:
			allBlank := true
			for _, lhs := range st.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || id.Name != "_" {
					allBlank = false
					break
				}
			}
			if allBlank {
				for _, rhs := range st.Rhs {
					if call, ok := rhs.(*ast.CallExpr); ok {
						out[call] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// accumulatesTerminalErr implements accepted shape 4.
//
// It requires BOTH halves: an assignment inside a range loop whose right-hand
// side mentions <rangeIdent>.Err, AND — after that loop, in the same statement
// list — an `if` comparing the assigned identifier against nil. Assigning ev.Err
// and never checking it is still a violation, which is precisely the distinction
// a token grep cannot make.
func accumulatesTerminalErr(body *ast.BlockStmt) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		blk, ok := n.(*ast.BlockStmt)
		if !ok {
			return true
		}
		if statementListAccumulates(blk.List) {
			found = true
			return false
		}
		return true
	})
	return found
}

func statementListAccumulates(list []ast.Stmt) bool {
	for i, st := range list {
		rng, ok := st.(*ast.RangeStmt)
		if !ok {
			continue
		}
		// For a channel range (`for ev := range ch`) the event binds to Key, not
		// Value. Accept either so slice/map ranges over collected events work too.
		candidates := map[string]bool{}
		for _, expr := range []ast.Expr{rng.Key, rng.Value} {
			if id, ok := expr.(*ast.Ident); ok && id.Name != "_" {
				candidates[id.Name] = true
			}
		}
		if len(candidates) == 0 {
			continue
		}

		assigned := assignedFromErr(rng.Body, candidates)
		if len(assigned) == 0 {
			continue
		}
		for _, later := range list[i+1:] {
			if checksAgainstNil(later, assigned) {
				return true
			}
		}
	}
	return false
}

// assignedFromErr returns the identifiers assigned a value derived from
// <candidate>.Err anywhere inside the range body. The right-hand side is
// searched rather than matched exactly, so wrapping — `streamErr =
// fmt.Errorf("nuclei: %w", ev.Err)` — still counts.
func assignedFromErr(body *ast.BlockStmt, candidates map[string]bool) map[string]bool {
	assigned := map[string]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		mentionsErr := false
		for _, rhs := range as.Rhs {
			ast.Inspect(rhs, func(inner ast.Node) bool {
				sel, ok := inner.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Err" {
					return true
				}
				if id, ok := sel.X.(*ast.Ident); ok && candidates[id.Name] {
					mentionsErr = true
					return false
				}
				return true
			})
		}
		if !mentionsErr {
			return true
		}
		for _, lhs := range as.Lhs {
			if id, ok := lhs.(*ast.Ident); ok && id.Name != "_" {
				assigned[id.Name] = true
			}
		}
		return true
	})
	return assigned
}

// checksAgainstNil reports whether stmt contains an `if` whose condition compares
// one of the assigned identifiers against nil.
func checksAgainstNil(stmt ast.Stmt, assigned map[string]bool) bool {
	found := false
	ast.Inspect(stmt, func(n ast.Node) bool {
		if found {
			return false
		}
		ifStmt, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		ast.Inspect(ifStmt.Cond, func(inner ast.Node) bool {
			bin, ok := inner.(*ast.BinaryExpr)
			if !ok || (bin.Op != token.NEQ && bin.Op != token.EQL) {
				return true
			}
			if isAssignedIdent(bin.X, assigned) && isNilIdent(bin.Y) {
				found = true
			}
			if isAssignedIdent(bin.Y, assigned) && isNilIdent(bin.X) {
				found = true
			}
			return !found
		})
		return !found
	})
	return found
}

func isAssignedIdent(e ast.Expr, assigned map[string]bool) bool {
	id, ok := e.(*ast.Ident)
	return ok && assigned[id.Name]
}

func isNilIdent(e ast.Expr) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == "nil"
}

// --- path + slice helpers ---------------------------------------------------

// repoRelPath renders path relative to the enclosing Go module root, with
// forward slashes, so allowlist keys read as repo-relative paths
// ("internal/modules/web/ffuf.go") no matter which directory the test runs from.
// It degrades to the cleaned input when the module root cannot be located.
func repoRelPath(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.ToSlash(filepath.Clean(path))
	}
	dir := filepath.Dir(abs)
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			rel, relErr := filepath.Rel(dir, abs)
			if relErr != nil {
				return filepath.ToSlash(filepath.Clean(path))
			}
			return filepath.ToSlash(rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.ToSlash(filepath.Clean(path))
		}
		dir = parent
	}
}

// funcNamesOf strips the "<path>:" prefix from detector output so assertions read
// as sets of function names.
func funcNamesOf(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if idx := strings.LastIndex(e, ":"); idx >= 0 {
			out = append(out, e[idx+1:])
			continue
		}
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	for i := range g {
		if g[i] != w[i] {
			return false
		}
	}
	return true
}

func containsString(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
