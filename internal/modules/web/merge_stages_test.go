// merge_stages_test.go — completeness guard for directArtefactWriterStages.
//
// Plan 15-03 Task 2 gave web.MergeStage a never-truncate rule for the four
// merged stages whose artefact ALSO has a direct app.Tree.Append writer outside
// the merge path. That rule is only correct while the set is COMPLETE: if
// someone adds a direct artefact writer for a merged stage and forgets to
// declare it, the merge silently starts truncating an artefact it does not own
// — reintroducing exactly the data loss 15-03 fixed.
//
// This test AST-scans the four module packages for app.Tree.Append("<literal>")
// calls outside merge.go and asserts the two directions:
//
//	forward — every such artefact name that is ALSO a webStagingPrefixes member
//	          must appear in directArtefactWriterStages;
//	inverse — every directArtefactWriterStages member must be a
//	          webStagingPrefixes member (a stage nobody merges needs no guard).
//
// Declared `package web` (internal test) so it can read the unexported
// webStagingPrefixes and directArtefactWriterStages, matching merge_hosts_test.go.
package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// collectDirectArtefactWriters returns artefact name → "file:line" for every
// app.Tree.Append("<literal>", …) call in a non-test file outside merge.go.
func collectDirectArtefactWriters(t *testing.T, dirs ...string) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	fset := token.NewFileSet()

	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return fs.SkipDir
				}
				return nil
			}
			name := d.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || name == "merge.go" {
				return nil
			}
			af, perr := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			ast.Inspect(af, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "Append" {
					return true
				}
				// Match ….Tree.Append(…): the receiver's own selector is "Tree".
				inner, ok := sel.X.(*ast.SelectorExpr)
				if !ok || inner.Sel.Name != "Tree" {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				artefact, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					return true
				}
				pos := fset.Position(call.Pos())
				out[artefact] = append(out[artefact],
					filepath.ToSlash(p)+":"+strconv.Itoa(pos.Line))
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return out
}

func TestDirectArtefactWriterStagesComplete(t *testing.T) {
	writers := collectDirectArtefactWriters(t, ".", "../subdomains", "../vulns", "../osint")

	merged := map[string]bool{}
	for _, s := range webStagingPrefixes {
		merged[s] = true
	}

	// FORWARD: a direct artefact writer for a MERGED stage must be declared.
	var missing []string
	for artefact, sites := range writers {
		if !merged[artefact] {
			continue // nobody merges this artefact — the merge cannot truncate it
		}
		if !directArtefactWriterStages[artefact] {
			sort.Strings(sites)
			missing = append(missing, artefact+" ("+strings.Join(sites, ", ")+")")
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("these merged stages have a DIRECT app.Tree.Append writer outside merge.go but "+
			"are not in directArtefactWriterStages — web.MergeStage will TRUNCATE the artefact "+
			"they just produced whenever the staging glob comes up empty (15-03 Case B):\n  %s\n\n"+
			"Add them to directArtefactWriterStages in internal/modules/web/merge.go, with the "+
			"file:line evidence in its comment.", strings.Join(missing, "\n  "))
	}

	// INVERSE: a stage nobody merges does not need the never-truncate guard.
	for stage := range directArtefactWriterStages {
		if !merged[stage] {
			t.Errorf("directArtefactWriterStages contains %q, which is not in webStagingPrefixes — "+
				"no merge writes that artefact, so the guard entry is dead weight", stage)
		}
	}

	// The four declared members must each still HAVE a direct writer; if the last
	// one is deleted the entry becomes stale and the merge could own the artefact.
	for stage := range directArtefactWriterStages {
		if len(writers[stage]) == 0 {
			t.Errorf("directArtefactWriterStages declares %q but no direct app.Tree.Append writer "+
				"for it remains outside merge.go — re-check whether the merge is now the "+
				"authoritative writer", stage)
		}
	}
}

// TestArtefactSeedStagesIsHostsOnly pins the OTHER named set. Widening it to
// "urls" would re-import the pre-dedup staging URLs on top of urldedup's
// deduplicated artefact and undo WEB-14; the two sets encode different
// concerns and must not be conflated.
func TestArtefactSeedStagesIsHostsOnly(t *testing.T) {
	if len(artefactSeedStages) != 1 || !artefactSeedStages["hosts"] {
		t.Fatalf("artefactSeedStages must contain exactly {\"hosts\"}, got %v", artefactSeedStages)
	}
}
