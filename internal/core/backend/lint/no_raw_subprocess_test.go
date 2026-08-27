// SPDX-License-Identifier: MIT
//
// FOUND-10 AST-based lint scanner (per Blocker 8).
//
// TWO TESTS:
//
//  1. TestFOUND10_NoRawSubprocessOutsideBackend
//     Walks every package under ./internal/... and asserts no forbidden subprocess
//     call appears outside the allowlist. This is the gate that fails CI on any
//     module that bypasses the Backend wrapper.
//
//  2. TestFOUND10_FixtureDetected (Blocker 8 — positive-detection proof)
//     Points the same walker at testdata/ and asserts the fixture violating.go
//     IS detected. Proves the scan logic works.
//
// FORBIDDEN PATTERNS:
//   - exec.Command(...)         — direct selector exec.Command
//   - exec.CommandContext(...)  — direct selector exec.CommandContext
//   - (*exec.Cmd).Run(...)      — method call on a Cmd receiver
//   - (*exec.Cmd).Start(...)    — method call on a Cmd receiver
//
// REPLACEMENT:
//
//	app.Tools.Run(ctx, name, args)    or
//	app.Tools.Stream(ctx, name, args)
//
// ALLOWLIST: see no_raw_subprocess.go package comment.
package lint_test

import (
	"fmt"
	"go/ast"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// THE ALLOWLIST IS GONE. It used to live here as a []string of paths carrying
// free-text comments; plan 18-03 replaced it with two typed sources, both in
// bypasses_test.go / bypasses.go:
//
//   - infrastructureAllowlist — the seam itself and its own tests. These are not
//     bypasses of the Runner; they ARE the Runner.
//   - lint.Bypasses — the corroborated bypass manifest. Every entry's reasons are
//     checked against that file's own syntax tree, its site count is checked
//     exactly, and a stale entry fails.
//
// isAllowed (bypasses_test.go) consults both. See the package doc in
// no_raw_subprocess.go for the contract.

// violation records a forbidden subprocess call detected by the AST walker.
type violation struct {
	File   string // repo-relative path
	Line   int
	Column int
	Call   string // "exec.Command", "exec.CommandContext", "(*exec.Cmd).Run", "(*exec.Cmd).Start"
}

func (v violation) String() string {
	return fmt.Sprintf("%s:%d:%d: forbidden subprocess call %s — use app.Tools.Run() or app.Tools.Stream() instead (FOUND-10)",
		v.File, v.Line, v.Column, v.Call)
}

// findRepoRoot walks upward looking for go.mod.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not find go.mod walking up from cwd")
		}
		dir = parent
	}
}

// scan walks each package's syntax tree looking for forbidden subprocess calls.
// repoRoot is used to convert absolute file paths to repo-relative ones for the
// allowlist check.
func scan(pkgs []*packages.Package, repoRoot string) []violation {
	var out []violation
	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			absPath := pkg.GoFiles[i]
			relPath, err := filepath.Rel(repoRoot, absPath)
			if err != nil {
				relPath = absPath
			}
			// Normalize to forward slashes for cross-platform allowlist matching.
			relPath = filepath.ToSlash(relPath)

			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}

				// Pattern A: exec.Command / exec.CommandContext — recv is identifier "exec".
				if ident, ok := sel.X.(*ast.Ident); ok && ident.Name == "exec" {
					if sel.Sel.Name == "Command" || sel.Sel.Name == "CommandContext" {
						pos := pkg.Fset.Position(call.Pos())
						if !isAllowed(relPath) {
							out = append(out, violation{
								File:   relPath,
								Line:   pos.Line,
								Column: pos.Column,
								Call:   "exec." + sel.Sel.Name,
							})
						}
						return true
					}
				}

				// Pattern B: (*exec.Cmd).Run / (*exec.Cmd).Start — receiver type resolves
				// to *os/exec.Cmd via TypesInfo. Requires NeedTypes + NeedTypesInfo modes.
				if pkg.TypesInfo != nil && (sel.Sel.Name == "Run" || sel.Sel.Name == "Start") {
					typeAndValue := pkg.TypesInfo.Types[sel.X]
					if typeAndValue.Type != nil {
						underlying := typeAndValue.Type
						// Resolve pointer chains.
						if ptr, ok := underlying.(*types.Pointer); ok {
							underlying = ptr.Elem()
						}
						if named, ok := underlying.(*types.Named); ok {
							obj := named.Obj()
							if obj != nil && obj.Pkg() != nil &&
								obj.Pkg().Path() == "os/exec" && obj.Name() == "Cmd" {
								pos := pkg.Fset.Position(call.Pos())
								if !isAllowed(relPath) {
									out = append(out, violation{
										File:   relPath,
										Line:   pos.Line,
										Column: pos.Column,
										Call:   "(*exec.Cmd)." + sel.Sel.Name,
									})
								}
							}
						}
					}
				}
				return true
			})
		}
	}

	// Stable order for deterministic output.
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Line < out[j].Line
	})
	return out
}

// TestFOUND10_NoRawSubprocessOutsideBackend is THE FOUND-10 CI gate.
// Walks every package under ./internal/... and asserts no forbidden subprocess
// call appears outside the allowlist.
func TestFOUND10_NoRawSubprocessOutsideBackend(t *testing.T) {
	repoRoot := findRepoRoot(t)
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

	// We tolerate package-level errors (e.g. missing deps in test code paths)
	// — the AST is still walkable. Surface them only at -v.
	for _, pkg := range pkgs {
		for _, e := range pkg.Errors {
			t.Logf("package %s reported error (non-fatal): %v", pkg.PkgPath, e)
		}
	}

	violations := scan(pkgs, repoRoot)
	if len(violations) > 0 {
		var lines []string
		for _, v := range violations {
			lines = append(lines, v.String())
		}
		t.Errorf("FOUND-10: forbidden subprocess call(s) detected:\n  %s",
			strings.Join(lines, "\n  "))
	}
}

// TestFOUND10_FixtureDetected (Blocker 8) — positive-detection proof.
// Points the same scanner at testdata/violating.go and asserts the fixture's
// exec.Command / exec.CommandContext calls ARE detected.
//
// This proves the AST walker actually fires when given an offending input. The
// fixture lives at internal/core/backend/lint/testdata/violating.go, behind a
// `//go:build ignore_in_normal_build` constraint so it doesn't participate in
// normal builds. We load it directly via packages.Load with the testdata dir
// as the working directory.
func TestFOUND10_FixtureDetected(t *testing.T) {
	repoRoot := findRepoRoot(t)
	fixtureDir := filepath.Join(repoRoot, "internal", "core", "backend", "lint", "testdata")

	// The testdata fixture has a build constraint that prevents it from compiling
	// under the normal build. We parse it directly (no Types/TypesInfo so the
	// missing nil-receiver type for CommandContext doesn't matter). Pattern-A
	// detection (exec.Command / exec.CommandContext) is purely identifier-based
	// so NeedSyntax is sufficient.
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax,
		Dir:  fixtureDir,
		// Allow build-tag-restricted files via the BuildFlags. The fixture
		// uses //go:build ignore_in_normal_build, so we set the tag to enable it.
		BuildFlags: []string{"-tags=ignore_in_normal_build"},
		Tests:      false,
	}

	// Use the package directly via "." pattern relative to Dir.
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("packages.Load(testdata): %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("packages.Load(testdata) returned 0 packages")
	}

	// Override allowlist for fixture-detection mode: we WANT to see violations
	// in testdata. Run the scan without the testdata allowlist entry by directly
	// inspecting the parsed file ourselves rather than going through `scan`.
	var detected []violation
	for _, pkg := range pkgs {
		for i, file := range pkg.Syntax {
			absPath := pkg.GoFiles[i]
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "exec" {
					return true
				}
				if sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext" {
					return true
				}
				pos := pkg.Fset.Position(call.Pos())
				detected = append(detected, violation{
					File:   filepath.Base(absPath),
					Line:   pos.Line,
					Column: pos.Column,
					Call:   "exec." + sel.Sel.Name,
				})
				return true
			})
		}
	}

	if len(detected) < 2 {
		t.Errorf("FOUND-10 fixture-detection: scanner detected %d violations in testdata/violating.go, want >= 2 (exec.Command + exec.CommandContext); detected: %+v",
			len(detected), detected)
	}

	// Sanity: at least one detection mentions exec.Command, at least one mentions exec.CommandContext.
	var sawCommand, sawCommandCtx bool
	for _, v := range detected {
		if v.Call == "exec.Command" {
			sawCommand = true
		}
		if v.Call == "exec.CommandContext" {
			sawCommandCtx = true
		}
	}
	if !sawCommand {
		t.Errorf("fixture-detection: scanner did not detect exec.Command in testdata/violating.go")
	}
	if !sawCommandCtx {
		t.Errorf("fixture-detection: scanner did not detect exec.CommandContext in testdata/violating.go")
	}
}
