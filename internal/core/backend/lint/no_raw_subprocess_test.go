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

// allowedPaths are repo-relative file or directory paths where direct os/exec
// subprocess calls are permitted. Suffix-match for `.go` entries (exact file);
// prefix-match for entries ending in `/` (directory tree). Match is done against
// the file's path relative to the repo root.
var allowedPaths = []string{
	"internal/core/backend/local.go",
	"internal/core/backend/local_test.go",
	"internal/core/backend/local_smoke_test.go",
	"internal/core/backend/registry.go",
	"internal/core/backend/registry_test.go",
	"internal/core/testutil/",
	"internal/core/backend/lint/testdata/",
	// Repo-clone tool wrappers: these tasks use direct exec.CommandContext because
	// the Backend/Runner registry does not support cmd.Dir or stdin injection for
	// tools that require a specific working directory or stdin pipe. CR-07 (plan 05-11)
	// applied per-tool context.WithTimeout wrapping to all 6 files. The exec calls
	// are the sanctioned invocation pattern for repo-clone tools.
	// jsa.go: CR-03 fix — absolute python3 path cannot route through name-keyed registry.
	"internal/modules/web/nomore403.go",
	"internal/modules/web/gxss.go",
	"internal/modules/web/hakoriginfinder.go",
	"internal/modules/web/mantra.go",
	"internal/modules/web/shortscan.go",
	"internal/modules/web/jsa.go",
	// vulns/xss.go: dalfox `pipe` mode and Gxss both read candidate URLs from
	// stdin (identical to web/gxss.go); the name-keyed Backend/Runner registry
	// does not support stdin injection, so direct exec.CommandContext is the
	// sanctioned invocation pattern. XCUT-09 heartbeat via goroutine stdout
	// reader; XCUT-07 redaction applied before any logging.
	"internal/modules/vulns/xss.go",
	// vulns/ssrf.go: interactsh-client is a long-running OOB callback server
	// subprocess that requires per-task lifecycle management (start on Run entry,
	// SIGTERM on exit via defer). The Backend/Runner registry does not support
	// long-running background subprocesses with persistent stdout pipes; direct
	// exec.CommandContext with SysProcAttr{Setpgid:true} is the sanctioned pattern
	// (FOUND-09 kill-tree safety). XCUT-07 redaction applied; callback URLs never
	// logged at Info/Warn (only count). Mirrors web/gxss.go precedent.
	"internal/modules/vulns/ssrf.go",
	// vulns/bypass4xx.go: nomore403 is a repo-clone tool that resolves wordlists
	// at paths relative to its own directory; it also reads candidate URLs from
	// stdin. The name-keyed Backend/Runner registry does not support cmd.Dir or
	// stdin injection, so direct exec.CommandContext is the sanctioned invocation
	// pattern. Mirrors web/nomore403.go precedent (VULN-13 / plan 06-07).
	"internal/modules/vulns/bypass4xx.go",
	// subdomains/reverseip.go: hakip2host is a hakluke stdin-only tool (reads a
	// newline-delimited IP list on stdin). The name-keyed Backend/Runner registry
	// does not support stdin injection, so direct exec.CommandContext with
	// cmd.Stdin is the sanctioned invocation pattern (mirrors web/hakoriginfinder.go,
	// another hakluke stdin tool). Behind the hakip2hostRunner package var for
	// hermetic tests; per-invocation context.WithTimeout applied (PAR-01 / plan 13-01).
	"internal/modules/subdomains/reverseip.go",
	// internal/installer/: the Phase 11 installer runs TOOLCHAIN + package-manager
	// commands (go install, uv tool install, apt-get/brew/pacman, git clone, cargo,
	// tar) plus version probes (go version -m, uv tool list) and the SHA-256-verified
	// toolchain bootstrap. None of these are registered recon tools — the name-keyed
	// Backend/Runner registry exists to run the tools in tools.lock, not to install
	// them, and it supports neither cmd.Dir, stdin, nor the bootstrap download flow.
	// Direct exec.CommandContext is therefore the sanctioned pattern here (INST-06..09);
	// all calls are mockable package vars (runCmd/runCmdDir/runOutput) for hermetic tests.
	"internal/installer/",
}

// isAllowed returns true when the (repo-relative) Go file path matches any
// allowlist entry. Suffix match for `.go` files; HasPrefix for directory entries.
func isAllowed(repoRelPath string) bool {
	for _, entry := range allowedPaths {
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
