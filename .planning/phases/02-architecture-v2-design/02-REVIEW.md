---
phase: 02-architecture-v2-design
reviewed: 2026-05-28T00:00:00Z
depth: standard
files_reviewed: 3
files_reviewed_list:
  - .planning/decisions/verify-0002.sh
  - interfaces_check/main.go
  - go.mod
findings:
  critical: 0
  warning: 4
  info: 5
  total: 9
status: issues_found
---

# Phase 02: Code Review Report

**Reviewed:** 2026-05-28T00:00:00Z
**Depth:** standard
**Files Reviewed:** 3
**Status:** issues_found

## Summary

Phase 2's review scope is small: a maintainer-only pre-sign verification gate (`verify-0002.sh`), a throwaway compile-only Go stub (`interfaces_check/main.go`), and a minimal new root `go.mod`. The bulk of Phase 2's deliverable is the 137KB ADR markdown, which is out of scope here.

Severity is graded against context: the verify script runs only locally before signing the ADR, so injection vectors are nil; however it gates whether the ADR is signed at all, so silent-pass bugs (where it returns success on a malformed ADR) are real defects. The Go stub is throwaway and will be replaced in Phase 3, so structural issues are scored lightly. `go.mod` is well-formed but the declared `go 1.23` minimum should be cross-checked against the install script's behavior.

Four warnings worth fixing pre-sign center on `verify-0002.sh`: a cwd-relative ADR path that silently fails from any directory other than the repo root, a `grep '` `` `` `` `toml'` pattern that matches indented/quoted fences and produces noisy false-positive `FAIL` lines that taint the gate's signal, a missing prerequisite check (no `tomljson`/`go` presence test), and a shellcheck SC2015 (`A && B || C`) misuse in the TOML loop. Five info items cover gofmt-clean style, glossary check fragility, and minor polish.

No critical issues. No security vulnerabilities. No source files modified.

## Warnings

### WR-01: ADR path is relative to PWD — script silently fails outside repo root

**File:** `.planning/decisions/verify-0002.sh:4`
**Issue:** `ADR=".planning/decisions/0002-architecture-v2.md"` is resolved against `$PWD`. Running `bash .planning/decisions/verify-0002.sh` from `/tmp` (or any cwd that is not the repo root) reproduces this exact session:

```
=== Check 1: ARCH-NN requirement coverage ===
grep: .planning/decisions/0002-architecture-v2.md: No such file or directory
FAIL: ARCH-01 not found in ADR
exit=1
```

The script does exit non-zero, so the gate doesn't silently approve — but the error message blames "ARCH-01 not found in ADR" when the real problem is `cwd != repo_root`. A maintainer debugging this would chase the wrong root cause. Worse, if a future change re-orders checks (e.g., the TOML or Go check is moved to run first against a file that does exist via a fallback), this latent bug becomes a silent pass.

**Fix:** Anchor the ADR path to the script location:

```bash
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
ADR="$REPO_ROOT/.planning/decisions/0002-architecture-v2.md"

if [[ ! -f "$ADR" ]]; then
    echo "FAIL: ADR not found at $ADR" >&2
    exit 1
fi
```

Add a working-directory change for the Go build step too, since `go build ./interfaces_check/...` is also cwd-relative:

```bash
cd "$REPO_ROOT"
```

### WR-02: `grep '` `` `` `` `toml'` matches indented and blockquoted fences — noisy false-positive FAILs taint the gate signal

**File:** `.planning/decisions/verify-0002.sh:17`
**Issue:** `grep -n '` `` `` `` `toml'` matches the substring anywhere on a line, including:
- Indented fences inside list items / nested code blocks (e.g., `    ` `` `` `` `toml`)
- Blockquoted fences (`> ` `` `` `` `toml`) common in "example" callouts
- Inline mentions inside prose (`the ` `` `` `` `toml` block above")

Verified with a synthetic test: a blockquoted `> ` `` `` `` `toml` fence at line 7 followed by `> [not_in_a_real_block]` produces:

```
matched at 7: > ```toml
1| > [not_in_a_real_block]
 | ~ invalid character at start of key: >
FAIL: TOML block at line 7
```

The current ADR (137KB) has 3 `^` `` `` `` `toml$` fences, so today this happens to pass — but the moment the ADR is edited to include a blockquoted or indented example fence (a likely outcome of future amendments), the gate will FAIL on a false positive and block signing of an otherwise-valid ADR. Conversely, if the prose around a real fence contains content that happens to parse as valid TOML, a buggy block could pass.

**Fix:** Anchor the fence pattern to start-of-line and end-of-line, and use a proper extractor that tracks open/close state rather than range expressions:

```bash
# Anchor to line start only
grep -nE '^```toml[[:space:]]*$' "$ADR" | while read -r line; do
    ...
done
```

Or, better, replace the awk/grep/while pipeline with a single awk pass that tracks fence state:

```bash
awk '
    /^```toml[[:space:]]*$/ { in_block=1; block_start=NR; buf=""; next }
    /^```[[:space:]]*$/ && in_block { print buf | "tomljson > /dev/null"; if (close("tomljson > /dev/null") != 0) { print "FAIL: block at " block_start; exit 1 } else print "  OK: block at " block_start; in_block=0; next }
    in_block { buf = buf $0 ORS }
' "$ADR"
```

### WR-03: No prerequisite check for `tomljson` or `go` — gate fails with cryptic errors if either is missing

**File:** `.planning/decisions/verify-0002.sh:1-2`
**Issue:** Checks 2 and 3 depend on `tomljson` (Go binary from `pelletier/go-toml/v2`) and the `go` toolchain respectively. Neither is in the Bash project's normal install path (`install.sh` installs Go but not `tomljson`). If a maintainer runs the gate without `tomljson` in `$PATH`, they'll see:

```
=== Check 2: TOML blocks parse as valid TOML ===
bash: tomljson: command not found
```

The pipe behavior under `set -o pipefail` causes the loop body to fail, but the message is opaque ("command not found") rather than actionable ("install go-toml/v2 cmd/tomljson"). Worse, if the loop body's `||` branch runs the `echo FAIL ... exit 1` from a missing-binary failure, the maintainer sees `FAIL: TOML block at line N` and may incorrectly conclude their ADR's TOML is broken.

**Fix:** Add a prereq check at the top after `set -euo pipefail`:

```bash
require_tool() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "FAIL: required tool '$1' not found in PATH" >&2
        echo "  install: $2" >&2
        exit 2
    fi
}
require_tool tomljson "go install github.com/pelletier/go-toml/v2/cmd/tomljson@latest"
require_tool go "https://go.dev/dl/"
require_tool awk "system package"
require_tool grep "system package"
```

### WR-04: ShellCheck SC2015 — `A && B || C` is not if-then-else

**File:** `.planning/decisions/verify-0002.sh:20-22`
**Issue:** ShellCheck flags:

```
SC2015 (info): Note that A && B || C is not if-then-else. C may run when A is true.
```

The current code:

```bash
awk ... | tomljson > /dev/null && echo "  OK: TOML block at line $block_start" || \
    { echo "FAIL: TOML block at line $block_start"; exit 1; }
```

If `tomljson` succeeds (TOML valid, A=true) but `echo "  OK: ..."` fails for any reason (B=false — e.g., stdout closed, disk full when writing to a redirected log) the C branch runs and the script falsely reports `FAIL` on a valid block and exits 1. The practical risk is low (terminal stdout rarely fails), but in a CI context where stdout is piped through a buffering wrapper that can disconnect, this becomes a real flaky-fail vector.

This is precisely the maintainer-tool-correctness concern that justifies the verify gate's existence — false negatives in the gate erode trust.

**Fix:** Use an explicit `if`:

```bash
if awk ... | tomljson > /dev/null; then
    echo "  OK: TOML block at line $block_start"
else
    echo "FAIL: TOML block at line $block_start" >&2
    exit 1
fi
```

This also makes `set -o pipefail` behavior explicit and clarifies the failure path.

## Info

### IN-01: `mkdir -p interfaces_check` line is dead/misleading

**File:** `.planning/decisions/verify-0002.sh:26`
**Issue:** The script runs `mkdir -p interfaces_check` immediately before `go build ./interfaces_check/...`. The build only succeeds because `interfaces_check/main.go` already exists; `mkdir -p` cannot create the source file. If `main.go` is ever deleted by accident, `mkdir -p` silently creates an empty directory and `go build ./interfaces_check/...` then fails with `no Go files in /.../interfaces_check`. The `mkdir -p` line is therefore both a) unnecessary in the happy path and b) misleading in the failure path (suggests the script can self-repair when it cannot).

**Fix:** Drop the `mkdir -p` and assert prerequisites instead:

```bash
if [[ ! -f interfaces_check/main.go ]]; then
    echo "FAIL: interfaces_check/main.go missing — gate cannot verify Go snippets" >&2
    exit 1
fi
go build -o /tmp/interfaces_check_verify ./interfaces_check/...
```

### IN-02: Glossary check uses `\b` word boundary — matches substrings inadvertently could be tightened

**File:** `.planning/decisions/verify-0002.sh:32-37`
**Issue:** The glossary check uses `grep -q "\\b$term\\b"`. This correctly rejects substring matches (e.g., `ToolError` does not match `MyToolError`) — verified in this review. However, it accepts any occurrence anywhere in the ADR, including inside code blocks, comments, or example prose. The check title says "Glossary completeness" but it does not actually verify the term appears in a glossary section — only that the symbol exists somewhere in the document.

This means a typo'd glossary section that omits `Backend` while the term still appears in §5.2 code blocks would pass undetected.

**Fix (optional polish):** Restrict the search to a glossary section if one exists:

```bash
# Extract the Glossary section by markdown heading
glossary=$(awk '/^## .*[Gg]lossary/,/^## /' "$ADR")
for term in AppContext Backend Task ...; do
    if ! grep -q "\\b$term\\b" <<<"$glossary"; then
        echo "FAIL: glossary missing term $term"
        exit 1
    fi
done
```

If the ADR has no formal glossary section, leave the check as-is but rename it to "Term coverage" in the echo header for honesty.

### IN-03: Inline comment in `interfaces_check/main.go` references field types via interface{}

**File:** `interfaces_check/main.go:38-50`
**Issue:** The `AppContext` struct uses `interface{}` for all fields with type hints in comments:

```go
type AppContext struct {
    Log        interface{} // *slog.Logger
    Cfg        interface{} // *config.Config
    ...
}
```

This is intentional and documented in lines 14-18 ("uses interface{} for cross-package types"). However, since this stub will be replaced in Phase 3 with the real types, the type-hint comments duplicate information that should live in the ADR itself. If Phase 3 changes a type (e.g., `*config.Config` → `*config.Resolved`), the ADR is the source of truth — the comments here will drift silently. Given the file is throwaway and explicitly marked `DO NOT import into production code`, this is acceptable but worth a one-line note.

**Fix:** Add a single comment near the struct: `// Field types are illustrative; see ADR 0002 §5 for the canonical signatures.` Then drop the per-field type-hint comments to avoid drift. Or, since the file is throwaway, leave as-is and ensure Phase 3's replacement file removes these placeholders.

### IN-04: `go.mod` declares `go 1.23` while the project's install script provisions latest (currently 1.26)

**File:** `go.mod:3`
**Issue:** `go 1.23` is a minimum-version directive, not a pin. It's compatible with the project's `install.sh` behavior of installing the latest Go release. However, the bash project's `install.sh` defaults to `go1.23.6` (per `CLAUDE.md`), so 1.23 is a defensible floor. The concern is forward — Phase 3 may need newer language features (range-over-func from 1.22, swap+for-range from 1.23, generic type aliases from 1.24) and the constraint should be deliberate.

**Fix:** Add a comment to `go.mod` or to the Phase 3 plan documenting why `go 1.23` was chosen as the floor:

```go
module github.com/six2dez/reconftw

// 1.23 minimum: required for range-over-func and clear(map/slice).
// Bump deliberately; coordinated with install.sh GO_VERSION.
go 1.23
```

### IN-05: `go.mod` trailing whitespace / final-newline

**File:** `go.mod:4`
**Issue:** `od -c` shows the file ends with `\n` (one final newline) — well-formed. No fix needed; logged for completeness because the file was flagged in the review scope as "44 bytes" and worth confirming structural cleanliness. `gofmt -l interfaces_check/main.go` also returns clean (no formatting issues). Both files pass `go vet`.

**Fix:** None required.

---

_Reviewed: 2026-05-28T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
