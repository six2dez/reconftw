---
phase: 01-language-adr-spike
reviewed: 2026-05-28T00:00:00Z
depth: standard
files_reviewed: 13
files_reviewed_list:
  - spike/compare.sh
  - spike/corpus/mock_stubborn_tool.sh
  - spike/go/cmd/spike/main.go
  - spike/go/internal/httpxprobe/httpx.go
  - spike/go/internal/output/atomic.go
  - spike/go/internal/output/output.go
  - spike/go/internal/passive/crt.go
  - spike/go/internal/passive/github.go
  - spike/go/internal/passive/gitlab.go
  - spike/go/internal/passive/passive.go
  - spike/go/internal/passive/subfinder.go
  - spike/go/internal/proc/proc.go
  - spike/go/internal/ui/ui.go
findings:
  critical: 2
  warning: 9
  info: 6
  total: 17
status: issues_found
---

# Phase 1: Code Review Report

**Reviewed:** 2026-05-28T00:00:00Z
**Depth:** standard
**Files Reviewed:** 13
**Status:** issues_found

## Summary

Reviewed the Go spike (12 source files) plus the comparison runner (`compare.sh`). The mock fixture (`mock_stubborn_tool.sh`) was inspected and intentionally trap-handles SIGTERM — no findings against it per phase context.

Most concerning findings concentrate in code that Phase 3 Foundation is meant to inherit: `httpx.go` has a data-loss bug in its intermediate-flush path, `proc.go` has a goroutine leak whose pattern will propagate to long-running modules, and `compare.sh` has a JSONL parse mismatch that silently degrades the M6/M7 measurement. Two stub remnants (`output.go` `AtomicWriter`) and one dead branch (`passive.go` g.Wait error path) suggest the slice wasn't quite cleaned up for review.

None of the auth-token bootstrap, validation, or kill-tree primitives carry security gaps once you accept the phase's "auth-token bootstrap intentionally minimal" framing.

## Critical Issues

### CR-01: httpx intermediate flush overwrites output file — every batch except the last is lost

**File:** `spike/go/internal/httpxprobe/httpx.go:62-94`
**Issue:** The streaming loop accumulates lines into a `lines` slice. When `len(lines) >= flushAt` (1000), it calls `output.WriteJSONL(outFile, lines)` and resets the slice (`lines = lines[:0]`). However, `output.WriteJSONL` is a **truncate-and-rename** atomic write — every call replaces the entire file with the supplied lines. So after, say, 2500 hosts:
- Flush at 1000 → `out/hosts.jsonl` contains hosts 1..1000
- Flush at 2000 → `out/hosts.jsonl` is overwritten with hosts 1001..2000 (1..1000 are gone)
- Final write at 2500 → `out/hosts.jsonl` is overwritten with hosts 2001..2500

Production data loss bug. For hackerone.com (≤few-hundred hosts) the buffer never exceeds 1000, so the bug is latent in spike runs but guarantees breakage at scale. The comment ("intermediate flush at 1000 lines — production would use a persistent writer") describes the future fix but the present code is actively wrong, not "buffers up to 1000" as the file header claims.
**Fix:** Either remove the intermediate-flush branch entirely for the spike (the buffer can hold a few thousand JSON lines easily — `out/hosts.jsonl` is bounded by passive subdomain count) OR open `outFile` for append and use a non-atomic line-buffered write, OR accumulate `allLines := append(allLines, lines...)` and never reset until the final atomic write:
```go
// Drop the flushAt branch entirely; just append:
err = proc.Run(ctx, "httpx", args, func(line []byte) error {
    if len(line) == 0 { return nil }
    lineCopy := make([]byte, len(line))
    copy(lineCopy, line)
    lines = append(lines, lineCopy)
    return nil
})
// ... single atomic write at end (already there on line 93).
```

### CR-02: `compare.sh` `jq` invocation cannot parse JSONL — `subdomain_set_diff_lines` is silently broken

**File:** `spike/compare.sh:114-116`
**Issue:** Both spikes emit `out/subs.jsonl` as JSON-Lines (one JSON object per line). The diff step reads them with `jq -r '.subdomain // empty' subs.jsonl`. By default `jq` parses its input as **a single JSON value** — it does NOT auto-detect JSONL. With multi-line JSONL input, `jq` will either error out (`parse error: Expected value`) on the second `{` token, or — depending on jq version — emit only the first record. The `2>/dev/null` swallows the parse error and `sort -u` returns whatever partial output emerged. M-comparison diff metric in `comparison.json` ends up consistently `0` or a stale number, masking real divergence between the Go and Python spikes — defeating the ADR's whole "subdomain set parity" check.
**Fix:** Use jq's slurp/streaming flags appropriate for JSONL:
```bash
GO_SUBS=$(jq -r '.subdomain // empty' spike/go/out/subs.jsonl 2>/dev/null | sort -u)
# replace with:
GO_SUBS=$(jq -nr 'inputs | .subdomain // empty' spike/go/out/subs.jsonl 2>/dev/null | sort -u)
# or (slurp-into-array):
GO_SUBS=$(jq -sr '.[] | .subdomain // empty' spike/go/out/subs.jsonl 2>/dev/null | sort -u)
```
The `jq -n 'inputs | …'` form is the canonical JSONL idiom and avoids slurping the whole file into memory.

## Warnings

### WR-01: `proc.Run` leaks a goroutine for every successful subprocess invocation

**File:** `spike/go/internal/proc/proc.go:73-89, 117-127`
**Issue:** Both branches (lineFn and no-lineFn) spawn a goroutine:
```go
go func() {
    defer close(killGroupDone)
    select {
    case <-ctx.Done():
        time.Sleep(cmd.WaitDelay + 500*time.Millisecond)
        _ = syscall.Kill(-pgid, syscall.SIGKILL)
    case <-killGroupDone:
    }
}()
```
This is a closed-over-itself bug: the `killGroupDone` channel is created inside the function, and the goroutine's only path to exit besides `ctx.Done()` is `<-killGroupDone`. But `killGroupDone` is **only closed by the goroutine itself** (via `defer close`). Therefore, when the subprocess completes normally and `cmd.Wait()` returns (lines 109/129), the goroutine is still parked in the `select` waiting for `ctx.Done()`. It will only exit when the *parent* context cancels — which in the spike happens at process exit. Over a long-lived run (Phase 3 Foundation will source proc.Run many times across a target), this leaks one goroutine per subprocess call (~4 passive + 1 httpx = 5 per target; thousands per long monitor run).

Bonus issue: even on `ctx.Done()` the goroutine sends SIGKILL to the group **even if cmd already exited normally** — sending a signal to a non-existent PGID is harmless (returns ESRCH) but it's wasted work and racy if PIDs have been reused.

**Fix:** Close `killGroupDone` from the cmd-finished path:
```go
err := cmd.Wait()
close(killGroupDone)   // signal the watchdog to exit
return err
```
And remove the goroutine's `defer close(killGroupDone)`. This makes ownership of the channel clear: the main path closes it; the goroutine only reads it.

### WR-02: `passive.Run` swallows all subprocess errors and `g.Wait()` error path is dead code

**File:** `spike/go/internal/passive/passive.go:60-71`
**Issue:** Each `*Run` helper (subfinderRun, crtRun, githubRun, gitlabRun) catches the subprocess error and returns `nil` (e.g. `subfinder.go:46-48`: "Non-fatal: return nil so errgroup doesn't cancel other sources"). So `g.Wait()` on line 68 always returns `nil`. The `ui.Warn("passive: one or more sources returned an error: " + err.Error())` on line 70 is unreachable.

This is also a behavioral concern for Phase 3 inheritance: silently swallowing errors at the source layer means the orchestrator can never decide "all four sources failed — abort the run". The spike accepts this; production cannot. Flagging now so the pattern isn't carried forward.
**Fix:** Either remove the dead `g.Wait()` error handling for honesty, or — better — have each `*Run` return a sentinel error (e.g. `errSourceFailed`) that errgroup propagates without cancelling siblings (errgroup cancels on first error; use `golang.org/x/sync/errgroup` differently, or collect errors via a separate channel). For the spike, at minimum:
```go
_ = g.Wait()  // intentionally ignored — each source logs its own error
```

### WR-03: `output.AtomicWriter` is a stub that returns `(nil, nil)` — callers will nil-deref

**File:** `spike/go/internal/output/output.go:13`
**Issue:** `func AtomicWriter(path string) (io.WriteCloser, error) { return nil, nil }`. Returns `nil, nil` — any caller that does `w, err := output.AtomicWriter(p); if err != nil {...}; w.Write(...)` will panic with nil pointer dereference. Currently no production code calls it (grep -rn "AtomicWriter" finds no callers), so the bomb is unarmed — but it sits in the public-ish API surface of an `internal/` package. Phase 3 Foundation could inherit this and hit it the day a developer reaches for the name.
**Fix:** Either delete `spike/go/internal/output/output.go` entirely (the real implementation lives in `atomic.go` as `WriteJSONL`), or make `AtomicWriter` return `nil, errors.New("not implemented")` so callers get a loud failure.

### WR-04: `compare.sh` JSON heredoc interpolates unsanitized tool output → invalid JSON or shell-quote injection

**File:** `spike/compare.sh:120-145`
**Issue:** The output JSON is built via shell heredoc with raw substitutions like `$GO_LOC`, `$GO_HOURS`, `$GO_BINSIZE`. These come from `tokei`/`cloc`/`stat`/`awk` output and from `$(date -Iseconds)`. Any unexpected character (quotes, backslashes, control chars, parentheses) in those values produces invalid JSON. Examples:
- `tokei --output json | jq -r '.Go.code'` returns a number normally, but a custom `jq` filter or unusual repo state could return `"123"` (with quotes) — fine, but if it returned the literal string `null` or a multi-line value, the JSON becomes `"loc": null` (OK) or `"loc": 12\n34` (broken).
- `$(uname -srm)` on `compare.sh:124` runs verbatim — if the platform name contains a `"` it breaks the JSON (in practice safe, but cargo-cult fragility).
- `$( [[ "$X" == "NA" ]] && echo "null" || echo "$X" )` for numeric fields: if `$X` is non-numeric (e.g. tokei mis-parses and returns `bytes:`), the emitted JSON parses as garbage.

This isn't a security vulnerability (the operator runs it themselves), but it's brittle: a tokei/cloc output schema change silently corrupts `comparison.json` and the ADR draft (Plan 01-04) consumes it as ground truth.
**Fix:** Generate the JSON with `jq` to guarantee well-formed output:
```bash
jq -n \
  --arg target "$TARGET" \
  --arg ts "$(date -Iseconds 2>/dev/null)" \
  --arg platform "$(uname -srm)" \
  --argjson go_loc "${GO_LOC/NA/null}" \
  --argjson go_hours "${GO_HOURS/NA/null}" \
  '{ target: $target, timestamp: $ts, platform: $platform, go: { loc: $go_loc, hours: $go_hours, … } }' \
  > "$OUT"
```
This shifts validation to jq, which fails loud rather than silently emitting malformed JSON.

### WR-05: `compare.sh` arithmetic conversion crashes under `set -e` for non-numeric input

**File:** `spike/compare.sh:82, 99`
**Issue:** `[[ "$RSS_UNIT" == "bytes" && "$GO_RSS" != "NA" ]] && GO_RSS=$((GO_RSS / 1024))`. With `set -euo pipefail`, if `awk` on line 81 returns a non-numeric token (e.g. `time` failed and the file contains an error message, so the grep+awk yields something like `"command not found"`), the `$((...))` arithmetic will fail with a syntax error and the script exits prematurely with exit-code 2. This kills `comparison.json` emission entirely.

Adjacent: the `&&` short-circuit means a failing arithmetic returns non-zero but the `&&` chain swallows it. Then again with set -e, `$((bad))` may still abort. The result is non-deterministic depending on which shell.
**Fix:** Pre-validate before doing arithmetic:
```bash
if [[ "$RSS_UNIT" == "bytes" && "$GO_RSS" != "NA" && "$GO_RSS" =~ ^[0-9]+$ ]]; then
    GO_RSS=$((GO_RSS / 1024))
fi
```

### WR-06: `proc.Run` discards `cmd.Wait()` error after a lineFn or scanner error

**File:** `spike/go/internal/proc/proc.go:99, 105`
**Issue:** When `lineFn` returns a non-nil error or the scanner errors out, the code does `_ = cmd.Wait()` and returns the lineFn/scanner error directly. The cmd.Wait() error contains the subprocess exit status — often *more* informative than the lineFn error (e.g. "exit status 1" with stderr saying "DNS resolution failed"). Losing it makes debugging proc.Run callers in Phase 3 harder.

Per the contract documented in the proc.go comment block, the lineFn error is the abort signal — but the subprocess's death cause is also useful diagnostic information.
**Fix:** Wrap both errors:
```go
if err := lineFn(scanner.Bytes()); err != nil {
    if waitErr := cmd.Wait(); waitErr != nil {
        return fmt.Errorf("linefn aborted: %w (subprocess: %v)", err, waitErr)
    }
    return err
}
```

### WR-07: Domain regex duplicated across `main.go` and `passive.go` with identical bodies

**File:** `spike/go/cmd/spike/main.go:29`, `spike/go/internal/passive/passive.go:22`
**Issue:** Both files define `var domainRe = regexp.MustCompile(\`^[a-zA-Z0-9.-]+$\`)` — same pattern, two copies. The comments in both reference "lib/validation.sh validate_domain()" as the source. If either gets updated (e.g. to handle internationalized domain names, or to add a max-length check), the other won't. Production bug pattern: this regex notably permits `..` (two consecutive dots, not a real domain) and a leading dot — known shortcomings of `validate_domain()` worth fixing upstream, but at minimum should not be duplicated.
**Fix:** Move to a shared internal package, e.g. `spike/go/internal/validate/domain.go`:
```go
package validate

import "regexp"

var DomainRe = regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)

func Domain(target string) bool {
    return DomainRe.MatchString(target)
}
```
Then both `main.go` and `passive.go` call `validate.Domain(target)`.

### WR-08: `os.Exit` in `main.go` skips deferred `stop()` (signal handler restoration)

**File:** `spike/go/cmd/spike/main.go:58-69`
**Issue:** Three `os.Exit(...)` calls inside the RunE closure (lines 58, 65, 69). Each bypasses the `defer stop()` registered on line 48 by `signal.NotifyContext`. The `stop()` call de-registers the SIGINT/SIGTERM handler. Bypassing it during normal exit is harmless (the OS reaps the handler anyway) but:
1. Pattern propagates to production where deferred cleanup (DB closes, temp file removal, telemetry flush) matters.
2. The `os.Exit(0); return nil` on lines 69-70 makes the `return nil` literally unreachable.
3. Cobra's `RunE` already handles non-nil errors → exit-1 via `root.Execute()`. The explicit `os.Exit(1)` on line 58 short-circuits Cobra's error handling, losing the chance for upstream code to print structured exit info.
**Fix:** Return errors instead of calling os.Exit:
```go
if err := passive.Run(ctx, target, "out/subs.jsonl"); err != nil {
    return fmt.Errorf("passive: %w", err)
}
if err := httpxprobe.Run(ctx, "out/subs.jsonl", "out/hosts.jsonl"); err != nil {
    return fmt.Errorf("httpx: %w", err)
}
ui.Info("spike: done")
return nil
```

### WR-09: github.go / gitlab.go don't TrimSpace subdomain lines

**File:** `spike/go/internal/passive/github.go:43-45`, `spike/go/internal/passive/gitlab.go:43-45`
**Issue:** `subdomain := string(line)` — bufio.Scanner strips the trailing newline but not trailing CR (on CRLF outputs), nor leading/trailing whitespace. If `github-subdomains` ever emits whitespace-padded lines (it's a Go tool, unlikely — but not contractual), every subdomain gets stored with leading space and dedup in `passive.go:54` fails. Also: empty-after-trim lines (just `\r\n`) bypass the `subdomain != ""` check and get collected as empty strings (caught by `passive.go:49`, but still wasteful).
**Fix:**
```go
subdomain := strings.TrimSpace(string(line))
if subdomain == "" { return nil }
```
And do the same in gitlab.go. Subfinder is OK because it goes through json.Unmarshal which handles whitespace.

## Info

### IN-01: Custom `itoa` reimplementation is O(n²) and a needless dependency-avoidance

**File:** `spike/go/internal/passive/passive.go:98-108`
**Issue:** `func itoa(n int) string` is a manual int-to-string. The comment says "avoid importing strconv for 1 call", but passive.go already imports four other stdlib packages — `strconv` is in the same import group with effectively zero cost. The implementation also uses `append([]byte{byte('0' + n%10)}, b...)` which prepends — O(n²) for n-digit numbers (allocates a new slice each iteration). Cosmetic but propagates a bad habit: avoid stdlib for stylistic reasons.
**Fix:** Replace with `strconv.Itoa(n)`.

### IN-02: `g.SetLimit(4)` is redundant when exactly 4 goroutines are spawned

**File:** `spike/go/internal/passive/passive.go:61-66`
**Issue:** `errgroup.SetLimit(4)` only matters when more than 4 calls to `g.Go` are made (it blocks the 5th). Since exactly 4 sources fan out, the limiter is dead. If the count later changes, the limit becomes meaningful but silently caps parallelism. Confusing for the reader.
**Fix:** Drop `g.SetLimit(4)` (errgroup with no limit allows all 4 to run concurrently anyway) or add a comment: `// SetLimit(4) explicit so adding a 5th source later doesn't silently raise concurrency`.

### IN-03: `crt.go` redundant check for `"null"` literal

**File:** `spike/go/internal/passive/crt.go:51-54`
**Issue:** The check `bytes.Equal(data, []byte("null"))` is redundant — `json.Unmarshal([]byte("null"), &entries)` succeeds with a nil slice; the loop on line 64 over nil slice is a no-op. Same for `[]`. The early-return is correct but defensive beyond necessity, and the `len(data) == 0` case alone would let json.Unmarshal return an "unexpected end of JSON input" error caught by the next branch. Trivial.
**Fix:** Simplify or leave as belt-and-suspenders documentation; not a real defect.

### IN-04: `crt.go` line-callback indirection for buffering is awkward

**File:** `spike/go/internal/passive/crt.go:36-41`
**Issue:** `proc.Run` is line-streaming. For `crt -json` (JSON array, not NDJSON), the callback re-joins lines into a buffer that is then JSON-decoded. This works but is convoluted — it's why the proc.Run docstring (proc.go:30-36) added a paragraph explaining "dual-mode usage". Cleaner would be a sibling `proc.RunCapture(ctx, name, args) ([]byte, error)` that returns full stdout for buffered consumers. The comment on proc.go:35 acknowledges this is a "mid-implementation workaround" — flagging for Phase 3 inheritance, not as a spike defect.
**Fix:** Add `proc.RunCapture` in Phase 3 Foundation; route crt-shaped consumers through it.

### IN-05: `compare.sh:67-68` uses `| head -1` defensively after `jq -r` — masks multi-line output

**File:** `spike/compare.sh:67-68`
**Issue:** `GO_LOC=$(extract_loc spike/go Go | head -1)` — `jq -r ".Go.code"` should only ever emit one line for a top-level scalar field, but `| head -1` is bolted on. If tokei's output schema changes and `.Go.code` becomes an array, this silently picks the first element. Cleaner: omit head and let the bug crash, OR document why.
**Fix:** Either delete `| head -1` (trust jq's output shape) or add a comment explaining why it's defensive: `# head -1: tokei sometimes wraps in array on edge inputs (jq returns first); see issue #N`.

### IN-06: `spike/go/internal/output/output.go` exists only to hold a stub and inflates LoC metric

**File:** `spike/go/internal/output/output.go` (entire file)
**Issue:** Per Plan 01-02, the file is the Task 1 stub superseded by `atomic.go` in Task 2. It still occupies LoC budget that feeds M1 in `comparison.json`. For an ADR that gates on LoC count between Go and Python, leaving Task 1 stubs around inflates Go's count. Possibly negligible but worth a sweep.
**Fix:** Delete the file. (Also resolves WR-03.)

---

_Reviewed: 2026-05-28T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
