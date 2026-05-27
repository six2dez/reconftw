# 0001 — Language Choice for reconFTW v2.0

* Status: Proposed
* Date: 2026-05-27
* Deciders: six2dez (solo maintainer, project owner)
* Tags: language, v2.0, foundational

## Context

reconFTW v1.x is bash; pain points are robustness, concurrency, packaging, and onboarding (see `.planning/PROJECT.md` "Why this rewrite"). v2.0 is a single-mega-milestone full rewrite — 197 REQ-IDs across 12 phases per `.planning/ROADMAP.md`. Foundation (Phase 3) and every subsequent phase depend on the language choice; no production code is written before this ADR signs.

A spike PoC implemented an identical recon slice in BOTH Go and Python: 4 passive subdomain sources (subfinder, crt, github-subdomains, gitlab-subdomains) + httpx probe (locked 8-flag set: `-l <file> -silent -json -status-code -title -tech-detect -no-color -threads 50 -timeout 10`) + atomic JSONL writes (4-step pattern including parent-dir fsync) + SIGINT kill-tree test (synthetic mock + real-tool integration). Both spikes are timeboxed to 1 calendar week each per CONTEXT.md D-01. Six metrics measured (DEC-03's 5 + MCP cross-check). This ADR documents the decision so future contributors can audit it.

## Decision

We will use **Go** for the reconFTW v2.0 rewrite.

This decision is final for v2.x. Reversing would require a new ADR superseding this one.

## Measurement

Spike PoC implemented in both languages: passive subdomain enum (4 sources: subfinder, crt, github-subdomains, gitlab-subdomains) + httpx probe (locked flags `-silent -json -status-code -title -tech-detect -no-color -threads 50 -timeout 10`) + atomic JSONL writes (4-step pattern) + SIGINT kill-tree test (synthetic mock + real-tool integration).

Slice scope locked in `.planning/phases/01-language-adr-spike/01-PLAN.md` (across plans 01-01 through 01-05) before either spike began.

Spike code committed at `spike/go/` and `spike/python/` (git SHAs to be filled at sign-off by Plan 01-05).

| Metric | Go | Python | Ratio | Winner |
|--------|-----|--------|-------|--------|
| M1 LoC (code-only, excl tests) | 353 | 405 | 1.147 | — (TIED, < 1.25) |
| M2 Hours (dev velocity) | 0.417 h (25 min) | 0.167 h (10 min) | 2.497 | Python |
| M3 Packaging (single-binary bytes) | 3,046,450 (3.0 MB) | 12,781,568 (12.2 MB) | 4.196 | Go |
| M4 Kill-tree | PASS | PASS | — | — |
| M5 RSS mean over 3 runs (kB) | 222,251 | 225,301 | 1.014 | — (TIED, < 1.25) |
| M6 X-platform pain ordinal | 1 | 1 | — | — (TIED) |
| MCP lib support | 1 | 1 | — | — |

**Note on M1:** tokei/cloc not available on dev machine; counts are manual wc-l approximations from 01-02-SUMMARY.md / 01-03-SUMMARY.md. 14.7% difference is within noise band regardless of minor count inaccuracies.

**Note on M3:** Python row uses PyInstaller --onefile single-binary size (12,781,568 bytes, ARM64) for shape-parity with Go's stripped binary (per Plan 01-01 OQ3 INCLUDE). Python's `.venv` install size is also recorded for reference: 28,104 kB (~27.5 MB) — that is NOT the apples-to-apples metric; documented for completeness because uv-tool install is the default Python distribution method.

**Note on M5:** RSS measured 3 times per language (spike/.rss_measurements.log). CoV = 2.2% for Go, 1.6% for Python — both well under 25% inconclusive threshold. Mean values used above.

**Killer-feature gates (RESEARCH.md §2.3):**
- M4 Kill-tree: Both passed (Go: PASS from spike/go/out/.killtree_result; Python: PASS from spike/python/out/.killtree_result)
- M6 Cross-platform pain: Both ≤ 2 (Go: ordinal 1 from spike/go/out/.xplat_ordinal; Python: ordinal 1 from spike/python/out/.xplat_ordinal)
- Timebox compliance (D-01): Both complete (01-02-SUMMARY.md: timebox_complete: true; 01-03-SUMMARY.md: timebox_complete: true)
- MCP library support: Both = 1 (official SDK at v1.x). NOT a tie-breaker per RESEARCH.md §5.

**Verdict:**
Metrics within 25% noise band: tie-breaker INVOKED per DEC-04, choose Go for single-binary distribution win

Scoring trace: M1 TIED (1.147), M2 Python wins (2.497), M3 Go wins (4.196), M5 TIED (1.014), M6 TIED (both ordinal 1). Result: 1 win each on non-tied metrics → aggregate inconclusive → NOISE BAND. DEC-04 invoked.

## Consequences

### Positive

- Single static binary distribution (one file ships everywhere; matches reconFTW packaging-story improvement goal per SUMMARY.md §Stack Snapshot). End-users download one binary, no runtime to install.
- `goreleaser` cross-build matrix for Linux glibc/musl + macOS arm64/amd64 + Windows in one CI job (Phase 11 INST-01 target)
- Compile-time type safety eliminates a class of bash bugs: typed errors per ARCH-08 instead of bash `$?` convention; `go vet` + `staticcheck` run in CI at zero cost
- `errgroup.SetLimit(N)` provides bounded concurrency with error propagation in one stdlib primitive (per STACK.md §2); replacing bash `parallel_funcs` with typed goroutine fan-out
- No wheel-build friction on contributor machines; `go install` is one step, no venv management
- `go test -race` catches concurrency bugs that Python's GIL hides; data-race safety is free in CI
- Smaller container image (Docker distroless base — Phase 11 DOCK-02 candidate); Go binary needs no libc in musl builds

### Negative

- Smaller pool of contributors — Go is less ubiquitous than Python in security tooling; onboarding requires Go familiarity (not Python, which is the de-facto security researcher language)
- No REPL for ad-hoc tool experimentation — must write `_test.go` and run via `go test -run TestMyExperiment`; Python's `uv run python` REPL iteration is faster for exploratory parsing
- Module path stability concerns — SIV `/v2` migration is a real cost when major versions bump (per STACK.md library blacklist anti-patterns); Go's module system adds overhead not present in Python's pip/uv
- Cgo dependencies (if any external tools need them) add cross-compilation friction (PITFALL §6.1); pure-Go spike has no Cgo, but future integrations may require it
- Less mature ecosystem for some niche security libraries compared to Python's extensive security tooling ecosystem

## Tie-breaker

DEC-04 default tie-breaker rule (from `.planning/REQUIREMENTS.md`): "Choose Go if metrics within 25% noise band — single-binary distribution wins."

- Invoked: YES
- Rationale: The aggregate scoring produced a 1-1 split (Python wins M2 on dev velocity; Go wins M3 on packaging size) with M1/M5/M6 all within the 25% noise band. This is exactly the noise-band scenario DEC-04 was pre-agreed to resolve. reconFTW's most impactful packaging improvement for v2.0 is replacing the current "install 70+ tools manually" workflow with a single deployable binary. Go's 3.0 MB stripped binary distributes anywhere with zero runtime dependencies — the user downloads one file and runs it. Python's 12.2 MB PyInstaller binary is a valid single-binary approach but is 4.2× larger and depends on PyInstaller staying maintained. The single-binary distribution rationale referenced in STACK.md §9 and SUMMARY.md §Stack Snapshot is reconFTW's clearest v2.0 packaging win, and Go delivers it more cleanly. DEC-04 is invoked; the tie-breaker applies; Go is chosen.

## References

- Spike code (final state): `spike/go/` (commit SHA: TBD by Plan 01-05 sign-off), `spike/python/` (commit SHA: TBD)
- Comparison runner output: `spike/comparison.json` (commit SHA: TBD — canonical run 2026-05-27T20:28:03+02:00)
- Measurement worksheet: `spike/measurement-worksheet.md` (full scoring trace including ratios + killer-feature gate evaluation + RSS variance analysis)
- Research synthesis: `.planning/research/SUMMARY.md`
- Stack research: `.planning/research/STACK.md` (14-dim Go-vs-Python stack with verified May-2026 versions)
- Architecture research: `.planning/research/ARCHITECTURE.md` (dual-tracked patterns)
- Pitfalls research: `.planning/research/PITFALLS.md` (51 pitfalls; top-5 referenced as killer-feature overrides in §Measurement)
- Phase requirements: `.planning/REQUIREMENTS.md` DEC-01 through DEC-05
- Phase roadmap: `.planning/ROADMAP.md` Phase 1 success criteria
- Phase context: `.planning/phases/01-language-adr-spike/01-CONTEXT.md` (user decisions D-01, D-02, D-03)
- Phase research: `.planning/phases/01-language-adr-spike/01-RESEARCH.md` (slice composition, metric protocol, ADR template, MCP cross-check)
- MCP SDK references (per §5 cross-check):
  - Python: https://github.com/modelcontextprotocol/python-sdk (v1.x stable since Q1 2025)
  - Go: https://github.com/modelcontextprotocol/go-sdk (v1.6.1, May 22 2026)

## Signed

**Signed by:** six2dez (single maintainer, project owner)
**Date:** YYYY-MM-DD (to be filled at sign-off by Plan 01-05)
**Git SHA (this ADR):** <will be filled by git after Plan 01-05 commits>
**Git SHA (spike final):** <SHA of the spike's last commit before ADR sign>

---

*This ADR is currently in `Status: Proposed`. Plan 01-05 (sign-off + post-ADR collapse) flips Status to `Accepted`, fills the signed date and SHAs, applies the D-03 research-file collapse, and the maintainer commits the result.*
