---
phase: 01-language-adr-spike
plan: 01
subsystem: spike-harness
tags:
  - spike
  - scaffolding
  - foundational
  - harness
dependency_graph:
  requires: []
  provides:
    - spike/README.md (locked contract for Plans 01-02/01-03)
    - spike/compare.sh (comparison runner; consumed by Plan 01-04)
    - spike/corpus/targets.txt (3-target test corpus)
    - spike/corpus/mock_stubborn_tool.sh (kill-tree test fixture; consumed by Plans 01-02/01-03)
    - spike/baselines/hackerone.com.expected (bash v1 baseline or placeholder)
    - .gitignore spike entries (prevents token files from reaching git history)
  affects:
    - spike/go/ (skeleton ready for Plan 01-02 Go implementation)
    - spike/python/ (skeleton ready for Plan 01-03 Python implementation)
    - .gitignore
tech_stack:
  added:
    - bash (compare.sh: spike harness runner; bash -n + shellcheck -S error clean)
  patterns:
    - atomic write (tempfile + mv) for baseline and compare.sh scaffolding
    - gitignore token file exclusion (T-01-SI-02 threat mitigation)
key_files:
  created:
    - spike/README.md
    - spike/compare.sh
    - spike/corpus/targets.txt
    - spike/corpus/mock_stubborn_tool.sh
    - spike/baselines/hackerone.com.expected
    - spike/go/.gitkeep
    - spike/python/.gitkeep
    - spike/corpus/expected/.gitkeep
    - spike/baselines/.gitkeep
  modified:
    - .gitignore (appended spike PoC generated-output exclusions)
decisions:
  - "OQ1 (config loader): EXCLUDED from spike — --target only via stdlib flag/argparse"
  - "OQ2 (CLI lib): INCLUDED — Go uses cobra v1.9.1, Python uses typer 0.21.x"
  - "OQ3 (PyInstaller measurement): INCLUDED — PY_BIN=spike/python/dist/spike is canonical M5 RSS target (NOT .venv wrapper)"
  - "OQ4 (credentials): throwaway tokens at spike/corpus/.tokens.* (gitignored); graceful [SKIP] if absent"
  - "OQ5 (target rotation): compare.sh <target> one arg; defaults to hackerone.com; maintainer runs manually per target"
  - "bash v1 baseline: placeholder (no v1 Recon/hackerone.com/subdomains/subdomains.txt in repo); subdomain-set-diff metric is advisory until regenerated before Plan 01-04"
metrics:
  duration: "9m"
  completed_date: "2026-05-27"
  tasks_completed: 3
  tasks_total: 3
  files_created: 9
  files_modified: 1
---

# Phase 1 Plan 1: Spike Harness Scaffolding Summary

Spike harness scaffolded for apples-to-apples Go vs Python comparison: directory tree with `.gitkeep` skeletons, gitignore token-file exclusions, README locking 5 Open Questions, 3-target corpus, kill-tree mock matching RESEARCH.md Example 3 exactly, placeholder baseline, and a shellcheck-clean comparison runner with all 6 metric extractors.

## What Was Built

### Task 1: Directory tree + .gitignore + spike/README.md (commit: bd70cb41)

Created the full `spike/` directory skeleton per RESEARCH.md §3.1:
- `spike/go/`, `spike/python/` — empty with `.gitkeep` (ready for Plans 01-02/01-03)
- `spike/corpus/expected/`, `spike/baselines/` — empty with `.gitkeep`
- Appended 10 gitignore entries: `spike/go/out/`, `spike/python/out/`, `spike/go/bin/`, `spike/python/.venv/`, `spike/comparison.json`, `spike/corpus/.tokens.*`, `spike/baselines/.regen-*`, two `.spike_session_start` sentinels, `spike/.spike_sessions.log`
- Created `spike/README.md` with all 7 required sections (Purpose, Scope, Layout, Running, Slice Locked, Metrics, Throwaway)
- README locks all 5 Open Questions (OQ1-OQ5) from RESEARCH.md as planner decisions
- README names all 4 passive sources, all 8 httpx flags, the 4-step atomic-write contract, and the kill-tree (Setpgid/setsid + group-kill + 5s WaitDelay + SIGKILL) contract

### Task 2: Test corpus + mock_stubborn_tool.sh + bash v1 baseline (commit: fc3b65b6)

- `spike/corpus/targets.txt`: exactly 3 lines — `hackerone.com`, `example.com`, `controlled-lab.test` (placeholder per RESEARCH.md §3.2)
- `spike/corpus/mock_stubborn_tool.sh`: EXACT contents from RESEARCH.md Example 3 — `trap '' TERM` on parent + 2 backgrounded children (`( trap '' TERM; sleep 3600 ) &`), all 3 ignore SIGTERM. Executable bit set; `bash -n` passes.
- `spike/baselines/hackerone.com.expected`: placeholder (see Baseline Decision below). Written atomically via `mktemp` + `mv` to follow PITFALL 3.1 hygiene even for harness scaffolding.

### Task 3: spike/compare.sh comparison runner (commit: bab142bf)

- `bash -n` passes; `shellcheck -S error` passes
- `set -euo pipefail` at top (CLAUDE.md convention)
- OS detection branch: `Darwin` → `TIME_FLAG="-l"` (BSD), else → `TIME_FLAG="-v"` (GNU)
- All 6 metric extractors present:
  - M1: `tokei` (cloc fallback) on `spike/go/` and `spike/python/`
  - M2: `awk` sum on `spike/.spike_sessions.log` (format: `<lang> <minutes>`)
  - M3a: `du -sk spike/python/.venv` (venv reference size); M3b: `stat` on `spike/python/dist/spike` (PyInstaller binary bytes)
  - M4: reads `spike/{lang}/out/.killtree_result` sentinel (written by Plans 01-02/01-03 test suites)
  - M5: `grep` on `/usr/bin/time` stderr for "maximum/Maximum resident set size"; converts bytes→kB on macOS
  - M6: reads `spike/{lang}/out/.xplat_ordinal` sentinel (written by Plans 01-02/01-03)
  - `mcp_lib_support`: hardcoded `{ "go": 1, "python": 1 }` per RESEARCH.md §5 (not a tie-breaker)
- `PY_BIN="spike/python/dist/spike"` — PyInstaller --onefile binary per OQ3 INCLUDE (shape-parity with Go stripped binary for M5 RSS measurement). NOT `.venv/bin/spike`.
- Graceful `[SKIP]` on missing binaries; still emits valid `spike/comparison.json` with JSON `null` values (not empty strings)
- First run with no binaries: exits 1 (expected — "at least one spike missing"), produces valid JSON
- Written atomically: `mktemp` + `mv` before `chmod +x`

## Open Questions Locked (OQ1-OQ5)

| OQ | Decision | Rationale |
|----|----------|-----------|
| OQ1 (config loader) | EXCLUDED | `--target` only via stdlib; config loading tests the config library, not orchestration. Biases LoC without comparison signal. |
| OQ2 (CLI lib) | INCLUDED: Go=cobra v1.9.1, Python=typer 0.21.x | Both locked for Phase 3 already; spike uses them for code-shape parity so spike→production mapping is direct. |
| OQ3 (PyInstaller) | INCLUDED: `PY_BIN=spike/python/dist/spike` | Apples-to-apples M5 RSS comparison requires both sides to be single binaries. `.venv` wrapper would systematically under-measure Python's process RSS. |
| OQ4 (credentials) | `spike/corpus/.tokens.github` + `spike/corpus/.tokens.gitlab` (gitignored) | Both entries confirmed in `.gitignore`; graceful `[SKIP]` on absent credentials is itself a testable code path. |
| OQ5 (target rotation) | One target per invocation; default `hackerone.com` | Manual maintainer operation; no automation needed for 1-week PoC harness. |

## Baseline Decision

**Outcome: placeholder** — `spike/baselines/hackerone.com.expected` was created as a placeholder because no bash v1 reconFTW output for `hackerone.com` exists in the repository (`Recon/hackerone.com/subdomains/subdomains.txt` not found).

The placeholder file starts with `# PLACEHOLDER` and includes complete regeneration instructions:
```
# PLACEHOLDER — regenerate by running: ./reconftw.sh -d hackerone.com -s
# Then: sort -u Recon/hackerone.com/subdomains/subdomains.txt > spike/baselines/hackerone.com.expected
```

**Impact on Plans 01-02/01-03:** Neither plan is blocked. Both spikes can still run; `compare.sh` reports `subdomain_set_diff_lines: null` (from missing `subs.jsonl` files) rather than comparing against the baseline. The subdomain-set-diff metric is advisory and does not gate the ADR verdict (which uses only M1-M6 per RESEARCH.md §2.1).

**Impact on Plan 01-04 (ADR draft):** If the baseline is still a placeholder at Plan 01-04 time, the ADR Measurement section explicitly notes "subdomain-set-diff metric unavailable (baseline never regenerated)" — does NOT block the verdict.

## compare.sh First Run Confirmation

Script run with no spike binaries: `./spike/compare.sh hackerone.com`
- Stderr: `[SKIP] spike/go/bin/spike not built` and `[SKIP] spike/python/dist/spike not built`
- Exit code: 1 (expected — "at least one spike missing")
- `spike/comparison.json` produced and valid JSON

```json
{
  "target":    "hackerone.com",
  "timestamp": "2026-05-27T14:50:15+02:00",
  "platform":  "Darwin 25.5.0 arm64",
  "go": { "loc": null, "hours": null, "binary_bytes": null, "killtree": "NA", "rss_kb": null, "xplat_ordinal": null },
  "python": { "loc": null, "hours": null, "venv_kb": null, "pyinstaller_bin": null, "killtree": "NA", "rss_kb": null, "xplat_ordinal": null },
  "mcp_lib_support": { "go": 1, "python": 1, "note": "Both v1.x stable per RESEARCH.md §5; not a tie-breaker" },
  "subdomain_set_diff_lines": null
}
```

Top-level keys present: `target`, `timestamp`, `platform`, `go`, `python`, `mcp_lib_support`, `subdomain_set_diff_lines` ✓

## PY_BIN Canonical Path Confirmation

`compare.sh` contains: `PY_BIN="spike/python/dist/spike"` (the PyInstaller `--onefile` binary per OQ3 INCLUDE)

`compare.sh` does NOT contain any reference to `spike/python/.venv/bin/spike` for RSS measurement. The `.venv` is only used for M3a venv-size measurement.

## Deviations from Plan

None — plan executed exactly as written.

The baseline decision (placeholder vs. real data) was pre-defined in the plan: step 3b applies when `Recon/hackerone.com/subdomains/subdomains.txt` does not exist. That condition held; the placeholder path was followed correctly.

## Known Stubs

- `spike/baselines/hackerone.com.expected`: intentional placeholder per plan design. The regeneration procedure is documented in the file itself. This stub does NOT prevent the plan's goal (harness scaffolding) from being achieved — it prevents the subdomain-set-diff advisory metric from showing a real number until the maintainer runs `./reconftw.sh -d hackerone.com -s` and copies the output. Plans 01-02/01-03 are not blocked by this.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced at trust boundaries. All threat mitigations from the plan's STRIDE register were applied:

| Threat ID | Mitigation Applied |
|-----------|-------------------|
| T-01-SI-01 | `set -euo pipefail` in compare.sh + `shellcheck -S error` gate passed |
| T-01-SI-02 | `spike/corpus/.tokens.github` and `spike/corpus/.tokens.gitlab` both listed in `.gitignore` |
| T-01-SI-03 | compare.sh emits JSON `null` for missing values (NOT empty strings); jq-parseable |
| T-01-SI-04 | Accepted — spike runs are maintainer-initiated against authorized targets |
| T-01-SI-05 | mock_stubborn_tool.sh is intentionally minimal; `bash -n` gate passes |
| T-01-SI-SC | No package installs in Plan 01-01 — pure bash scaffolding |

## Self-Check: PASSED

**Files verified:**

- `spike/go/.gitkeep`: FOUND
- `spike/python/.gitkeep`: FOUND
- `spike/corpus/expected/.gitkeep`: FOUND
- `spike/baselines/.gitkeep`: FOUND
- `spike/README.md`: FOUND (7 sections, OQ1-OQ5 all locked)
- `spike/corpus/targets.txt`: FOUND (3 lines: hackerone.com, example.com, controlled-lab.test)
- `spike/corpus/mock_stubborn_tool.sh`: FOUND (executable, bash -n passes, 3x `trap '' TERM`)
- `spike/baselines/hackerone.com.expected`: FOUND (placeholder, starts with `# PLACEHOLDER`)
- `spike/compare.sh`: FOUND (executable, bash -n passes, shellcheck -S error passes, valid JSON produced)

**Commits verified:**

- bd70cb41 feat(01-01): create spike harness directory tree, .gitignore updates, and README
- fc3b65b6 feat(01-01): create spike test corpus, kill-tree mock, and bash v1 baseline placeholder
- bab142bf feat(01-01): create spike/compare.sh comparison runner with all 6 metric extractors
