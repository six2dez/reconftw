---
phase: 05-web-pipeline-e2e
plan: "07"
subsystem: web
tags: [acceptance, parity, fixtures, dod, checkpoint]
key-files:
  created:
    - .planning/phases/05-web-pipeline-e2e/05-VERIFICATION.md
  modified:
    - internal/modules/web/testdata/fixtures/httpx/httpx_hackerone.jsonl
    - internal/modules/web/testdata/fixtures/nuclei/nuclei_hackerone.jsonl
metrics:
  tasks: 2
  task_1: complete
  task_2: deferred-pending-vps
---

# 05-07 — Phase 5 Acceptance (SUMMARY)

## What was done

**Task 1 (auto) — DoD-2 leg (a) seeded-local run + fixture population: COMPLETE.**
Maintainer authorized local capture against hackerone.com (2026-06-02). Ran real tools against a
`www/docs/api.hackerone.com` seed (with `-duc` — the PD update check hangs in this env):
- httpx → 2 live hosts (cloudflare) → froze `httpx_hackerone.jsonl` (provenance header).
- nuclei (-severity info, no-headless) → 21 info findings → froze first 15 to `nuclei_hackerone.jsonl`
  (request/response/curl-command/template-path/ip stripped for size + portability; no secrets).
- wafw00f → 3× Cloudflare (captured; not written — see deviation).
- `reconftw web --dry-run` confirmed 22 enabled tasks / 4 stages wired; tools.lock = 43 tools.

Frozen-replay hard gates flipped real: TestWebParityHTTPX + TestWebParityNuclei now PASS (were skip).
Full suite `go test ./...` = 22 ok / 0 FAIL; `go build`/`go vet` clean.

**Task 2 (checkpoint:human-verify) — DoD-2 leg (b) VPS parity: DEFERRED (pending-vps).**
Mirrors Phase 4's 04-11 open gate. The authoritative full subs→web parity on hackerone.com +
tesla.com (v2-vs-v1 counts) requires a provisioned VPS/Axiom and is the maintainer's to run.
05-VERIFICATION.md §DoD-2 leg (b) has the runbook; flip its `status:` → `passed` on sign-off.

## Commits
| Commit | Description |
|--------|-------------|
| 0fa0ecdd | test(05-07): populate httpx + nuclei fixtures from real hackerone.com capture (DoD-2 leg a) |

## Deviations
- **wafw00f_hackerone.txt NOT overwritten** — 05-06 made it a synthetic golden backing the MUST-PASS
  `TestWebParityWAF` (exact assertion). Writing real capture would break a green test. Parity-test
  reality overrides the plan's files_modified listing. (Real wafw00f output recorded in VERIFICATION instead.)
- **ffuf + katana fixtures left as pending stubs** — one-shot capture too long (per plan); their parity
  tests skip cleanly until VPS capture.
- **Full live pipeline not run locally** — scoped capture to the 3 maintainer-authorized tools; the
  aggressive stages (ffuf fuzz / katana crawl / waymore) deferred to leg (b) on VPS.
- **DoD-1 surfaced a Phase-4 bug (out of scope):** `subzy --verify-ssl` should be `--verify_ssl`. Not
  fixed here (Phase-4 takeover code); logged in VERIFICATION for the 04-11 sign-off.

## Self-Check: PASSED
go build ./... = 0 · go test ./... = 22 ok/0 FAIL · go vet = 0 · 4/6 parity gates pass (2 pending-VPS
skips) · co-author-clean commits · maintainer WIP untouched. Phase 5 is code-complete; only DoD-2
leg (b) VPS sign-off remains (deferred by design, same as Phase 4).
