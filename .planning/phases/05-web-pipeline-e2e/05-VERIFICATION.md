---
status: gaps-found
phase: 05-web-pipeline-e2e
verified: 2026-06-02
verifier: orchestrator (inline, 05-07 acceptance) + gsd-code-reviewer
dod_1: pass (web tools)
dod_2_leg_a: pass
dod_2_leg_b: pending-vps
code_review: 7 blockers / 9 warnings / 5 info (see 05-REVIEW.md)
---

# Phase 5 — Web Pipeline E2E — Verification

## ⛔ BLOCKED — Code review found 7 confirmed blockers (2026-06-02)

The DoD acceptance below (DoD-1, DoD-2 leg a) is real, BUT an independent code review
(`05-REVIEW.md`) found systemic correctness defects that mean the pipeline is NOT
production-correct. Orchestrator-confirmed the headline blocker against kernel code:

- **Concurrent-write DATA LOSS (CR-01/CR-02/CR-04/CR-05):** web tasks call
  `app.Tree.Append("urls"|"findings"|"waf", …)` DIRECTLY, but `OutputTree.Append` is
  REPLACE-semantics (atomic rename over target), and `RunStage` runs same-stage tasks
  CONCURRENTLY. 6 tasks write `urls` in stage 3 (katana/urlfinder/waymore/subjs/jsluice/jsa),
  5 write `findings` (nuclei stage-2 then arjun/gxss/nomore403/shortscan stage-4), 2 write
  `waf` — each Append clobbers the prior → only the last writer survives. The web module
  abandoned Phase 4's staging-contract (per-task `inputs/<stage>.*` staging + single
  `MergeStage` Append writer); `MergeAllWebArtefacts` is effectively dead for these artefacts.
- **CR-03:** `web.jsa` passes an absolute python path as the tool *name* to `Tools.Run`
  (registry name-lookup) → always fails → JSA never runs but reports success.
- **CR-06:** `hakoriginfinder` attributes origin IPs to hosts by output line index → wrong data.
- **CR-07:** 5 tasks shell out via raw `exec.Command`, bypassing rate-limit/timeout/circuit-breaker
  governance (no per-tool timeout → a hung tool stalls the whole stage).

Why isolated tests passed: `parity_test.go` exercises each task ALONE, so the multi-writer
clobber and stage-ordering races are never exercised. `go build`/`go test ./...` are green but
do not cover the concurrent pipeline.

**Phase status: gaps-found — needs a gap-closure cycle before it can be marked verified.**
Recommended fix: mirror Phase 4 (`internal/modules/subdomains/passive.go` + `merge.go`) —
tasks write per-task staging files, MergeStage is the single Append caller per artefact; fix
stage/DependsOn assignment so same-artefact writers don't share a concurrent stage; fix JSA
tool invocation; route exec through `Tools.Run`/`Stream` governance.

---


Mirrors Phase 4's 04-11 model: code-complete with the authoritative VPS/Axiom parity
sign-off (DoD-2 leg b) deferred. Everything Claude-executable for acceptance is done.

## DoD-1 — Real-tool ARG-VECTOR smoke (`go test -tags realtools ./internal/core/backend/...`)

Result on this machine: **42 PASS / 3 SKIP / 1 real FAIL**.

- All Phase-5 **web** tool golden arg vectors PASS (httpx, nuclei, screenshot, ffuf, wafw00f,
  cdncheck, hakoriginfinder, csprecon, favirecon, vhostfinder, katana, urlfinder, waymore,
  urldedup, subjs, jsluice, mantra, jsa, sourcemapper, nomore403, shortscan, gxss, arjun).
- 3 SKIP = tools not on PATH (not a CI failure; skip-on-absent by design).
- The **only** real FAIL is `subzy run … --verify-ssl …` — subzy is a **Phase-4 takeover tool**,
  not a Phase-5 web tool. Real flag is `--verify_ssl` (underscore). **Out of scope for Phase 5**
  (Phase 5 never touched subzy/takeover). Surfaced here for the maintainer to fix during the
  Phase-4 (04-11) live-parity sign-off. → ACTION (Phase 4): `internal/modules/subdomains/takeover.go`
  subzy arg `--verify-ssl` → `--verify_ssl`.

During 05-06 the smoke test also caught + auto-fixed 3 Phase-5 flag-drift bugs (D-W9):
`csprecon -i→-l`, `hakoriginfinder -i→stdin+-h`, `mantra -i→stdin`. These now pass.

## DoD-2 leg (a) — Seeded-local run with real tools (authorized by maintainer, 2026-06-02)

Seed (bypasses mass-DNS; regular A-record resolution works here): `www/docs/api.hackerone.com`.
NOTE: ProjectDiscovery tools required `-duc` (disable-update-check) — the update probe hangs in
this environment; without it httpx/nuclei stall indefinitely. (DNS/UDP-53 is NOT blocked in this
session — `dig`/`curl` resolve fine; earlier project note was stale for this run.)

Real tool output captured and frozen into fixtures:
- **httpx** → 2 live hosts (www 200, docs 200; cloudflare) → `testdata/fixtures/httpx/httpx_hackerone.jsonl`
- **nuclei** (-severity info, no-headless) → 21 info findings (waf-detect/tech) → `…/nuclei/nuclei_hackerone.jsonl` (first 15, request/response bodies stripped for size + portability)
- **wafw00f** → 3× Cloudflare detections (www/docs/api) — captured but NOT written to a fixture (see deviations).

Pipeline wiring (`reconftw web --hosts <seed> --target hackerone.com --dry-run`): **22 enabled tasks /
4 stages** (probe → analysis → url-discovery → bypass); tools.lock loaded 43 tools. Build clean.

Frozen-replay hard gates (`go test ./internal/modules/web/... -run TestWebParity`):
- TestWebParityHTTPX — **PASS** (real fixture, was skip)
- TestWebParityNuclei — **PASS** (real fixture, was skip)
- TestWebParityWAF — **PASS** (synthetic golden)
- TestWebParityJSSecrets — **PASS** (synthetic golden, XCUT-07 redaction)
- TestWebParityFFUF — SKIP (pending-VPS; ffuf one-shot capture too long)
- TestWebParityURLDedup — SKIP (pending-VPS; katana one-shot capture too long)

Full suite `go test ./...`: **22 ok / 0 FAIL**. `go build ./...` clean. `go vet` clean.

### Deviations
- `testdata/fixtures/waf/wafw00f_hackerone.txt` was NOT overwritten with the real wafw00f capture.
  05-06 made it a **synthetic golden** that `TestWebParityWAF` asserts exactly (support+api =
  Cloudflare, docs+root = "(None)", exactly 2 results). Overwriting it would break a green
  MUST-PASS test. The plan listed it for population, but the parity-test reality takes precedence.
- ffuf + katana fixtures remain `pending` stubs (their one-shot capture runs too long per the plan);
  their parity tests skip cleanly until VPS capture.
- Local capture scoped to maintainer-authorized tools (httpx + nuclei -severity info + wafw00f).
  The full live pipeline (ffuf fuzzing / katana crawl / waymore) was NOT run locally — deferred to leg (b).

## DoD-2 leg (b) — VPS/Axiom full-chain parity sign-off — PENDING (human gate)

Same posture as Phase 4's 04-11. To complete:
1. Provision VPS (Ubuntu 24.04) + `reconftw install`.
2. `reconftw subs --target hackerone.com` then `reconftw web --target hackerone.com`; repeat for tesla.com.
3. Compare v2 vs v1 per-category counts (±5% investigate-only per D-W7):
   hosts.jsonl vs webs_all.txt; findings.jsonl vs nuclei; urls.jsonl vs url_extract.txt.
   Hard gates (exact): scope filter (no out-of-scope hosts), JS-secret redaction.
4. Record counts in this file §DoD-2 leg (b); flip `status:` → `passed` on sign-off.

## Requirements
WEB-01..WEB-16 implemented (code complete). WEB-16 (parity harness + smoke) verified locally.
Final WEB-* sign-off contingent on leg (b) VPS parity.
