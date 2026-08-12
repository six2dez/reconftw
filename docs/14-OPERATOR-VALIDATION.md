# Phase 14 — Operator Validation Runbook (close the cutover)

The Go engine and the cutover machinery are code-complete and pass every **offline**
gate. Three checks remain that **cannot run on a UDP/53-blocked box** — they need a
host with real network, DNS/UDP-53 open, `bash` v1, and the full external toolchain
installed. Run them on such a host, then verification flips from `human_needed` →
`passed` and you can do the real `main`→v2 cutover.

> Reference host for the perf numbers: **8-core / 16 GB**. Use a ~1000-subdomain target.

---

## 0. One-time setup — frozen bash v1 baseline

Both the parity and throughput checks drive bash v1 from a **versioned, frozen**
checkout (not a drifting install), so the A/B baseline is reproducible:

```bash
# from the repo root, on the network host:
git worktree add ../reconftw-v1-baseline v4.1     # LEGACY_REF override: any v1 tag/branch
go build -o ./bin/reconftw ./cmd/reconftw          # build the v2 binary
```

---

## 1. Live parity pass — CUT-11 (HARD gate)

Runs bash v1 and Go v2 against the same target and diffs the three core sets
(subdomain set, live-host set, finding classes), emitting ADDED / REMOVED lists.
**PASS = core sets match within the documented noise tolerance** (ordering + known
run-to-run nondeterminism excluded); exact set equality is NOT required.

```bash
scripts/parity-full.sh --help          # exact target/flag synopsis
scripts/parity-full.sh <target>        # e.g. a controlled lab target first (primary),
                                        # then 2-3 canonical public targets (best-effort)
```

- Review the emitted **markdown + JSON** report. REMOVED (v1-only) entries are the
  ones that matter — potential regressions. A short, explainable REMOVED list on the
  lab target = sign-off.
- Never wired into CI by design (live/nondeterministic). This is a human-reviewed pass.

## 2. Live throughput benchmark — XCUT-01 (HARD gate)

Assert Go v2 runs **within 10 %** of bash v1 on the same ~1000-subdomain target.

```bash
# a) bash v1 baseline (frozen worktree):
( cd ../reconftw-v1-baseline && time ./reconftw.sh -d <target> -r )
#    → record the wall-clock seconds into tests/bench/baseline_metrics.json  ("total_duration_sec")

# b) Go v2, SAME target:
time ./bin/reconftw recon --target <target> --no-update
#    → write {"total_duration_sec": <sec>} to current_perf_summary.json

# c) gate (exit 0 = within 10%):
tests/bench/compare_baseline.sh tests/bench/baseline_metrics.json current_perf_summary.json
```

## 3. Full lib coverage including resolvers — XCUT-03 tracked risk

`scripts/coverage-lib.sh` deliberately EXCLUDES `internal/core/resolvers` (it hangs on
this box's blocked UDP/53) and gates the resolvers-excluded aggregate at 79.3 % ≥ 75 %.
On a network host, measure the excluded package to retire the tracked risk:

```bash
go test ./internal/core/resolvers/... -cover        # get the resolvers number (historically ~36%)
bash scripts/coverage-lib.sh                          # resolvers-excluded gate still applies
```

If the full-lib-incl-resolvers figure is below 75 %, that is a real coverage gap in
`resolvers` to close (add tests) — not a gate to silently relax.

---

## After all three pass

1. Re-run `/gsd-execute-phase 14` (or the verifier) so `14-VERIFICATION.md` flips to
   `status: passed`.
2. Then the **out-of-phase** cutover (documented in `MIGRATION.md`, NOT automated):
   the `main`→v2 branch swap, bash `main` → `archive/v1.x` (frozen 12 months), and the
   `complete-milestone` ceremony.

## Notes

- **Compat writer is now LIVE** (wired into `RunCompositeAsync`/`RunSubsAsync` finalization,
  commit `6c2775f`) — a real v2 scan now materializes the bash-shape `Recon/<domain>/`
  (`_compat/`) tree. No longer a pending item.
- Deferred code-review items still open on the branch (see `.planning/phases/14-cutover-and-migration/14-REVIEW.md`):
  WR-03 (latent duplicate `[output]` table), WR-04 (`HEADER=#foo` → empty value),
  WR-05 (loader `[legacy]`-collision prints a secret; the migrator never emits `[legacy]`).
- macOS local-run caveats: `\cp -f` (the `cp -i`/`rm -i` alias trap) and pass `-duc`/`--no-update`
  to projectdiscovery tools.
