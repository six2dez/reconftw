# reconFTW v2 beta — `v5.0.0-beta.1`

reconFTW has been rewritten from bash to Go. This is the first public build of
that rewrite, and it ships as an **opt-in pre-release**.

This document is the canonical announcement for `v5.0.0-beta.1`. It leads with
what the beta is, and then — at more length, because it matters more — with what
it is not.

---

## What this is

A single statically-linked binary that replaces the sourced-bash engine. Same
recon philosophy: one command, a complete passive/active/vulnerability picture of
a target. Different machinery underneath:

- **Resumable by construction.** Every task records a checkpoint keyed by a hash
  of its inputs — config slice, target, wordlist contents. Re-running skips
  completed work.
- **Structured output.** Artefacts are JSONL with a schema, written atomically,
  scope-checked at the write boundary.
- **Bounded concurrency.** One scheduler with a global ceiling and per-tool rate
  limits, instead of unbounded background jobs sharing global state.
- **Portable.** No bash 4.3+ requirement, no GNU-coreutils-on-macOS dance. Linux
  and macOS, amd64 and arm64, plus a fully-static musl build for Alpine.
- **TOML config**, with a migrator that reads your existing `reconftw.cfg` and
  tells you loudly about every key it could not map.

The ~100 external tools are still the ~100 external tools. The rewrite changed
the orchestrator, not the toolbox.

---

## What this is NOT

Three things are open. None of them is a surprise we are hoping you will not
notice; they are the reason the beta exists at all.

### 1. Parity is measured against ONE target, not three to five

Bug-for-bug parity against bash v1 has been measured on **one** canonical target,
run side-by-side with the outputs diffed. The acceptance criterion, **CUT-11**,
asks for **three to five** canonical targets.

That gap matters in a specific way: differences on any other target are
**unmeasured, not verified-absent**. If v2 returns something bash v1 did not — or
misses something bash v1 found — on a target we have not run, no test currently
in the tree would have caught it. Please report those. A side-by-side diff on a
target we have never run is the single most valuable thing a beta tester can
send us.

### 2. Throughput is unmeasured

**No claim is made that v2 is faster than bash v1, or slower.** Nobody has
benchmarked the two end to end against the same targets under the same rate
limits, so any number you might expect to see here would be invented.

The architecture changed in ways that plausibly cut either way — a bounded
scheduler replaces unbounded background jobs, which can trade peak speed for
predictability. Which way it actually lands is an open empirical question. If
you run both, the timings are worth reporting; treat any assertion about v2's
speed, including a favourable one, as unsupported until then.

### 3. `Recon/<domain>/` is not created — **CUT-08** is open

This is the one most likely to break something of yours.

The beta does **not** create the top-level `Recon/<domain>/` tree. The
bash-shape output tree is written under the workspace root as **`_compat/`**
instead. Filenames inside it follow the v1 shape; the parent path does not.

So a pipeline that reads `Recon/<domain>/subdomains/subdomains.txt` finds
nothing under the beta, and a pipeline pointed at `_compat/` finds what it
expects.

Whether v2 should *also* create the top-level `Recon/<domain>/` path is an
**open decision**, tracked as CUT-08 — not an oversight, and not something the
beta is quietly hoping to skip. It is open because the answer depends on how
many people actually script against that path and how, which is exactly what a
beta period is for. **If this breaks a script of yours, say so.** That report is
the input the decision is waiting on.

---

## Why the tag is `v5.0.0-beta.1` and not `v2.0.0-beta`

"v2" is the **internal milestone name** for the Go rewrite. It is not the public
version number, and it never will be.

Public reconFTW tags are already at **`v4.1`**. A `v2.0.0-beta` tag would sort
*below* the current public release: every tool that orders versions — package
managers, update checkers, humans skimming a releases page — would read it as a
downgrade, and some would refuse to install it over an existing v4.x. So the
rewrite's first public tag continues the public sequence instead of restarting
it: `v5.0.0-beta.1`.

Expect `v5.0.0-beta.2`, `-beta.3` and so on during the beta period, and
`v5.0.0` when it is no longer a beta.

---

## You are not affected unless you opt in

**`releases/latest` continues to resolve to bash `v4.1`.**

That is not a promise we are keeping by hand — it is how GitHub works. GitHub
never points `releases/latest` at a pre-release, and the release pipeline marks
this build as a pre-release. The install command documented at the top of the
README resolves through `releases/latest`, so it keeps serving the bash release
for the entire beta period.

**If you do nothing, nothing changes for you.** To get the beta you have to name
the tag explicitly — see the opt-in section in the README. The Go binary is
`reconftw` and the bash entry point is `reconftw.sh`; they do not overwrite each
other, so you can install the beta alongside your existing setup and fall back at
any time by just running the other one.

Migration details, and every breaking change with a before/after example, are in
[MIGRATION.md](../MIGRATION.md) — start at §0.

---

## Where feedback goes

Use the **[v2 beta feedback](https://github.com/six2dez/reconftw/issues/new?template=v2-beta-feedback.md)**
issue template (`.github/ISSUE_TEMPLATE/v2-beta-feedback.md`). It applies the
`v2-beta` and `feedback` labels automatically, which is what makes the triage
below possible.

Bugs in the bash release still go to the normal Bug report template. The beta
template is for the Go rewrite only.

Nothing in the template is required. A one-line "this broke" with the output of
`reconftw version` is already useful.

**Triage commitment (CUT-10):** a triage pass over open `v2-beta` issues once a
month, with the summary posted publicly as a repository issue tagged `v2-beta` —
what came in, what was fixed, what was deferred and why. The first pass happens
the month after the beta ships.

**No triage has happened yet, because the beta has not shipped yet.** This
section describes a commitment, not a track record; judge it once there is
something to judge.

---

## Known issues already tracked

Please skip these — they are open on purpose, and reporting them adds noise
rather than information:

- `Recon/<domain>/` is not created (CUT-08, above). **Do tell us if it breaks a
  script** — that specific report is wanted.
- `dnscewl` and `dnstake` do not resolve on macOS in this beta.
- `dalfox` may exit non-zero on `--no-spinner` if you have dalfox v3.x
  installed; the pinned argument vector targets v2.9.2.
