---
name: "v2 beta feedback"
about: "Report anything you hit while running the reconFTW Go beta (v5.0.0-beta.x)"
title: "[v2-beta] "
labels: ["v2-beta", "feedback"]
assignees: []
---

<!--
CUT-10. This template is the beta feedback channel. Please use it for the Go
rewrite (v5.0.0-beta.x) ONLY — for the bash release (v4.1 and earlier) use the
normal Bug report template instead.

Nothing here is required. A one-line report of "this broke" with the version is
already useful; the rest just saves a round-trip.
-->

## What happened

<!-- What you ran, and what you expected instead. -->

## Version

```
# paste the output of:
reconftw version
```

- Installed from: <!-- release tarball / built from source / Docker -->
- OS + arch: <!-- e.g. Ubuntu 24.04 x86_64, macOS 15 arm64 -->

## Are you migrating from bash v4.x?

- [ ] Yes — I ran `reconftw migrate` on an existing `reconftw.cfg`
- [ ] Yes — but I wrote a fresh TOML config by hand
- [ ] No — this is a new install

If you migrated: **please paste any `⚠ unknown key` warnings** the migrator
printed. Those are the ones we most need to see — an unknown key means your
config had something the migrator does not yet map.

## Which of these does it touch?

<!-- Tick anything relevant; this routes the issue faster. -->

- [ ] Config migration (`reconftw.cfg` → TOML)
- [ ] Output tree / file layout — see the note below
- [ ] CLI flags behaving differently from bash
- [ ] A tool not being found, or found but not running
- [ ] Results differ from bash v1 on the same target
- [ ] Performance
- [ ] Docker / install
- [ ] Something else

### Known and already tracked — no need to report these

Please skip these; they are open on purpose and reporting them just adds noise:

- **`Recon/<domain>/` is not created.** The bash-shape compat tree currently
  lives under the workspace root as `_compat/`. Whether v2 should also create the
  top-level `Recon/<domain>/` symlink is an open decision (CUT-08), not an
  oversight. **Do tell us if this breaks a script of yours** — that is exactly the
  input we need to decide it.
- **`dnscewl` / `dnstake` report as missing.** Neither resolves on macOS in this
  beta.
- **`dalfox` may exit non-zero** with `unexpected argument '--no-spinner'` if your
  installed dalfox is v3.x — the pinned vector targets v2.9.2.

## Logs

<!--
`logs/tools.jsonl` in the workspace records every tool invocation with its argv
and outcome — it is usually the single most useful thing to attach.

Secrets registered with the redactor are scrubbed from it, but PLEASE SKIM IT
before pasting: it contains the command lines your scan actually ran, including
target names.
-->

```
# relevant log lines here
```
