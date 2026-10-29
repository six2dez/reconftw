# Branches and tags

reconFTW has two code lines in one repository while the Go rewrite is in beta.
This file says which branch is which, so nobody has to infer it from the commit
graph.

| Branch | What it is | Who should use it |
|---|---|---|
| `main` | **bash v1**. Carries every `dev` fix up to 2026-09-22 (#1060), 116 commits past the `v4.1` tag; no release has been cut since `v4.1`. The GitBook docs and the DockerHub `main` / `nightly` images are built from it; `releases/latest` still points at the `v4.1` tag. | Anyone who has not opted into the beta. |
| `dev` | bash v1 maintenance. Bug fixes for the bash line land here first and are merged to `main` at release time. PRs against the bash code go here. | v1 contributors. |
| `dev-go` | **Go v2** (the rewrite). Single binary, TOML config, `workspaces/` output tree. Tagged `v5.x` pre-releases (`v5.0.0-beta.1`, …) are cut from here. CI (`.github/workflows/ci.yml`) and the release gates run on this branch. | Beta users, v2 contributors. |
| `rewrite/v2` | A stale duplicate of early `dev-go` work. **Not maintained; to be deleted by the maintainer.** Do not branch from it or open PRs against it. | Nobody. |

## Tags

- `v4.x` and older — bash releases. `v4.1` (2026-03-06) is the current public
  release.
- `v5.0.0-beta.N` — Go v2 pre-releases. They are tagged on `dev-go`.
- `v5.0.0` will be the first stable Go release. Until it exists, every v5 tag is
  a pre-release.

### Pre-release tags never take `latest`

GitHub only moves `releases/latest` to a **non-pre-release** release, so
`curl …/releases/latest/download/…` keeps serving the bash line until `v5.0.0`
ships. The same rule is applied to container tags by hand: the Docker workflow
assigns `latest` only on a published GitHub release, and a beta is published as
a pre-release. If you want v2 you must **name the tag** (`v5.0.0-beta.1`,
`six2dez/reconftw:5.0.0-beta.1`); if you do nothing you keep getting v1. That is
deliberate — see `docs/V2-BETA-ANNOUNCEMENT.md`.

## Cutover

When v2 leaves beta, `main` swaps to the Go line and the bash `main` becomes
`archive/v1.x`, frozen for 12 months with security-only fixes. `MIGRATION.md`
§3 and §4 describe the rollback path and the two deprecation clocks. Until that
swap happens, `main` is bash and `dev-go` is Go.

## Where to send a change

- Bash bug → PR against `dev`.
- Go bug or feature → PR against `dev-go` (see `CONTRIBUTING.md`).
- A fix that applies to both (installer, wordlists, docs about v1) → `dev`
  first; the maintainer forwards it to `dev-go` with the merge gates that
  catch what v1 brings (`migrate` corpus, bats parity map).
