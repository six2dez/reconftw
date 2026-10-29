# Contributing to reconFTW

Thank you for your interest in contributing to reconFTW! There are two code
lines in this repository (see [BRANCHES.md](BRANCHES.md)):

- **Go v2** on `dev-go` — the rewrite, in beta. New work goes here.
- **bash v1** on `dev`/`main` — the current public release, maintenance only.

## Code of Conduct

Please read and follow the [Code of Conduct](CODE_OF_CONDUCT.md) in all interactions.

## Security Vulnerabilities

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

---

## Go v2 (`dev-go`)

### Setup

```bash
git clone https://github.com/<your-username>/reconftw
cd reconftw
git remote add upstream https://github.com/six2dez/reconftw
git checkout dev-go

go version                     # must satisfy the `go` line in go.mod
make build                     # → bin/reconftw (stamped with git describe)
./bin/reconftw install         # the ~100 external tools (optional for most tests)

# dev tools CI uses — same versions as .github/workflows/ci.yml
go install mvdan.cc/gofumpt@v0.7.0
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2
go install golang.org/x/vuln/cmd/govulncheck@v1.6.0
```

### Layout

```
cmd/reconftw/            cobra entry point, subcommands, v1 flag aliases
internal/core/           kernel: config · appctx · task · scheduler · backend ·
                         output · checkpoint · findings · ingest · report · notifier
internal/modules/        the recon work: subdomains/ web/ osint/ vulns/
internal/mcp/            MCP server (+ embedded openapi.json)
internal/installer/      `reconftw install`
internal/store/sqlc/     hand-maintained store.db queries (no sqlc generate)
internal/core/backend/tools.lock   the v2 tool manifest (NOT the root tools.lock)
docs/ARCHITECTURE.md     how it fits together — read this first
```

### The loop

```bash
make fmt                         # gofumpt -w .
make lint                        # golangci-lint run ./...
go test -race -short ./...       # = make test — the per-push ring
make integration-smoke           # the ^TestE2E gate (fails on zero matches)
make ci                          # what ci.yml runs: fmt-check lint test coverage gates
```

`go test ./...` alone is **not** enough: `-race` has caught data races that a
plain run hides, and the coverage gates (`make coverage-critical`,
`make coverage-lib`) are part of CI. Run `make ci` before pushing.

Two things CI cannot check and you should, when you have the tools installed:

```bash
make realtools-args              # //go:build realtools — runs the real binaries
                                 # against the pinned arg vectors; absent tools skip
./bin/reconftw health-check      # exits 1 by design on an incomplete PATH
```

`make release-gates` is the full cutover sign-off (slow; needs nuclei). It is
run before a tag, not before every PR.

### Rules the tests enforce

- **No raw subprocesses.** Only `internal/core/backend/local.go` may call
  `exec.Command`. Tasks use `app.Tools.Run(...)` / `app.Tools.Stream(...)`.
- **Staging → merge.** Multi-producer artefacts (`urls`, `findings`, `waf`,
  `subdomains`, …) are written to `inputs/<artefact>.<tool>.jsonl` via
  `output.StageJSONL`/`StageLines` (which *remove* the file on an empty run)
  and appended once by the module's merge task. `staging_contract_test.go`
  and `silent_success_test.go` ratchet this across every task.
- **Consume the terminal stream error.** A `Stream` call must `Drain`/`Collect`
  and act on the final error (`stream_contract_test.go`).
- **Secrets are `log.Secret`.** Any `*Key/*Token/*Password/*Secret` config
  field must use that type; the XCUT-07 sentinel fails the build if a
  secret-shaped string reaches a log.
- **Scope at the write boundary.** Never bypass `app.Tree.Append`.
- **`--dry-run` before any mutation** in a stateful subcommand.

### Adding a task

1. Create `internal/modules/<module>/<tool>.go` with a type implementing
   `task.Task` (`Name` = `"<module>.<action>"`, `Module`, `Description`,
   `DependsOn`, `Enabled`, `Run`) and register it from `init()` with
   `task.Register(&myTask{})`. Copy the closest existing task — e.g.
   `internal/modules/web/shortscan.go` for a single-producer finding task.
2. `Enabled(cfg)` must gate on a config field. Add the field to the right
   struct in `internal/core/config/config.go` with `koanf` + `validate` tags,
   its default in `defaults.go`, and — if v1 had an equivalent variable — its
   mapping in `legacy_aliases.go` (the migrator corpus test will tell you if
   you forgot). Document the key in `MIGRATION.md` §2.3.
3. **Tool manifest entry.** Add the tool to
   `internal/core/backend/tools.lock` (`[[tool]]` table: `name`, `kind`,
   `go_module`/install coordinates, `description`, `default_args`,
   `timeout_seconds`, `critical`, plus `clone_*` for repo-clone tools). The
   installer, `health-check` and the registry all read this file; the root
   `tools.lock` is the v1 installer's and must not be synced with it.
4. **Flag table.** The arg vector your task passes is data. Register it in the
   backend arg-vector coverage (`internal/core/backend/argvector_*_test.go`
   and, for anything the real binary must accept, a `realtools`-tagged probe
   in `smoke_test.go`). `make realtools-args` reports every task nobody
   verifies (`ARGV_COVERAGE registered=… driven=…`).
5. **Fixture with provenance.** Parser tests must run against **real captured
   tool output**, not JSON typed to match the struct — that is how a wrong
   `port` type once silently zeroed the whole web layer. Put the capture under
   `internal/modules/<module>/testdata/<tool>_real_output.<ext>` and say in
   the test file header which tool version produced it, with which flags,
   against what (see `internal/modules/web/httpx_real_fixture_test.go`).
   Sanitise secrets before committing. Mock-backend fixtures for
   subprocess-free tests go under `internal/core/testutil/fixtures/<tool>/`
   (its README has the layout).
6. Wire the task into the stage list of the subcommand(s) that should run it
   (`cmd/reconftw/composite_subcommands.go`) and add a DAG test if it adds a
   dependency edge (`dag_test.go` in each module guards against cycles).
7. If the task produces a new artefact, add it to the compat mapping
   (`internal/core/output/compat.go`) only if v1 had the file, and to
   `docs/ARCHITECTURE.md`'s workspace layout.

### Pull requests

1. Target **`dev-go`**.
2. One behaviour change per PR; say what the user sees differently.
3. `make ci` green; new tests for new behaviour.
4. Mention the issue (`refs #N`, or `closes #N` only when it is fully fixed —
   a partial fix in the *title* closes the issue on merge).

---

## Legacy v1 (bash, `dev`)

The bash framework is in maintenance. Bug fixes are welcome; new features
should target v2.

### Setup

```bash
git checkout dev
./install.sh
brew install shellcheck shfmt bats-core   # or apt
```

### Structure

```
reconftw.sh      entry point — arg parsing, module loading, dispatch
reconftw.cfg     default configuration
install.sh       installer (reads the root tools.lock)
lib/             validation.sh · common.sh · ui.sh · parallel.sh
modules/         core.sh · modes.sh · subdomains.sh · web.sh · vulns.sh · osint.sh · axiom.sh · utils.sh
tests/           unit/ integration/ security/ (bats), mocks/, fixtures/
```

### Style and safety

- Bash 4.3+, `#!/bin/bash`; `shfmt -i 4 -bn -ci`; `shellcheck -S warning`.
- Sanitize every input: `sanitize_domain()`, `sanitize_ip()`,
  `sanitize_interlace_input()`; never `eval` user input; always quote.
- `reconftw.sh` sets `IFS=$'\n\t'` globally: bare `read` and unquoted `${VAR}`
  do not split on spaces. Assert on the *second* element when testing list
  variables.

### Adding a function

```bash
function my_new_check() {
    start_func "${FUNCNAME[0]}" "Running my new check"
    # ... run_command tool args ...
    end_func "Results: ${FUNCNAME[0]}" "${FUNCNAME[0]}"
}
```

Add a toggle in `reconftw.cfg`, wire it in `modules/modes.sh`, add a bats test
under `tests/unit/` using `source ./reconftw.sh --source-only`, and remember CI's
unit job installs **no** recon tools — stub them.

### Tests

```bash
make bash-lint          # shellcheck
make bash-fmt           # shfmt
make bash-test-unit     # bats tests/unit
make bash-test-security # bats tests/security
make bash-test-all
```

### Pull requests

Target **`dev`**. Keep PRs focused, pass `make bash-lint`, include tests.

---

## Bug Reports and Feature Requests

Submit via [GitHub Issues](https://github.com/six2dez/reconftw/issues/new/choose).
For v2 use the *v2 beta feedback* template and include `reconftw version`,
`reconftw config sources`, OS/arch, the command, and `workspaces/<target>/logs/run.log`.
For v1 include `git describe --tags`, `bash --version`, steps and log output.
