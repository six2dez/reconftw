# reconFTW v2 architecture (Go)

This describes the Go binary on `dev-go` (tagged `v5.0.0-beta.N`). The bash v1
architecture that `main` still ships is preserved in
[`ARCHITECTURE-v1-bash.md`](ARCHITECTURE-v1-bash.md).

## One binary, one process, one scheduler

```
reconftw <subcommand> --target example.com
  │
  ├─ cmd/reconftw          cobra commands, v1 flag aliases, config/secrets paths
  ├─ internal/core/config  8-layer merge → one validated *Config (secrets redacted)
  ├─ internal/core/appctx  Boot(): logger · backend · checkpoint store · output tree
  │                        · scheduler · notifier · UI — the dependency kernel
  └─ internal/core/scheduler
        runs the task DAG for the subcommand with bounded concurrency
        ├─ internal/modules/subdomains   passive → resolve → permut/brute → enrichment
        ├─ internal/modules/web          httpx → analysis → urls → js → bypass
        ├─ internal/modules/osint        dorks · leaks · emails · cloud · metadata
        └─ internal/modules/vulns        gf classify → injection → oob → dast
              └─ internal/core/backend   every tool call: local exec (or Axiom),
                                         rate-limited, resolved from tools.lock
```

There is no sourcing chain and no shared mutable globals: every capability is a
**task** registered in `internal/core/task`, and everything a task needs
arrives through `*appctx.AppContext`.

## Packages under `internal/core/`

| Package | Responsibility |
|---|---|
| `config` | Loads `Defaults()` → `/etc/reconftw/config.toml` → `~/.config/reconftw/config.toml` → `./reconftw.toml` → `--config` → `secrets.toml` → `RECONFTW_*` env → CLI flags (koanf + TOML). Validates with struct tags. `log.Secret`-typed fields are redacted everywhere. Also hosts `migrate` (v1 `.cfg` → TOML) and `profiles` (zen/deep). |
| `log` | slog handler with a Redactor. Every secret value is registered at boot; `log.Secret` implements `LogValuer` so it can never print itself. |
| `appctx` | `Target` (canonical identity → workspace slug, scope) and `Boot()`, which wires the kernel in the ADR-mandated order: logger, config, backend+runner, checkpoint store, output tree, scheduler, notifier, UI. |
| `task` | The `Task` interface (`Name`, `Module`, `Description`, `DependsOn`, `Enabled`, `Run`), the global registry (`task.Register` from `init()`), topological sort, and module/prefix filters shared by the CLI and MCP. |
| `scheduler` | Bounded concurrent dispatcher over the sorted DAG (`errgroup`, `concurrency.max_jobs`). Per-module failure policy (fail-fast vs best-effort), heartbeats for long tasks, checkpoint skip/record around every `Run`. One scheduler per scan — never shared between concurrent scans. |
| `backend` | `Runner` / `Backend` abstraction over tool execution. `LocalBackend` is the only place that may spawn a subprocess (a lint test enforces this); `AxiomBackend` dispatches a whitelisted subset to an Ax fleet and falls back locally; `PassiveBackend` refuses active tools. The embedded `tools.lock` (`internal/core/backend/tools.lock`) is the registry: per-tool kind, install coordinates, default args, timeout, critical tier. Token-bucket rate limiting and a recorder (`logs/tools.jsonl`) live here too. |
| `output` | The workspace tree and the write contract: atomic writes (temp → fsync → rename), a scope filter at the write boundary, **staging** files under `inputs/` and the single-writer merge into `artefacts/*.jsonl`, the `_compat/` v1-shape writer, the per-workspace lock, `manifest.json`. |
| `checkpoint` | SQLite `checkpoints.db` per workspace. A task is skipped when a row exists for `(task, target, input_hash)` where the hash covers the task name, target, its config slice and wordlist contents; `--force` ignores it. Incomplete runs are recorded as errored so they retry. |
| `findings` | The SARIF-compatible finding record and mappers from tool output. |
| `ingest` | End-of-scan import of `artefacts/*.jsonl` into the shared `store.db` (hosts, urls, findings, scan rows) that `report`, `monitor`, SARIF/hotlist and AI read. |
| `report` | HTML, SARIF 2.1.0, CSV, Markdown, hotlist and Faraday renderers over `store.db`, scoped to one scan. |
| `notifier` | Slack / Telegram / Discord with a digest coalescer; `notify --test` is the only path that propagates failures. |
| `resolvers` | Resolver list acquisition and `gen-resolvers` (dnsvalidator). |
| `ui` | Status badges, TTY/NO_COLOR handling, verbosity. |
| `errors`, `testutil` | Typed error reasons; `MockBackend` and fixture loading for tests. |

`internal/store/sqlc/` is the hand-maintained query layer for `store.db`
(there is no `sqlc generate`; edit the `.sql.go` files directly).
`internal/installer/` implements `reconftw install` from the embedded
`tools.lock`. `internal/mcp/` is the MCP server.

## A task's life

1. **Registration.** A module file declares a type implementing `task.Task` and
   calls `task.Register(&myTask{})` from `init()`. `Enabled(cfg)` gates it on
   the config slice it owns; `DependsOn()` names the tasks that must finish
   first. A nil `DependsOn` means "first concurrent group", not "no gate".
2. **Selection.** The subcommand picks a module prefix list (`subs`, `web`,
   `recon` = subs+web+osint, `all` = recon+vulns, …); `task.FilterByModuleAndEnabled`
   narrows the registry; `topo` orders it.
3. **Run.** The scheduler checks the checkpoint, starts a heartbeat, and calls
   `Run(ctx, app)`. The task invokes tools only through `app.Tools.Run(...)`
   (buffered) or `app.Tools.Stream(...)` (line events), never `exec.Command`.
4. **Staging → merge.** A task that is one of several producers of an
   artefact writes `inputs/<artefact>.<tool>.jsonl` through
   `output.StageJSONL`/`StageLines` — which **removes** the staging file when
   the run produced nothing, so stale results never republish. A single
   merge task per artefact (`subdomains.merge`, web `MergeStage`/`urldedup`, …)
   globs the staging files, deduplicates, applies scope and calls
   `app.Tree.Append` once. Single-producer artefacts append directly.
5. **Checkpoint.** On success the scheduler records the row; on an incomplete
   tool run it records "errored" so the next invocation retries.
6. **Finalise.** After the last stage: compat writer (`_compat/`), ingest into
   `store.db`, reports, notifications, summary.

## Workspace layout

```
workspaces/<target-slug>/
├── artefacts/        subdomains · hosts · urls · findings · buckets · asns … (.jsonl)
├── inputs/           per-tool staging files (inputs/urls.katana.jsonl …)
├── raw/              untouched tool output (raw/nuclei/, raw/screenshots/ …)
├── reports/<scan>/   html · sarif · csv · markdown · hotlist · faraday
├── logs/             run.log, tools.jsonl (every invocation, redacted)
├── checkpoints.db    resume state for THIS workspace
├── manifest.json     artefact inventory
└── _compat/          v1-shape .txt files (+ Recon/<domain> symlink, see MIGRATION §2.2)

<data_dir>/store.db   cross-scan SQLite: scans, hosts, urls, findings — read by
                      report / monitor / SARIF / AI; written by ingest at scan end
```

`workspaces/` is the default root (`-o/--output`); the target slug comes from
`appctx.NewTarget` (punycode-folded hostname, IP or CIDR).

## Cross-cutting rules

- **Scope** is enforced at the write boundary (`output.ScopeFilter`), not just
  on input: an out-of-scope host/URL never lands in `artefacts/`.
- **No raw subprocesses** outside `backend/local.go`
  (`internal/core/backend/lint`). Arg vectors are data in `tools.lock` plus
  per-task flags; their drift is guarded by `argvector_*` tests and the
  `realtools`-tagged probes (`make realtools-args`, needs the tools on PATH).
- **Dry run** (`--dry-run`) is honoured before any filesystem mutation in every
  stateful subcommand.
- **Secrets** are `log.Secret` in config, registered with the Redactor at boot,
  and stripped from logs, `config show`, snapshots and migrate output.
- **Axiom** is experimental: dispatch is time-capped, failures re-run locally,
  a dead fleet is abandoned for the rest of the run.

## MCP server (`internal/mcp/`)

`reconftw mcp serve` exposes the pipelines as MCP tools over stdio or HTTP
(`127.0.0.1:<port>`, Bearer `mcp.api_key`). Each session captures its scope
once; runs are owned by the session that started them (`cancel_scan`), run
under the config the server booted with, and publish `scan://…` resources
backed by the workspace JSONL. The OpenAPI schema is embedded from
`internal/mcp/openapi.json` and served at `/openapi.json`. See `mcp.md`.

## Where the tests live

`go test -race -short ./...` is the per-push ring; `-tags smoke` and the
`^TestE2E` gate are the integration rings; `make ci` mirrors `ci.yml`;
`make release-gates` is the cutover sign-off. Contract tests under
`internal/modules/*_contract_test.go` ratchet the staging, stream and
silent-success rules above across every task. `CONTRIBUTING.md` has the
workflow.
