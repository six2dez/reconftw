# Security Policy

## Supported Versions

| Line | Version | Branch | Supported |
| --- | --- | --- | --- |
| Go v2 (beta) | `v5.0.0-beta.x` | `dev-go` | :white_check_mark: security fixes land in the next beta |
| bash v1 | `v4.1` (`main`) | `main` / `dev` | :white_check_mark: |
| bash v1 | `< 4.0` | — | :x: |

See `BRANCHES.md` for which branch is which.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report them responsibly by emailing **six2dez** directly:

- Email: [six2dez@gmail.com](mailto:six2dez@gmail.com)
- Subject: `[reconFTW Security] <brief description>`

You should receive a response within 72 hours acknowledging the report. The maintainer will work with you to understand and remediate the issue before any public disclosure.

## Secrets Management

### v2 (Go binary)

Secrets are ordinary config keys whose Go type is `log.Secret`. There are three
ways to supply them; later layers win:

1. **`secrets.toml`** — config layer 6. Pass it with `--secrets FILE`; the
   file is gitignored (`secrets.toml`, `secrets.toml.*`) and
   [`secrets.toml.example`](secrets.toml.example) lists every key the loader
   understands:

   ```toml
   [api_keys]
   shodan   = "…"
   whoisxml = "…"
   pdcp     = "…"

   [notifications.slack]
   webhook_url = "https://hooks.slack.com/…"
   [notifications.telegram]
   bot_token = "…"
   [notifications.discord]
   webhook_url = "https://discord.com/api/webhooks/…"

   [ai]
   openai_key    = "…"
   anthropic_key = "…"

   [mcp]
   api_key = "…"
   ```

2. **`RECONFTW_*` environment variables** — config layer 7, e.g.
   `RECONFTW_API_KEYS_SHODAN`, `RECONFTW_MCP_API_KEY`, `RECONFTW_AI_OPENAI_KEY`.
   The mapper turns the first underscore after the section name into a dot
   (`RECONFTW_API_KEYS_SHODAN` → `api_keys.shodan`), so keys in nested tables
   such as `notifications.slack.webhook_url` cannot be set this way — use the
   file.

3. **Docker runtime secrets** — pass `-e RECONFTW_API_KEYS_SHODAN=…` or mount a
   `secrets.toml` and pass `--secrets /run/secrets/reconftw.toml`. Never bake
   secrets into the image.

**Redaction.** Every `log.Secret` value is registered with the log Redactor at
boot. It is masked in: every log line (`logs/run.log`, `logs/tools.jsonl`),
`reconftw config show`, the workspace config snapshot, `reconftw migrate
--dry-run` output and MCP responses. `reconftw migrate` writes the migrated
`reconftw.toml` with mode `0600` because it carries the real values. Token
*files* (`paths.github_tokens`, `paths.gitlab_tokens`) are referenced by path and
must be kept out of version control yourself.

### v1 (bash)

1. **Environment variables**: `SHODAN_API_KEY`, `WHOISXML_API`, `PDCP_API_KEY`,
   `XSS_SERVER`, `COLLAB_SERVER` are read before `reconftw.cfg`.
2. **`secrets.cfg`** in the reconFTW root, sourced automatically and gitignored
   (`secrets.cfg.example` is the template). `register_secret` adds each value to
   the log redactor.
3. **Docker**: `-e` flags at runtime against the `six2dez/reconftw:main` (v1)
   image.

## Files to Never Commit

| File | Line | Purpose |
|------|------|---------|
| `secrets.toml` | v2 | Secret material (layer 6); only `secrets.toml.example` is tracked |
| `reconftw.toml` (repo root) | v2 | Auto-loaded project config; may hold migrated secrets — gitignored |
| `secrets.cfg` | v1 | Local secrets override file |
| `reconftw.cfg` (with keys) | v1 | Configuration with API keys filled in |
| `.env`, `*.tokens`, `.github_tokens`, `.gitlab_tokens` | both | Environment and token files |

Verify these are covered by `.gitignore` before pushing (`git check-ignore -v <file>`).

## Input Sanitization

**v2:** targets go through `appctx.NewTarget` (hostname folded to punycode and
syntactically validated; IPv4/IPv6/CIDR parsed), every `[paths]` value is
checked for path traversal, and no tool is ever invoked through a shell:
`internal/core/backend/local.go` is the only place that may spawn a
subprocess (enforced by an AST lint test) and it passes argv arrays, never
strings. Scope is applied again at the artefact write boundary.

**v1:** `sanitize_domain()`, `sanitize_ip()`, `sanitize_interlace_input()`,
`validate_domain()`, `validate_ipv4()` in `lib/validation.sh` /
`modules/utils.sh`; no `eval` on user input; variables quoted throughout.

## Security Testing

- v2: `go test -race -short ./...` includes the raw-subprocess lint, the
  logging-hygiene sentinel (no secret-shaped string may reach a log), the scope
  and path-traversal validators and the MCP auth/scope tests. `govulncheck
  ./...` runs in CI on every push.
- v1: `make bash-test-security` (injection, pipe/redirect, substitution and
  path-traversal cases under `tests/security/`).

## Security-Related Configuration (v2)

| Key | Default | Description |
|---|---|---|
| `output.min_disk_space_gb` | `0` | Refuse to start below this free space (0 = disabled) |
| `output.log_rotation.*` | — | Cap log count/age per workspace |
| `output.structured_logging` | `false` | JSON logs for audit trails |
| `mcp.enabled` / `mcp.api_key` | `false` / `""` | MCP server is opt-in and always requires a Bearer token; HTTP binds `127.0.0.1` only |
| `ai.redact` | — | Redact findings before they are sent to an AI provider |
| `integrations.proxy.*` | off | Route tool traffic through proxychains |
| `axiom.enabled` | `false` | Provisions billable cloud instances; experimental |

The v1 equivalents (`MIN_DISK_SPACE_GB`, `MAX_LOG_FILES`, `STRUCTURED_LOGGING`,
`SHOW_COMMANDS`, `INTRUSIVE`, …) live in `reconftw.cfg`.

## Docker Security

The v2 image (`Docker/Dockerfile`) runs as a non-root user with `cap_net_raw`
granted only to the binaries that need raw sockets, compiles the binary
in-image per platform, takes secrets only at runtime, and ships a `HEALTHCHECK`
(`reconftw health-check`). See `Docker/README.md`.
