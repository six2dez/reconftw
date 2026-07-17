# reconFTW v1 → v2 Migration Guide

reconFTW v2 is a ground-up rewrite of the bash framework in Go. It keeps the same
recon philosophy — one command, a complete passive/active/vulnerability picture of a
target — but replaces the sourced-bash engine with a single statically-linked binary,
a scheduler, a TOML config, and a structured JSONL output tree.

**This document is the single authoritative record of every breaking change between
v1 (bash) and v2 (Go), each with a before/after example, plus the rollback procedure,
the deprecation timeline, and the consolidated ledger of capabilities intentionally
deferred past cutover.** Per **XCUT-05** (zero silent breakages) there are no
undocumented behavior changes: every difference discoverable in the codebase — CLI
flags, output paths, config keys, changed defaults — appears here.

> **Audience:** existing v1 users upgrading an installed reconFTW, and script authors
> whose pipelines read the `Recon/<domain>/` output tree.

---

## Table of contents

1. [Quick start — migrate your config](#1-quick-start--migrate-your-config)
2. [Breaking changes](#2-breaking-changes) — the four categories, each with before/after
   - [2.1 CLI flags → subcommands](#21-cli-flags--subcommands-cut-07)
   - [2.2 Output tree](#22-output-tree-recondomaintxt--workspacestarget-idartefactsjsonl-cut-07)
   - [2.3 Config key renames](#23-config-key-renames-cut-07)
   - [2.4 Default-behavior changes](#24-default-behavior-changes-cut-07)
3. [Rollback — reverting v2 → v1](#3-rollback--reverting-v2--v1-cut-15)
4. [Deprecation timeline (two distinct clocks)](#4-deprecation-timeline-two-distinct-clocks-cut-14)
5. [Consolidated deferral ledger](#5-consolidated-deferral-ledger-d-06) — capabilities intentionally deferred past cutover
6. [Documented as deferred — manual / out of this phase](#6-documented-as-deferred--manual--out-of-this-phase) — beta, sign-off, branch swap, comms, doc rewrites
7. [Zero silent breakages attestation](#7-zero-silent-breakages-attestation-xcut-05)

---

## 1. Quick start — migrate your config

v2 reads **`reconftw.toml`**, not `reconftw.cfg`. Convert your existing v1 config with
the built-in migrator — it is schema-complete, offline, and never shells out:

```console
# Preview every mapping decision without writing anything (CUT-05):
reconftw migrate --from-bash ./reconftw.cfg --dry-run

# Write the migrated TOML:
reconftw migrate --from-bash ./reconftw.cfg --to ./reconftw.toml
```

The migrator disposes **every** v1 key three ways (nothing is silently dropped — CUT-06):

| Disposition | What it means | Output in `reconftw.toml` |
|---|---|---|
| **mapped** | key has a v2-native home (see §2.3) | a live `dotted.path = <value>` with an inline `# was KEY` comment |
| **superseded** | key is a bash global / auto-computed / file-read value v2 no longer needs | a `# SUPERSEDED (…): KEY = <value>` comment — preserved, never a live key |
| **unknown** | key is not recognised | a `# UNKNOWN (needs human review): KEY = <raw>` comment **plus** a loud `⚠ unknown key KEY` line on stderr |

Superseded/unknown keys are emitted as **TOML comments**, so a migrated file loads with
zero spurious warnings while still preserving your full v1 intent.

---

## 2. Breaking changes

Four categories change between v1 and v2. Each is documented below with a concrete
before/after. Examples use **placeholder** secret values (`YOUR_SHODAN_KEY`, `***`) —
never paste a real token into a shared config.

### 2.1 CLI flags → subcommands (CUT-07)

v1 selected modes with positional short/long flags on `./reconftw.sh`. v2 makes
**subcommands primary**; the v1 short flags survive as **deprecated aliases** that print
a stderr warning and are **removed in v2.2.0** (ADR §8, ARCH-10).

**Before (v1 bash):**

```console
./reconftw.sh -d example.com -r          # recon mode
./reconftw.sh -l targets.txt -a          # all (recon + vulns) over a list
./reconftw.sh -d example.com -s           # subdomains only
./reconftw.sh -d example.com --passive    # passive only
./reconftw.sh -d example.com -v           # via Axiom (VPS)
```

**After (v2 Go):**

```console
reconftw recon   --target example.com     # recon mode
reconftw all     --list targets.txt       # all (recon + vulns) over a list
reconftw subs    --target example.com     # subdomains only
reconftw passive --target example.com     # passive only
reconftw recon   --target example.com --axiom   # via Axiom
```

**Flag/subcommand mapping (ADR §8.1 / §8.2):**

| v1 flag | v2 subcommand / flag | v1 short flag (deprecated alias, removed v2.2.0) |
|---|---|---|
| `--recon` | `reconftw recon` | `-r` |
| `--all` | `reconftw all` | `-a` |
| `--passive` | `reconftw passive` | `-p` |
| `--subdomains` | `reconftw subs` | `-s` |
| `--web` | `reconftw web` | `-w` |
| `--osint` | `reconftw osint` | `-n` |
| _(none)_ | `reconftw zen` | `-z` |
| _(none)_ | `reconftw deep` | `-y` |
| `--monitor` | `reconftw monitor` | — |
| `-d <domain>` | `--target <domain>` | `-d` |
| `-l <file>` | `--list <file>` | `-l` |
| `--vps` | `--axiom` | `--vps` / `-v` |

**Transitional behavior:** during v2.0.x–v2.1.x the deprecated flags remain **fully
functional** and set the same override variables as their v2 equivalents; using one
prints, e.g.:

```
Flag --recon has been deprecated, use subcommand 'recon' instead: `reconftw recon -d example.com`
```

They are **removed in v2.2.0** (see §4, and the note on the `-o`/`-n` reassignment in
ADR §8.2 — v2 assigns `-o` to `--output`, so OSINT's short flag is `-n`).

### 2.2 Output tree (`Recon/<domain>/*.txt` → `workspaces/<target-id>/artefacts/*.jsonl`) (CUT-07)

v1 wrote a per-domain tree of **plain-text** files under `Recon/<domain>/`. v2 writes a
per-target **workspace** whose canonical artefacts are **JSONL** (one JSON object per
line) under `workspaces/<target-id>/artefacts/`.

**Before (v1 bash) — plain text, one value per line:**

```text
Recon/example.com/
├── subdomains/subdomains.txt        # one hostname per line
├── webs/webs.txt                    # one URL per line
├── hosts/ips.txt                    # one IP per line
└── nuclei_output/                   # raw nuclei output
```

```console
$ cat Recon/example.com/subdomains/subdomains.txt
api.example.com
www.example.com
```

**After (v2 Go) — canonical JSONL:**

```text
workspaces/example.com/
├── artefacts/subdomains.jsonl       # {"subdomain":"api.example.com", ...} per line
├── artefacts/hosts.jsonl            # {"host":"…","ip":"…","url":"…", ...} per line
├── artefacts/urls.jsonl
├── artefacts/findings.jsonl         # SARIF-compatible findings
└── raw/nuclei/                      # raw nuclei output
```

```console
$ jq -r '.subdomain' workspaces/example.com/artefacts/subdomains.jsonl
api.example.com
www.example.com
```

**Compat window — your `Recon/<domain>/` scripts keep working (CUT-08).** For the
6-month compat window (see §4) v2's compat writer reads the JSONL artefacts and
re-emits the high-value bash-shape `.txt` files under `_compat/`, with a top-level
`Recon/<domain>` symlink pointing at it:

```text
workspaces/example.com/_compat/
├── subdomains/subdomains.txt        # extracted .subdomain (sorted, unique)
├── subdomains/all.txt
├── subdomains/subdomains_alive.txt  # extracted .host from hosts.jsonl
├── webs/webs.txt                    # .url (or scheme://host)
├── webs/webs_all.txt
├── webs/url_extract.txt
├── hosts/ips.txt                    # extracted .ip
├── vulns/findings.txt               # "severity host rule_id"
├── nuclei_output/  → ../raw/nuclei/       (directory symlink)
└── screenshots/    → ../raw/screenshots/  (directory symlink)

Recon/example.com  → workspaces/example.com/_compat/   (top-level contract symlink)
```

**Two migration paths for scripts** that read `Recon/<domain>/subdomains/subdomains.txt`:

1. **Structured (recommended):** read `workspaces/<target-id>/artefacts/subdomains.jsonl`
   and extract with `jq -r '.subdomain'`.
2. **Plain-list (no rewrite):** read `workspaces/<target-id>/_compat/subdomains/all.txt`.

The compat writer is a **subset by design** — niche v1 files are intentionally not
reproduced (D-04). It never fails a scan: a missing/empty artefact is skipped with a
WARN. Migrate within the 6-month window (§4).

### 2.3 Config key renames (CUT-07)

Every v1 `KEY=value` in `reconftw.cfg` becomes a **dotted path** in `reconftw.toml`.
v2 uses a nested TOML schema (koanf) that preserves key case and validates on load.

**Before (v1 `reconftw.cfg`):**

```bash
HTTPX_RATELIMIT=150
NUCLEI_SEVERITY="info,low,medium,high,critical"
SHODAN_API_KEY=YOUR_SHODAN_KEY          # (usually in secrets.cfg)
```

**After (v2 `reconftw.toml`):**

```toml
[web.probe]
rate_limit = 150            # was HTTPX_RATELIMIT

[web.nuclei]
severity = "info,low,medium,high,critical"   # was NUCLEI_SEVERITY

[api_keys]
shodan = "YOUR_SHODAN_KEY"  # was SHODAN_API_KEY
```

> **Secrets:** the migrator writes secret **values** verbatim into your own target file,
> but **redacts them to `***`** in `--dry-run`/stderr output. Never echo a real key.

The complete rename table below is **generated from the `legacyAliasMap` in
`internal/core/config/legacy_aliases.go`** — the same table the migrator uses — and a
drift-guard test (`internal/core/config/migration_doc_test.go`,
`TestMigrationDocRenameTableCoversLegacyAliasMap`) fails CI if any rename row here falls
out of sync with the code. That guarantee is why this section cannot silently drift
(CUT-07 / XCUT-05).

There are **312** mapped v1→v2 keys. (Keys with no v2-native home are not renamed — they
are emitted as `# SUPERSEDED` comments by the migrator; see §1 and §5.)

<!-- BEGIN generated rename table (source: internal/core/config/legacy_aliases.go legacyAliasMap) -->

#### `[concurrency]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `PARALLEL_MAX_JOBS` | `concurrency.max_jobs` |
| `DNS_HEARTBEAT_INTERVAL_SECONDS` | `concurrency.heartbeat_seconds` |
| `PARALLEL_LOG_MODE` | `concurrency.log_mode` |
| `PARALLEL_TAIL_LINES` | `concurrency.tail_lines` |
| `PARALLEL_JOB_TIMEOUT_SECONDS` | `concurrency.job_timeout_seconds` |
| `PARALLEL_KILL_GRACE_SECONDS` | `concurrency.kill_grace_seconds` |

#### `[subdomains]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `SUBDOMAINS_GENERAL` | `subdomains.enabled` |
| `SUBPASSIVE` | `subdomains.passive.enabled` |
| `SUBFINDER_ENUM_TIMEOUT` | `subdomains.passive.timeout_minutes` |
| `SUBCRT` | `subdomains.crt.enabled` |
| `CTR_LIMIT` | `subdomains.crt.limit` |
| `DNS_TIME_FENCE_DAYS` | `subdomains.crt.dns_time_fence_days` |
| `SUBANALYTICS` | `subdomains.analytics.enabled` |
| `SUBBRUTE` | `subdomains.brute.enabled` |
| `SUBSCRAPING` | `subdomains.scraping.enabled` |
| `SUBPERMUTE` | `subdomains.permut.enabled` |
| `PERMUTATIONS_LIMIT` | `subdomains.permut.limit_bytes` |
| `SUBIAPERMUTE` | `subdomains.permut.ia_enabled` |
| `SUBREGEXPERMUTE` | `subdomains.permut.regex_enabled` |
| `PERMUTATIONS_WORDLIST_MODE` | `subdomains.permut.wordlist_mode` |
| `PERMUTATIONS_SHORT_THRESHOLD` | `subdomains.permut.short_threshold` |
| `SUBTAKEOVER` | `subdomains.takeover.enabled` |
| `ASN_ENUM` | `subdomains.asn.enabled` |
| `SUB_RECURSIVE_PASSIVE` | `subdomains.recursive.passive_enabled` |
| `DEEP_RECURSIVE_PASSIVE` | `subdomains.recursive.passive_depth` |
| `SUB_RECURSIVE_BRUTE` | `subdomains.recursive.brute_enabled` |
| `ZONETRANSFER` | `subdomains.zone_transfer.enabled` |
| `S3BUCKETS` | `subdomains.s3_buckets.enabled` |
| `REVERSE_IP` | `subdomains.reverse_ip.enabled` |
| `PTR_SWEEP` | `subdomains.ptr_sweep.enabled` |
| `PTR_SWEEP_MAX_IPS` | `subdomains.ptr_sweep.max_ips` |
| `SRV_ENUM` | `subdomains.srv_enum.enabled` |
| `NS_DELEGATION` | `subdomains.ns_delegation.enabled` |
| `INSCOPE` | `subdomains.scope.only_resolved` |
| `EXCLUDE_SENSITIVE` | `subdomains.scope.exclude_sensitive` |
| `DEEP_WILDCARD_FILTER` | `subdomains.scope.deep_wildcard_filter` |
| `SUBNOERROR` | `subdomains.scope.no_error_check` |
| `DNS_RESOLVER` | `subdomains.dns_resolve.resolver` |
| `DNS_BRUTE_TIMEOUT` | `subdomains.dns_resolve.brute_timeout` |
| `PUREDNS_PUBLIC_LIMIT` | `subdomains.dns_resolve.puredns_public_limit` |
| `PUREDNS_TRUSTED_LIMIT` | `subdomains.dns_resolve.puredns_trusted_limit` |
| `PUREDNS_WILDCARDTEST_LIMIT` | `subdomains.dns_resolve.puredns_wildcardtest_limit` |
| `PUREDNS_WILDCARDBATCH_LIMIT` | `subdomains.dns_resolve.puredns_wildcardbatch_limit` |
| `DNSX_THREADS` | `subdomains.dns_resolve.dnsx_threads` |
| `DNSX_RATE_LIMIT` | `subdomains.dns_resolve.dnsx_rate_limit` |
| `generate_resolvers` | `subdomains.dns_resolve.generate_resolvers` |
| `update_resolvers` | `subdomains.dns_resolve.update_resolvers` |
| `TLS_IP_PIVOTS` | `subdomains.tls_pivot.enabled` |
| `TLS_IP_SNI_BATCH_SIZE` | `subdomains.tls_pivot.sni_batch_size` |
| `TLS_IP_DELTA_PROBE` | `subdomains.tls_pivot.delta_probe` |

#### `[web]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `WEBPROBEFULL` | `web.probe.enabled` |
| `HTTPX_RATELIMIT` | `web.probe.rate_limit` |
| `HTTPX_TIMEOUT` | `web.probe.timeout_seconds` |
| `HTTPX_UNCOMMONPORTS_TIMEOUT` | `web.probe.uncommon_timeout` |
| `WEBSCREENSHOT` | `web.screenshots.enabled` |
| `VIRTUALHOSTS` | `web.virtual_hosts.enabled` |
| `FAVIRECON` | `web.favirecon.enabled` |
| `FAVIRECON_CONCURRENCY` | `web.favirecon.concurrency` |
| `FAVIRECON_TIMEOUT` | `web.favirecon.timeout` |
| `FAVIRECON_RATE_LIMIT` | `web.favirecon.rate_limit` |
| `FAVIRECON_PROXY` | `web.favirecon.proxy` |
| `WAF_DETECTION` | `web.waf.enabled` |
| `NUCLEICHECK` | `web.nuclei.enabled` |
| `NUCLEI_RATELIMIT` | `web.nuclei.rate_limit` |
| `NUCLEI_SEVERITY` | `web.nuclei.severity` |
| `NUCLEI_TEMPLATES_PATH` | `web.nuclei.templates_path` |
| `NUCLEI_EXTRA_ARGS` | `web.nuclei.extra_args` |
| `NUCLEI_DAST` | `web.nuclei_dast.enabled` |
| `NUCLEI_DAST_EXTRA_ARGS` | `web.nuclei_dast.extra_args` |
| `FUZZ` | `web.fuzz.enabled` |
| `FFUF_RATELIMIT` | `web.fuzz.rate_limit` |
| `FFUF_MAXTIME` | `web.fuzz.max_time_seconds` |
| `FUZZ_RECURSION_DEPTH` | `web.fuzz.recursion_depth` |
| `IIS_SHORTNAME` | `web.iis_shortname.enabled` |
| `CMS_SCANNER` | `web.cms.enabled` |
| `JSCHECKS` | `web.js.enabled` |
| `JS_SUB_EXTRACT` | `web.js.sub_extract` |
| `GETJSWORDS_PYTHON` | `web.js.getjswords_python` |
| `URL_CHECK` | `web.urls.enabled` |
| `URL_CHECK_PASSIVE` | `web.urls.passive_enabled` |
| `URL_CHECK_ACTIVE` | `web.urls.active_enabled` |
| `WAYMORE_TIMEOUT` | `web.urls.waymore_timeout` |
| `WAYMORE_LIMIT` | `web.urls.waymore_limit` |
| `URL_GF` | `web.urls.gf_patterns` |
| `URL_EXT` | `web.urls.ext_classify` |
| `WELLKNOWN_PIVOTS` | `web.wellknown.enabled` |
| `WELLKNOWN_MAX_TARGETS` | `web.wellknown.max_targets` |
| `WORDLIST` | `web.wordlist.enabled` |
| `ROBOTSWORDLIST` | `web.wordlist.robots_enabled` |
| `PASSWORD_DICT` | `web.wordlist.password_dict` |
| `PASSWORD_DICT_ENGINE` | `web.wordlist.password_engine` |
| `PASSWORD_DICT_MAX_TARGETS` | `web.wordlist.password_max_targets` |
| `PASSWORD_DICT_CEWLER_DEPTH` | `web.wordlist.password_depth` |
| `PASSWORD_DICT_CEWLER_TIMEOUT` | `web.wordlist.password_timeout` |
| `PASSWORD_MIN_LENGTH` | `web.wordlist.password_min_len` |
| `PASSWORD_MAX_LENGTH` | `web.wordlist.password_max_len` |
| `PORTSCANNER` | `web.portscan.enabled` |
| `PORTSCAN_PASSIVE` | `web.portscan.passive_enabled` |
| `PORTSCAN_ACTIVE` | `web.portscan.active_enabled` |
| `PORTSCAN_STRATEGY` | `web.portscan.strategy` |
| `PORTSCAN_UDP` | `web.portscan.udp_enabled` |
| `GEO_INFO` | `web.portscan.geo_info` |
| `CDN_IP` | `web.portscan.cdn_check` |
| `CDN_BYPASS` | `web.portscan.cdn_bypass` |
| `NAABU_ENABLE` | `web.portscan.naabu.enabled` |
| `NAABU_RATE` | `web.portscan.naabu.rate` |
| `NAABU_PORTS` | `web.portscan.naabu.ports` |
| `SERVICE_FINGERPRINT` | `web.portscan.service_fingerprint.enabled` |
| `SERVICE_FINGERPRINT_ENGINE` | `web.portscan.service_fingerprint.engine` |
| `SERVICE_FINGERPRINT_TIMEOUT_MS` | `web.portscan.service_fingerprint.timeout_ms` |
| `GRAPHQL_CHECK` | `web.graphql.enabled` |
| `GQLSPECTION` | `web.graphql.deep_introspect` |
| `PARAM_DISCOVERY` | `web.param_discovery.enabled` |
| `GRPC_SCAN` | `web.grpc.enabled` |
| `LLM_PROBE` | `web.llm_probe.enabled` |
| `LLM_PROBE_AUGUSTUS` | `web.llm_probe.augustus` |
| `CLOUD_ENUM_S3_PROFILE` | `web.cloud_enum.s3_profile` |
| `CLOUD_ENUM_S3_THREADS` | `web.cloud_enum.s3_threads` |
| `KATANA_HEADLESS_PROFILE` | `web.katana.headless_profile` |
| `KATANA_HEADLESS_SMART_LIMIT` | `web.katana.headless_smart_limit` |

#### `[vulns]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `VULNS_GENERAL` | `vulns.enabled` |
| `XSS` | `vulns.xss.enabled` |
| `SQLI` | `vulns.sqli.enabled` |
| `SQLMAP` | `vulns.sqli.sqlmap` |
| `GHAURI` | `vulns.sqli.ghauri` |
| `SSRF_CHECKS` | `vulns.ssrf.enabled` |
| `SSRF_ALT_MATCH_REGEX` | `vulns.ssrf.alt_match_regex` |
| `LFI` | `vulns.lfi.enabled` |
| `LFI_MAX_URLS` | `vulns.lfi.max_urls` |
| `SSTI` | `vulns.ssti.enabled` |
| `SSTI_ENGINE` | `vulns.ssti.engine` |
| `CRLF_CHECKS` | `vulns.crlf.enabled` |
| `SMUGGLING` | `vulns.smuggling.enabled` |
| `COMM_INJ` | `vulns.cmdi.enabled` |
| `WEBCACHE` | `vulns.cache.enabled` |
| `WEBCACHE_TOXICACHE` | `vulns.cache.toxicache` |
| `BYPASSER4XX` | `vulns.bypass_4xx.enabled` |
| `FUZZPARAMS` | `vulns.fuzz_params.enabled` |
| `NUCLEI_DAST_TEMPLATE_PATH` | `vulns.nuclei_dast.templates_path` |
| `SPRAY` | `vulns.spray.enabled` |
| `SPRAY_ENGINE` | `vulns.spray.engine` |
| `SPRAY_BRUTUS_ONLY_DEEP` | `vulns.spray.deep_only` |
| `BROKENLINKS` | `vulns.broken_links.enabled` |
| `BROKENLINKS_ENGINE` | `vulns.broken_links.engine` |
| `TEST_SSL` | `vulns.ssl.enabled` |
| `METADATA` | `vulns.metadata.enabled` |
| `FRAY_EXTRA` | `vulns.fray.enabled` |
| `FRAY_CATEGORIES` | `vulns.fray.categories` |
| `FRAY_MAX_PAYLOADS` | `vulns.fray.max_payloads` |
| `FRAY_TIMEOUT` | `vulns.fray.timeout` |
| `FRAY_DELAY` | `vulns.fray.delay` |

#### `[osint]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `OSINT` | `osint.enabled` |
| `GOOGLE_DORKS` | `osint.google_dorks.enabled` |
| `GITHUB_DORKS` | `osint.github.enabled` |
| `GITHUB_REPOS` | `osint.github.enabled` | _(collision: OR-combined with GITHUB_DORKS)_
| `GITHUB_LEAKS` | `osint.github.leaks_enabled` |
| `GHLEAKS_THREADS` | `osint.github.threads` |
| `SECRETS_ENGINE` | `osint.github.secrets_engine` |
| `SECRETS_SCAN_GIT_HISTORY` | `osint.github.scan_git_history` |
| `SECRETS_VALIDATE` | `osint.github.validate_secrets` |
| `GITHUB_ACTIONS_AUDIT` | `osint.github.actions_audit.enabled` |
| `GATO_INCLUDE_ALL_ARTIFACT_SECRETS` | `osint.github.actions_audit.include_all_artifact_secrets` |
| `CLOUD_ENUM` | `osint.cloud.enabled` |
| `EMAILS` | `osint.emails.enabled` |
| `API_LEAKS_POSTLEAKS` | `osint.postman.enabled` |
| `POSTLEAKS_THREADS` | `osint.postman.threads` |
| `POSTLEAKS_INCLUDE` | `osint.postman.include` |
| `POSTLEAKS_EXCLUDE` | `osint.postman.exclude` |
| `API_LEAKS` | `osint.api_leaks.enabled` |
| `THIRD_PARTIES` | `osint.swagger.enabled` |
| `SPOOF` | `osint.spoofy.enabled` |
| `MAIL_HYGIENE` | `osint.mail_hygiene.enabled` |
| `DOMAIN_INFO` | `osint.domain_info.enabled` |
| `IP_INFO` | `osint.ip_info.enabled` |
| `IPV6_SCAN` | `osint.ipv6.enabled` |

#### `[notifications]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `NOTIFICATION` | `notifications.enabled` |
| `SOFT_NOTIFICATION` | `notifications.soft_enabled` |
| `slack_channel` | `notifications.slack.channel` |
| `slack_auth` | `notifications.slack.webhook_url` |

#### `[axiom]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `AXIOM_FLEET_NAME` | `axiom.fleet_name` |
| `AXIOM_FLEET_COUNT` | `axiom.fleet_count` |
| `AXIOM_FLEET_REGIONS` | `axiom.fleet_regions` |
| `AXIOM_FLEET_SHUTDOWN` | `axiom.shutdown_on_end` |
| `AXIOM_AUTO_FIX_HOSTKEY` | `axiom.auto_fix_hostkey` |
| `AXIOM_FLEET_LAUNCH` | `axiom.fleet_launch` |
| `AXIOM_EXTRA_ARGS` | `axiom.extra_args` |

#### `[output]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `OUTPUT_VERBOSITY` | `output.verbosity` |
| `EXPORT_FORMAT` | `output.export_format` |
| `ASSET_STORE` | `output.asset_store` |
| `REPORT_ONLY` | `output.report_only` |
| `HOTLIST_TOP` | `output.hotlist_top` |
| `CHUNK_LIMIT` | `output.chunk_limit` |
| `REMOVETMP` | `output.remove_tmp` |
| `REMOVELOG` | `output.remove_log` |
| `PRESERVE` | `output.preserve_called_fn` |
| `SENDZIPNOTIFY` | `output.send_zip_notify` |
| `STRUCTURED_LOGGING` | `output.structured_logging` |
| `MIN_DISK_SPACE_GB` | `output.min_disk_space_gb` |
| `MAX_LOG_FILES` | `output.log_rotation.max_files` |
| `MAX_LOG_AGE_DAYS` | `output.log_rotation.max_age_days` |

#### `[ai]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `AI_EXECUTABLE` | `ai.executable` |
| `AI_MODEL` | `ai.model` |
| `AI_REPORT_TYPE` | `ai.report_type` |
| `AI_REPORT_PROFILE` | `ai.report_profile` |
| `AI_PROMPTS_FILE` | `ai.prompts_file` |
| `AI_MAX_CHARS_PER_FILE` | `ai.max_chars_per_file` |
| `AI_MAX_FILES_PER_CATEGORY` | `ai.max_files_per_category` |
| `AI_REDACT` | `ai.redact` |
| `AI_ALLOW_MODEL_PULL` | `ai.allow_model_pull` |
| `AI_STRICT` | `ai.strict` |

#### `[integrations]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `FARADAY` | `integrations.faraday.enabled` |
| `FARADAY_WORKSPACE` | `integrations.faraday.workspace` |
| `PROXY` | `integrations.proxy.enabled` |
| `proxy_url` | `integrations.proxy.url` |

#### `[incremental / monitor]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `INCREMENTAL_MODE` | `incremental.enabled` |
| `MONITOR_MODE` | `monitor.enabled` |
| `MONITOR_INTERVAL_MIN` | `monitor.interval_minutes` |
| `MONITOR_MAX_CYCLES` | `monitor.max_cycles` |
| `MONITOR_MIN_SEVERITY` | `monitor.min_severity` |
| `ALERT_SUPPRESSION` | `monitor.alert_suppression` |

#### `[adaptive_rate]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `ADAPTIVE_RATE_LIMIT` | `adaptive_rate.enabled` |
| `MIN_RATE_LIMIT` | `adaptive_rate.min_rate` |
| `MAX_RATE_LIMIT` | `adaptive_rate.max_rate` |
| `RATE_LIMIT_BACKOFF_FACTOR` | `adaptive_rate.backoff_factor` |
| `RATE_LIMIT_INCREASE_FACTOR` | `adaptive_rate.increase_factor` |

#### `[cache]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `CACHE_MAX_AGE_DAYS` | `cache.max_age_days` |
| `CACHE_MAX_AGE_DAYS_RESOLVERS` | `cache.max_age_days_resolvers` |
| `CACHE_MAX_AGE_DAYS_WORDLISTS` | `cache.max_age_days_wordlists` |
| `CACHE_MAX_AGE_DAYS_TOOLS` | `cache.max_age_days_tools` |
| `CACHE_REFRESH` | `cache.refresh` |

#### `[paths]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `DATA_DIR` | `paths.data_dir` |
| `WORDLISTS_DIR` | `paths.wordlists_dir` |
| `PATTERNS_DIR` | `paths.patterns_dir` |
| `fuzz_wordlist` | `paths.fuzz_wordlist` |
| `lfi_wordlist` | `paths.lfi_wordlist` |
| `ssti_wordlist` | `paths.ssti_wordlist` |
| `subs_wordlist` | `paths.subs_wordlist` |
| `subs_wordlist_big` | `paths.subs_wordlist_big` |
| `headers_inject` | `paths.headers_inject` |
| `resolvers` | `paths.resolvers` |
| `resolvers_trusted` | `paths.resolvers_trusted` |
| `GITHUB_TOKENS` | `paths.github_tokens` |
| `GITLAB_TOKENS` | `paths.gitlab_tokens` |
| `resolvers_url` | `paths.resolvers_download.url` |
| `resolvers_trusted_url` | `paths.resolvers_download.trusted_url` |
| `RESOLVER_DOWNLOAD_CONNECT_TIMEOUT` | `paths.resolvers_download.connect_timeout` |
| `RESOLVER_DOWNLOAD_MAX_TIME` | `paths.resolvers_download.max_time` |
| `RESOLVER_DOWNLOAD_RETRY` | `paths.resolvers_download.retry` |
| `RESOLVER_DOWNLOAD_RETRY_DELAY` | `paths.resolvers_download.retry_delay` |

#### `[api_keys]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `SHODAN_API_KEY` | `api_keys.shodan` |
| `WHOISXML_API` | `api_keys.whoisxml` |
| `PDCP_API_KEY` | `api_keys.pdcp` |
| `XSS_SERVER` | `api_keys.xss_server` |
| `COLLAB_SERVER` | `api_keys.collab_server` |

#### `[advanced]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `DEEP` | `advanced.deep` |
| `DEEP_LIMIT` | `advanced.deep_limit` |
| `DEEP_LIMIT2` | `advanced.deep_limit2` |
| `DIFF` | `advanced.diff` |
| `QUICK_RESCAN` | `advanced.quick_rescan` |
| `SHOW_COMMANDS` | `advanced.show_commands` |
| `install_golang` | `advanced.install_golang` |
| `upgrade_tools` | `advanced.upgrade_tools` |
| `upgrade_before_running` | `advanced.upgrade_before_running` |
| `HEADER` | `advanced.header` |
| `PERF_PROFILE` | `advanced.perf_profile` |

#### `[advanced.tools]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `FFUF_FLAGS` | `advanced.tools.ffuf.flags` |
| `GOTATOR_FLAGS` | `advanced.tools.gotator.flags` |
| `TLSX_THREADS` | `advanced.tools.tlsx.threads` |
| `XNLINKFINDER_DEPTH` | `advanced.tools.xnlinkfinder.depth` |
| `DNSVALIDATOR_THREADS` | `advanced.tools.dnsvalidator.threads` |
| `INTERLACE_THREADS` | `advanced.tools.interlace.threads` |
| `TInjA_RATELIMIT` | `advanced.tools.tinja.rate_limit` |
| `TInjA_TIMEOUT` | `advanced.tools.tinja.timeout` |
| `SSTIMAP_LEVEL` | `advanced.tools.sstimap.level` |
| `SSTIMAP_DELAY` | `advanced.tools.sstimap.delay` |
| `SSTIMAP_LEGACY` | `advanced.tools.sstimap.legacy` |
| `SSTIMAP_GENERIC` | `advanced.tools.sstimap.generic` |
| `SECOND_ORDER_CONFIG` | `advanced.tools.second_order.config` |
| `SECOND_ORDER_DEPTH` | `advanced.tools.second_order.depth` |
| `SECOND_ORDER_THREADS` | `advanced.tools.second_order.threads` |
| `SECOND_ORDER_INSECURE` | `advanced.tools.second_order.insecure` |
| `TOXICACHE_THREADS` | `advanced.tools.toxicache.threads` |
| `TOXICACHE_USER_AGENT` | `advanced.tools.toxicache.user_agent` |
| `BRUTUS_USERNAMES` | `advanced.tools.brutus.usernames` |
| `BRUTUS_PASSWORDS` | `advanced.tools.brutus.passwords` |
| `BRUTUS_KEY_FILE` | `advanced.tools.brutus.key_file` |
| `AXIOM_RESOLVERS_PATH` | `advanced.tools.axiom.resolvers_path` |
| `AXIOM_RESOLVERS_TRUSTED_PATH` | `advanced.tools.axiom.resolvers_trusted_path` |

#### `[advanced.timing_estimates]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `TIME_EST_NUCLEI` | `advanced.timing_estimates.nuclei` |
| `TIME_EST_FUZZ` | `advanced.timing_estimates.fuzz` |
| `TIME_EST_URLCHECKS` | `advanced.timing_estimates.urlchecks` |
| `TIME_EST_JSCHECKS` | `advanced.timing_estimates.jschecks` |
| `TIME_EST_API` | `advanced.timing_estimates.api` |
| `TIME_EST_GQL` | `advanced.timing_estimates.gql` |
| `TIME_EST_PARAM` | `advanced.timing_estimates.param` |
| `TIME_EST_GRPC` | `advanced.timing_estimates.grpc` |
| `TIME_EST_IIS` | `advanced.timing_estimates.iis` |

#### `[advanced.parallel_batch_sizes]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `PAR_OSINT_GROUP1_SIZE` | `advanced.parallel_batch_sizes.osint_group1` |
| `PAR_OSINT_GROUP2_SIZE` | `advanced.parallel_batch_sizes.osint_group2` |
| `PAR_SUB_PASSIVE_GROUP_SIZE` | `advanced.parallel_batch_sizes.sub_passive` |
| `PAR_SUB_DEP_ACTIVE_GROUP_SIZE` | `advanced.parallel_batch_sizes.sub_dep_active` |
| `PAR_SUB_POST_ACTIVE_GROUP_SIZE` | `advanced.parallel_batch_sizes.sub_post_active` |
| `PAR_SUB_BRUTE_GROUP_SIZE` | `advanced.parallel_batch_sizes.sub_brute` |
| `PAR_WEB_DETECT_GROUP_SIZE` | `advanced.parallel_batch_sizes.web_detect` |
| `PAR_VULNS_GROUP1_SIZE` | `advanced.parallel_batch_sizes.vulns_group1` |
| `PAR_VULNS_GROUP2_SIZE` | `advanced.parallel_batch_sizes.vulns_group2` |
| `PAR_VULNS_GROUP4_SIZE` | `advanced.parallel_batch_sizes.vulns_group4` |

#### `[advanced.parallel_ui]`

| v1 `reconftw.cfg` key | v2 TOML path |
|---|---|
| `PARALLEL_UI_MODE` | `advanced.parallel_ui.mode` |
| `PARALLEL_PROGRESS_SHOW_ETA` | `advanced.parallel_ui.show_eta` |
| `PARALLEL_PROGRESS_SHOW_ACTIVE` | `advanced.parallel_ui.show_active` |
| `PARALLEL_PROGRESS_COMPACT_ACTIVE_MAX` | `advanced.parallel_ui.compact_active_max` |
| `PARALLEL_TRACE_SLOW_SECONDS` | `advanced.parallel_ui.trace_slow_seconds` |

<!-- END generated rename table -->

### 2.4 Default-behavior changes (CUT-07)

**The vast majority of v1 defaults are preserved 1:1** so a default v2 scan behaves like a
default v1 scan (`vulns.enabled = false`, `web.portscan.strategy = "legacy"`,
`vulns.xss.enabled = true`, `vulns.sqli.sqlmap = true`, `vulns.sqli.ghauri = false`,
`vulns.lfi.max_urls = 150`, `output.verbosity = 1`, `subdomains.permut.limit_bytes =
2147483648`, `web.virtual_hosts.enabled = false`, `web.wellknown.enabled = false`,
`concurrency.max_jobs = 4`, …). The genuine behavior changes are:

| # | Area | Before (v1 `reconftw.cfg`) | After (v2 `defaults.go`) | Why |
|---|---|---|---|---|
| 1 | **Thread counts auto-scale** | Concrete numbers computed from CPU at config-source time, e.g. `AVAILABLE_CORES=$(nproc …)` then `FFUF_THREADS=$((AVAILABLE_CORES * 10))`, `HTTPX_THREADS`, `KATANA_THREADS`, … | The `*.threads` fields default to **`0` = auto**; v2 derives the value from `runtime.NumCPU()` at run time. The migrator therefore emits the old computed numbers as `# SUPERSEDED` comments (with a `# to pin, set web.fuzz.threads = <N>` hint), not live keys. | v2 owns concurrency via the scheduler; pinning a stale host's CPU math would fight auto-scale. |
| 2 | **Dalfox/XSS threads capped** | `dalfox` threads = `AVAILABLE_CORES * 15` | `vulns.xss.threads = 5` (fixed) | WAF-friendly default (ADR D-V6) — fewer parallel XSS probes. |
| 3 | **Fray payloads capped** | n/a (fray tuned per-run) | `vulns.fray.max_payloads = 20`, `vulns.fray.delay = 0.5` | WAF-friendly modern-payload defaults (ADR D-V6). |
| 4 | **Portscan strategy coupling** | Raw nmap option strings (`PORTSCAN_ACTIVE_OPTIONS`, `PORTSCAN_DEEP_OPTIONS`, …) drove nmap directly | `web.portscan.strategy = "legacy"` (full nmap, bash parity). `web.portscan.naabu.enabled = true` is **latent** — naabu only runs under `strategy = "naabu_nmap"`. | No behavior change vs bash, but the naabu block is inert by default. Documented coupling — see the IN-02 note in §5.2. |
| 5 | **Zen mode is stealth** | `zen` menu tweaked several knobs | `reconftw zen` sets `web.portscan.active_enabled = false` (and UDP stays off) | No active/UDP port scanning under zen — an OPSEC guarantee. |

Raw nmap option strings, computed thread counts, and bash bootstrap globals have **no v2
key** and are emitted as `# SUPERSEDED` comments by the migrator (they are listed in
`supersededKeys` in `internal/core/config/legacy_aliases.go`). They are preserved in your
migrated file for reference but do not change v2 behavior.

---

## 3. Rollback — reverting v2 → v1 (CUT-15)

If v2 hits a critical issue in production, revert to the v1 bash engine via the frozen
legacy branch. Your existing `Recon/<domain>/` data is untouched.

```console
# 1. Fetch and check out the frozen v1 bash branch.
#    Post-cutover this is `archive/v1.x`; pre-cutover, use the pinned tag (e.g. v4.1)
#    or `main` before the swap.
git fetch origin
git checkout archive/v1.x        # or: git checkout v4.1

# 2. (If you use secrets.cfg) it is unchanged — v1 sources it as before.

# 3. Run v1 exactly as you did before the upgrade.
./reconftw.sh -d example.com -r
```

**Your v1 output keeps resolving.** During the 6-month compat window (see §4) v2 also
populated the bash-shape `Recon/<domain>/` tree via the compat writer, so scripts that
read those paths continue to work whether you are on v1 or v2. If you already migrated
scripts to the JSONL artefacts, note that v1 does **not** produce `artefacts/*.jsonl` —
keep a copy of the last v2 `workspaces/<target-id>/` if you need that data after rolling
back.

> **Scope note (authoritative per `.planning/REQUIREMENTS.md`):** **CUT-15 is this
> rollback procedure** ("users can revert to v1 via a documented procedure"). The
> irreversible **branch swap** itself — flipping `main` to Go, moving bash to
> `archive/v1.x`, and the `complete-milestone` ceremony — is a manual release action
> (see §6.4). An earlier SPEC draft mislabeled that branch swap "CUT-15"; the
> REQUIREMENTS.md definition (rollback docs) governs and is what this section delivers.

---

## 4. Deprecation timeline (two distinct clocks) (CUT-14)

Two independent clocks govern the v1→v2 transition. **They are NOT the same duration —
do not conflate them.**

**Clock A — Compat output window: 6-month.** (ADR §4.5) For **6 months** after v2.0 GA,
the compat writer keeps `Recon/<domain>/` populated on every scan (§2.2), with no
deprecation warnings. After the 6-month mark the top-level `Recon/<domain>` symlink stops
being created, `_compat/` persists for one further minor version, then the compat writer
is removed. Migrate scripts to the JSONL artefacts (or the `_compat/*.txt` plain lists)
within this window.

**Clock B — v1 bash branch freeze: 12-month.** (CUT-14) At cutover, bash `main` becomes
**`archive/v1.x`**, **frozen for 12 months**. During that freeze the v1 branch receives
**security-critical bugfixes only** — no features, no tool bumps. This is the window in
which the §3 rollback remains supported. After 12 months the v1 branch is archived
read-only.

**Related, also distinct — CLI-flag/`[legacy]` removal: version-based, not calendar.**
(ADR §8.4) The deprecated v1 short flags (§2.1) and the runtime `[legacy]` TOML alias
table remain functional through v2.1.x and are **removed in v2.2.0** — measured in
release count (two minor bumps after v2.0.0), not months.

| Clock | Duration | What it governs | Source |
|---|---|---|---|
| A — compat output window | **6 months** | `Recon/<domain>/` compat tree stays populated | ADR §4.5 |
| B — v1 branch freeze | **12 months** | `archive/v1.x` gets security-only fixes; rollback supported | CUT-14 |
| (related) CLI/`[legacy]` removal | v2.2.0 (release-based) | deprecated short flags + `[legacy]` table removed | ADR §8.4 |

---

## 5. Consolidated deferral ledger (D-06)

Phases 1–13 delivered **≥95% per-domain parity** on the default `recon`/`all` path
(`13-PARITY-AUDIT.md`). A small set of niche, default-off, or intentional-divergence
capabilities were deliberately **not** ported to v2. This is the single, complete ledger
of them. **Every deferred capability remains available on the frozen bash legacy branch**
(§3/§4), so default recon parity is unaffected — nothing here is a silent drop.

### 5.1 Phase-13 parity-audit deferrals (8 items)

Folded verbatim from `13-PARITY-AUDIT.md` §3, each with its rationale:

| # | Capability | Domain | Default state | Rationale |
|---|---|---|---|---|
| 1 | **PTR** full ASN→CIDR sweep (`sub_ptr_cidrs`) | subs | default-off (`PTR_SWEEP=false`) | Niche; `hakip2host` covers the default-path reverse-IP lookup. The dead `SubPTRTask` scaffold was removed in 13-01. Opt-in only. |
| 2 | `deep_wildcard_filter` (**wildcard** deep-filter) | subs | config-only flag | Puredns `--wildcard-tests` covers the baseline wildcard filtering; the deep variant is niche. |
| 3 | `ip.**thc**.org` secondary reverse-DNS source (`sub_dns`) | subs | secondary source | A secondary/niche reverse-IP source; the primary reverse-IP path is implemented. |
| 4 | **metadata** active-discovery (exifray + urlfinder) | osint | intentional divergence (D-O2) | v2 keeps exiftool-over-existing-docs; bash's active exifray+urlfinder document discovery+download is an opportunistic divergence, deferred by design. |
| 5 | `mail_hygiene` dedicated file | osint | niche sub-report | The core email-spoofing posture is covered by `osint.spoofy`; the standalone `mail_hygiene.txt` report is niche. |
| 6 | `apileaks` trufflehog enrichment | osint | niche enrichment | Core postman/swagger leak detection **is** implemented; only the trufflehog enrichment pass is deferred. |
| 7 | `pydictor` leet wordlists | web | niche fuzz augmentation | A "deferred idea" that only augments fuzzing wordlists; `roboxtractor` + `getjswords` + `cewler` cover wordlist generation. |
| 8 | `noseyparker` secrets engine | osint | non-default engine | Absent from `install.sh` (unverifiable module path); `osint.github.secrets_engine` defaults to `"hybrid"` and every value except `"noseyparker"` runs the titus (default) + trufflehog pair, which covers the path (13-01/13-06). |

### 5.2 Code-review deferrals (13-REVIEW / 13-REVIEW-FIX)

**WR-02 — interactsh out-of-band (OOB) callback harvesting (`vulns.ssrf`).**
13-07 landed a **bounded** interactsh auto-start (the SSRF task starts and stops
`interactsh-client` under a `WithTimeout` + `interactshStartupTimeout` guard, closing
the earlier DoD-2 unbounded-hang regression). **Residual deferral:** the restored OOB
path does not yet **read** interactsh callbacks back into `VulnFindingRecord`s — genuine
OOB SSRF hits are not captured as findings; the OOB feature is currently decorative. A
fully-bounded, safe OOB-**harvesting** implementation (keep the stdout reader alive past
domain parse, ingest late callbacks) is tracked as a Phase-14 follow-up. Nuclei-based and
regex-match SSRF detection are unaffected and fully implemented.

**IN-02 — naabu default-strategy coupling (`web.portscan`).** `web.portscan.strategy`
defaults to **`"legacy"`** (a plain full nmap over every non-CDN IP — the bash-parity
default). The naabu→nmap targeted path (`portscan.go`) is gated on
`strategy == "naabu_nmap" && naabu.enabled`, so the fully-populated
`web.portscan.naabu.*` block is **latent** under the default strategy — naabu never runs
unless you set `strategy = "naabu_nmap"`. **This is a documented coupling, NOT a default
change:** the value was deliberately left at `"legacy"` (defaults.go, commit `c5567d4`);
flipping it to `"naabu_nmap"` changes every scan and is a deliberate product decision, not
made here.

### 5.3 Niche "deferred ideas" (13-CONTEXT)

The 13-CONTEXT "Deferred Ideas" list — `deep_wildcard_filter`, `pydictor` leet wordlists,
`mail_hygiene` dedicated file, `apileaks` trufflehog enrichment, and `metadata`
active-discovery — is **already folded into §5.1** (items 2, 7, 5, 6, and 4 respectively).
No additional niche capability is outstanding beyond those enumerated above; §5 is the
complete post-cutover ledger for all four domains.

---

## 6. Documented as deferred — manual / out of this phase

The following are **release and community-gated process steps**, not cutover-blocking
code. **This phase does NOT execute them** — it does NOT run a beta, does NOT perform the
`main`→v2 branch swap, and does NOT rewrite the README. For each item the **in-phase
deliverable IS this documentation**; **execution is manual and happens post-phase**, on
the maintainer's own timeline.

### 6.1 Beta period + `v2-beta` binary (CUT-09)

- **Deferred (manual, out of phase):** distribute a `reconftw v2-beta` binary for a
  ~1–2 month beta **prior** to cutover; existing users opt in.
- **Deliverable here:** this note. **Execution:** manual, post-phase (calendar-gated).

### 6.2 Beta feedback template + triage (CUT-10)

- **Deferred (manual, out of phase):** a GitHub Issues template `v2-beta-feedback` plus a
  monthly issue-triage cadence with the community during the beta window.
- **Deliverable here:** this note. **Execution:** manual, post-phase.

### 6.3 Community sign-off criteria (CUT-12)

- **Deferred (manual, out of phase):** cutover sign-off requires **(a)** the migrator
  corpus passing (CUT-03), **(b)** the parity harness green (CUT-11), **(c)** the beta
  period clean of P0/P1 issues, and **(d)** a user-community survey / GitHub Discussions
  thread reaching a sign-off threshold. This is a human-judgment gate that cannot be
  automated.
- **Deliverable here:** the criteria above. **Execution:** manual, post-phase.

### 6.4 Cutover-gate policy + the branch swap (CUT-04)

- **Cutover-gate policy (CUT-04):** the cutover is **BLOCKED** until the migrator corpus
  (CUT-03), the parity harness (CUT-11), and the §6.3 sign-off criteria are all met;
  milestone v2.0 cannot ship until then.
- **The branch swap is out of scope (manual, out of phase):** the irreversible release
  action — flipping `main` to Go, moving bash to `archive/v1.x`, the `complete-milestone`
  ceremony, and the post-cutover PROJECT.md/STATE.md updates — is gated on beta feedback
  and is **not performed by this phase**. (As noted in §3, an earlier SPEC draft
  mislabeled this branch swap "CUT-15"; the authoritative CUT-15 is the rollback doc.)
- **Deliverable here:** the gate policy + scope note. **Execution:** manual, post-phase.

### 6.5 Release communications (CUT-13)

- **Deferred (manual, out of phase):** the cutover announcement — README rewrite, GitHub
  release notes, and social announcement on the project's user comms channels.
- **Deliverable here:** this note. **Execution:** manual, post-phase (overlaps §6.6).

### 6.6 Documentation rewrites (XCUT-06)

- **Deferred (manual, out of phase):** auto-generated godoc/API docs, a README rewritten
  with v2 examples + quickstart, an updated `INSTALL.md`, and a `CONTRIBUTING.md` for new
  contributors. This is release marketing/docs, not cutover-blocking code.
- **Deliverable here:** this note. **Execution:** manual, post-phase.

---

## 7. Zero silent breakages attestation (XCUT-05)

**MIGRATION.md is the zero-silent-breakages record for the bash→Go cutover.** Every
behavior change discoverable in the codebase is documented here with a before/after:
CLI flags (§2.1), the output tree (§2.2), the 312 config-key renames (§2.3, drift-guarded
against `legacyAliasMap`), and default-behavior changes (§2.4). Every intentionally
deferred capability is enumerated with a rationale in the consolidated ledger (§5), and
every manual/community-gated release step is documented-as-deferred (§6). There are **no
silent breakages**: a config rename cannot ship without appearing in §2.3 (enforced by
`TestMigrationDocRenameTableCoversLegacyAliasMap`), and no capability is dropped without a
ledger entry. This attestation satisfies XCUT-05; it cross-references the before/after
evidence authored in §2.
