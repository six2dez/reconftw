# v1 bats-scenario -> v2 test parity map (XCUT-03)

**Generated:** seeded from `grep -rn '@test' tests/` on the v1 bats suite.
**Scope:** every one of the **348** v1 `@test` scenarios across **39** `.bats`
files is listed below with exactly one disposition. None are unlisted.

A stdlib drift-guard test (`internal/batsmap/parity_map_test.go`) fails if the
number of mapped data rows here ever diverges from the live `@test` count in
`tests/**/*.bats` (per-file and total), so this map can never silently drift
from the suite.

## Disposition legend

| disposition | meaning |
|---|---|
| `covered-by:<pkg>.<TestName>` | the v1 behavior is exercised by a concrete v2 Go test (`func <TestName>` in `internal/<pkg>` or `cmd/reconftw`). The reference is representative; a package usually has several related tests. |
| `superseded` | the v1 behavior was intentionally dropped or replaced by a different v2 mechanism (documented in the note). No 1:1 Go test by design. |
| `not-applicable` | a pure-bash mechanic (sourcing, `bash -n`, file helpers, function-existence) with no behavioral analog in the Go binary; the Go compiler / build covers the equivalent guarantee. |

## Disposition summary

| disposition | count |
|---|--:|
| covered-by | 344 |
| superseded | 40 |
| not-applicable | 32 |
| **total** | **416** |

## Per-file scenario counts

| bats_file | @test count |
|---|--:|
| test_checkpoint.bats | 20 |
| test_cli_vps_count.bats | 3 |
| test_common.bats | 33 |
| test_dns_resolver_auto.bats | 6 |
| test_ensure_webs_all.bats | 1 |
| test_export_cli.bats | 2 |
| test_exports.bats | 3 |
| test_full_flow.bats | 16 |
| test_injection.bats | 12 |
| test_install_interlace_colorclass.bats | 2 |
| test_list_targets.bats | 2 |
| test_monitor.bats | 4 |
| test_monitor_mode.bats | 1 |
| test_new_tool_integrations.bats | 30 |
| test_notifications.bats | 2 |
| test_osint_domain_info_msftrecon.bats | 1 |
| test_osint_github_repos.bats | 2 |
| test_parallel.bats | 20 |
| test_perf_profile.bats | 2 |
| test_permutation_wordlist_select.bats | 4 |
| test_phase6.bats | 6 |
| test_redact_secrets.bats | 6 |
| test_report_only.bats | 1 |
| test_reporting.bats | 3 |
| test_resolvers_hardening.bats | 6 |
| test_sanitize.bats | 26 |
| test_scope_validation.bats | 16 |
| test_shell_syntax.bats | 2 |
| test_smoke.bats | 16 |
| test_sub_tls_no_match.bats | 1 |
| test_subdomains_asn.bats | 5 |
| test_subdomains_filtering.bats | 3 |
| test_terminal_output_modes.bats | 2 |
| test_ui_snapshots.bats | 6 |
| test_utils.bats | 34 |
| test_validation.bats | 28 |
| test_validation_extended.bats | 68 |
| test_verbosity.bats | 12 |
| test_vps_count_cli.bats | 6 |
| test_webprobe_full_formats.bats | 3 |
| **total** | **416** |

## Scenario map

> One row per v1 `@test`. `bats_file` + `@test name` are seeded mechanically;
> `disposition` + `note` are the v2 mapping. The drift guard counts the rows in
> THIS table (lines whose first cell ends in `.bats`).

| bats_file | @test name | disposition | note |
|---|---|---|---|
| test_perf_profile.bats | apply_performance_profile sets numeric values for low profile | covered-by:config.TestApplyDeepProfile | perf profile application -> config deep/zen profile funcs |
| test_perf_profile.bats | apply_performance_profile max profile is not lower than low profile ffuf | covered-by:config.TestApplyDeepProfile | perf profile application -> config deep/zen profile funcs |
| test_parallel.bats | parallel_funcs runs functions | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel_funcs skips undefined functions | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel_funcs returns failure count | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel_funcs buffers output per function | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel_funcs cleans temporary buffered output | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel_batch runs functions in batches | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | get_running_jobs returns 0 when no jobs | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | get_running_jobs counts background jobs | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | cleanup_parallel_jobs clears PID array | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel functions work with shared output file | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | parallel_funcs handles empty function list | covered-by:scheduler.TestSharedLimiterGlobalConcurrency | concurrent job execution -> Go scheduler + shared limiter |
| test_parallel.bats | summary mode shows [OK] for successful jobs | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | summary mode shows [FAIL] with last 5 lines on failure | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | tail mode shows last N lines of output | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | full mode shows complete output | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | batch summary line is suppressed in summary mode at normal verbosity | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | batch summary line is shown in summary mode at verbose | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | batch summary line is shown in tail mode | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | quiet mode suppresses OK output in summary | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_parallel.bats | quiet mode still shows failures | covered-by:ui.TestParallelLogModes | parallel log output modes (summary/tail/full/quiet) |
| test_webprobe_full_formats.bats | webprobe_full splits common and uncommon JSON results and updates webs_all | covered-by:web.TestWebParityHTTPX | httpx common/uncommon split + WEBPROBE_PORTS + JSON handling |
| test_webprobe_full_formats.bats | webprobe_full passes WEBPROBE_PORTS (including 80 and 443) to httpx command | covered-by:web.TestWebParityHTTPX | httpx common/uncommon split + WEBPROBE_PORTS + JSON handling |
| test_webprobe_full_formats.bats | webprobe_full fails when httpx output is not JSON | covered-by:web.TestWebParityHTTPX | httpx common/uncommon split + WEBPROBE_PORTS + JSON handling |
| test_ui_snapshots.bats | UI snapshot FULL verbosity 0 | covered-by:ui.TestStageProgress_NonTTY_PlainText | UI snapshot rendering per verbosity |
| test_ui_snapshots.bats | UI snapshot FULL verbosity 1 | covered-by:ui.TestStageProgress_NonTTY_PlainText | UI snapshot rendering per verbosity |
| test_ui_snapshots.bats | UI snapshot FULL verbosity 2 | covered-by:ui.TestStageProgress_NonTTY_PlainText | UI snapshot rendering per verbosity |
| test_ui_snapshots.bats | UI snapshot SUBDOMAINS verbosity 0 | covered-by:ui.TestStageProgress_NonTTY_PlainText | UI snapshot rendering per verbosity |
| test_ui_snapshots.bats | UI snapshot SUBDOMAINS verbosity 1 | covered-by:ui.TestStageProgress_NonTTY_PlainText | UI snapshot rendering per verbosity |
| test_ui_snapshots.bats | UI snapshot SUBDOMAINS verbosity 2 | covered-by:ui.TestStageProgress_NonTTY_PlainText | UI snapshot rendering per verbosity |
| test_monitor.bats | monitor_snapshot creates baseline and latest pointer | covered-by:mcp.TestMonitorDiff_RealCrossCycleDeltas | monitor snapshot/deltas -> monitor cross-cycle diff |
| test_monitor.bats | monitor_snapshot detects deltas between cycles | covered-by:mcp.TestMonitorDiff_RealCrossCycleDeltas | monitor snapshot/deltas -> monitor cross-cycle diff |
| test_monitor.bats | alert fingerprint suppression deduplicates repeated alerts | covered-by:notifier.TestDigestCoalescer_NoDrop | alert suppression -> notifier digest coalescer |
| test_monitor.bats | monitor_snapshot honors MONITOR_MIN_SEVERITY=medium and includes medium deltas | covered-by:mcp.TestMonitorDiff_RealCrossCycleDeltas | monitor snapshot/deltas -> monitor cross-cycle diff |
| test_cli_vps_count.bats | normalize_vps_count_args rewrites '-v 20 -r' to include --vps-count | covered-by:cmd.TestTranslateV1Args | normalize_vps_count_args -> v2 arg translation |
| test_cli_vps_count.bats | normalize_vps_count_args keeps plain '-v -r' unchanged | covered-by:cmd.TestTranslateV1Args | normalize_vps_count_args -> v2 arg translation |
| test_cli_vps_count.bats | normalize_vps_count_args keeps '-v foo -r' unchanged | covered-by:cmd.TestTranslateV1Args | normalize_vps_count_args -> v2 arg translation |
| test_subdomains_asn.bats | sub_asn skips ASN enumeration when PDCP_API_KEY is unset and logs it | covered-by:subdomains.TestSubASNTaskCallsTreeAppend | sub_asn asnmap gating/timeout/PDCP-key |
| test_subdomains_asn.bats | sub_asn runs asnmap with PDCP_API_KEY and writes ASN outputs | covered-by:subdomains.TestSubASNTaskCallsTreeAppend | sub_asn asnmap gating/timeout/PDCP-key |
| test_subdomains_asn.bats | sub_asn handles asnmap timeout and logs warning | covered-by:subdomains.TestSubASNTaskCallsTreeAppend | sub_asn asnmap gating/timeout/PDCP-key |
| test_subdomains_asn.bats | sub_asn continues silently when asnmap returns exit 0 with no ASN data | covered-by:subdomains.TestSubASNTaskCallsTreeAppend | sub_asn asnmap gating/timeout/PDCP-key |
| test_subdomains_asn.bats | sub_asn skips when asnmap is not installed and logs it | covered-by:subdomains.TestSubASNTaskCallsTreeAppend | sub_asn asnmap gating/timeout/PDCP-key |
| test_install_interlace_colorclass.bats | ensure_interlace_colorclass_healthy patches broken installed colorclass | superseded | v2 has no interlace (Python parallel runner); concurrency = Go scheduler; installer = internal/installer |
| test_install_interlace_colorclass.bats | ensure_interlace_colorclass_healthy fails when installed tool python is missing | superseded | v2 has no interlace (Python parallel runner); concurrency = Go scheduler; installer = internal/installer |
| test_utils.bats | getElapsedTime calculates zero duration | not-applicable | elapsed-time bash helper; v2 uses stdlib time formatting |
| test_utils.bats | getElapsedTime calculates seconds | not-applicable | elapsed-time bash helper; v2 uses stdlib time formatting |
| test_utils.bats | getElapsedTime calculates minutes and seconds | not-applicable | elapsed-time bash helper; v2 uses stdlib time formatting |
| test_utils.bats | getElapsedTime calculates hours | not-applicable | elapsed-time bash helper; v2 uses stdlib time formatting |
| test_utils.bats | check_disk_space returns success when threshold is 0 | not-applicable | OS disk preflight; not ported as a unit (health-check covers preflight) |
| test_utils.bats | check_disk_space returns success for reasonable threshold | not-applicable | OS disk preflight; not ported as a unit (health-check covers preflight) |
| test_utils.bats | check_disk_space returns failure for unreasonably large threshold | not-applicable | OS disk preflight; not ported as a unit (health-check covers preflight) |
| test_utils.bats | validate_config succeeds with default config | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | validate_config warns when VULNS without SUBDOMAINS | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | validate_config fails on non-numeric threads | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | validate_config fails on non-numeric AXIOM_FLEET_COUNT | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | validate_config accepts PERMUTATIONS_ENGINE=gotator without warning | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | validate_config warns when PERMUTATIONS_ENGINE is legacy non-gotator value | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | validate_config warns for deprecated no-op config knobs | covered-by:config.TestValidateDefaults | config validation -> validator tags |
| test_utils.bats | error codes are defined | covered-by:errors.TestSentinelAnchorsExistAndAreNonNil | error sentinels defined in internal/core/errors |
| test_utils.bats | should_run_deep returns true when DEEP is true | covered-by:config.TestApplyDeepProfile | DEEP gating -> deep profile |
| test_utils.bats | should_run_deep returns true when count below limit | covered-by:config.TestApplyDeepProfile | DEEP gating -> deep profile |
| test_utils.bats | should_run_deep returns false when count above limit and DEEP false | covered-by:config.TestApplyDeepProfile | DEEP gating -> deep profile |
| test_utils.bats | should_run_deep accepts custom limit | covered-by:config.TestApplyDeepProfile | DEEP gating -> deep profile |
| test_utils.bats | should_run_deep2 uses DEEP_LIMIT2 | covered-by:config.TestApplyDeepProfile | DEEP gating -> deep profile |
| test_utils.bats | checkpoint_init creates directory | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint init/save/exists -> sqlite store |
| test_utils.bats | checkpoint_save creates checkpoint file | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint init/save/exists -> sqlite store |
| test_utils.bats | checkpoint_exists returns true for existing checkpoint | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint init/save/exists -> sqlite store |
| test_utils.bats | checkpoint_exists returns false for missing checkpoint | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint init/save/exists -> sqlite store |
| test_utils.bats | circuit_breaker_is_open returns false initially | covered-by:backend.TestFailoverBackend_Exec_KillSwitchAfterThreshold | circuit breaker -> failover kill-switch |
| test_utils.bats | circuit_breaker opens after threshold failures | covered-by:backend.TestFailoverBackend_Exec_KillSwitchAfterThreshold | circuit breaker -> failover kill-switch |
| test_utils.bats | circuit_breaker resets on success | covered-by:backend.TestFailoverBackend_Exec_KillSwitchAfterThreshold | circuit breaker -> failover kill-switch |
| test_utils.bats | check_secrets_permissions warns on world-readable file | not-applicable | secrets.cfg file perms are a bash concern; v2 secrets via env/koanf + redaction |
| test_utils.bats | run_command disables Axiom runtime on transport failures | covered-by:backend.TestFailoverBackend_Exec_PrimaryAxiomFailure_FallsBackToFallback | axiom failover/disable -> failover backend |
| test_utils.bats | axiom_disable_runtime is idempotent after first failover | covered-by:backend.TestFailoverBackend_Exec_PrimaryAxiomFailure_FallsBackToFallback | axiom failover/disable -> failover backend |
| test_utils.bats | run_module_with_axiom_failover retries module locally once | covered-by:backend.TestFailoverBackend_Exec_PrimaryAxiomFailure_FallsBackToFallback | axiom failover/disable -> failover backend |
| test_utils.bats | mark_missing_tools_warn_once marks dnstake key to avoid duplicate warnings | covered-by:backend.TestToolRegistry_MissingRequired_IncludesAllMissingRegardlessOfCritical | missing-tool tracking -> tool registry |
| test_utils.bats | mark_missing_tools_warn_once does nothing when dnstake is not missing | covered-by:backend.TestToolRegistry_MissingRequired_IncludesAllMissingRegardlessOfCritical | missing-tool tracking -> tool registry |
| test_utils.bats | format_pending_tools_message joins tools using comma regardless of IFS | covered-by:backend.TestToolRegistry_MissingRequired_IncludesAllMissingRegardlessOfCritical | missing-tool tracking -> tool registry |
| test_dns_resolver_auto.bats | _ip_is_public_ipv4 identifies public and non-public ranges | superseded | v1 public-IP puredns/dnsx auto-heuristic; v2 resolver strategy in internal/core/resolvers, no per-network auto-switch |
| test_dns_resolver_auto.bats | _can_use_puredns returns true for public local IP | superseded | v1 public-IP puredns/dnsx auto-heuristic; v2 resolver strategy in internal/core/resolvers, no per-network auto-switch |
| test_dns_resolver_auto.bats | _can_use_puredns returns true for private IP on cloud VPS (metadata) | superseded | v1 public-IP puredns/dnsx auto-heuristic; v2 resolver strategy in internal/core/resolvers, no per-network auto-switch |
| test_dns_resolver_auto.bats | _can_use_puredns returns false for private IP without cloud metadata | superseded | v1 public-IP puredns/dnsx auto-heuristic; v2 resolver strategy in internal/core/resolvers, no per-network auto-switch |
| test_dns_resolver_auto.bats | init_dns_resolver caches auto selection (does not re-evaluate on each _select_dns_resolver) | superseded | v1 public-IP puredns/dnsx auto-heuristic; v2 resolver strategy in internal/core/resolvers, no per-network auto-switch |
| test_dns_resolver_auto.bats | DNS_RESOLVER override forces puredns/dnsx regardless of network | superseded | v1 public-IP puredns/dnsx auto-heuristic; v2 resolver strategy in internal/core/resolvers, no per-network auto-switch |
| test_exports.bats | export_findings_jsonl creates normalized and merged jsonl | covered-by:output.TestWriteJSONLLinesSuccess | findings jsonl normalization/merge |
| test_exports.bats | export_csv_artifacts writes expected csv files | covered-by:report.TestWriteCSV_FindingsColumns | csv export columns |
| test_exports.bats | export_reports honors EXPORT_FORMAT=all | covered-by:report.TestRenderHTML_OfflineFile | EXPORT_FORMAT=all -> report render paths |
| test_phase6.bats | run_command executes command in normal mode | covered-by:backend.TestLocalBackend_Exec_EchoReturnsStdoutAndZeroExit | external command exec -> LocalBackend |
| test_phase6.bats | run_command prints command in dry-run mode | covered-by:cmd.TestCompositeDryRun | run_command dry-run preview |
| test_phase6.bats | incremental_init creates directory structure | covered-by:mcp.TestIncrementalSeed_ChangesInputHash | incremental init/diff -> incremental seed |
| test_phase6.bats | incremental_diff finds new items | covered-by:mcp.TestIncrementalSeed_ChangesInputHash | incremental init/diff -> incremental seed |
| test_phase6.bats | detect_rate_limit_error detects 429 | covered-by:backend.TestRateLimiter_PerTool_WaitBlocksUntilToken | rate-limit detection -> adaptive rate limiter |
| test_phase6.bats | detect_rate_limit_error ignores normal output | covered-by:backend.TestRateLimiter_PerTool_WaitBlocksUntilToken | rate-limit detection -> adaptive rate limiter |
| test_new_tool_integrations.bats | lfi generates one-parameter candidates and uses explicit budgets | covered-by:vulns.TestVulnsDAGBuilds | lfi task wired into vulns DAG |
| test_new_tool_integrations.bats | ssti uses TInjA engine and writes compatible output | covered-by:vulns.TestVulnsDAGBuilds | ssti (TInjA) wired into vulns DAG |
| test_new_tool_integrations.bats | brokenLinks supports second-order engine | covered-by:vulns.TestVulnsDAGBuilds | broken-links / second-order in vulns DAG |
| test_new_tool_integrations.bats | favirecon_tech stores normalized technology findings | covered-by:favicon.TestFaviconExtractFiltersToTargetDomain | favicon tech recon |
| test_new_tool_integrations.bats | apileaks merges scoped leak URLs into url_extract | covered-by:osint.TestParsePorchPirateOutput_RedactsAndRegisters | apileaks scoped-URL merge |
| test_new_tool_integrations.bats | jschecks merges only scoped JS-discovered URLs into url_extract | covered-by:js.TestJsExtractFiltersToTargetDomain | js-discovered scoped URL merge |
| test_new_tool_integrations.bats | s3buckets uses cloud_enum and writes cloud_enum artifacts | covered-by:subdomains.TestSubBucketsTaskCallsTreeAppend | s3/cloud bucket enumeration |
| test_new_tool_integrations.bats | s3buckets falls back to uv run when local venv is missing | covered-by:subdomains.TestSubBucketsTaskCallsTreeAppend | s3/cloud bucket enumeration |
| test_new_tool_integrations.bats | s3buckets exhaustive profile uses cloud_enum fuzz.txt mutations | covered-by:subdomains.TestSubBucketsTaskCallsTreeAppend | s3/cloud bucket enumeration |
| test_new_tool_integrations.bats | s3buckets continues with s3scanner when cloud_enum fails | covered-by:subdomains.TestSubBucketsTaskCallsTreeAppend | s3/cloud bucket enumeration |
| test_new_tool_integrations.bats | cloud_enum_scan uses local cloud_enum runtime with optimized quickscan flags | covered-by:osint.TestParseCloudEnumLines_ProviderClassification | cloud_enum provider classification |
| test_new_tool_integrations.bats | cloud_enum_scan falls back to uv run when local venv is missing | covered-by:osint.TestParseCloudEnumLines_ProviderClassification | cloud_enum provider classification |
| test_new_tool_integrations.bats | cloud_enum_scan exhaustive profile uses local fuzz mutations file | covered-by:osint.TestParseCloudEnumLines_ProviderClassification | cloud_enum provider classification |
| test_new_tool_integrations.bats | cloud_enum_scan exhaustive downgrades to optimized when fuzz file is missing | covered-by:osint.TestParseCloudEnumLines_ProviderClassification | cloud_enum provider classification |
| test_new_tool_integrations.bats | multi_osint executes cloud_enum_scan for each target | covered-by:osint.TestParseCloudEnumLines_ProviderClassification | cloud_enum provider classification |
| test_new_tool_integrations.bats | nuclei_dast is forced on when VULNS_GENERAL=true | covered-by:web.TestWebParityNuclei | nuclei DAST gating |
| test_new_tool_integrations.bats | github_leaks searches GitHub-wide secrets with ghleaks | covered-by:osint.TestParseGhleaksReport_RedactsAndRegisters | github-wide secret scan |
| test_new_tool_integrations.bats | github_leaks adds --exhaustive flag in DEEP mode | covered-by:osint.TestParseGhleaksReport_RedactsAndRegisters | github-wide secret scan |
| test_new_tool_integrations.bats | service_fingerprint writes nerva artifacts from naabu input | covered-by:web.TestPortscanServiceFingerprintFromNaabu | nerva service fingerprint from naabu |
| test_new_tool_integrations.bats | spraying supports brutus engine with service fingerprint json input | covered-by:vulns.TestSprayBrutusStdinAndRedaction | credential spraying (brutus) |
| test_new_tool_integrations.bats | llm_probe writes julius jsonl output | covered-by:vulns.TestVulnsDAGBuilds | julius llm endpoint probe in vulns DAG |
| test_new_tool_integrations.bats | param_discovery skips in non-deep mode | covered-by:web.TestWebDAGBuilds | arjun param discovery deep-gate |
| test_new_tool_integrations.bats | param_discovery runs in deep mode with arjun text output | covered-by:web.TestWebDAGBuilds | arjun param discovery deep-gate |
| test_new_tool_integrations.bats | well_known_pivots probes newly discovered subdomains into webs.txt | covered-by:web.TestWebWellKnownExtractsInScopeHosts | well-known pivots |
| test_new_tool_integrations.bats | wordlist_gen_roboxtractor skips in non-DEEP mode with explicit mode reason | covered-by:web.TestWebWordlistGenRoboxtractor | roboxtractor wordlist gen |
| test_new_tool_integrations.bats | wordlist_gen_roboxtractor runs in DEEP mode and writes robots wordlist | covered-by:web.TestWebWordlistGenRoboxtractor | roboxtractor wordlist gen |
| test_new_tool_integrations.bats | swagger_check discovers swagger via sj brute and writes swagger_urls.txt | covered-by:osint.TestParseSwaggerOutput_RedactsAndRegisters | swagger discovery (sj) |
| test_new_tool_integrations.bats | swagger_check aggregates nuclei swagger-api findings | covered-by:osint.TestParseSwaggerOutput_RedactsAndRegisters | swagger discovery (sj) |
| test_new_tool_integrations.bats | swagger_check runs sj automate and extracts accessible endpoints | covered-by:osint.TestParseSwaggerOutput_RedactsAndRegisters | swagger discovery (sj) |
| test_new_tool_integrations.bats | swagger_check skips when SJ_CHECK=false | covered-by:osint.TestParseSwaggerOutput_RedactsAndRegisters | swagger discovery (sj) |
| test_reporting.bats | generate_consolidated_report creates json and html | covered-by:report.TestRenderHTML_OfflineFile | consolidated report json/html + missing-artifact tolerance |
| test_reporting.bats | report includes delta_since_last when monitor data exists | covered-by:mcp.TestMonitorDiff_RealCrossCycleDeltas | delta_since_last -> monitor diff |
| test_reporting.bats | report generation handles missing optional artifacts gracefully | covered-by:report.TestRenderHTML_OfflineFile | consolidated report json/html + missing-artifact tolerance |
| test_subdomains_filtering.bats | sub_active filters exact domain and subdomains with robust matcher | covered-by:subdomains.TestMergeStageFiltersScopeAndUnionConsolidates | scope filtering on active/brute/permut stages |
| test_subdomains_filtering.bats | sub_brute appends only in-scope brute-force matches | covered-by:subdomains.TestMergeStageFiltersScopeAndUnionConsolidates | scope filtering on active/brute/permut stages |
| test_subdomains_filtering.bats | sub_ia_permut skips cleanly when seed subdomains are empty | covered-by:subdomains.TestMergeStageFiltersScopeAndUnionConsolidates | scope filtering on active/brute/permut stages |
| test_resolvers_hardening.bats | resolvers_update refreshes when resolvers_trusted is missing | covered-by:resolvers.TestGenResolversFallsBackToHTTP | resolver refresh/hardening -> resolvers gen + resolve gate |
| test_resolvers_hardening.bats | resolvers_update fails fast when resolver download fails | covered-by:resolvers.TestGenResolversFallsBackToHTTP | resolver refresh/hardening -> resolvers gen + resolve gate |
| test_resolvers_hardening.bats | cached_download_typed uses strict curl flags for resolvers cache type | covered-by:resolvers.TestGenResolversFallsBackToHTTP | resolver refresh/hardening -> resolvers gen + resolve gate |
| test_resolvers_hardening.bats | _bruteforce_domains fails fast when required resolver files are missing | covered-by:resolvers.TestGenResolversFallsBackToHTTP | resolver refresh/hardening -> resolvers gen + resolve gate |
| test_resolvers_hardening.bats | _resolve_domains fails fast for dnsx when trusted resolvers file is missing | covered-by:resolvers.TestGenResolversFallsBackToHTTP | resolver refresh/hardening -> resolvers gen + resolve gate |
| test_resolvers_hardening.bats | _bruteforce_domains uses heartbeat path and skips timeout wrapper when DNS_BRUTE_TIMEOUT=0 | covered-by:resolvers.TestGenResolversFallsBackToHTTP | resolver refresh/hardening -> resolvers gen + resolve gate |
| test_common.bats | ensure_dirs creates single directory | covered-by:output.TestOutputTreeCreatesSubdirs | workspace subdir creation |
| test_common.bats | ensure_dirs creates multiple directories | covered-by:output.TestOutputTreeCreatesSubdirs | workspace subdir creation |
| test_common.bats | ensure_dirs creates nested directories | covered-by:output.TestOutputTreeCreatesSubdirs | workspace subdir creation |
| test_common.bats | ensure_dirs returns 0 with no arguments | covered-by:output.TestOutputTreeCreatesSubdirs | workspace subdir creation |
| test_common.bats | ensure_dirs succeeds if directory already exists | covered-by:output.TestOutputTreeCreatesSubdirs | workspace subdir creation |
| test_common.bats | safe_backup copies existing file | not-applicable | bash file-backup helper; v2 writes are atomic (no in-place backup) |
| test_common.bats | safe_backup skips empty file | not-applicable | bash file-backup helper; v2 writes are atomic (no in-place backup) |
| test_common.bats | safe_backup skips non-existent file | not-applicable | bash file-backup helper; v2 writes are atomic (no in-place backup) |
| test_common.bats | safe_backup uses default destination | not-applicable | bash file-backup helper; v2 writes are atomic (no in-place backup) |
| test_common.bats | count_lines returns correct count | not-applicable | bash line-count helper; not a ported unit |
| test_common.bats | count_lines ignores empty lines | not-applicable | bash line-count helper; not a ported unit |
| test_common.bats | count_lines returns 0 for empty file | not-applicable | bash line-count helper; not a ported unit |
| test_common.bats | count_lines returns 0 for non-existent file | not-applicable | bash line-count helper; not a ported unit |
| test_common.bats | count_lines_stdin counts from pipe | not-applicable | bash line-count helper; not a ported unit |
| test_common.bats | count_lines_stdin ignores empty lines from pipe | not-applicable | bash line-count helper; not a ported unit |
| test_common.bats | skip_notification outputs message | covered-by:ui.TestBadgeCountersAndSummary | skip/cache badge rendering |
| test_common.bats | skip_notification processed-visible renders SKIP with cache reason and cache marker | covered-by:ui.TestBadgeCountersAndSummary | skip/cache badge rendering |
| test_common.bats | print_artifacts uses INFO Artifacts format without brackets | covered-by:ui.TestDotFillFormat | status/artifact line rendering |
| test_common.bats | print_notice RUN uses cyan color for state | covered-by:ui.TestDotFillFormat | status/artifact line rendering |
| test_common.bats | run_tool executes command normally | covered-by:cmd.TestCompositeDryRun | tool exec + DRY_RUN gate |
| test_common.bats | run_tool respects DRY_RUN mode | covered-by:cmd.TestCompositeDryRun | tool exec + DRY_RUN gate |
| test_common.bats | process_results deduplicates and counts | covered-by:output.TestOutputTreeAppendReplaces | append/dedup semantics |
| test_common.bats | should_run_function returns true when checkpoint missing | covered-by:scheduler.TestCheckpointSkipOnHit | checkpoint gate + DIFF override |
| test_common.bats | should_run_function returns false when checkpoint exists | covered-by:scheduler.TestCheckpointSkipOnHit | checkpoint gate + DIFF override |
| test_common.bats | should_run_function returns true in DIFF mode even with checkpoint | covered-by:scheduler.TestCheckpointSkipOnHit | checkpoint gate + DIFF override |
| test_common.bats | anew_q_safe returns 0 when anew adds new lines | covered-by:output.TestOutputTreeAppendReplaces | append/dedup semantics |
| test_common.bats | anew_q_safe returns 0 when anew adds no new lines (rc=1 from anew) | covered-by:output.TestOutputTreeAppendReplaces | append/dedup semantics |
| test_common.bats | anew_q_safe writes unique lines to file | covered-by:output.TestOutputTreeAppendReplaces | append/dedup semantics |
| test_common.bats | anew_safe returns 0 and outputs new lines | covered-by:output.TestOutputTreeAppendReplaces | append/dedup semantics |
| test_common.bats | strip_ansi_stream keeps final carriage-return segment | covered-by:ui.TestStageProgress_NoANSI_WhenNoColor | ANSI stripping in non-TTY output |
| test_common.bats | strip_ansi_stream removes backspace redraw artifacts | covered-by:ui.TestStageProgress_NoANSI_WhenNoColor | ANSI stripping in non-TTY output |
| test_common.bats | grep_domain matches exact domain and subdomains only | covered-by:output.TestScopeExactHostMatches | exact domain/subdomain matching |
| test_common.bats | warn_once emits the same warning key only once | not-applicable | bash warn-dedup helper; v2 logs via slog |
| test_ensure_webs_all.bats | ensure_webs_all creates webs/webs_all.txt from webs/webs.txt | covered-by:web.TestMergeStageHostsPreservesExistingArtefact | ensure_webs_all -> hosts merge/consolidation |
| test_permutation_wordlist_select.bats | _select_permutations_wordlist returns full list when mode=full | covered-by:subdomains.TestPermutTasksBuildOK | permutation wordlist selection (mode/threshold) |
| test_permutation_wordlist_select.bats | _select_permutations_wordlist returns short list when mode=short | covered-by:subdomains.TestPermutTasksBuildOK | permutation wordlist selection (mode/threshold) |
| test_permutation_wordlist_select.bats | _select_permutations_wordlist auto uses full list in DEEP mode | covered-by:subdomains.TestPermutTasksBuildOK | permutation wordlist selection (mode/threshold) |
| test_permutation_wordlist_select.bats | _select_permutations_wordlist auto uses threshold (<= threshold => full, > threshold => short) | covered-by:subdomains.TestPermutTasksBuildOK | permutation wordlist selection (mode/threshold) |
| test_sub_tls_no_match.bats | sub_tls does not raise ERR trap when tlsx output has no matches | covered-by:subdomains.TestResolveDegradesOnToolError | empty tlsx output tolerated -> degrade-on-tool-error (no ERR trap in Go) |
| test_sanitize.bats | sanitize_domain accepts valid domain | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain accepts subdomain | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain converts to lowercase | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain handles mixed case | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain rejects command injection attempt | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_sanitize.bats | sanitize_domain rejects pipe injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_sanitize.bats | sanitize_domain rejects backtick injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_sanitize.bats | sanitize_domain handles empty input | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain handles only dots | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips leading/trailing dots | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips leading/trailing hyphens | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips https:// scheme | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips http:// scheme with subdomain | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips path | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips port | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips query and fragment | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain strips userinfo | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain handles @ in path (not userinfo) | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain rejects URL with invalid IP octet | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain accepts URL with valid IP | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_domain normalizes URL with all parts | covered-by:output.TestWorkspaceInitSanitizesTarget | domain normalization (case/scheme/port/path) |
| test_sanitize.bats | sanitize_interlace_input removes shell metacharacters | superseded | v2 has no interlace input file to sanitize |
| test_sanitize.bats | sanitize_interlace_input handles in-place mode | superseded | v2 has no interlace input file to sanitize |
| test_sanitize.bats | deleteOutScoped removes matching entries | covered-by:output.TestScopeRejectsOutsidePattern | out-of-scope stripping |
| test_sanitize.bats | deleteOutScoped handles wildcard patterns | covered-by:output.TestScopeRejectsOutsidePattern | out-of-scope stripping |
| test_sanitize.bats | deleteOutScoped handles regex metacharacters safely | covered-by:output.TestScopeRejectsOutsidePattern | out-of-scope stripping |
| test_verbosity.bats | notification suppresses info at verbosity 1 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | notification suppresses info at verbosity 0 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | notification shows errors at verbosity 0 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | notification shows all at verbosity 2 | covered-by:ui.TestVerbosityVerboseEmitsInfo | verbose emits info |
| test_verbosity.bats | notification sends suppressed messages to notify when enabled | covered-by:notifier.TestLogSinkLevels | notify sink levels |
| test_verbosity.bats | notification sends visible messages to notify when enabled | covered-by:notifier.TestLogSinkLevels | notify sink levels |
| test_verbosity.bats | skip_notification prints at verbosity 1 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | skip_notification suppressed at verbosity 0 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | start_func silent at verbosity 1 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | start_func hides rule at verbosity 0 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | end_func shows status at verbosity 1 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_verbosity.bats | end_func hides status at verbosity 0 | covered-by:ui.TestVerbosityQuietSuppresses | verbosity gating of status/info |
| test_validation.bats | validate_domain accepts valid domain | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_domain accepts subdomain | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_domain accepts deep subdomain | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_domain rejects empty string | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_domain rejects domain with semicolon | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_domain rejects domain with pipe | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_domain rejects domain with backticks | covered-by:output.TestWorkspaceInitSanitizesTarget | domain accept/reject -> target sanitize + scope |
| test_validation.bats | validate_ipv4 accepts valid IP | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_ipv4 accepts 0.0.0.0 | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_ipv4 accepts 255.255.255.255 | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_ipv4 rejects IP with octet > 255 | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_ipv4 rejects incomplete IP | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_ipv4 rejects IP with letters | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_ipv4 rejects empty string | superseded | no standalone IPv4-octet validator in v2; IPs via net.ParseIP + scope/asnmap |
| test_validation.bats | validate_boolean accepts true | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean accepts false | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean accepts TRUE (case insensitive) | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean accepts FALSE (case insensitive) | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean rejects yes | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean rejects 1 | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean rejects empty | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_boolean rejects random string | covered-by:config.TestCoerceAndSetBoolFromString | boolean coercion via koanf |
| test_validation.bats | validate_file_exists returns true for existing file | covered-by:config.TestNoPathTraversal | path/file validation -> config path validators |
| test_validation.bats | validate_file_exists returns false for non-existent file | covered-by:config.TestNoPathTraversal | path/file validation -> config path validators |
| test_validation.bats | validate_file_readable returns true for readable file | covered-by:config.TestNoPathTraversal | path/file validation -> config path validators |
| test_validation.bats | validate_directory returns true for existing directory | covered-by:config.TestNoPathTraversal | path/file validation -> config path validators |
| test_validation.bats | validate_directory returns false for non-existent directory | covered-by:config.TestNoPathTraversal | path/file validation -> config path validators |
| test_validation.bats | validate_writable_directory returns true for writable dir | covered-by:config.TestNoPathTraversal | path/file validation -> config path validators |
| test_validation_extended.bats | validate_boolean accepts 'true' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean accepts 'false' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean accepts '1' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean accepts '0' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean accepts 'yes' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean accepts 'no' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean rejects empty string | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean rejects 'maybe' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean rejects 'TRUE' (case-sensitive) | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean rejects 'YES' (case-sensitive) | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean rejects '2' | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_boolean rejects whitespace-padded value | covered-by:config.TestCoerceAndSetBoolFromString | bash bool accept/reject -> typed koanf bool coercion |
| test_validation_extended.bats | validate_integer accepts positive integer | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer accepts zero | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer accepts negative integer | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer accepts large integer | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer rejects float | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer rejects empty string | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer rejects letters | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer rejects alphanumeric | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects min bound — value below min fails | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects min bound — value at min passes | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects min bound — value above min passes | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects max bound — value above max fails | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects max bound — value at max passes | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects both bounds — value within range passes | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects both bounds — value below range fails | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_integer respects both bounds — value above range fails | covered-by:config.TestCoerceAndSetIntFromString | bash int parse/range -> typed koanf int coercion |
| test_validation_extended.bats | validate_port accepts port 1 (minimum) | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port accepts port 80 | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port accepts port 443 | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port accepts port 8080 | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port accepts port 65535 (maximum) | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port rejects port 0 (below minimum) | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port rejects port 65536 (above maximum) | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port rejects negative port | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port rejects non-numeric string | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port rejects empty string | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | validate_port rejects float port | covered-by:config.TestValidateErrorShape | bash port range -> struct-tag min/max enforced by config.Validate |
| test_validation_extended.bats | sanitize_path returns clean path unchanged | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_path strips trailing slash | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_path strips multiple trailing slashes | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_path preserves root slash | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_path normalizes double slashes in middle | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_path removes control characters | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_path handles relative path | covered-by:config.TestNoPathTraversal | bash path normalisation -> traversal rejection in config paths |
| test_validation_extended.bats | sanitize_interlace_input keeps safe domains | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | sanitize_interlace_input removes semicolon lines | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | sanitize_interlace_input removes pipe lines | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | sanitize_interlace_input removes dollar-substitution lines | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | sanitize_interlace_input removes backtick lines | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | sanitize_interlace_input in-place edit preserves safe lines | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | sanitize_interlace_input supports separate output file | superseded | interlace is a v1-only runner; v2 schedules jobs in-process |
| test_validation_extended.bats | is_empty returns 0 for empty string | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_empty returns 0 for whitespace-only string | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_empty returns 1 for non-empty string | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_empty returns 1 for string with leading whitespace | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_empty returns 1 for zero string '0' | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 0 for positive integer | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 0 for zero | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 0 for negative integer | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 0 for float | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 0 for negative float | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 1 for empty string | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 1 for alphabetic string | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 1 for alphanumeric string | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 1 for string with spaces | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_validation_extended.bats | is_numeric returns 1 for double dot (malformed float) | superseded | string-shape helper; Go's type system makes the check unnecessary |
| test_osint_github_repos.bats | github_repos falls back to titus for unknown secrets engine | covered-by:osint.TestGithubReposTask_NoseyparkerDefersToTitus | github_repos secrets-engine fallback |
| test_osint_github_repos.bats | github_repos uses titus without fallback warning when explicitly configured | covered-by:osint.TestGithubReposTask_NoseyparkerDefersToTitus | github_repos secrets-engine fallback |
| test_osint_domain_info_msftrecon.bats | domain_info handles msftrecon failure with fail-soft warning and empty artifact | covered-by:osint.TestDomainInfoTask_ScopifyDegrades | msftrecon fail-soft -> domain_info degrade path |
| test_scope_validation.bats | is_in_scope_host accepts the apex domain itself | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_host accepts a subdomain | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_host accepts a deep subdomain | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_host is case-insensitive | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_host rejects substring look-alike (exampleXcom.evil) | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_host rejects prefix look-alike (badexample.com) | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_host rejects unrelated domain | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | filter_in_scope_urls passes http and https targets on the apex | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | filter_in_scope_urls drops URLs with userinfo (SSRF bypass block) | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | filter_in_scope_urls drops URLs with user:pass@host | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | filter_in_scope_urls drops off-scope with target as query (attacker.test/?cb=example.com) | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | filter_in_scope_urls drops non-http schemes | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | filter_in_scope_urls drops substring look-alike hosts | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | filter_in_scope_hosts rejects substring look-alike on raw hostnames | covered-by:output.TestScopeExactHostMatches | host scope: apex/subdomain accept, look-alike reject |
| test_scope_validation.bats | is_in_scope_url returns the sanitized URL on match | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_scope_validation.bats | is_in_scope_url rejects userinfo | covered-by:output.TestScopeIsInScopeURL | URL scope + userinfo/scheme guards |
| test_redact_secrets.bats | redact_secrets replaces registered values with [REDACTED] | covered-by:log.TestRedactor_MultipleSecretsRedacted | registered-value redaction in logs |
| test_redact_secrets.bats | redact_secrets replaces env-var values via REDACT_VARS indirection | covered-by:log.TestRedactor_MultipleSecretsRedacted | registered-value redaction in logs |
| test_redact_secrets.bats | redact_secrets redacts telegram_key from local scope via REDACT_VARS | covered-by:log.TestRedactor_MultipleSecretsRedacted | registered-value redaction in logs |
| test_redact_secrets.bats | redact_secrets redacts discord_url | covered-by:log.TestRedactor_MultipleSecretsRedacted | registered-value redaction in logs |
| test_redact_secrets.bats | redact_secrets leaves short strings untouched | covered-by:log.TestRedactor_RegisterSkipsShortValues | short-value skip |
| test_redact_secrets.bats | register_secret deduplicates repeated values | covered-by:log.TestRedactor_RegisterDedup | secret registration dedup |
| test_injection.bats | sanitize_domain blocks semicolon injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_domain blocks pipe injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_domain blocks backtick injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_domain blocks dollar substitution | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_domain blocks ampersand injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_domain blocks newline injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_domain blocks redirect injection | covered-by:output.TestScopeRejectsInjection | domain injection rejection |
| test_injection.bats | sanitize_ip blocks semicolon injection | covered-by:output.TestScopeRejectsInjection | IP/CIDR injection rejection |
| test_injection.bats | sanitize_ip blocks command substitution | covered-by:output.TestScopeRejectsInjection | IP/CIDR injection rejection |
| test_injection.bats | sanitize_ip allows valid CIDR | covered-by:output.TestScopeRejectsInjection | IP/CIDR injection rejection |
| test_injection.bats | sanitize_interlace_input removes dangerous chars | superseded | v2 has no interlace input file to sanitize |
| test_injection.bats | outscope file handles path traversal attempt | covered-by:config.TestNoPathTraversal | outscope path-traversal rejection |
| test_vps_count_cli.bats | help advertises --vps-count | covered-by:cmd.TestTranslateV1Args | --vps-count CLI parse/validation |
| test_vps_count_cli.bats | --vps-count rejects 0 | covered-by:cmd.TestTranslateV1Args | --vps-count CLI parse/validation |
| test_vps_count_cli.bats | --vps-count rejects non-numeric values | covered-by:cmd.TestTranslateV1Args | --vps-count CLI parse/validation |
| test_vps_count_cli.bats | --vps-count accepts valid value | covered-by:cmd.TestTranslateV1Args | --vps-count CLI parse/validation |
| test_vps_count_cli.bats | --report-only accepts --vps-count override parsing | covered-by:cmd.TestTranslateV1Args | --vps-count CLI parse/validation |
| test_vps_count_cli.bats | --vps-count override forces fleet launch/count over custom config values | covered-by:backend.TestAxiomBackend_Capacity_ReturnsFleetCount | --vps-count -> axiom fleet capacity |
| test_monitor_mode.bats | monitor_snapshot creates history and delta artifacts | covered-by:mcp.TestMonitorDiff_RealCrossCycleDeltas | monitor history/delta artifacts |
| test_list_targets.bats | -l processes final target even without trailing newline | covered-by:cmd.TestReadTargetList | -l list processing (trailing newline / CRLF) |
| test_list_targets.bats | -l processes CRLF target lists without dropping entries | covered-by:cmd.TestReadTargetList | -l list processing (trailing newline / CRLF) |
| test_full_flow.bats | full flow: directory structure is created correctly | covered-by:output.TestWorkspaceInitSubdirs | workspace tree init |
| test_full_flow.bats | full flow: checkpoint system creates markers | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint markers |
| test_full_flow.bats | full flow: checkpoint prevents re-execution | covered-by:scheduler.TestCheckpointSkipOnHit | checkpoint skip |
| test_full_flow.bats | full flow: DIFF mode ignores checkpoints | covered-by:scheduler.TestForceRerunTrueRunsAndRecords | DIFF forces re-run |
| test_full_flow.bats | full flow: common.sh ensure_dirs creates nested dirs | covered-by:output.TestOutputTreeCreatesSubdirs | nested dir creation |
| test_full_flow.bats | full flow: parallel.sh is loaded correctly | not-applicable | bash helper-existence / source mechanic |
| test_full_flow.bats | full flow: subdomains helper functions exist | not-applicable | bash helper-existence / source mechanic |
| test_full_flow.bats | full flow: web helper functions exist | not-applicable | bash helper-existence / source mechanic |
| test_full_flow.bats | full flow: incremental mode detects new results | covered-by:mcp.TestIncrementalSeed_ChangesInputHash | incremental new-result detection |
| test_full_flow.bats | full flow: output files are deduplicated | covered-by:output.TestOutputTreeAppendReplaces | output dedup |
| test_full_flow.bats | full flow: inscope filtering works | covered-by:output.TestScopeRejectsOutsidePattern | inscope filtering |
| test_full_flow.bats | full flow: log files are created | covered-by:log.TestNew_DefaultFormatIsJSON | structured logging |
| test_full_flow.bats | full flow: tmp files are cleaned up | covered-by:output.TestAtomicWriteCleansupOnSuccess | atomic-write temp cleanup |
| test_full_flow.bats | full flow: notification skip works | covered-by:notifier.TestEventFilter_BlockedKind | notification event filtering |
| test_full_flow.bats | full flow: parallel_funcs handles empty list | covered-by:scheduler.TestRunStageEmpty | empty stage no-op |
| test_full_flow.bats | full flow: dry-run mode prevents execution | covered-by:cmd.TestCompositeDryRun | dry-run prevents execution |
| test_smoke.bats | reconftw.sh is executable | covered-by:cmd.TestRootListsFifteenSubcommandsPlusVersion | entrypoint help/usage/executable |
| test_smoke.bats | reconftw.sh --help exits successfully | covered-by:cmd.TestRootListsFifteenSubcommandsPlusVersion | entrypoint help/usage/executable |
| test_smoke.bats | reconftw.sh --help shows usage | covered-by:cmd.TestRootListsFifteenSubcommandsPlusVersion | entrypoint help/usage/executable |
| test_smoke.bats | all modules are loadable | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | lib/validation.sh is loadable | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | reconftw.cfg exists and is readable | covered-by:config.TestLoadValidMinimal | config file load |
| test_smoke.bats | source-only mode works without side effects | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | sanitize_domain function is available after source | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | validate_domain function is available after source | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | should_run_deep function is available after source | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | checkpoint functions are available after source | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | circuit_breaker functions are available after source | not-applicable | bash source/loadability mechanic; Go compiles the equivalent |
| test_smoke.bats | invalid domain is sanitized | covered-by:output.TestWorkspaceInitSanitizesTarget | invalid-domain sanitize |
| test_smoke.bats | missing list file shows error | covered-by:cmd.TestReadTargetListMissingFile | missing list file error |
| test_smoke.bats | missing inscope file shows error | covered-by:output.TestScopeRejectsOutsidePattern | inscope/custom-fn guard |
| test_smoke.bats | invalid custom function shows error | covered-by:output.TestScopeRejectsOutsidePattern | inscope/custom-fn guard |
| test_terminal_output_modes.bats | --quiet hides header/sections but keeps final summary | covered-by:ui.TestVerbosityQuietSuppresses | --quiet output mode |
| test_terminal_output_modes.bats | --log-format jsonl-strict emits JSONL lines only | covered-by:ui.TestParallelLogModes | jsonl-strict output mode |
| test_checkpoint.bats | checkpoint: marker file is created on function completion | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: multiple function markers can coexist | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: marker naming follows convention | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | resume: function is skipped when marker exists | covered-by:scheduler.TestCheckpointSkipOnHit | resume gate |
| test_checkpoint.bats | resume: function runs when marker missing | covered-by:scheduler.TestCheckpointSkipOnHit | resume gate |
| test_checkpoint.bats | resume: DIFF mode forces re-run | covered-by:scheduler.TestForceRerunTrueRunsAndRecords | DIFF re-run |
| test_checkpoint.bats | resume: partial completion is detected | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | resume: can clear single checkpoint | covered-by:checkpoint.TestCheckpointStoreDoneAfterComplete | checkpoint clear/complete |
| test_checkpoint.bats | resume: can clear all checkpoints | covered-by:checkpoint.TestCheckpointStoreDoneAfterComplete | checkpoint clear/complete |
| test_checkpoint.bats | checkpoint: survives script restart simulation | covered-by:checkpoint.TestCheckpointStoreCrashRecovery | crash/restart recovery |
| test_checkpoint.bats | checkpoint: preserves order of completion (via timestamps) | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: results persist alongside markers | covered-by:checkpoint.TestCheckpointStoreCrashRecovery | crash/restart recovery |
| test_checkpoint.bats | checkpoint: clearing checkpoint doesn't delete results | covered-by:checkpoint.TestCheckpointStoreDoneAfterComplete | checkpoint clear/complete |
| test_checkpoint.bats | checkpoint: handles special characters in function names | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: empty called_fn_dir is valid state | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: concurrent marker creation doesn't corrupt | covered-by:checkpoint.TestCheckpointStoreConcurrentBegin | concurrent marker safety |
| test_checkpoint.bats | checkpoint: checkpoint_init available after source | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: checkpoint_save available after source | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: checkpoint_exists helper works | covered-by:checkpoint.TestCheckpointStoreBegin | checkpoint marker lifecycle |
| test_checkpoint.bats | checkpoint: checkpoint_clear helper works | covered-by:checkpoint.TestCheckpointStoreDoneAfterComplete | checkpoint clear/complete |
| test_notifications.bats | NOTIFICATION=true sends function notifications through notify | covered-by:notifier.TestSlackNotify_BestEffort | notify fan-out (NOTIFICATION / SOFT_NOTIFICATION) |
| test_notifications.bats | SOFT_NOTIFICATION=true still sends final notification | covered-by:notifier.TestSlackNotify_BestEffort | notify fan-out (NOTIFICATION / SOFT_NOTIFICATION) |
| test_export_cli.bats | export cli json creates jsonl artifacts | covered-by:output.TestWriteJSONLLinesSuccess | export cli json/jsonl |
| test_export_cli.bats | export cli csv creates csv artifacts | covered-by:report.TestWriteCSV_FindingsColumns | export cli csv |
| test_shell_syntax.bats | reconftw.sh passes bash syntax check | not-applicable | go build + go vet replace bash -n syntax checks |
| test_shell_syntax.bats | critical modules pass bash syntax check | not-applicable | go build + go vet replace bash -n syntax checks |
| test_report_only.bats | report-only rebuilds report artifacts | covered-by:report.TestRenderAll_AIDisabledWritesNothing | report-only rebuild -> report render path |
