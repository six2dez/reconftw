// Legacy v1→v2 migration tables (Phase 14 — `reconftw migrate`, D-03).
//
// Three data tables drive the migrator's D-02 three-way key disposition:
//
//   1. legacyAliasMap    — Case A: v1 UPPER_CASE (and a few lowercase) keys →
//                          v2-native koanf dotted paths. Every value here MUST
//                          bind to a real scalar field in Defaults() (proven by
//                          TestMigrateSchemaPathValidity). This is ALSO the
//                          runtime [legacy]-table lookup consumed by
//                          applyLegacyAliases (loader.go).
//   2. legacyAliasSecretKeys — v1 keys whose v2 target is log.Secret-typed;
//                          their values are redacted in stderr/--dry-run output
//                          but written verbatim to the target .toml.
//   3. supersededKeys    — Case B: v1 keys with NO active v2-native home
//                          (bash globals, computed thread counts, file-read
//                          command-subs, ${VAR}-assembled values, or v1-only
//                          tuning knobs v2 does not expose). The migrator emits
//                          these as `# SUPERSEDED …` comments — never live keys
//                          — so they never trip the loader's per-load warning.
//
// Any v1 key found in neither table is Case C (unknown): the migrator emits a
// `# UNKNOWN …` comment AND a loud stderr `⚠ unknown key …` line (CUT-06).
//
// The migrator's OUTPUT is always v2-native keys + comments; it NEVER writes a
// live [legacy] table (that would re-introduce the per-load applyLegacyAliases
// warning for superseded/unknown keys — RESEARCH ★Q1 / §D-02).

package config

// legacyAliasMap is the v1 → v2-native key mapping (Case A). It is both the
// migrator's translation table and the runtime [legacy] alias resolver
// (applyLegacyAliases in loader.go). Extended from the W18 5-entry corpus to the
// full v1 surface (D-03) — every target path is a real Defaults() scalar field.
var legacyAliasMap = map[string]string{
	// ── concurrency ──
	"PARALLEL_MAX_JOBS":              "concurrency.max_jobs",
	"DNS_HEARTBEAT_INTERVAL_SECONDS": "concurrency.heartbeat_seconds",
	"PARALLEL_LOG_MODE":              "concurrency.log_mode",
	"PARALLEL_TAIL_LINES":            "concurrency.tail_lines",
	"PARALLEL_JOB_TIMEOUT_SECONDS":   "concurrency.job_timeout_seconds",
	"PARALLEL_KILL_GRACE_SECONDS":    "concurrency.kill_grace_seconds",

	// ── subdomains ──
	"SUBDOMAINS_GENERAL":           "subdomains.enabled",
	"SUBPASSIVE":                   "subdomains.passive.enabled",
	"SUBFINDER_ENUM_TIMEOUT":       "subdomains.passive.timeout_minutes",
	"SUBCRT":                       "subdomains.crt.enabled",
	"CTR_LIMIT":                    "subdomains.crt.limit",
	"DNS_TIME_FENCE_DAYS":          "subdomains.crt.dns_time_fence_days",
	"SUBANALYTICS":                 "subdomains.analytics.enabled",
	"SUBBRUTE":                     "subdomains.brute.enabled",
	"SUBSCRAPING":                  "subdomains.scraping.enabled",
	"SUBPERMUTE":                   "subdomains.permut.enabled",
	"PERMUTATIONS_LIMIT":           "subdomains.permut.limit_bytes",
	"SUBIAPERMUTE":                 "subdomains.permut.ia_enabled",
	"SUBREGEXPERMUTE":              "subdomains.permut.regex_enabled",
	"PERMUTATIONS_WORDLIST_MODE":   "subdomains.permut.wordlist_mode",
	"PERMUTATIONS_SHORT_THRESHOLD": "subdomains.permut.short_threshold",
	"SUBTAKEOVER":                  "subdomains.takeover.enabled",
	"ASN_ENUM":                     "subdomains.asn.enabled",
	"SUB_RECURSIVE_PASSIVE":        "subdomains.recursive.passive_enabled",
	"DEEP_RECURSIVE_PASSIVE":       "subdomains.recursive.passive_depth",
	"SUB_RECURSIVE_BRUTE":          "subdomains.recursive.brute_enabled",
	"ZONETRANSFER":                 "subdomains.zone_transfer.enabled",
	"S3BUCKETS":                    "subdomains.s3_buckets.enabled",
	"REVERSE_IP":                   "subdomains.reverse_ip.enabled",
	"PTR_SWEEP":                    "subdomains.ptr_sweep.enabled",
	"PTR_SWEEP_MAX_IPS":            "subdomains.ptr_sweep.max_ips",
	"SRV_ENUM":                     "subdomains.srv_enum.enabled",
	"NS_DELEGATION":                "subdomains.ns_delegation.enabled",
	"INSCOPE":                      "subdomains.scope.only_resolved",
	"EXCLUDE_SENSITIVE":            "subdomains.scope.exclude_sensitive",
	"DEEP_WILDCARD_FILTER":         "subdomains.scope.deep_wildcard_filter",
	"SUBNOERROR":                   "subdomains.scope.no_error_check",
	"DNS_RESOLVER":                 "subdomains.dns_resolve.resolver",
	"DNS_BRUTE_TIMEOUT":            "subdomains.dns_resolve.brute_timeout",
	"PUREDNS_PUBLIC_LIMIT":         "subdomains.dns_resolve.puredns_public_limit",
	"PUREDNS_TRUSTED_LIMIT":        "subdomains.dns_resolve.puredns_trusted_limit",
	"PUREDNS_WILDCARDTEST_LIMIT":   "subdomains.dns_resolve.puredns_wildcardtest_limit",
	"PUREDNS_WILDCARDBATCH_LIMIT":  "subdomains.dns_resolve.puredns_wildcardbatch_limit",
	"DNSX_THREADS":                 "subdomains.dns_resolve.dnsx_threads",
	"DNSX_RATE_LIMIT":              "subdomains.dns_resolve.dnsx_rate_limit",
	"generate_resolvers":           "subdomains.dns_resolve.generate_resolvers",
	"update_resolvers":             "subdomains.dns_resolve.update_resolvers",
	"TLS_IP_PIVOTS":                "subdomains.tls_pivot.enabled",
	"TLS_IP_SNI_BATCH_SIZE":        "subdomains.tls_pivot.sni_batch_size",
	"TLS_IP_DELTA_PROBE":           "subdomains.tls_pivot.delta_probe",

	// ── web ──
	"WEBPROBEFULL":                   "web.probe.enabled",
	"HTTPX_RATELIMIT":                "web.probe.rate_limit",
	"HTTPX_TIMEOUT":                  "web.probe.timeout_seconds",
	"HTTPX_UNCOMMONPORTS_TIMEOUT":    "web.probe.uncommon_timeout",
	"WEBSCREENSHOT":                  "web.screenshots.enabled",
	"VIRTUALHOSTS":                   "web.virtual_hosts.enabled",
	"FAVIRECON":                      "web.favirecon.enabled",
	"FAVIRECON_CONCURRENCY":          "web.favirecon.concurrency",
	"FAVIRECON_TIMEOUT":              "web.favirecon.timeout",
	"FAVIRECON_RATE_LIMIT":           "web.favirecon.rate_limit",
	"FAVIRECON_PROXY":                "web.favirecon.proxy",
	"WAF_DETECTION":                  "web.waf.enabled",
	"NUCLEICHECK":                    "web.nuclei.enabled",
	"NUCLEI_RATELIMIT":               "web.nuclei.rate_limit",
	"NUCLEI_SEVERITY":                "web.nuclei.severity",
	"NUCLEI_TEMPLATES_PATH":          "web.nuclei.templates_path",
	"NUCLEI_EXTRA_ARGS":              "web.nuclei.extra_args",
	"NUCLEI_DAST":                    "web.nuclei_dast.enabled",
	"NUCLEI_DAST_EXTRA_ARGS":         "web.nuclei_dast.extra_args",
	"FUZZ":                           "web.fuzz.enabled",
	"FFUF_RATELIMIT":                 "web.fuzz.rate_limit",
	"FFUF_MAXTIME":                   "web.fuzz.max_time_seconds",
	"FUZZ_RECURSION_DEPTH":           "web.fuzz.recursion_depth",
	"IIS_SHORTNAME":                  "web.iis_shortname.enabled",
	"CMS_SCANNER":                    "web.cms.enabled",
	"JSCHECKS":                       "web.js.enabled",
	"JS_SUB_EXTRACT":                 "web.js.sub_extract",
	"GETJSWORDS_PYTHON":              "web.js.getjswords_python",
	"URL_CHECK":                      "web.urls.enabled",
	"URL_CHECK_PASSIVE":              "web.urls.passive_enabled",
	"URL_CHECK_ACTIVE":               "web.urls.active_enabled",
	"WAYMORE_TIMEOUT":                "web.urls.waymore_timeout",
	"WAYMORE_LIMIT":                  "web.urls.waymore_limit",
	"URL_GF":                         "web.urls.gf_patterns",
	"URL_EXT":                        "web.urls.ext_classify",
	"WELLKNOWN_PIVOTS":               "web.wellknown.enabled",
	"WELLKNOWN_MAX_TARGETS":          "web.wellknown.max_targets",
	"WORDLIST":                       "web.wordlist.enabled",
	"ROBOTSWORDLIST":                 "web.wordlist.robots_enabled",
	"PASSWORD_DICT":                  "web.wordlist.password_dict",
	"PASSWORD_DICT_ENGINE":           "web.wordlist.password_engine",
	"PASSWORD_DICT_MAX_TARGETS":      "web.wordlist.password_max_targets",
	"PASSWORD_DICT_CEWLER_DEPTH":     "web.wordlist.password_depth",
	"PASSWORD_DICT_CEWLER_TIMEOUT":   "web.wordlist.password_timeout",
	"PASSWORD_MIN_LENGTH":            "web.wordlist.password_min_len",
	"PASSWORD_MAX_LENGTH":            "web.wordlist.password_max_len",
	"PORTSCANNER":                    "web.portscan.enabled",
	"PORTSCAN_PASSIVE":               "web.portscan.passive_enabled",
	"PORTSCAN_ACTIVE":                "web.portscan.active_enabled",
	"PORTSCAN_STRATEGY":              "web.portscan.strategy",
	"PORTSCAN_UDP":                   "web.portscan.udp_enabled",
	"GEO_INFO":                       "web.portscan.geo_info",
	"CDN_IP":                         "web.portscan.cdn_check",
	"CDN_BYPASS":                     "web.portscan.cdn_bypass",
	"NAABU_ENABLE":                   "web.portscan.naabu.enabled",
	"NAABU_RATE":                     "web.portscan.naabu.rate",
	"NAABU_PORTS":                    "web.portscan.naabu.ports",
	"SERVICE_FINGERPRINT":            "web.portscan.service_fingerprint.enabled",
	"SERVICE_FINGERPRINT_ENGINE":     "web.portscan.service_fingerprint.engine",
	"SERVICE_FINGERPRINT_TIMEOUT_MS": "web.portscan.service_fingerprint.timeout_ms",
	"GRAPHQL_CHECK":                  "web.graphql.enabled",
	"GQLSPECTION":                    "web.graphql.deep_introspect",
	"PARAM_DISCOVERY":                "web.param_discovery.enabled",
	"GRPC_SCAN":                      "web.grpc.enabled",
	"LLM_PROBE":                      "web.llm_probe.enabled",
	"LLM_PROBE_AUGUSTUS":             "web.llm_probe.augustus",
	"CLOUD_ENUM_S3_PROFILE":          "web.cloud_enum.s3_profile",
	"CLOUD_ENUM_S3_THREADS":          "web.cloud_enum.s3_threads",
	"KATANA_HEADLESS_PROFILE":        "web.katana.headless_profile",
	"KATANA_HEADLESS_SMART_LIMIT":    "web.katana.headless_smart_limit",

	// ── vulns ──
	"VULNS_GENERAL":             "vulns.enabled",
	"XSS":                       "vulns.xss.enabled",
	"SQLI":                      "vulns.sqli.enabled",
	"SQLMAP":                    "vulns.sqli.sqlmap",
	"GHAURI":                    "vulns.sqli.ghauri",
	"SSRF_CHECKS":               "vulns.ssrf.enabled",
	"SSRF_ALT_MATCH_REGEX":      "vulns.ssrf.alt_match_regex",
	"LFI":                       "vulns.lfi.enabled",
	"LFI_MAX_URLS":              "vulns.lfi.max_urls",
	"SSTI":                      "vulns.ssti.enabled",
	"SSTI_ENGINE":               "vulns.ssti.engine",
	"CRLF_CHECKS":               "vulns.crlf.enabled",
	"SMUGGLING":                 "vulns.smuggling.enabled",
	"COMM_INJ":                  "vulns.cmdi.enabled",
	"WEBCACHE":                  "vulns.cache.enabled",
	"WEBCACHE_TOXICACHE":        "vulns.cache.toxicache",
	"BYPASSER4XX":               "vulns.bypass_4xx.enabled",
	"FUZZPARAMS":                "vulns.fuzz_params.enabled",
	"NUCLEI_DAST_TEMPLATE_PATH": "vulns.nuclei_dast.templates_path",
	"SPRAY":                     "vulns.spray.enabled",
	"SPRAY_ENGINE":              "vulns.spray.engine",
	"SPRAY_BRUTUS_ONLY_DEEP":    "vulns.spray.deep_only",
	"BROKENLINKS":               "vulns.broken_links.enabled",
	"BROKENLINKS_ENGINE":        "vulns.broken_links.engine",
	"TEST_SSL":                  "vulns.ssl.enabled",
	"METADATA":                  "vulns.metadata.enabled",
	"FRAY_EXTRA":                "vulns.fray.enabled",
	"FRAY_CATEGORIES":           "vulns.fray.categories",
	"FRAY_MAX_PAYLOADS":         "vulns.fray.max_payloads",
	"FRAY_TIMEOUT":              "vulns.fray.timeout",
	"FRAY_DELAY":                "vulns.fray.delay",

	// ── osint ──
	"OSINT":                             "osint.enabled",
	"GOOGLE_DORKS":                      "osint.google_dorks.enabled",
	"GITHUB_DORKS":                      "osint.github.enabled",
	"GITHUB_REPOS":                      "osint.github.enabled", // collision: OR-combined with GITHUB_DORKS
	"GITHUB_LEAKS":                      "osint.github.leaks_enabled",
	"GHLEAKS_THREADS":                   "osint.github.threads",
	"SECRETS_ENGINE":                    "osint.github.secrets_engine",
	"SECRETS_SCAN_GIT_HISTORY":          "osint.github.scan_git_history",
	"SECRETS_VALIDATE":                  "osint.github.validate_secrets",
	"GITHUB_ACTIONS_AUDIT":              "osint.github.actions_audit.enabled",
	"GATO_INCLUDE_ALL_ARTIFACT_SECRETS": "osint.github.actions_audit.include_all_artifact_secrets",
	"CLOUD_ENUM":                        "osint.cloud.enabled",
	"EMAILS":                            "osint.emails.enabled",
	"API_LEAKS_POSTLEAKS":               "osint.postman.enabled",
	"POSTLEAKS_THREADS":                 "osint.postman.threads",
	"POSTLEAKS_INCLUDE":                 "osint.postman.include",
	"POSTLEAKS_EXCLUDE":                 "osint.postman.exclude",
	"API_LEAKS":                         "osint.api_leaks.enabled",
	"THIRD_PARTIES":                     "osint.swagger.enabled",
	"SPOOF":                             "osint.spoofy.enabled",
	"MAIL_HYGIENE":                      "osint.mail_hygiene.enabled",
	"DOMAIN_INFO":                       "osint.domain_info.enabled",
	"IP_INFO":                           "osint.ip_info.enabled",
	"IPV6_SCAN":                         "osint.ipv6.enabled",

	// ── notifications ──
	"NOTIFICATION":      "notifications.enabled",
	"SOFT_NOTIFICATION": "notifications.soft_enabled",
	"slack_channel":     "notifications.slack.channel",
	"slack_auth":        "notifications.slack.webhook_url",

	// ── axiom ──
	"AXIOM_FLEET_NAME":       "axiom.fleet_name",
	"AXIOM_FLEET_COUNT":      "axiom.fleet_count",
	"AXIOM_FLEET_REGIONS":    "axiom.fleet_regions",
	"AXIOM_FLEET_SHUTDOWN":   "axiom.shutdown_on_end",
	"AXIOM_AUTO_FIX_HOSTKEY": "axiom.auto_fix_hostkey",
	"AXIOM_FLEET_LAUNCH":     "axiom.fleet_launch",
	"AXIOM_EXTRA_ARGS":       "axiom.extra_args",

	// ── output ──
	"OUTPUT_VERBOSITY":   "output.verbosity",
	"EXPORT_FORMAT":      "output.export_format",
	"ASSET_STORE":        "output.asset_store",
	"REPORT_ONLY":        "output.report_only",
	"HOTLIST_TOP":        "output.hotlist_top",
	"CHUNK_LIMIT":        "output.chunk_limit",
	"REMOVETMP":          "output.remove_tmp",
	"REMOVELOG":          "output.remove_log",
	"PRESERVE":           "output.preserve_called_fn",
	"SENDZIPNOTIFY":      "output.send_zip_notify",
	"STRUCTURED_LOGGING": "output.structured_logging",
	"MIN_DISK_SPACE_GB":  "output.min_disk_space_gb",
	"MAX_LOG_FILES":      "output.log_rotation.max_files",
	"MAX_LOG_AGE_DAYS":   "output.log_rotation.max_age_days",

	// ── ai ──
	"AI_EXECUTABLE":             "ai.executable",
	"AI_MODEL":                  "ai.model",
	"AI_REPORT_TYPE":            "ai.report_type",
	"AI_REPORT_PROFILE":         "ai.report_profile",
	"AI_PROMPTS_FILE":           "ai.prompts_file",
	"AI_MAX_CHARS_PER_FILE":     "ai.max_chars_per_file",
	"AI_MAX_FILES_PER_CATEGORY": "ai.max_files_per_category",
	"AI_REDACT":                 "ai.redact",
	"AI_ALLOW_MODEL_PULL":       "ai.allow_model_pull",
	"AI_STRICT":                 "ai.strict",

	// ── integrations ──
	"FARADAY":           "integrations.faraday.enabled",
	"FARADAY_WORKSPACE": "integrations.faraday.workspace",
	"PROXY":             "integrations.proxy.enabled",
	"proxy_url":         "integrations.proxy.url",

	// ── incremental / monitor ──
	"INCREMENTAL_MODE":     "incremental.enabled",
	"MONITOR_MODE":         "monitor.enabled",
	"MONITOR_INTERVAL_MIN": "monitor.interval_minutes",
	"MONITOR_MAX_CYCLES":   "monitor.max_cycles",
	"MONITOR_MIN_SEVERITY": "monitor.min_severity",
	"ALERT_SUPPRESSION":    "monitor.alert_suppression",

	// ── adaptive_rate ──
	"ADAPTIVE_RATE_LIMIT":        "adaptive_rate.enabled",
	"MIN_RATE_LIMIT":             "adaptive_rate.min_rate",
	"MAX_RATE_LIMIT":             "adaptive_rate.max_rate",
	"RATE_LIMIT_BACKOFF_FACTOR":  "adaptive_rate.backoff_factor",
	"RATE_LIMIT_INCREASE_FACTOR": "adaptive_rate.increase_factor",

	// ── cache ──
	"CACHE_MAX_AGE_DAYS":           "cache.max_age_days",
	"CACHE_MAX_AGE_DAYS_RESOLVERS": "cache.max_age_days_resolvers",
	"CACHE_MAX_AGE_DAYS_WORDLISTS": "cache.max_age_days_wordlists",
	"CACHE_MAX_AGE_DAYS_TOOLS":     "cache.max_age_days_tools",
	"CACHE_REFRESH":                "cache.refresh",

	// ── paths (lowercase list keys + tokens; ${VAR}-valued ones route to Case B
	//    at migrate-time because their value carries unresolved shell expansion) ──
	"DATA_DIR":                          "paths.data_dir",
	"WORDLISTS_DIR":                     "paths.wordlists_dir",
	"PATTERNS_DIR":                      "paths.patterns_dir",
	"fuzz_wordlist":                     "paths.fuzz_wordlist",
	"lfi_wordlist":                      "paths.lfi_wordlist",
	"ssti_wordlist":                     "paths.ssti_wordlist",
	"subs_wordlist":                     "paths.subs_wordlist",
	"subs_wordlist_big":                 "paths.subs_wordlist_big",
	"headers_inject":                    "paths.headers_inject",
	"resolvers":                         "paths.resolvers",
	"resolvers_trusted":                 "paths.resolvers_trusted",
	"GITHUB_TOKENS":                     "paths.github_tokens",
	"GITLAB_TOKENS":                     "paths.gitlab_tokens",
	"resolvers_url":                     "paths.resolvers_download.url",
	"resolvers_trusted_url":             "paths.resolvers_download.trusted_url",
	"RESOLVER_DOWNLOAD_CONNECT_TIMEOUT": "paths.resolvers_download.connect_timeout",
	"RESOLVER_DOWNLOAD_MAX_TIME":        "paths.resolvers_download.max_time",
	"RESOLVER_DOWNLOAD_RETRY":           "paths.resolvers_download.retry",
	"RESOLVER_DOWNLOAD_RETRY_DELAY":     "paths.resolvers_download.retry_delay",

	// ── api_keys ──
	"SHODAN_API_KEY": "api_keys.shodan",
	"WHOISXML_API":   "api_keys.whoisxml",
	"PDCP_API_KEY":   "api_keys.pdcp",
	"XSS_SERVER":     "api_keys.xss_server",
	"COLLAB_SERVER":  "api_keys.collab_server",

	// ── advanced ──
	"DEEP":                   "advanced.deep",
	"DEEP_LIMIT":             "advanced.deep_limit",
	"DEEP_LIMIT2":            "advanced.deep_limit2",
	"DIFF":                   "advanced.diff",
	"QUICK_RESCAN":           "advanced.quick_rescan",
	"SHOW_COMMANDS":          "advanced.show_commands",
	"install_golang":         "advanced.install_golang",
	"upgrade_tools":          "advanced.upgrade_tools",
	"upgrade_before_running": "advanced.upgrade_before_running",
	"HEADER":                 "advanced.header",
	"PERF_PROFILE":           "advanced.perf_profile",

	// ── advanced.tools ──
	"FFUF_FLAGS":                   "advanced.tools.ffuf.flags",
	"GOTATOR_FLAGS":                "advanced.tools.gotator.flags",
	"TLSX_THREADS":                 "advanced.tools.tlsx.threads",
	"XNLINKFINDER_DEPTH":           "advanced.tools.xnlinkfinder.depth",
	"DNSVALIDATOR_THREADS":         "advanced.tools.dnsvalidator.threads",
	"INTERLACE_THREADS":            "advanced.tools.interlace.threads",
	"TInjA_RATELIMIT":              "advanced.tools.tinja.rate_limit",
	"TInjA_TIMEOUT":                "advanced.tools.tinja.timeout",
	"SSTIMAP_LEVEL":                "advanced.tools.sstimap.level",
	"SSTIMAP_DELAY":                "advanced.tools.sstimap.delay",
	"SSTIMAP_LEGACY":               "advanced.tools.sstimap.legacy",
	"SSTIMAP_GENERIC":              "advanced.tools.sstimap.generic",
	"SECOND_ORDER_CONFIG":          "advanced.tools.second_order.config",
	"SECOND_ORDER_DEPTH":           "advanced.tools.second_order.depth",
	"SECOND_ORDER_THREADS":         "advanced.tools.second_order.threads",
	"SECOND_ORDER_INSECURE":        "advanced.tools.second_order.insecure",
	"TOXICACHE_THREADS":            "advanced.tools.toxicache.threads",
	"TOXICACHE_USER_AGENT":         "advanced.tools.toxicache.user_agent",
	"BRUTUS_USERNAMES":             "advanced.tools.brutus.usernames",
	"BRUTUS_PASSWORDS":             "advanced.tools.brutus.passwords",
	"BRUTUS_KEY_FILE":              "advanced.tools.brutus.key_file",
	"AXIOM_RESOLVERS_PATH":         "advanced.tools.axiom.resolvers_path",
	"AXIOM_RESOLVERS_TRUSTED_PATH": "advanced.tools.axiom.resolvers_trusted_path",

	// ── advanced.timing_estimates ──
	"TIME_EST_NUCLEI":    "advanced.timing_estimates.nuclei",
	"TIME_EST_FUZZ":      "advanced.timing_estimates.fuzz",
	"TIME_EST_URLCHECKS": "advanced.timing_estimates.urlchecks",
	"TIME_EST_JSCHECKS":  "advanced.timing_estimates.jschecks",
	"TIME_EST_API":       "advanced.timing_estimates.api",
	"TIME_EST_GQL":       "advanced.timing_estimates.gql",
	"TIME_EST_PARAM":     "advanced.timing_estimates.param",
	"TIME_EST_GRPC":      "advanced.timing_estimates.grpc",
	"TIME_EST_IIS":       "advanced.timing_estimates.iis",

	// ── advanced.parallel_batch_sizes ──
	"PAR_OSINT_GROUP1_SIZE":          "advanced.parallel_batch_sizes.osint_group1",
	"PAR_OSINT_GROUP2_SIZE":          "advanced.parallel_batch_sizes.osint_group2",
	"PAR_SUB_PASSIVE_GROUP_SIZE":     "advanced.parallel_batch_sizes.sub_passive",
	"PAR_SUB_DEP_ACTIVE_GROUP_SIZE":  "advanced.parallel_batch_sizes.sub_dep_active",
	"PAR_SUB_POST_ACTIVE_GROUP_SIZE": "advanced.parallel_batch_sizes.sub_post_active",
	"PAR_SUB_BRUTE_GROUP_SIZE":       "advanced.parallel_batch_sizes.sub_brute",
	"PAR_WEB_DETECT_GROUP_SIZE":      "advanced.parallel_batch_sizes.web_detect",
	"PAR_VULNS_GROUP1_SIZE":          "advanced.parallel_batch_sizes.vulns_group1",
	"PAR_VULNS_GROUP2_SIZE":          "advanced.parallel_batch_sizes.vulns_group2",
	"PAR_VULNS_GROUP4_SIZE":          "advanced.parallel_batch_sizes.vulns_group4",

	// ── advanced.parallel_ui ──
	"PARALLEL_UI_MODE":                     "advanced.parallel_ui.mode",
	"PARALLEL_PROGRESS_SHOW_ETA":           "advanced.parallel_ui.show_eta",
	"PARALLEL_PROGRESS_SHOW_ACTIVE":        "advanced.parallel_ui.show_active",
	"PARALLEL_PROGRESS_COMPACT_ACTIVE_MAX": "advanced.parallel_ui.compact_active_max",
	"PARALLEL_TRACE_SLOW_SECONDS":          "advanced.parallel_ui.trace_slow_seconds",
}

// legacyAliasSecretKeys is the set of v1 keys whose v2 target is log.Secret-typed.
// The migrator redacts their values to "***" in stderr/--dry-run output but writes
// the real value to the target .toml (RESEARCH landmine / threat T-14-02).
var legacyAliasSecretKeys = map[string]bool{
	"SHODAN_API_KEY": true,
	"WHOISXML_API":   true,
	"PDCP_API_KEY":   true,
	"slack_auth":     true,
	// Additional secret v1 names that live in secrets.cfg (handled if present).
	"telegram_key":       true,
	"telegram_bot_token": true,
	"discord_url":        true,
	"discord_webhook":    true,
}

// supersededInfo annotates a Case-B key: WHY it has no live v2 home, and the
// optional v2 path a user can set to pin the value manually.
type supersededInfo struct {
	reason string // human-readable reason (rendered in the # SUPERSEDED comment)
	pin    string // optional v2 path hint ("" = none)
}

// supersededKeys is the Case-B set: v1 keys the migrator preserves as
// `# SUPERSEDED …` comments rather than live v2 keys. These are ADR §2.4
// drop-list keys (bash globals, computed thread counts auto-scaled by v2,
// file-read/${VAR}-assembled values) plus v1-only tuning knobs with no v2 field.
// Emitting them as comments preserves the value (D-02 keep-all) without tripping
// the loader's per-load unknown-key warning (CUT-06).
var supersededKeys = map[string]supersededInfo{
	// Bash bootstrap globals / shell introspection (ADR §2.4).
	"tools":            {reason: "v2 resolves external binaries via PATH; set GOPATH/GOBIN in the environment", pin: ""},
	"SCRIPTPATH":       {reason: "computed at runtime by the Go binary", pin: ""},
	"_detected_shell":  {reason: "internal bash runtime var; not applicable in a Go binary", pin: ""},
	"profile_shell":    {reason: "bash shell detection; not applicable in a Go binary", pin: ""},
	"reconftw_version": {reason: "v2 embeds the version at build time via -ldflags", pin: ""},
	"GOROOT":           {reason: "Go environment; set as an OS environment variable", pin: ""},
	"GOPATH":           {reason: "Go environment; set as an OS environment variable", pin: ""},
	"DEBUG_STD":        {reason: "bash redirect syntax; v2 uses the slog level", pin: "output.verbosity"},
	"DEBUG_ERROR":      {reason: "bash redirect syntax; v2 uses the slog level", pin: "output.log_level"},

	// Auto-scaled thread counts — v2 derives these from runtime.NumCPU() when the
	// corresponding v2 field is 0 (auto). The migrator evaluates the arithmetic to
	// the concrete host value for reference but does NOT pin it (ADR §2.4).
	"AVAILABLE_CORES":             {reason: "v2 auto-detects CPU count via runtime.NumCPU()", pin: ""},
	"FFUF_THREADS":                {reason: "v2 auto-scales fuzz threads (0 = auto)", pin: "web.fuzz.threads"},
	"HTTPX_THREADS":               {reason: "v2 auto-scales probe threads (0 = auto)", pin: "web.probe.threads"},
	"HTTPX_UNCOMMONPORTS_THREADS": {reason: "v2 auto-scales uncommon-port probe threads (0 = auto)", pin: "web.probe.uncommon_threads"},
	"KATANA_THREADS":              {reason: "v2 auto-scales katana threads (0 = auto)", pin: "web.katana.threads"},
	"BRUTESPRAY_CONCURRENCE":      {reason: "v2 auto-scales brutespray concurrence (0 = auto)", pin: "advanced.tools.brutespray.concurrence"},
	"DNSTAKE_THREADS":             {reason: "v2 auto-scales dnstake threads (0 = auto)", pin: "advanced.tools.dnstake.threads"},
	"DALFOX_THREADS":              {reason: "v2 auto-scales dalfox threads (0 = auto)", pin: "advanced.tools.dalfox.threads"},
	"ARJUN_THREADS":               {reason: "v2 auto-scales arjun threads (0 = auto)", pin: "advanced.tools.arjun.threads"},

	// File-read / ${VAR}-assembled port lists — v2 reads the config files directly.
	"TLS_PORTS":          {reason: "v2 reads config/tls_ports.txt directly; no config key needed", pin: ""},
	"UNCOMMON_PORTS_WEB": {reason: "v2 reads config/uncommon_ports_web.txt directly", pin: ""},
	"WEBPROBE_PORTS":     {reason: "set web.probe.ports; uncommon ports are appended automatically", pin: "web.probe.ports"},

	// v1-only orchestration knobs with no v2 field (v2 uses the scheduler).
	"PARALLEL_MODE":               {reason: "v2 always uses the scheduler; concurrency.max_jobs controls parallelism", pin: "concurrency.max_jobs"},
	"CONTINUE_ON_TOOL_ERROR":      {reason: "v2 uses scheduler.failure_policy + per-module overrides (true→best_effort, false→fail_fast)", pin: "scheduler.failure_policy"},
	"PAR_WEB_ANALYSIS_LIGHT_SIZE": {reason: "no v2 analog; light web-analysis batch merged into web_detect", pin: "advanced.parallel_batch_sizes.web_detect"},

	// Duration whose v2 field is integer-minutes (type mismatch — set manually).
	"DNS_RESOLVE_TIMEOUT": {reason: "v2 subdomains.dns_resolve.timeout_minutes is integer minutes; v1 used a duration", pin: "subdomains.dns_resolve.timeout_minutes"},

	// Raw nmap option strings — v2 uses portscan.strategy + naabu settings.
	"PORTSCAN_ACTIVE_OPTIONS": {reason: "v2 uses web.portscan.strategy + naabu settings", pin: "web.portscan.strategy"},
	"PORTSCAN_DEEP_OPTIONS":   {reason: "v2 uses web.portscan.strategy + naabu settings", pin: "web.portscan.strategy"},
	"PORTSCAN_UDP_OPTIONS":    {reason: "v2 uses web.portscan.udp_enabled + naabu settings", pin: "web.portscan.udp_enabled"},

	// Swagger/sj-specific tuning — v2 exposes only osint.swagger.enabled.
	"SJ_CHECK":       {reason: "v2 exposes only osint.swagger.enabled", pin: "osint.swagger.enabled"},
	"SJ_BRUTE":       {reason: "no v2 analog (sj brute tuning)", pin: ""},
	"SJ_AUTOMATE":    {reason: "no v2 analog (sj automate tuning)", pin: ""},
	"SJ_TIMEOUT":     {reason: "no v2 analog (sj per-request timeout)", pin: ""},
	"SJ_MAX_TARGETS": {reason: "no v2 analog (sj brute target cap)", pin: ""},

	// LFI-specific tool tuning — no dedicated v2 fields.
	"LFI_INTERLACE_THREADS": {reason: "no v2 analog (LFI interlace concurrency)", pin: ""},
	"LFI_INTERLACE_TIMEOUT": {reason: "no v2 analog (LFI interlace timeout)", pin: ""},
	"LFI_FFUF_THREADS":      {reason: "no v2 analog (LFI ffuf threads)", pin: ""},
	"LFI_FFUF_RATELIMIT":    {reason: "no v2 analog (LFI ffuf rate limit)", pin: ""},
	"LFI_FFUF_TIMEOUT":      {reason: "no v2 analog (LFI ffuf request timeout)", pin: ""},
	"LFI_FFUF_MAXTIME":      {reason: "no v2 analog (LFI ffuf max time)", pin: ""},
	"LFI_FOLLOW_REDIRECTS":  {reason: "no v2 analog (LFI follow-redirects flag)", pin: ""},

	// Misc v1-only knobs with no v2 field.
	"CMSSCAN_TIMEOUT":         {reason: "no v2 analog (CMSeeK scan timeout)", pin: ""},
	"WAF_PER_HOST_TIMEOUT":    {reason: "no v2 analog (wafw00f per-host timeout)", pin: ""},
	"EXIFRAY_TIMEOUT":         {reason: "no v2 analog (exifray HTTP timeout)", pin: ""},
	"EXIFRAY_RETRIES":         {reason: "no v2 analog (exifray retry count)", pin: ""},
	"PARAM_DISCOVERY_TIMEOUT": {reason: "no v2 analog (arjun global timeout)", pin: ""},
	"PARAM_MAX_URLS":          {reason: "no v2 analog (arjun URL cap)", pin: ""},
	"RESOLVER_IQ":             {reason: "no v2 analog (experimental resolver preference)", pin: ""},
	"METADATA_URLFINDER":      {reason: "no v2 analog; v2 metadata discovery is opportunistic", pin: "vulns.metadata.enabled"},
	"ALERT_SEEN_FILE":         {reason: "v2 manages the alert-fingerprint store internally", pin: ""},
	"GETJSWORDS_VENV":         {reason: "no v2 analog; v2 uses web.js.getjswords_python", pin: "web.js.getjswords_python"},
	"fuzzing_remote_list":     {reason: "no v2 analog (Axiom remote fuzzing wordlist URL)", pin: ""},

	// Bash terminal color codes — not config.
	"bred":    {reason: "bash terminal color code; not config", pin: ""},
	"bblue":   {reason: "bash terminal color code; not config", pin: ""},
	"bgreen":  {reason: "bash terminal color code; not config", pin: ""},
	"byellow": {reason: "bash terminal color code; not config", pin: ""},
	"red":     {reason: "bash terminal color code; not config", pin: ""},
	"blue":    {reason: "bash terminal color code; not config", pin: ""},
	"green":   {reason: "bash terminal color code; not config", pin: ""},
	"cyan":    {reason: "bash terminal color code; not config", pin: ""},
	"yellow":  {reason: "bash terminal color code; not config", pin: ""},
	"reset":   {reason: "bash terminal color code; not config", pin: ""},
}
