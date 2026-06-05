// Package config is the v2-native TOML configuration schema for reconFTW.
//
// The schema is BINDING per ADR 0002 §2.2 (lines 288-1023). Every key, every
// default, and every validation rule is locked there; this Go code IMPLEMENTS
// the schema — it does NOT invent it. Any change to the schema requires an
// ADR amendment (D-06/D-07 governance).
//
// Loader entry point: Load(cliOverrides) (*Config, error). 8-source precedence
// per ADR §2.3; see loader.go for the merge sequence.
//
// Secret-typed fields use log.Secret so that any slog.Attr referencing them
// auto-redacts to "***" (Layer 1 of two-layer redaction defense — ADR §10).
// Plus, after Load returns, the caller MUST iterate every Secret field and call
// Redactor.Register(string(value)) so Layer 2 substring scrubbing also covers
// values that escape through error strings or %s format calls.
//
// Library mandate: knadh/koanf/v2 + pelletier/go-toml/v2 ONLY. The competing
// configuration library is BANNED here — it silently lowercases TOML keys,
// which breaks the [legacy] table alias mechanism (ADR §2.1 lines 279-282;
// RESEARCH.md PITFALL §1).
package config

import (
	"io"

	"github.com/six2dez/reconftw/internal/core/log"
)

// Config is the root configuration struct mirroring ADR §2.2 verbatim. Every
// sub-struct is named after its TOML section. Every leaf field carries a koanf
// tag (BINDING — the TOML key name) and, where ADR §2.5 specifies a rule, a
// validate tag.
//
// Field-naming convention: Go fields are PascalCase versions of the TOML
// snake_case keys. The koanf tag is the source of truth for the merge layer.
//
// SECRET FIELD ENUMERATION (W10 — these MUST be log.Secret-typed and registered
// with the Redactor immediately after Load returns):
//   - Notifications.Slack.WebhookURL    log.Secret
//   - Notifications.Telegram.BotToken   log.Secret
//   - Notifications.Discord.WebhookURL  log.Secret
//   - AI.OpenAIKey                      log.Secret
//   - AI.AnthropicKey                   log.Secret
//   - MCP.APIKey                        log.Secret
//   - APIKeys.Shodan                    log.Secret
//   - APIKeys.WhoisXML                  log.Secret
//   - APIKeys.PDCP                      log.Secret
//
// Axiom credentials (SSH/fleet token) flow through subprocess env vars and ssh
// stderr; they are NOT stored in Config as Go fields (per ADR §6 Axiom note).
// The Redactor.Register() call must still be made for them at Boot time once
// they are read from environment (Plan 03-06 owns this wiring).
type Config struct {
	Concurrency   ConcurrencyConfig   `koanf:"concurrency"`
	Subdomains    SubdomainsConfig    `koanf:"subdomains"`
	Web           WebConfig           `koanf:"web"`
	Vulns         VulnsConfig         `koanf:"vulns"`
	OSINT         OSINTConfig         `koanf:"osint"`
	Notifications NotificationsConfig `koanf:"notifications"`
	Axiom         AxiomConfig         `koanf:"axiom"`
	MCP           MCPConfig           `koanf:"mcp"`
	Scheduler     SchedulerConfig     `koanf:"scheduler"`
	Output        OutputConfig        `koanf:"output"`
	AI            AIConfig            `koanf:"ai"`
	Integrations  IntegrationsConfig  `koanf:"integrations"`
	Incremental   IncrementalConfig   `koanf:"incremental"`
	Monitor       MonitorConfig       `koanf:"monitor"`
	AdaptiveRate  AdaptiveRateConfig  `koanf:"adaptive_rate"`
	Cache         CacheConfig         `koanf:"cache"`
	Paths         PathsConfig         `koanf:"paths"`
	APIKeys       APIKeysConfig       `koanf:"api_keys"`
	Advanced      AdvancedConfig      `koanf:"advanced"`

	// Legacy is populated from the [legacy] TOML table by the v2 migrator
	// (Phase 11). The loader resolves these to v2-native keys via the static
	// legacyAliasMap; on collision the v2-native value wins and a WARN log
	// line is emitted (ADR §2.3 lines 1039-1055).
	Legacy map[string]any `koanf:"legacy"`
}

// ---------------- Concurrency ----------------

// ConcurrencyConfig mirrors ADR §2.2 [concurrency].
type ConcurrencyConfig struct {
	MaxJobs           int    `koanf:"max_jobs"             validate:"min=1,max=64"`
	HeartbeatSeconds  int    `koanf:"heartbeat_seconds"    validate:"min=1,max=3600"`
	LogMode           string `koanf:"log_mode"             validate:"oneof=summary tail full"`
	TailLines         int    `koanf:"tail_lines"           validate:"min=0,max=1000"`
	JobTimeoutSeconds int    `koanf:"job_timeout_seconds"  validate:"min=0,max=86400"`
	KillGraceSeconds  int    `koanf:"kill_grace_seconds"   validate:"min=1,max=300"`
}

// ---------------- Subdomains ----------------

// SubdomainsConfig mirrors ADR §2.2 [subdomains.*].
type SubdomainsConfig struct {
	Enabled      bool                 `koanf:"enabled"`
	Passive      SubPassive           `koanf:"passive"`
	CRT          SubCRT               `koanf:"crt"`
	Analytics    SubAnalytics         `koanf:"analytics"`
	Brute        SubBrute             `koanf:"brute"`
	Scraping     SubScraping          `koanf:"scraping"`
	Permut       SubPermut            `koanf:"permut"`
	Takeover     SubTakeover          `koanf:"takeover"`
	ASN          SubASN               `koanf:"asn"`
	Recursive    SubRecursive         `koanf:"recursive"`
	ZoneTransfer SubZoneTransfer      `koanf:"zone_transfer"`
	S3Buckets    SubS3Buckets         `koanf:"s3_buckets"`
	ReverseIP    SubReverseIP         `koanf:"reverse_ip"`
	PTRSweep     SubPTRSweep          `koanf:"ptr_sweep"`
	SRVEnum      SubSRVEnum           `koanf:"srv_enum"`
	NSDelegation SubNSDelegation      `koanf:"ns_delegation"`
	Scope        SubScope             `koanf:"scope"`
	DNSResolve   SubDNSResolve        `koanf:"dns_resolve"`
	TLSPivot     SubTLSPivot          `koanf:"tls_pivot"`
}

type SubPassive struct {
	Enabled        bool `koanf:"enabled"`
	TimeoutMinutes int  `koanf:"timeout_minutes" validate:"min=0,max=86400"`
}

type SubCRT struct {
	Enabled          bool `koanf:"enabled"`
	Limit            int  `koanf:"limit"               validate:"min=1,max=9999999"`
	DNSTimeFenceDays int  `koanf:"dns_time_fence_days" validate:"min=0,max=3650"`
}

type SubAnalytics struct {
	Enabled bool `koanf:"enabled"`
}

type SubBrute struct {
	Enabled      bool `koanf:"enabled"`
	MinResolvers int  `koanf:"min_resolvers" validate:"min=0,max=10000"`
}

type SubScraping struct {
	Enabled bool `koanf:"enabled"`
}

type SubPermut struct {
	Enabled        bool   `koanf:"enabled"`
	LimitBytes     int64  `koanf:"limit_bytes"      validate:"min=0,max=10737418240"`
	IAEnabled      bool   `koanf:"ia_enabled"`
	RegexEnabled   bool   `koanf:"regex_enabled"`
	WordlistMode   string `koanf:"wordlist_mode"    validate:"oneof=auto full short"`
	ShortThreshold int    `koanf:"short_threshold"  validate:"min=0,max=1000000"`
	MinFreeMemGB   int    `koanf:"min_free_mem_gb"  validate:"min=0,max=1024"`
}

type SubTakeover struct {
	Enabled bool `koanf:"enabled"`
}

type SubASN struct {
	Enabled bool `koanf:"enabled"`
}

type SubRecursive struct {
	PassiveEnabled bool `koanf:"passive_enabled"`
	PassiveDepth   int  `koanf:"passive_depth"   validate:"min=0,max=1000"`
	BruteEnabled   bool `koanf:"brute_enabled"`
}

type SubZoneTransfer struct {
	Enabled bool `koanf:"enabled"`
}

type SubS3Buckets struct {
	Enabled bool `koanf:"enabled"`
}

type SubReverseIP struct {
	Enabled bool `koanf:"enabled"`
}

type SubPTRSweep struct {
	Enabled bool `koanf:"enabled"`
	MaxIPs  int  `koanf:"max_ips" validate:"min=0,max=10000000"`
}

type SubSRVEnum struct {
	Enabled bool `koanf:"enabled"`
}

type SubNSDelegation struct {
	Enabled bool `koanf:"enabled"`
}

type SubScope struct {
	OnlyResolved       bool `koanf:"only_resolved"`
	ExcludeSensitive   bool `koanf:"exclude_sensitive"`
	DeepWildcardFilter bool `koanf:"deep_wildcard_filter"`
	NoErrorCheck       bool `koanf:"no_error_check"`
}

type SubDNSResolve struct {
	Resolver                    string `koanf:"resolver"                       validate:"oneof=auto puredns dnsx"`
	TimeoutMinutes              int    `koanf:"timeout_minutes"                validate:"min=0,max=86400"`
	BruteTimeout                string `koanf:"brute_timeout"`
	PurednsPublicLimit          int    `koanf:"puredns_public_limit"           validate:"min=0,max=100000"`
	PurednsTrustedLimit         int    `koanf:"puredns_trusted_limit"          validate:"min=0,max=100000"`
	PurednsWildcardtestLimit    int    `koanf:"puredns_wildcardtest_limit"     validate:"min=0,max=10000"`
	PurednsWildcardbatchLimit   int    `koanf:"puredns_wildcardbatch_limit"    validate:"min=0,max=10000000"`
	DNSXThreads                 int    `koanf:"dnsx_threads"                   validate:"min=0,max=10000"`
	DNSXRateLimit               int    `koanf:"dnsx_rate_limit"                validate:"min=0,max=100000"`
	GenerateResolvers           bool   `koanf:"generate_resolvers"`
	UpdateResolvers             bool   `koanf:"update_resolvers"`
}

type SubTLSPivot struct {
	Enabled      bool `koanf:"enabled"`
	SNIBatchSize int  `koanf:"sni_batch_size" validate:"min=0,max=100000"`
	DeltaProbe   bool `koanf:"delta_probe"`
}

// ---------------- Web ----------------

// WebConfig mirrors ADR §2.2 [web.*].
type WebConfig struct {
	Probe         WebProbe         `koanf:"probe"`
	Screenshots   WebScreenshots   `koanf:"screenshots"`
	VirtualHosts  WebVirtualHosts  `koanf:"virtual_hosts"`
	Favirecon     WebFavirecon     `koanf:"favirecon"`
	WAF           WebWAF           `koanf:"waf"`
	Nuclei        WebNuclei        `koanf:"nuclei"`
	NucleiDAST    WebNucleiDAST    `koanf:"nuclei_dast"`
	Fuzz          WebFuzz          `koanf:"fuzz"`
	IISShortname  WebIISShortname  `koanf:"iis_shortname"`
	CMS           WebCMS           `koanf:"cms"`
	JS            WebJS            `koanf:"js"`
	URLs          WebURLs          `koanf:"urls"`
	WellKnown     WebWellKnown     `koanf:"wellknown"`
	Wordlist      WebWordlist      `koanf:"wordlist"`
	Portscan      WebPortscan      `koanf:"portscan"`
	GraphQL       WebGraphQL       `koanf:"graphql"`
	ParamDiscover WebParamDiscover `koanf:"param_discovery"`
	GRPC          WebGRPC          `koanf:"grpc"`
	LLMProbe      WebLLMProbe      `koanf:"llm_probe"`
	CloudEnum     WebCloudEnum     `koanf:"cloud_enum"`
	Katana        WebKatana        `koanf:"katana"`
}

type WebProbe struct {
	Enabled         bool   `koanf:"enabled"`
	Ports           string `koanf:"ports"`
	RateLimit       int    `koanf:"rate_limit"        validate:"min=0,max=10000"`
	TimeoutSeconds  int    `koanf:"timeout_seconds"   validate:"min=1,max=300"`
	Threads         int    `koanf:"threads"           validate:"min=0,max=10000"`
	UncommonEnabled bool   `koanf:"uncommon_enabled"`
	UncommonThreads int    `koanf:"uncommon_threads"  validate:"min=0,max=10000"`
	UncommonTimeout int    `koanf:"uncommon_timeout"  validate:"min=0,max=300"`
}

type WebScreenshots struct {
	Enabled bool `koanf:"enabled"`
}

type WebVirtualHosts struct {
	Enabled bool `koanf:"enabled"`
}

type WebFavirecon struct {
	Enabled     bool   `koanf:"enabled"`
	Concurrency int    `koanf:"concurrency" validate:"min=0,max=10000"`
	Timeout     int    `koanf:"timeout"     validate:"min=0,max=600"`
	RateLimit   int    `koanf:"rate_limit"  validate:"min=0,max=10000"`
	Proxy       string `koanf:"proxy"       validate:"omitempty,url"`
}

type WebWAF struct {
	Enabled bool `koanf:"enabled"`
}

type WebNuclei struct {
	Enabled       bool   `koanf:"enabled"`
	RateLimit     int    `koanf:"rate_limit"     validate:"min=0,max=10000"`
	Severity      string `koanf:"severity"       validate:"omitempty,nuclei_severity"`
	TemplatesPath string `koanf:"templates_path" validate:"omitempty,nopath_traversal"`
	ExtraArgs     string `koanf:"extra_args"`
}

type WebNucleiDAST struct {
	Enabled   bool   `koanf:"enabled"`
	ExtraArgs string `koanf:"extra_args"`
}

type WebFuzz struct {
	Enabled         bool `koanf:"enabled"`
	RateLimit       int  `koanf:"rate_limit"        validate:"min=0,max=10000"`
	Threads         int  `koanf:"threads"           validate:"min=0,max=500"`
	MaxTimeSeconds  int  `koanf:"max_time_seconds"  validate:"min=0,max=86400"`
	RecursionDepth  int  `koanf:"recursion_depth"   validate:"min=0,max=20"`
}

type WebIISShortname struct {
	Enabled bool `koanf:"enabled"`
}

type WebCMS struct {
	Enabled bool `koanf:"enabled"`
}

type WebJS struct {
	Enabled          bool   `koanf:"enabled"`
	SubExtract       bool   `koanf:"sub_extract"`
	GetJSWordsPython string `koanf:"getjswords_python"`
}

type WebURLs struct {
	Enabled         bool   `koanf:"enabled"`
	PassiveEnabled  bool   `koanf:"passive_enabled"`
	ActiveEnabled   bool   `koanf:"active_enabled"`
	WaymoreTimeout  string `koanf:"waymore_timeout"`
	WaymoreLimit    int    `koanf:"waymore_limit"   validate:"min=0,max=1000000"`
	GFPatterns      bool   `koanf:"gf_patterns"`
	ExtClassify     bool   `koanf:"ext_classify"`
}

type WebWellKnown struct {
	Enabled    bool `koanf:"enabled"`
	MaxTargets int  `koanf:"max_targets" validate:"min=0,max=100000"`
}

type WebWordlist struct {
	Enabled             bool   `koanf:"enabled"`
	RobotsEnabled       bool   `koanf:"robots_enabled"`
	PasswordDict        bool   `koanf:"password_dict"`
	PasswordEngine      string `koanf:"password_engine"      validate:"oneof=cewler pydictor"`
	PasswordMaxTargets  int    `koanf:"password_max_targets" validate:"min=0,max=10000"`
	PasswordDepth       int    `koanf:"password_depth"       validate:"min=0,max=20"`
	PasswordTimeout     int    `koanf:"password_timeout"     validate:"min=0,max=3600"`
	PasswordMinLen      int    `koanf:"password_min_len"     validate:"min=0,max=256"`
	PasswordMaxLen      int    `koanf:"password_max_len"     validate:"min=0,max=256"`
}

type WebPortscan struct {
	Enabled            bool   `koanf:"enabled"`
	PassiveEnabled     bool   `koanf:"passive_enabled"`
	ActiveEnabled      bool   `koanf:"active_enabled"`
	Strategy           string `koanf:"strategy"             validate:"oneof=legacy naabu_nmap"`
	UDPEnabled         bool   `koanf:"udp_enabled"`
	GeoInfo            bool   `koanf:"geo_info"`
	CDNCheck           bool   `koanf:"cdn_check"`
	CDNBypass          bool   `koanf:"cdn_bypass"`
	Naabu              WebNaabu              `koanf:"naabu"`
	ServiceFingerprint WebServiceFingerprint `koanf:"service_fingerprint"`
}

type WebNaabu struct {
	Enabled bool   `koanf:"enabled"`
	Rate    int    `koanf:"rate"  validate:"min=0,max=1000000"`
	Ports   string `koanf:"ports"`
}

type WebServiceFingerprint struct {
	Enabled   bool   `koanf:"enabled"`
	Engine    string `koanf:"engine"`
	TimeoutMS int    `koanf:"timeout_ms" validate:"min=0,max=300000"`
}

type WebGraphQL struct {
	Enabled        bool `koanf:"enabled"`
	DeepIntrospect bool `koanf:"deep_introspect"`
}

type WebParamDiscover struct {
	Enabled bool `koanf:"enabled"`
}

type WebGRPC struct {
	Enabled bool `koanf:"enabled"`
}

type WebLLMProbe struct {
	Enabled  bool `koanf:"enabled"`
	Augustus bool `koanf:"augustus"`
}

type WebCloudEnum struct {
	S3Profile string `koanf:"s3_profile" validate:"oneof=optimized exhaustive"`
	S3Threads int    `koanf:"s3_threads" validate:"min=0,max=10000"`
}

type WebKatana struct {
	HeadlessProfile    string `koanf:"headless_profile"      validate:"oneof=off smart full"`
	HeadlessSmartLimit int    `koanf:"headless_smart_limit"  validate:"min=0,max=10000"`
	Threads            int    `koanf:"threads"               validate:"min=0,max=10000"`
}

// ---------------- Vulns ----------------

// VulnsConfig mirrors ADR §2.2 [vulns.*].
//
// Phase 6 additions (D-V6 WAF-friendly caps, D-V3 folded-in tools):
//   - NucleiDAST VulnNucleiDAST — distinct from WebConfig.NucleiDAST; owns
//     vulns.nuclei_dast.* TOML keys (template_path, extra_args).
//   - Fray VulnFray — fray WAF-aware modern-payload scanner
//     (ai_prompt_injection / prototype_pollution / api_security / modern_bypasses).
//
// Existing struct additions:
//   - VulnXSS.Threads — WAF-friendly dalfox thread cap (D-V6 default 5).
//   - VulnLFI.MaxURLs — cap on single-param LFI candidates (D-V6 default 150).
//   - VulnFuzzParams.TemplatesPath — independently overridable template dir
//     (default cfg.Paths.NucleiTemplates+"/dast" same as NucleiDAST, but a
//     separate TOML key so users can diverge: vulns.fuzz_params.templates_path).
type VulnsConfig struct {
	Enabled       bool                `koanf:"enabled"`
	XSS           VulnXSS             `koanf:"xss"`
	SQLi          VulnSQLi            `koanf:"sqli"`
	SSRF          VulnSSRF            `koanf:"ssrf"`
	LFI           VulnLFI             `koanf:"lfi"`
	SSTI          VulnSSTI            `koanf:"ssti"`
	CRLF          VulnCRLF            `koanf:"crlf"`
	Smuggling     VulnSmuggling       `koanf:"smuggling"`
	CMDi          VulnCMDi            `koanf:"cmdi"`
	Cache         VulnCache           `koanf:"cache"`
	Bypass4xx     VulnBypass4xx       `koanf:"bypass_4xx"`
	FuzzParams    VulnFuzzParams      `koanf:"fuzz_params"`
	NucleiDAST    VulnNucleiDAST      `koanf:"nuclei_dast"`
	Fray          VulnFray            `koanf:"fray"`
	Spray         VulnSpray           `koanf:"spray"`
	BrokenLinks   VulnBrokenLinks     `koanf:"broken_links"`
	SSL           VulnSSL             `koanf:"ssl"`
	Metadata      VulnMetadata        `koanf:"metadata"`
	// D-V3 folded-in web.sh orphans (plan 06-08): routed from Phase 5 web domain
	// into Phase 6 vulns pipeline. These four probes are vuln-class by nature.
	GraphQL   VulnGraphQL   `koanf:"graphql"`
	GRPC      VulnGRPC      `koanf:"grpc"`
	LLM       VulnLLM       `koanf:"llm"`
	Websocket VulnWebsocket `koanf:"websocket"`
}

// VulnXSS configures the dalfox-based XSS scanner.
// Threads is the WAF-friendly dalfox worker count (D-V6 default 5,
// reduced from v1's AVAILABLE_CORES*15 to avoid triggering WAFs).
type VulnXSS struct {
	Enabled bool `koanf:"enabled"`
	Threads int  `koanf:"threads" validate:"min=0,max=1000"`
}

type VulnSQLi struct {
	Enabled bool `koanf:"enabled"`
	SQLMap  bool `koanf:"sqlmap"`
	Ghauri  bool `koanf:"ghauri"`
}

type VulnSSRF struct {
	Enabled       bool   `koanf:"enabled"`
	AltMatchRegex string `koanf:"alt_match_regex"`
}

// VulnLFI configures the LFI param-fuzz scanner.
// MaxURLs caps single-parameter LFI candidates per target (D-V6 default 150;
// v1 LFI_MAX_URLS=150; 0 = unlimited).
type VulnLFI struct {
	Enabled bool `koanf:"enabled"`
	MaxURLs int  `koanf:"max_urls" validate:"min=0,max=1000000"`
}

type VulnSSTI struct {
	Enabled bool   `koanf:"enabled"`
	Engine  string `koanf:"engine" validate:"oneof=TInjA SSTImap"`
}

type VulnCRLF struct {
	Enabled bool `koanf:"enabled"`
}

type VulnSmuggling struct {
	Enabled bool `koanf:"enabled"`
}

type VulnCMDi struct {
	Enabled bool `koanf:"enabled"`
}

type VulnCache struct {
	Enabled   bool `koanf:"enabled"`
	Toxicache bool `koanf:"toxicache"`
}

type VulnBypass4xx struct {
	Enabled bool `koanf:"enabled"`
}

// VulnFuzzParams configures the parameterized fuzzing pass (nuclei DAST on
// deduped URL corpus). TemplatesPath is a DISTINCT TOML key from
// VulnNucleiDAST.TemplatesPath so users can diverge the two template dirs
// independently (vulns.fuzz_params.templates_path vs
// vulns.nuclei_dast.templates_path). Both default to
// cfg.Paths.NucleiTemplates+"/dast" when empty.
type VulnFuzzParams struct {
	Enabled       bool   `koanf:"enabled"`
	TemplatesPath string `koanf:"templates_path" validate:"omitempty,nopath_traversal"`
}

// VulnNucleiDAST configures the dedicated nuclei DAST module (VULN-11).
// Distinct from WebConfig.NucleiDAST — this owns the vulns.nuclei_dast.*
// TOML keys. TemplatesPath defaults to cfg.Paths.NucleiTemplates+"/dast"
// (v1 NUCLEI_DAST_TEMPLATE_PATH="${NUCLEI_TEMPLATES_PATH}/dast").
type VulnNucleiDAST struct {
	Enabled       bool   `koanf:"enabled"`
	TemplatesPath string `koanf:"templates_path" validate:"omitempty,nopath_traversal"`
	ExtraArgs     string `koanf:"extra_args"`
}

// VulnFray configures the fray WAF-aware modern-payload scanner (D-V3 fold-in).
// v1 equivalents: FRAY_CATEGORIES, FRAY_MAX_PAYLOADS, FRAY_TIMEOUT, FRAY_DELAY.
// D-V6 WAF-friendly defaults: MaxPayloads=20, Delay=0.5s.
type VulnFray struct {
	Enabled     bool    `koanf:"enabled"`
	Categories  string  `koanf:"categories"`
	MaxPayloads int     `koanf:"max_payloads" validate:"min=0,max=10000"`
	Timeout     int     `koanf:"timeout"      validate:"min=0,max=3600"`
	Delay       float64 `koanf:"delay"        validate:"min=0,max=60"`
}

type VulnSpray struct {
	Enabled  bool   `koanf:"enabled"`
	Engine   string `koanf:"engine" validate:"oneof=brutespray brutus"`
	DeepOnly bool   `koanf:"deep_only"`
}

type VulnBrokenLinks struct {
	Enabled bool   `koanf:"enabled"`
	Engine  string `koanf:"engine" validate:"oneof=second-order legacy"`
}

type VulnSSL struct {
	Enabled bool `koanf:"enabled"`
}

type VulnMetadata struct {
	Enabled bool `koanf:"enabled"`
}

// VulnGraphQL configures the gqlspection-based GraphQL introspection scanner
// (D-V3 fold-in from web.sh graphql_scan; routes to vulns pipeline per plan 06-08).
// v1 equivalent: GRAPHQL_CHECK + GQLSPECTION flags.
type VulnGraphQL struct {
	Enabled bool `koanf:"enabled"`
}

// VulnGRPC configures the grpcurl-based gRPC reflection scanner
// (D-V3 fold-in from web.sh grpc_reflection; routes to vulns pipeline per plan 06-08).
// v1 equivalent: GRPC_SCAN flag.
type VulnGRPC struct {
	Enabled bool `koanf:"enabled"`
}

// VulnLLM configures the julius-based LLM endpoint probe
// (D-V3 fold-in from web.sh llm_probe; routes to vulns pipeline per plan 06-08).
// XCUT-07 binding: response content NEVER logged or written raw — only
// detected:bool + endpoint URL is recorded.
// v1 equivalent: LLM_PROBE + LLM_PROBE_AUGUSTUS flags.
type VulnLLM struct {
	Enabled  bool `koanf:"enabled"`
	Augustus bool `koanf:"augustus"`
}

// VulnWebsocket configures WebSocket endpoint detection via HTTP Upgrade probe
// (D-V3 fold-in from web.sh websocket_checks; routes to vulns pipeline per plan 06-08).
// v1 equivalent: URL_CHECK flag (websocket_checks ran under URL_CHECK gate).
type VulnWebsocket struct {
	Enabled bool `koanf:"enabled"`
}

// ---------------- OSINT ----------------

// OSINTConfig mirrors ADR §2.2 [osint.*].
type OSINTConfig struct {
	Enabled       bool             `koanf:"enabled"`
	GoogleDorks   OSINTGoogleDorks `koanf:"google_dorks"`
	GitHub        OSINTGitHub      `koanf:"github"`
	Cloud         OSINTCloud       `koanf:"cloud"`
	Emails        OSINTEmails      `koanf:"emails"`
	Postman       OSINTPostman     `koanf:"postman"`
	APILeaks      OSINTAPILeaks    `koanf:"api_leaks"`
	Swagger       OSINTSwagger     `koanf:"swagger"`
	Spoofy        OSINTSpoofy      `koanf:"spoofy"`
	MailHygiene   OSINTMailHygiene `koanf:"mail_hygiene"`
	MSFT          OSINTMSFT        `koanf:"msft"`
	DomainInfo    OSINTDomainInfo  `koanf:"domain_info"`
	IPInfo        OSINTIPInfo      `koanf:"ip_info"`
	IPv6          OSINTIPv6        `koanf:"ipv6"`
}

type OSINTGoogleDorks struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTGitHub struct {
	Enabled         bool   `koanf:"enabled"`
	LeaksEnabled    bool   `koanf:"leaks_enabled"`
	Threads         int    `koanf:"threads"          validate:"min=0,max=1000"`
	SecretsEngine   string `koanf:"secrets_engine"   validate:"oneof=gitleaks titus noseyparker hybrid"`
	ScanGitHistory  bool   `koanf:"scan_git_history"`
	ValidateSecrets bool   `koanf:"validate_secrets"`
	ActionsAudit    OSINTGitHubActionsAudit `koanf:"actions_audit"`
}

type OSINTGitHubActionsAudit struct {
	Enabled                   bool `koanf:"enabled"`
	IncludeAllArtifactSecrets bool `koanf:"include_all_artifact_secrets"`
}

type OSINTCloud struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTEmails struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTPostman struct {
	Enabled bool   `koanf:"enabled"`
	Threads int    `koanf:"threads" validate:"min=0,max=1000"`
	Include string `koanf:"include"`
	Exclude string `koanf:"exclude"`
}

type OSINTAPILeaks struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTSwagger struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTSpoofy struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTMailHygiene struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTMSFT struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTDomainInfo struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTIPInfo struct {
	Enabled bool `koanf:"enabled"`
}

type OSINTIPv6 struct {
	Enabled bool `koanf:"enabled"`
}

// ---------------- Notifications ----------------

// NotificationsConfig mirrors ADR §2.2 [notifications.*] and §10.1 lines
// 2381-2393 — Slack/Telegram/Discord webhooks are log.Secret-typed so
// Layer 1 auto-redacts them in slog output.
type NotificationsConfig struct {
	Enabled     bool             `koanf:"enabled"`
	SoftEnabled bool             `koanf:"soft_enabled"`
	Events      []string         `koanf:"events" validate:"dive,oneof=on-critical-finding on-scan-complete on-failure"`
	Slack       NotificationsSlack    `koanf:"slack"`
	Telegram    NotificationsTelegram `koanf:"telegram"`
	Discord     NotificationsDiscord  `koanf:"discord"`
}

type NotificationsSlack struct {
	Channel    string     `koanf:"channel"`
	WebhookURL log.Secret `koanf:"webhook_url" validate:"omitempty,url,startswith=https"`
}

type NotificationsTelegram struct {
	BotToken log.Secret `koanf:"bot_token" validate:"omitempty,max=256"`
	ChatID   string     `koanf:"chat_id"`
}

type NotificationsDiscord struct {
	WebhookURL log.Secret `koanf:"webhook_url" validate:"omitempty,url,startswith=https"`
}

// ---------------- Axiom ----------------

// AxiomConfig mirrors ADR §2.2 [axiom].
type AxiomConfig struct {
	Enabled            bool   `koanf:"enabled"`
	FleetName          string `koanf:"fleet_name"`
	FleetCount         int    `koanf:"fleet_count"         validate:"min=1,max=1000"`
	FleetRegions       string `koanf:"fleet_regions"`
	ShutdownOnEnd      bool   `koanf:"shutdown_on_end"`
	AutoFixHostkey     bool   `koanf:"auto_fix_hostkey"`
	FleetLaunch        bool   `koanf:"fleet_launch"`
	ExtraArgs          string `koanf:"extra_args"`
	FailoverThreshold  int    `koanf:"failover_threshold"  validate:"min=1,max=100"`
}

// ---------------- MCP ----------------

// MCPConfig mirrors ADR §2.2 [mcp]. NEW — no v1 equivalent.
type MCPConfig struct {
	Enabled   bool       `koanf:"enabled"`
	APIKey    log.Secret `koanf:"api_key"   validate:"omitempty,min=16,max=256"`
	Transport string     `koanf:"transport" validate:"oneof=stdio http"`
	Port      int        `koanf:"port"      validate:"min=1024,max=65535"`
}

// ---------------- Scheduler ----------------

// SchedulerConfig mirrors ADR §2.2 [scheduler.*] and §7.1.
type SchedulerConfig struct {
	FailurePolicy string                  `koanf:"failure_policy" validate:"oneof=best_effort fail_fast"`
	Overrides     SchedulerOverrides      `koanf:"overrides"`
}

type SchedulerOverrides struct {
	Subdomains string `koanf:"subdomains" validate:"oneof=best_effort fail_fast"`
	Web        string `koanf:"web"        validate:"oneof=best_effort fail_fast"`
	Vulns      string `koanf:"vulns"      validate:"oneof=best_effort fail_fast"`
	OSINT      string `koanf:"osint"      validate:"oneof=best_effort fail_fast"`
}

// ---------------- Output ----------------

// OutputConfig mirrors ADR §2.2 [output.*] PLUS adds the LogLevel/LogFormat/
// LogOutput sub-fields that the logger factory needs (see AsLoggerConfig).
// These three exist outside ADR §2.2 (the ADR did not enumerate them in §2.2
// but §10.3 makes them part of the build-order contract); we tag them with
// koanf for symmetry but keep the LogOutput un-tagged (programmatic-only,
// never set from TOML — runtime io.Writer).
type OutputConfig struct {
	Verbosity         int    `koanf:"verbosity"          validate:"min=0,max=2"`
	ExportFormat      string `koanf:"export_format"`
	AssetStore        bool   `koanf:"asset_store"`
	ReportOnly        bool   `koanf:"report_only"`
	HotlistTop        int    `koanf:"hotlist_top"        validate:"min=0,max=10000"`
	ChunkLimit        int    `koanf:"chunk_limit"        validate:"min=0,max=10000000"`
	RemoveTmp         bool   `koanf:"remove_tmp"`
	RemoveLog         bool   `koanf:"remove_log"`
	PreserveCalledFn  bool   `koanf:"preserve_called_fn"`
	SendZipNotify     bool   `koanf:"send_zip_notify"`
	StructuredLogging bool   `koanf:"structured_logging"`
	MinDiskSpaceGB    int    `koanf:"min_disk_space_gb"  validate:"min=0,max=10000"`
	LogRotation       OutputLogRotation `koanf:"log_rotation"`

	// LogLevel / LogFormat support the logger factory (§10.3 build order).
	// These are not strictly listed in ADR §2.2 but are required by the
	// logger contract. Defaults: LogLevel=info, LogFormat=json.
	LogLevel  string    `koanf:"log_level"  validate:"oneof=debug info warn error"`
	LogFormat string    `koanf:"log_format" validate:"oneof=json text"`
	// LogOutput is the runtime io.Writer; not loaded from TOML. Tests inject
	// a *bytes.Buffer; production code leaves nil → os.Stderr.
	LogOutput io.Writer `koanf:"-"`
}

type OutputLogRotation struct {
	MaxFiles   int `koanf:"max_files"    validate:"min=0,max=10000"`
	MaxAgeDays int `koanf:"max_age_days" validate:"min=0,max=3650"`
}

// ---------------- AI ----------------

// AIConfig mirrors ADR §2.2 [ai] PLUS adds OpenAIKey/AnthropicKey/Provider —
// the plan's must_haves explicitly enumerate these as Secret-typed.
type AIConfig struct {
	Enabled              bool       `koanf:"enabled"`
	Provider             string     `koanf:"provider"`
	Executable           string     `koanf:"executable"`
	Model                string     `koanf:"model"`
	ReportType           string     `koanf:"report_type"           validate:"omitempty,oneof=md txt"`
	ReportProfile        string     `koanf:"report_profile"        validate:"omitempty,oneof=executive brief bughunter"`
	PromptsFile          string     `koanf:"prompts_file"          validate:"omitempty,nopath_traversal"`
	MaxCharsPerFile      int        `koanf:"max_chars_per_file"    validate:"min=0,max=10000000"`
	MaxFilesPerCategory  int        `koanf:"max_files_per_category" validate:"min=0,max=100000"`
	Redact               bool       `koanf:"redact"`
	AllowModelPull       bool       `koanf:"allow_model_pull"`
	Strict               bool       `koanf:"strict"`
	OpenAIKey            log.Secret `koanf:"openai_key"            validate:"omitempty,max=256"`
	AnthropicKey         log.Secret `koanf:"anthropic_key"         validate:"omitempty,max=256"`
}

// ---------------- Integrations ----------------

// IntegrationsConfig mirrors ADR §2.2 [integrations.*].
type IntegrationsConfig struct {
	Faraday IntegrationsFaraday `koanf:"faraday"`
	Proxy   IntegrationsProxy   `koanf:"proxy"`
}

type IntegrationsFaraday struct {
	Enabled   bool   `koanf:"enabled"`
	Workspace string `koanf:"workspace"`
}

type IntegrationsProxy struct {
	Enabled bool   `koanf:"enabled"`
	URL     string `koanf:"url"     validate:"omitempty,url,oneof_scheme=http https"`
}

// ---------------- Incremental / Monitor ----------------

// IncrementalConfig mirrors ADR §2.2 [incremental].
type IncrementalConfig struct {
	Enabled bool `koanf:"enabled"`
}

// MonitorConfig mirrors ADR §2.2 [monitor].
type MonitorConfig struct {
	Enabled          bool   `koanf:"enabled"`
	IntervalMinutes  int    `koanf:"interval_minutes"  validate:"min=0,max=525600"`
	MaxCycles        int    `koanf:"max_cycles"        validate:"min=0,max=1000000"`
	MinSeverity      string `koanf:"min_severity"      validate:"oneof=critical high medium low info"`
	AlertSuppression bool   `koanf:"alert_suppression"`
}

// ---------------- AdaptiveRate ----------------

// AdaptiveRateConfig mirrors ADR §2.2 [adaptive_rate].
type AdaptiveRateConfig struct {
	Enabled         bool    `koanf:"enabled"`
	MinRate         int     `koanf:"min_rate"        validate:"min=0,max=100000"`
	MaxRate         int     `koanf:"max_rate"        validate:"min=0,max=1000000"`
	BackoffFactor   float64 `koanf:"backoff_factor"  validate:"min=0,max=1"`
	IncreaseFactor  float64 `koanf:"increase_factor" validate:"min=1,max=10"`
}

// ---------------- Cache ----------------

// CacheConfig mirrors ADR §2.2 [cache].
type CacheConfig struct {
	MaxAgeDays          int  `koanf:"max_age_days"            validate:"min=0,max=3650"`
	MaxAgeDaysResolvers int  `koanf:"max_age_days_resolvers"  validate:"min=0,max=3650"`
	MaxAgeDaysWordlists int  `koanf:"max_age_days_wordlists"  validate:"min=0,max=3650"`
	MaxAgeDaysTools     int  `koanf:"max_age_days_tools"      validate:"min=0,max=3650"`
	Refresh             bool `koanf:"refresh"`
}

// ---------------- Paths ----------------

// PathsConfig mirrors ADR §2.2 [paths.*]. ALL paths get the nopath_traversal
// validator (ADR §2.5 lines 1123-1124 — T-02-02-01 mitigation).
type PathsConfig struct {
	DataDir          string `koanf:"data_dir"          validate:"omitempty,nopath_traversal"`
	WordlistsDir     string `koanf:"wordlists_dir"     validate:"omitempty,nopath_traversal"`
	PatternsDir      string `koanf:"patterns_dir"      validate:"omitempty,nopath_traversal"`
	FuzzWordlist     string `koanf:"fuzz_wordlist"     validate:"omitempty,nopath_traversal"`
	LFIWordlist      string `koanf:"lfi_wordlist"      validate:"omitempty,nopath_traversal"`
	SSTIWordlist     string `koanf:"ssti_wordlist"     validate:"omitempty,nopath_traversal"`
	SubsWordlist     string `koanf:"subs_wordlist"     validate:"omitempty,nopath_traversal"`
	SubsWordlistBig  string `koanf:"subs_wordlist_big" validate:"omitempty,nopath_traversal"`
	HeadersInject    string `koanf:"headers_inject"    validate:"omitempty,nopath_traversal"`
	Resolvers        string `koanf:"resolvers"         validate:"omitempty,nopath_traversal"`
	ResolversTrusted string `koanf:"resolvers_trusted" validate:"omitempty,nopath_traversal"`
	GitHubTokens     string `koanf:"github_tokens"     validate:"omitempty,nopath_traversal"`
	GitLabTokens     string `koanf:"gitlab_tokens"     validate:"omitempty,nopath_traversal"`
	NucleiTemplates  string `koanf:"nuclei_templates"  validate:"omitempty,nopath_traversal"`
	ResolversDownload PathsResolversDownload `koanf:"resolvers_download"`
}

type PathsResolversDownload struct {
	URL            string `koanf:"url"             validate:"omitempty,url"`
	TrustedURL     string `koanf:"trusted_url"     validate:"omitempty,url"`
	ConnectTimeout int    `koanf:"connect_timeout" validate:"min=0,max=3600"`
	MaxTime        int    `koanf:"max_time"        validate:"min=0,max=86400"`
	Retry          int    `koanf:"retry"           validate:"min=0,max=100"`
	RetryDelay     int    `koanf:"retry_delay"     validate:"min=0,max=3600"`
}

// ---------------- APIKeys ----------------

// APIKeysConfig mirrors ADR §2.2 [api_keys]. All key fields are log.Secret-typed.
type APIKeysConfig struct {
	Shodan       log.Secret `koanf:"shodan"        validate:"omitempty,max=256"`
	WhoisXML     log.Secret `koanf:"whoisxml"      validate:"omitempty,max=256"`
	PDCP         log.Secret `koanf:"pdcp"          validate:"omitempty,max=256"`
	XSSServer    string     `koanf:"xss_server"    validate:"omitempty,url"`
	CollabServer string     `koanf:"collab_server" validate:"omitempty,url"`
}

// ---------------- Advanced ----------------

// AdvancedConfig mirrors ADR §2.2 [advanced.*].
type AdvancedConfig struct {
	Deep                bool   `koanf:"deep"`
	DeepLimit           int    `koanf:"deep_limit"            validate:"min=0,max=1000000"`
	DeepLimit2          int    `koanf:"deep_limit2"           validate:"min=0,max=1000000"`
	Diff                bool   `koanf:"diff"`
	QuickRescan         bool   `koanf:"quick_rescan"`
	ShowCommands        bool   `koanf:"show_commands"`
	InstallGolang       bool   `koanf:"install_golang"`
	UpgradeTools        bool   `koanf:"upgrade_tools"`
	UpgradeBeforeRun    bool   `koanf:"upgrade_before_running"`
	Header              string `koanf:"header"`
	PerfProfile         string `koanf:"perf_profile" validate:"oneof=low balanced max"`
	Tools               AdvancedTools `koanf:"tools"`
	TimingEstimates     AdvancedTimingEstimates `koanf:"timing_estimates"`
	ParallelBatchSizes  AdvancedParallelBatchSizes `koanf:"parallel_batch_sizes"`
	ParallelUI          AdvancedParallelUI `koanf:"parallel_ui"`
}

// AdvancedTools holds per-tool overrides. Each sub-struct mirrors one
// [advanced.tools.<tool>] section in ADR §2.2.
type AdvancedTools struct {
	Subfinder      AdvToolSubfinder      `koanf:"subfinder"`
	Nuclei         AdvToolNuclei         `koanf:"nuclei"`
	FFUF           AdvToolFFUF           `koanf:"ffuf"`
	HTTPX          AdvToolHTTPX          `koanf:"httpx"`
	Puredns        AdvToolPuredns        `koanf:"puredns"`
	GF             AdvToolGF             `koanf:"gf"`
	Dalfox         AdvToolDalfox         `koanf:"dalfox"`
	Dnstake        AdvToolDnstake        `koanf:"dnstake"`
	TLSX           AdvToolTLSX           `koanf:"tlsx"`
	XnLinkFinder   AdvToolXnLinkFinder   `koanf:"xnlinkfinder"`
	DNSValidator   AdvToolDNSValidator   `koanf:"dnsvalidator"`
	Interlace      AdvToolInterlace      `koanf:"interlace"`
	Brutespray     AdvToolBrutespray     `koanf:"brutespray"`
	Gotator        AdvToolGotator        `koanf:"gotator"`
	TInjA          AdvToolTInjA          `koanf:"tinja"`
	SSTImap        AdvToolSSTImap        `koanf:"sstimap"`
	SecondOrder    AdvToolSecondOrder    `koanf:"second_order"`
	Toxicache      AdvToolToxicache      `koanf:"toxicache"`
	Brutus         AdvToolBrutus         `koanf:"brutus"`
	Arjun          AdvToolArjun          `koanf:"arjun"`
	Axiom          AdvToolAxiom          `koanf:"axiom"`
}

type AdvToolSubfinder struct {
	TimeoutMinutes int `koanf:"timeout_minutes" validate:"min=0,max=86400"`
}

type AdvToolNuclei struct {
	RateLimit int    `koanf:"rate_limit" validate:"min=0,max=10000"`
	Severity  string `koanf:"severity"   validate:"omitempty,nuclei_severity"`
	Flags     string `koanf:"flags"`
}

type AdvToolFFUF struct {
	RateLimit      int    `koanf:"rate_limit"        validate:"min=0,max=10000"`
	Threads        int    `koanf:"threads"           validate:"min=0,max=500"`
	MaxTimeSeconds int    `koanf:"max_time_seconds"  validate:"min=0,max=86400"`
	Flags          string `koanf:"flags"`
}

type AdvToolHTTPX struct {
	RateLimit      int    `koanf:"rate_limit"       validate:"min=0,max=10000"`
	TimeoutSeconds int    `koanf:"timeout_seconds"  validate:"min=0,max=300"`
	Threads        int    `koanf:"threads"          validate:"min=0,max=10000"`
	Flags          string `koanf:"flags"`
}

type AdvToolPuredns struct {
	ResolversFile string `koanf:"resolvers_file" validate:"omitempty,nopath_traversal"`
}

type AdvToolGF struct {
	PatternsDir string `koanf:"patterns_dir" validate:"omitempty,nopath_traversal"`
}

type AdvToolDalfox struct {
	Threads int `koanf:"threads" validate:"min=0,max=10000"`
}

type AdvToolDnstake struct {
	Threads int `koanf:"threads" validate:"min=0,max=10000"`
}

type AdvToolTLSX struct {
	Threads int `koanf:"threads" validate:"min=0,max=100000"`
}

type AdvToolXnLinkFinder struct {
	Depth int `koanf:"depth" validate:"min=0,max=100"`
}

type AdvToolDNSValidator struct {
	Threads int `koanf:"threads" validate:"min=0,max=10000"`
}

type AdvToolInterlace struct {
	Threads int `koanf:"threads" validate:"min=0,max=10000"`
}

type AdvToolBrutespray struct {
	Concurrence int `koanf:"concurrence" validate:"min=0,max=10000"`
}

type AdvToolGotator struct {
	Flags string `koanf:"flags"`
}

type AdvToolTInjA struct {
	RateLimit int `koanf:"rate_limit" validate:"min=0,max=10000"`
	Timeout   int `koanf:"timeout"    validate:"min=0,max=3600"`
}

type AdvToolSSTImap struct {
	Level   int  `koanf:"level"   validate:"min=0,max=10"`
	Delay   int  `koanf:"delay"   validate:"min=0,max=3600"`
	Legacy  bool `koanf:"legacy"`
	Generic bool `koanf:"generic"`
}

type AdvToolSecondOrder struct {
	Config   string `koanf:"config"   validate:"omitempty,nopath_traversal"`
	Depth    int    `koanf:"depth"    validate:"min=0,max=100"`
	Threads  int    `koanf:"threads"  validate:"min=0,max=10000"`
	Insecure bool   `koanf:"insecure"`
}

type AdvToolToxicache struct {
	Threads   int    `koanf:"threads"    validate:"min=0,max=10000"`
	UserAgent string `koanf:"user_agent"`
}

type AdvToolBrutus struct {
	Usernames string `koanf:"usernames"`
	Passwords string `koanf:"passwords"`
	KeyFile   string `koanf:"key_file"  validate:"omitempty,nopath_traversal"`
}

type AdvToolArjun struct {
	Threads int `koanf:"threads" validate:"min=0,max=10000"`
}

type AdvToolAxiom struct {
	ResolversPath        string `koanf:"resolvers_path"         validate:"omitempty,nopath_traversal"`
	ResolversTrustedPath string `koanf:"resolvers_trusted_path" validate:"omitempty,nopath_traversal"`
	PostStart            string `koanf:"post_start"             validate:"omitempty,nopath_traversal"`
}

// AdvancedTimingEstimates mirrors [advanced.timing_estimates].
type AdvancedTimingEstimates struct {
	Nuclei    int `koanf:"nuclei"    validate:"min=0,max=86400"`
	Fuzz      int `koanf:"fuzz"      validate:"min=0,max=86400"`
	URLChecks int `koanf:"urlchecks" validate:"min=0,max=86400"`
	JSChecks  int `koanf:"jschecks"  validate:"min=0,max=86400"`
	API       int `koanf:"api"       validate:"min=0,max=86400"`
	GQL       int `koanf:"gql"       validate:"min=0,max=86400"`
	Param     int `koanf:"param"     validate:"min=0,max=86400"`
	GRPC      int `koanf:"grpc"      validate:"min=0,max=86400"`
	IIS       int `koanf:"iis"       validate:"min=0,max=86400"`
}

// AdvancedParallelBatchSizes mirrors [advanced.parallel_batch_sizes].
type AdvancedParallelBatchSizes struct {
	OSINTGroup1   int `koanf:"osint_group1"    validate:"min=0,max=100"`
	OSINTGroup2   int `koanf:"osint_group2"    validate:"min=0,max=100"`
	SubPassive    int `koanf:"sub_passive"     validate:"min=0,max=100"`
	SubDepActive  int `koanf:"sub_dep_active"  validate:"min=0,max=100"`
	SubPostActive int `koanf:"sub_post_active" validate:"min=0,max=100"`
	SubBrute      int `koanf:"sub_brute"       validate:"min=0,max=100"`
	WebDetect     int `koanf:"web_detect"      validate:"min=0,max=100"`
	VulnsGroup1   int `koanf:"vulns_group1"    validate:"min=0,max=100"`
	VulnsGroup2   int `koanf:"vulns_group2"    validate:"min=0,max=100"`
	VulnsGroup4   int `koanf:"vulns_group4"    validate:"min=0,max=100"`
}

// AdvancedParallelUI mirrors [advanced.parallel_ui].
type AdvancedParallelUI struct {
	Mode              string `koanf:"mode"               validate:"oneof=clean balanced trace"`
	ShowETA           bool   `koanf:"show_eta"`
	ShowActive        bool   `koanf:"show_active"`
	CompactActiveMax  int    `koanf:"compact_active_max" validate:"min=0,max=1000"`
	TraceSlowSeconds  int    `koanf:"trace_slow_seconds" validate:"min=0,max=86400"`
}

// ---------------- AsLoggerConfig ----------------

// AsLoggerConfig adapts a *Config to the minimal log.Config shim expected by
// log.New (per ADR §10.3 build order). This adapter pattern avoids the circular
// import that would arise if internal/core/log imported internal/core/config:
// config already imports log (for the Secret type), so log cannot import
// config without producing a cycle. The adapter copies just the three fields
// the logger needs and leaves the rest of the Config opaque to the log package.
//
// LogOutput defaults to nil (logger.New converts to os.Stderr). LogLevel parses
// "debug|info|warn|error" → slog.Level; unknown values default to LevelInfo.
func (c *Config) AsLoggerConfig() *log.Config {
	return &log.Config{
		Level:  parseLogLevel(c.Output.LogLevel),
		Format: c.Output.LogFormat,
		Output: c.Output.LogOutput,
	}
}
