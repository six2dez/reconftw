// Defaults() — canonical default *Config matching ADR §2.2 line-for-line.
// Plan 03-02 implements; ADR §2.2 owns the truth. Any change requires an ADR
// amendment (D-06 governance).

package config

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Defaults returns a *Config populated with every default value from ADR §2.2.
// This is the source layer of the koanf 8-source merge chain (loader.go).
// Callers MUST treat Defaults() as a read-only snapshot — mutate via koanf.
func Defaults() *Config {
	return &Config{
		Concurrency: ConcurrencyConfig{
			MaxJobs:           4,
			HeartbeatSeconds:  20,
			LogMode:           "summary",
			TailLines:         20,
			JobTimeoutSeconds: 0,
			KillGraceSeconds:  10,
		},
		Subdomains: SubdomainsConfig{
			Enabled: true,
			Passive: SubPassive{
				Enabled:        true,
				TimeoutMinutes: 180,
			},
			CRT: SubCRT{
				Enabled:          true,
				Limit:            999999,
				DNSTimeFenceDays: 0,
			},
			Analytics: SubAnalytics{Enabled: true},
			Brute:     SubBrute{Enabled: true, MinResolvers: 10},
			Scraping:  SubScraping{Enabled: true},
			Permut: SubPermut{
				Enabled:        true,
				LimitBytes:     2147483648,
				IAEnabled:      true,
				RegexEnabled:   true,
				WordlistMode:   "auto",
				ShortThreshold: 100,
				MinFreeMemGB:   1,
			},
			Takeover: SubTakeover{Enabled: true},
			ASN:      SubASN{Enabled: true},
			Recursive: SubRecursive{
				PassiveEnabled: false,
				PassiveDepth:   10,
				BruteEnabled:   false,
			},
			ZoneTransfer: SubZoneTransfer{Enabled: true},
			S3Buckets:    SubS3Buckets{Enabled: true},
			// ReverseIP default-on (13-01 PAR-01): the hakip2host reverse-IP
			// step folds into the default sub_dns path (bash runs it by default).
			ReverseIP: SubReverseIP{Enabled: true},
			// PTRSweep: dead scaffold — the full ASN-CIDR PTR sweep is deferred to
			// Phase 14; SubPTRTask was removed in 13-01. Default stays off (bash
			// PTR_SWEEP=false; not on the recon/all default path).
			PTRSweep: SubPTRSweep{
				Enabled: false,
				MaxIPs:  50000,
			},
			SRVEnum:      SubSRVEnum{Enabled: true},
			NSDelegation: SubNSDelegation{Enabled: true},
			Scope: SubScope{
				OnlyResolved:       false,
				ExcludeSensitive:   false,
				DeepWildcardFilter: false,
				NoErrorCheck:       false,
			},
			DNSResolve: SubDNSResolve{
				Resolver:                  "auto",
				TimeoutMinutes:            0,
				BruteTimeout:              "0",
				PurednsPublicLimit:        5000,
				PurednsTrustedLimit:       400,
				PurednsWildcardtestLimit:  30,
				PurednsWildcardbatchLimit: 1500000,
				DNSXThreads:               100,
				DNSXRateLimit:             500,
				GenerateResolvers:         false,
				UpdateResolvers:           true,
			},
			// TLSPivot default-on (13-01 PAR-01): bash runs sub_tls by default.
			TLSPivot: SubTLSPivot{
				Enabled:      true,
				SNIBatchSize: 1000,
				DeltaProbe:   true,
			},
		},
		Web: WebConfig{
			Probe: WebProbe{
				Enabled:         true,
				Ports:           "80,443",
				RateLimit:       150,
				TimeoutSeconds:  10,
				Threads:         0,
				UncommonEnabled: true,
				UncommonThreads: 0,
				UncommonTimeout: 10,
			},
			Screenshots:  WebScreenshots{Enabled: true},
			VirtualHosts: WebVirtualHosts{Enabled: false},
			Favirecon: WebFavirecon{
				Enabled:     true,
				Concurrency: 50,
				Timeout:     10,
				RateLimit:   0,
				Proxy:       "",
			},
			WAF: WebWAF{Enabled: true},
			Nuclei: WebNuclei{
				Enabled:       true,
				RateLimit:     150,
				Severity:      "info,low,medium,high,critical",
				TemplatesPath: "",
				ExtraArgs:     "",
			},
			NucleiDAST: WebNucleiDAST{Enabled: true, ExtraArgs: ""},
			Fuzz: WebFuzz{
				Enabled:        true,
				RateLimit:      0,
				Threads:        0,
				MaxTimeSeconds: 900,
				RecursionDepth: 2,
			},
			IISShortname: WebIISShortname{Enabled: true},
			CMS:          WebCMS{Enabled: true},
			JS: WebJS{
				Enabled:          true,
				SubExtract:       true,
				GetJSWordsPython: "python3",
			},
			URLs: WebURLs{
				Enabled:        true,
				PassiveEnabled: true,
				ActiveEnabled:  true,
				WaymoreTimeout: "30m",
				WaymoreLimit:   5000,
				GFPatterns:     true,
				ExtClassify:    true,
			},
			WellKnown: WebWellKnown{Enabled: false, MaxTargets: 200},
			Wordlist: WebWordlist{
				Enabled:            true,
				RobotsEnabled:      true,
				PasswordDict:       true,
				PasswordEngine:     "cewler",
				PasswordMaxTargets: 50,
				PasswordDepth:      1,
				PasswordTimeout:    45,
				PasswordMinLen:     5,
				PasswordMaxLen:     14,
			},
			Portscan: WebPortscan{
				Enabled:        true,
				PassiveEnabled: true,
				ActiveEnabled:  true,
				// IN-13-02: Strategy "legacy" (bash-parity default) runs a plain full
				// nmap over every non-CDN IP. The Naabu block below ONLY takes effect
				// under Strategy=="naabu_nmap" — portscan.go gates the naabu→nmap
				// targeted path on (Strategy=="naabu_nmap" && Naabu.Enabled). Under the
				// default "legacy" strategy naabu never runs, so Naabu.Enabled:true is
				// latent config, not active behaviour. Flipping this default changes
				// every scan and is a deliberate Phase-14 product decision — do NOT
				// change the value here (this note only documents the coupling).
				Strategy:   "legacy",
				UDPEnabled: false,
				GeoInfo:    true,
				CDNCheck:   true,
				CDNBypass:  true,
				// Naabu applies only under Strategy "naabu_nmap" (see the Strategy note
				// above); it is inert under the default "legacy" strategy.
				Naabu: WebNaabu{
					Enabled: true,
					Rate:    1000,
					Ports:   "--top-ports 1000",
				},
				ServiceFingerprint: WebServiceFingerprint{
					Enabled:   true,
					Engine:    "nerva",
					TimeoutMS: 2000,
				},
			},
			GraphQL:       WebGraphQL{Enabled: true, DeepIntrospect: false},
			ParamDiscover: WebParamDiscover{Enabled: true},
			GRPC:          WebGRPC{Enabled: false},
			LLMProbe:      WebLLMProbe{Enabled: true, Augustus: false},
			CloudEnum:     WebCloudEnum{S3Profile: "optimized", S3Threads: 20},
			Katana: WebKatana{
				HeadlessProfile:    "off",
				HeadlessSmartLimit: 15,
				Threads:            0,
			},
		},
		Vulns: VulnsConfig{
			Enabled: false,
			// D-V6: WAF-friendly dalfox cap — reduced from v1 AVAILABLE_CORES*15.
			XSS: VulnXSS{Enabled: true, Threads: 5},
			// D-V6: sqlmap on / ghauri off (opt-in, more invasive).
			SQLi: VulnSQLi{Enabled: true, SQLMap: true, Ghauri: false},
			SSRF: VulnSSRF{Enabled: true, AltMatchRegex: `169\.254\.169\.254|latest/meta-data|root:|127\.0\.0\.1|localhost|gopher://|dict://|file://`},
			// D-V6: cap at 150 LFI candidates per target (v1 LFI_MAX_URLS=150).
			LFI:       VulnLFI{Enabled: true, MaxURLs: 150},
			SSTI:      VulnSSTI{Enabled: true, Engine: "TInjA"},
			CRLF:      VulnCRLF{Enabled: true},
			Smuggling: VulnSmuggling{Enabled: true},
			CMDi:      VulnCMDi{Enabled: true},
			Cache:     VulnCache{Enabled: true, Toxicache: true},
			Bypass4xx: VulnBypass4xx{Enabled: true},
			// D-V6: TemplatesPath="" → fallback to cfg.Paths.NucleiTemplates+"/dast" at runtime.
			FuzzParams: VulnFuzzParams{Enabled: true, TemplatesPath: ""},
			// VULN-11: D-V6 TemplatesPath="" → fallback to cfg.Paths.NucleiTemplates+"/dast".
			// Distinct from WebConfig.NucleiDAST (web.nuclei_dast.*).
			NucleiDAST: VulnNucleiDAST{Enabled: true, TemplatesPath: "", ExtraArgs: ""},
			// D-V3 fold-in: fray WAF-aware modern payloads.
			// D-V6: MaxPayloads=20 + Delay=0.5 keep requests WAF-friendly.
			Fray: VulnFray{
				Enabled:     true,
				Categories:  "ai_prompt_injection,prototype_pollution,api_security,modern_bypasses",
				MaxPayloads: 20,
				Timeout:     10,
				Delay:       0.5,
			},
			Spray:       VulnSpray{Enabled: true, Engine: "brutespray", DeepOnly: true},
			BrokenLinks: VulnBrokenLinks{Enabled: true, Engine: "second-order"},
			SSL:         VulnSSL{Enabled: true},
			Metadata:    VulnMetadata{Enabled: true},
		},
		OSINT: OSINTConfig{
			Enabled: true,
			// D-O8: GoogleDorks on but key-gated; xnldorker (OSINT-15) on.
			GoogleDorks: OSINTGoogleDorks{Enabled: true, XnldorkerEnabled: true},
			GitHub: OSINTGitHub{
				Enabled:         true,
				LeaksEnabled:    true,
				Threads:         5,
				SecretsEngine:   "hybrid",
				ScanGitHistory:  true,
				ValidateSecrets: false,
				ActionsAudit: OSINTGitHubActionsAudit{
					Enabled:                   true,
					IncludeAllArtifactSecrets: true,
				},
			},
			Cloud:       OSINTCloud{Enabled: true},
			Emails:      OSINTEmails{Enabled: true},
			Postman:     OSINTPostman{Enabled: true, Threads: 10, Include: "", Exclude: ""},
			APILeaks:    OSINTAPILeaks{Enabled: true},
			Swagger:     OSINTSwagger{Enabled: true},
			Spoofy:      OSINTSpoofy{Enabled: true},
			MailHygiene: OSINTMailHygiene{Enabled: true},
			MSFT:        OSINTMSFT{Enabled: false},
			DomainInfo:  OSINTDomainInfo{Enabled: true},
			// D-O4 additive: ASN org + CIDR expansion on (OSINT-02).
			IPInfo: OSINTIPInfo{Enabled: true, ASNEnabled: true, CIDREnabled: true},
			IPv6:   OSINTIPv6{Enabled: true},
			// D-O4 additive Phase 7 sub-configs (default-on; key/best-effort gated).
			CMS:       OSINTCMS{Enabled: true, CMSeeKEnabled: true, FavireconEnabled: true}, // OSINT-12
			GraphQL:   OSINTGraphQL{Enabled: true},                                          // OSINT-13
			Cewler:    OSINTCewler{Enabled: true},                                           // OSINT-14
			Misconfig: OSINTMisconfig{Enabled: true},                                        // fold-in D-O10
			Metadata:  OSINTMetadata{Enabled: true},                                         // fold-in D-O10 (opportunistic D-O2)
		},
		Notifications: NotificationsConfig{
			Enabled:     false,
			SoftEnabled: false,
			Events:      []string{"on-critical-finding", "on-scan-complete", "on-failure", "on-scan-start"},
			Slack:       NotificationsSlack{Channel: "", WebhookURL: ""},
			Telegram:    NotificationsTelegram{BotToken: "", ChatID: ""},
			Discord:     NotificationsDiscord{WebhookURL: ""},
		},
		Axiom: AxiomConfig{
			Enabled:           false,
			FleetName:         "reconFTW",
			FleetCount:        10,
			FleetRegions:      "eu-central",
			ShutdownOnEnd:     true,
			AutoFixHostkey:    true,
			FleetLaunch:       true,
			ExtraArgs:         "",
			FailoverThreshold: 3,
		},
		MCP: MCPConfig{
			Enabled:   false,
			APIKey:    "",
			Transport: "stdio",
			Port:      8765,
		},
		Scheduler: SchedulerConfig{
			FailurePolicy: "best_effort",
			Overrides: SchedulerOverrides{
				Subdomains: "fail_fast",
				Web:        "best_effort",
				Vulns:      "best_effort",
				OSINT:      "best_effort",
			},
		},
		Output: OutputConfig{
			Verbosity:         1,
			ExportFormat:      "",
			AssetStore:        true,
			ReportOnly:        false,
			HotlistTop:        50,
			ChunkLimit:        2000,
			RemoveTmp:         false,
			RemoveLog:         false,
			PreserveCalledFn:  true,
			SendZipNotify:     false,
			StructuredLogging: false,
			MinDiskSpaceGB:    2,
			LogRotation:       OutputLogRotation{MaxFiles: 10, MaxAgeDays: 30},
			LogLevel:          "info",
			LogFormat:         "json",
			LogOutput:         nil,
		},
		AI: AIConfig{
			Enabled:             false,
			Provider:            "ollama",
			Executable:          "python3",
			Model:               "llama3:8b",
			OllamaHost:          "http://localhost:11434",
			ReportType:          "md",
			ReportProfile:       "bughunter",
			PromptsFile:         "",
			MaxCharsPerFile:     50000,
			MaxFilesPerCategory: 200,
			Redact:              true,
			AllowModelPull:      false,
			Strict:              false,
			OpenAIKey:           "",
			AnthropicKey:        "",
		},
		Integrations: IntegrationsConfig{
			Faraday: IntegrationsFaraday{Enabled: false, Workspace: "reconftw"},
			Proxy:   IntegrationsProxy{Enabled: false, URL: "http://127.0.0.1:8080/"},
		},
		Incremental: IncrementalConfig{Enabled: false},
		Monitor: MonitorConfig{
			Enabled:          false,
			IntervalMinutes:  60,
			MaxCycles:        0,
			MinSeverity:      "high",
			AlertSuppression: true,
		},
		AdaptiveRate: AdaptiveRateConfig{
			Enabled:        false,
			MinRate:        10,
			MaxRate:        500,
			BackoffFactor:  0.5,
			IncreaseFactor: 1.2,
		},
		Cache: CacheConfig{
			MaxAgeDays:          30,
			MaxAgeDaysResolvers: 7,
			MaxAgeDaysWordlists: 30,
			MaxAgeDaysTools:     14,
			Refresh:             false,
		},
		Paths: PathsConfig{
			ResolversDownload: PathsResolversDownload{
				URL:            "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt",
				TrustedURL:     "https://gist.githubusercontent.com/six2dez/ae9ed7e5c786461868abd3f2344401b6/raw/trusted_resolvers.txt",
				ConnectTimeout: 10,
				MaxTime:        120,
				Retry:          2,
				RetryDelay:     2,
			},
		},
		APIKeys: APIKeysConfig{
			Shodan:       "",
			WhoisXML:     "",
			PDCP:         "",
			XSSServer:    "",
			CollabServer: "",
		},
		Advanced: AdvancedConfig{
			Deep:             false,
			DeepLimit:        500,
			DeepLimit2:       1500,
			Diff:             false,
			QuickRescan:      false,
			ShowCommands:     false,
			InstallGolang:    true,
			UpgradeTools:     true,
			UpgradeBeforeRun: false,
			Header:           "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
			PerfProfile:      "balanced",
			Tools: AdvancedTools{
				Subfinder: AdvToolSubfinder{TimeoutMinutes: 180},
				Nuclei: AdvToolNuclei{
					RateLimit: 150,
					Severity:  "info,low,medium,high,critical",
					Flags:     "",
				},
				FFUF: AdvToolFFUF{
					RateLimit:      0,
					Threads:        0,
					MaxTimeSeconds: 900,
					Flags:          " -mc all -fc 404 -sf -noninteractive -of json",
				},
				HTTPX: AdvToolHTTPX{
					RateLimit:      150,
					TimeoutSeconds: 10,
					Threads:        0,
					Flags:          "",
				},
				Dalfox:       AdvToolDalfox{Threads: 0},
				Dnstake:      AdvToolDnstake{Threads: 0},
				TLSX:         AdvToolTLSX{Threads: 1000},
				XnLinkFinder: AdvToolXnLinkFinder{Depth: 3},
				DNSValidator: AdvToolDNSValidator{Threads: 200},
				Interlace:    AdvToolInterlace{Threads: 10},
				Brutespray:   AdvToolBrutespray{Concurrence: 0},
				Gotator: AdvToolGotator{
					Flags: " -depth 1 -numbers 3 -mindup -adv -md",
				},
				TInjA: AdvToolTInjA{RateLimit: 0, Timeout: 15},
				SSTImap: AdvToolSSTImap{
					Level: 1, Delay: 0, Legacy: false, Generic: false,
				},
				SecondOrder: AdvToolSecondOrder{
					Config: "", Depth: 1, Threads: 10, Insecure: false,
				},
				Toxicache: AdvToolToxicache{
					Threads:   70,
					UserAgent: "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
				},
				Arjun: AdvToolArjun{Threads: 10},
				Axiom: AdvToolAxiom{
					ResolversPath:        "/home/op/lists/resolvers.txt",
					ResolversTrustedPath: "/home/op/lists/resolvers_trusted.txt",
					PostStart:            "",
				},
			},
			TimingEstimates: AdvancedTimingEstimates{
				Nuclei: 600, Fuzz: 900, URLChecks: 300, JSChecks: 300,
				API: 300, GQL: 180, Param: 240, GRPC: 120, IIS: 60,
			},
			ParallelBatchSizes: AdvancedParallelBatchSizes{
				OSINTGroup1: 5, OSINTGroup2: 5,
				SubPassive: 4, SubDepActive: 3, SubPostActive: 2, SubBrute: 2,
				WebDetect:   3,
				VulnsGroup1: 4, VulnsGroup2: 4, VulnsGroup4: 3,
			},
			ParallelUI: AdvancedParallelUI{
				Mode:             "clean",
				ShowETA:          true,
				ShowActive:       true,
				CompactActiveMax: 4,
				TraceSlowSeconds: 30,
			},
		},
		Legacy: map[string]any{},
	}
}

// ToolsRoot resolves the repo-clone tools root — v1's ${tools}.
//
// PRECEDENCE: paths.tools_dir when set, else $HOME/Tools (the v1 default that
// install.sh clones into), else the relative "Tools" when the home directory
// cannot be determined.
//
// The default is applied HERE rather than in Defaults() on purpose: Defaults()
// is a pure, host-independent snapshot that feeds the koanf merge chain and is
// compared byte-for-byte by the dry-run and snapshot gates. Baking an absolute
// $HOME path into it would make those gates host-dependent, and would also make
// "the operator set it explicitly" indistinguishable from "we guessed".
//
// EVERY consumer of the tools root comes through this method. As of 18-05 that
// is literally true and it was not before: the three module-local copies this
// comment used to describe as still existing — web.resolveToolsDir (jsa.go),
// vulns.resolveToolsDirVulns (fuzzparams.go) and the inline $HOME/Tools join in
// vulns/second_order.go — were all DELETED, not merely deprecated. ZERO
// module-local tools-root resolvers survive, which is one better than the "at
// most one" 18-06 was told to expect. The claim is checked, not asserted:
// TestToolsRootHasNoModuleLocalRivals (18-06) greps the module tree for a
// second opinion about where the tools live and fails on any it finds.
//
// This paragraph previously said the three copies "still exist" and that
// "18-05 collapses them" — a sentence that stayed true-looking for exactly as
// long as nobody re-read it against the tree. 18-06 corrected it from source.
// A comment asserting an invariant nothing re-checks is the same defect shape
// as the census reasons this phase rewrote.
func (c *Config) ToolsRoot() string {
	if c != nil {
		if d := strings.TrimSpace(c.Paths.ToolsDir); d != "" {
			return filepath.Clean(d)
		}
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "Tools")
	}
	return "Tools"
}

// parseLogLevel converts an ADR-recognised log-level string to slog.Level.
// Unknown values default to LevelInfo (defensive: never panics at boot).
func parseLogLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	case "info", "":
		return slog.LevelInfo
	default:
		return slog.LevelInfo
	}
}
