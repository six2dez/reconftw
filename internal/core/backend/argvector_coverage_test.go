// argvector_coverage_test.go — the completeness census over EVERY registered
// Task, hermetically.
//
// NO BUILD TAG AND NO BINARIES. Like toolflags_test.go and
// argvector_drift_test.go, this runs under a PATH stripped of the tool tree.
//
// # WHY A THIRD LAYER
//
// Plan 16-04 built two hermetic layers and both work. What neither could do is
// say what they DID NOT COVER. `driveCases` held two entries against 97
// registered Tasks and `undrivableTasks` held three, so 92 Tasks were in no
// list at all — and `subdomains.brute` was one of them. That is precisely why
// CR-01 (`puredns bruteforce -d <bare domain>`) survived the guard built to
// catch its class: the guard never looked.
//
// 16-04's own summary states the number honestly — `PROBE_DRIFT_COVERAGE
// checked=1 of 44`. An honest number is not coverage. This file makes the
// number an ASSERTION: every registered Task lands in exactly one accounted
// bucket, the totals are pinned constants, and a Task that lands in none is a
// FAILURE rather than a silent omission.
//
// # THE THREE LAYERS, AND WHAT EACH CATCHES
//
// Say which class you are giving up before deleting one of these.
//
//	toolflags_test.go        an UNDEFINED flag NAME (`puredns -rt`,
//	                         `subzy --verify-ssl`). Hermetic.
//	argvector_drift_test.go  a DEFINED flag used with the WRONG MEANING, by
//	                         comparing the probe table's flag-name set against
//	                         the Task's. Hermetic.
//	this file                a Task NOBODY IS CHECKING AT ALL. Hermetic.
//
// The middle one is not a nicety, and the puredns bug is the proof. `-d` IS a
// real `puredns bruteforce` flag — it names a FILE of domains — so once
// knownToolFlags was re-sourced from `puredns bruteforce --help` the flag-name
// layer could no longer see the bug at all. What caught it was the drift
// detector, because the probe table has always used the POSITIONAL form that
// `puredns bruteforce --help` documents. One real bug, two different layers,
// two different failures, and neither layer alone was sufficient.
//
// # SANDBOX
//
// Driving 97 Tasks means running code that was never written to be run in a
// unit test. Two containment rules, both asserted:
//
//	filesystem  every Task gets a fresh t.TempDir() and nothing else; the
//	            workspace file count is compared before and after.
//	network     a few Tasks (osint.ip_info, subdomains.geo, web.wellknown,
//	            web.portscan) use net/http DIRECTLY, bypassing the
//	            arg-capturing backend entirely. HTTP(S)_PROXY is pointed at a
//	            closed local port for the duration, so any such call fails at
//	            connect instead of reaching a third party from `go test`.
package backend_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	tomlv2 "github.com/pelletier/go-toml/v2"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// censusTaskDeadline bounds one Task's drive. A Task that outruns it is
// REPORTED BY NAME and counted as NOT covered — never dropped.
const censusTaskDeadline = 5 * time.Second

// ---------------------------------------------------------------------------
// The reasoned buckets
// ---------------------------------------------------------------------------

// noDispatchTasks names Tasks that dispatch NO external tool under the generic
// seed, with the reason. Every entry needs a non-empty reason
// (TestCensusBucketsCarryReasons).
//
// A Task in here asserts nothing about an arg vector, and that is the point of
// writing it down: "it dispatched nothing" and "it has no arg vector to check"
// are different facts, and only one of them is coverage.
//
// EVERY REASON BELOW IS THE TASK'S OWN, read off the logger the census attaches
// to each drive — not inferred by reading the code. An inferred reason can be
// wrong, and this file exists because inferred coverage was wrong.
var noDispatchTasks = map[string]string{
	// --- no external tool at all -------------------------------------------
	"subdomains.ns_delegation":    "pure Go DNS/zone analysis over the seeded corpus; dispatches no external tool, so there is no arg vector to check",
	"subdomains.resolvers.health": "reads and scores the resolver file in Go; dispatches no external tool",
	"web.url_ext":                 "classifies the URL corpus by extension in Go; dispatches no external tool (logged \"completed corpus_urls=3 extensions=0\")",
	"web.wellknown":               "fetches /.well-known/* with its own net/http client, never a tool; also gated off by default (cfg.Web.WellKnown.Enabled=false)",

	// --- gated on richer input than a generic seed can fabricate ------------
	"osint.metadata":  "enriches documents already downloaded into the workspace; logs \"no workspace docs — skipping enrichment\". Seeding a realistic document corpus is a fixture, not a seed",
	"vulns.xss":       "chains behind Gxss: with no Gxss binary the reflection filter yields no candidates, so dalfox is never reached (\"no reflected candidates after Gxss filter\")",
	"web.wordlistgen": "generates wordlists in Go from robots/JS words; the pydictor leg is deferred and getjswords needs the tools root (\"robots_words=0 js_words=0 pydictor=deferred\")",

	// --- DEEP-gated: correct behaviour, not a gap --------------------------
	"vulns.spray": "DEEP-gated by design — \"use --deep or set spray.deep_only=false\". Flipping the gate in the seed would drive a credential-spraying Task from a unit test",
	"web.arjun":   "deep_only=true and the census runs in normal mode — \"skipped — deep_only=true and not in deep mode\"",

	// --- BYPASSES backend.Runner: a FINDING, recorded not fixed ------------
	//
	// These Tasks build their command with exec.CommandContext DIRECTLY, so the
	// arg-capturing backend never sees them and NO layer of this harness can
	// check their arg vectors — not toolflags, not the drift detector, not this
	// census. That is a structurally larger hole than the one this plan closes,
	// and it is out of scope here (it is an architectural change to the Runner
	// seam). Recorded for the phase-17 triage plans.
	//
	// Under the census sandbox (empty PATH, empty tools root) each one skips on
	// "binary not found", which is why they land here rather than being driven.
	"vulns.bypass4xx":     "exec.CommandContext(binaryPath) at vulns/bypass4xx.go:147, bypassing backend.Runner — its argv is invisible to every layer of this harness (FINDING, see 17-04-SUMMARY)",
	"vulns.llm":           "julius is not in tools.lock, so the Runner returns \"tool not registered\" and the best-effort branch swallows it; no argv is ever built",
	"web.gxss":            "exec.CommandContext at web/gxss.go:96, bypassing backend.Runner (FINDING)",
	"web.hakoriginfinder": "exec.CommandContext at web/hakoriginfinder.go, bypassing backend.Runner (FINDING)",
	"web.jsa":             "runs JSA from its own venv via exec, bypassing backend.Runner (FINDING)",
	"web.mantra":          "exec.CommandContext at web/mantra.go:115 (mantra reads stdin), bypassing backend.Runner (FINDING)",
	"web.nomore403":       "exec.CommandContext at web/nomore403.go:108 with cmd.Dir, bypassing backend.Runner (FINDING)",
	"web.screenshot":      "exec.CommandContext at web/screenshot.go, bypassing backend.Runner (FINDING)",
	"web.shortscan":       "exec.CommandContext at web/shortscan.go, bypassing backend.Runner (FINDING)",
}

// censusExcludedTasks names Tasks deliberately kept out of the generic drive,
// with the reason. Same reason requirement.
var censusExcludedTasks = map[string]string{}

// ---------------------------------------------------------------------------
// Pinned totals
// ---------------------------------------------------------------------------
//
// Every bucket is a constant. A Task added later cannot slip into an unchecked
// bucket without a visible diff, which is the whole mechanism: 16-04's coverage
// drained away without one.

// 17-07 (CR-05) DELETED subdomains.passive.hackertarget, so three constants fall
// by exactly one: registered 97 -> 96, driven 76 -> 75, checked 22 -> 21. This is
// the ONE case where a falling number is not coverage draining away — the Task it
// counted is gone, not unchecked. It was `driven` and `checked` because it did
// dispatch a tool (httpx, which has a flag table); the accounting-identity test
// named all three rather than the change being guessed at.
//
// Why it went: it ran `httpx -silent -u <hackertarget api url>` and parsed the
// output as the API response BODY. httpx prints the PROBED URL, which contains no
// comma, so the URL was lowercased and staged as a hostname and the Task reported
// `subdomains_found: 1` on every run; the scope filter dropped it downstream. It
// never once staged a real subdomain. subfinder queries hackertarget among its own
// sources, so the data source is retained.
const (
	censusRegistered = 96
	censusDriven     = 75
	// checked 17 -> 20 and notable 59 -> 56 when Task 2 added the sj and subjs
	// flag tables: three Tasks (osint.swagger, subdomains.scraping, web.subjs)
	// moved from "dispatched, checked by nothing" to "checked". A rise here is
	// what adding a flag table is FOR.
	//
	// checked 20 -> 22 and notable 56 -> 54 when 17-06 added the gotator and
	// regulator flag tables (CR-03, CR-04). Two more Tasks — subdomains.permut
	// and subdomains.permut.regex — moved from "dispatched, checked by nothing"
	// to "checked". Both had been dispatching a vector nothing looked at, and
	// both were wrong.
	// checked 22 -> 21 when 17-07 deleted subdomains.passive.hackertarget (above).
	censusChecked    = 21
	censusNotable    = 54
	censusNoDispatch = 18
	// A TIMED-OUT TASK IS A FAILURE, not a bucket to grow. Pinned at zero so a
	// Task that starts hanging cannot be absorbed as "accounted for".
	censusTimedOut = 0
	censusExcluded = 3
)

// ---------------------------------------------------------------------------
// The census
// ---------------------------------------------------------------------------

type censusOutcome struct {
	task     string
	tool     string
	argv     []string
	bucket   string // driven-checked | driven-notable | nodispatch | timedout | excluded
	panicked string
	// gaps names tools this Task dispatched that have NO flag table.
	gaps []string
	// why carries the Task's own log output when it dispatched nothing — its
	// reason in its own words, rather than a reason inferred from reading it.
	why string
}

// TestEveryRegisteredTaskIsAccountedFor is the guard that would have caught
// subdomains.brute.
func TestEveryRegisteredTaskIsAccountedFor(t *testing.T) {
	blockNetworkEgress(t)

	all := task.Default.All()
	if len(all) == 0 {
		t.Fatal("the Task registry is EMPTY — the blank imports in argvector_drift_test.go are the " +
			"only thing that populates it, and without them this whole file reports full coverage of nothing")
	}

	driven := map[string]driveCase{}
	for _, dc := range driveCases {
		driven[dc.taskName] = dc
	}

	var outcomes []censusOutcome
	for _, tk := range all {
		name := tk.Name()

		if why, ok := censusExcludedTasks[name]; ok {
			outcomes = append(outcomes, censusOutcome{task: name, bucket: "excluded"})
			t.Logf("EXCLUDED %s — %s", name, why)
			continue
		}
		if why, ok := undrivableTasks[name]; ok {
			outcomes = append(outcomes, censusOutcome{task: name, bucket: "excluded"})
			t.Logf("EXCLUDED %s — undrivable: %s", name, why)
			continue
		}

		res := driveTaskGeneric(t, tk, driven[name])
		outcomes = append(outcomes, res)
	}

	// Classify and assert.
	var (
		nChecked, nNotable, nNoDispatch, nTimedOut, nExcluded int
		notableTools                                          = map[string]int{}
	)
	for _, o := range outcomes {
		switch o.bucket {
		case "excluded":
			nExcluded++
		case "timedout":
			nTimedOut++
			t.Errorf("%s EXCEEDED the %s census deadline.\n"+
				"  It is therefore NOT COVERED, and a timed-out Task that is silently dropped is exactly\n"+
				"  the omission this census exists to remove. Give it a driveCase whose seed reaches its\n"+
				"  tool call quickly, or put it in censusExcludedTasks WITH a reason.",
				o.task, censusTaskDeadline)
		case "nodispatch":
			nNoDispatch++
			if o.why != "" {
				t.Logf("NO DISPATCH %s — its own log: %s", o.task, firstLines(o.why, 2))
			}
			if _, ok := noDispatchTasks[o.task]; !ok {
				t.Errorf("%s dispatched NO tool under the generic seed and is not in noDispatchTasks.\n"+
					"  This is the subdomains.brute shape: a Task in NEITHER driveCases NOR any reasoned\n"+
					"  bucket, so nothing checks its arg vector and nothing says so. Either seed it so it\n"+
					"  reaches its tool call, or add it to noDispatchTasks with the reason it has no\n"+
					"  external-tool arg vector to check.", o.task)
			}
		case "driven-checked":
			nChecked++
			for _, g := range o.gaps {
				notableTools[g]++
			}
		case "driven-notable":
			nNotable++
			for _, g := range o.gaps {
				notableTools[g]++
			}
			t.Logf("NOT CHECKED %s -> %s: the Task was driven and dispatched, but %q has no entry in\n"+
				"  knownToolFlags, so its argv is captured and asserted by NOTHING. argv: %v",
				o.task, o.tool, o.tool, o.argv)
		}
		if o.panicked != "" {
			t.Errorf("%s PANICKED under the generic drive: %s\n"+
				"  A Task that cannot survive a seeded workspace is not covered by this census, and the\n"+
				"  panic is itself a finding.", o.task, o.panicked)
		}
	}
	nDriven := nChecked + nNotable
	nRegistered := len(all)

	t.Logf("ARGV_COVERAGE registered=%d driven=%d checked=%d notable=%d nodispatch=%d timedout=%d excluded=%d",
		nRegistered, nDriven, nChecked, nNotable, nNoDispatch, nTimedOut, nExcluded)

	if len(notableTools) > 0 {
		var names []string
		for tool := range notableTools {
			names = append(names, tool)
		}
		sort.Strings(names)
		t.Logf("ARGV_COVERAGE_GAP tools dispatched but with NO flag table: %s", strings.Join(names, ","))
	}

	// The accounting identity. Without it the buckets could each be plausible
	// while a Task fell out of all of them.
	if got, want := nDriven+nNoDispatch+nTimedOut+nExcluded, nRegistered; got != want {
		t.Errorf("bucket totals sum to %d but %d Tasks are registered — %d Task(s) fell out of every "+
			"bucket, which is the exact silence this census removes", got, want, want-got)
	}

	pin := func(label string, got, want int) {
		if got != want {
			t.Errorf("ARGV_COVERAGE %s=%d, pinned constant says %d.\n"+
				"  If coverage went UP, raise the constant in the same change. If it went DOWN, say why:\n"+
				"  a falling number here is coverage draining away, which is how the subdomains.brute\n"+
				"  hole opened in the first place.", label, got, want)
		}
	}
	pin("registered", nRegistered, censusRegistered)
	pin("driven", nDriven, censusDriven)
	pin("checked", nChecked, censusChecked)
	pin("notable", nNotable, censusNotable)
	pin("nodispatch", nNoDispatch, censusNoDispatch)
	pin("timedout", nTimedOut, censusTimedOut)
	pin("excluded", nExcluded, censusExcluded)
}

// TestCensusBucketsCarryReasons asserts the reasoned buckets are reasoned,
// exactly as TestUndrivableListIsPinned already does for its list.
func TestCensusBucketsCarryReasons(t *testing.T) {
	for _, b := range []struct {
		name string
		m    map[string]string
	}{
		{"noDispatchTasks", noDispatchTasks},
		{"censusExcludedTasks", censusExcludedTasks},
	} {
		for name, why := range b.m {
			if strings.TrimSpace(why) == "" {
				t.Errorf("%s[%q] has no reason — an unexplained bucket entry is indistinguishable from "+
					"an oversight, and this census exists to tell those two apart", b.name, name)
			}
			if _, ok := task.Default.Lookup(name); !ok {
				t.Errorf("%s[%q] names a Task that is NOT REGISTERED — the entry is STALE and is "+
					"silently excusing nothing", b.name, name)
			}
		}
	}
	for name := range censusExcludedTasks {
		if _, dup := undrivableTasks[name]; dup {
			t.Errorf("%q is in BOTH censusExcludedTasks and undrivableTasks — one of the two reasons "+
				"is wrong", name)
		}
	}
}

// ---------------------------------------------------------------------------
// The generic drive
// ---------------------------------------------------------------------------

// driveTaskGeneric runs one Task against an arg-capturing backend under a
// deadline, using its explicit driveCase seed when it has one and the generic
// seed otherwise.
func driveTaskGeneric(t *testing.T, tk task.Task, dc driveCase) censusOutcome {
	t.Helper()
	name := tk.Name()
	out := censusOutcome{task: name}

	workDir := t.TempDir()
	cfg := config.Defaults()
	genericSeed(t, workDir, cfg)
	if dc.seed != nil {
		dc.seed(t, workDir, cfg)
	}

	before := countWorkspaceEntries(t, workDir)

	capture := &multiCapture{}
	// A logger, so a Task that dispatches nothing says WHY in its own words.
	// A reason inferred by reading the code is a reason that can be wrong, and
	// this file exists because inferred coverage was wrong.
	logBuf := &syncBuffer{}
	app := &appctx.AppContext{
		Log:    slog.New(slog.NewTextHandler(logBuf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Tools:  backend.NewRunner(capture, censusToolRegistry(t), nil),
		Tree:   permissiveTree{},
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}

	ctx, cancel := context.WithTimeout(context.Background(), censusTaskDeadline)
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer func() {
			if r := recover(); r != nil {
				out.panicked = fmt.Sprint(r)
			}
			close(done)
		}()
		_, _ = tk.Run(ctx, app)
	}()

	select {
	case <-done:
	case <-time.After(censusTaskDeadline + time.Second):
		out.bucket = "timedout"
		return out
	}

	if after := countWorkspaceEntries(t, workDir); after < before {
		t.Errorf("%s DELETED files from the seeded workspace (%d entries -> %d). The census sandbox is "+
			"a t.TempDir(); a Task that removes seeded input is a finding, not a seeding mistake",
			name, before, after)
	}

	dispatches := capture.all()
	if len(dispatches) == 0 {
		out.bucket = "nodispatch"
		out.why = logBuf.String()
		return out
	}

	// EVERY dispatch, not just the first. A Task that reaches for three tools
	// has three arg vectors, and checking only the first would report the other
	// two as covered. osint.domain_info is the case that proves it: its first
	// dispatch is `whois` (no flag table) and its dnsx record lookups — the ones
	// that were broken — come second.
	checked := false
	for _, d := range dispatches {
		if _, covered := knownToolFlags[d.tool]; !covered {
			out.gaps = appendUnique(out.gaps, d.tool)
			continue
		}
		assertFlagsDefined(t, d.tool, d.args)
		checked = true
		if out.tool == "" {
			out.tool, out.argv = d.tool, d.args
		}
	}
	if !checked {
		out.tool, out.argv = dispatches[0].tool, dispatches[0].args
		out.bucket = "driven-notable"
		return out
	}
	out.bucket = "driven-checked"
	return out
}

func appendUnique(xs []string, x string) []string {
	for _, e := range xs {
		if e == x {
			return xs
		}
	}
	return append(xs, x)
}

// blockNetworkEgress points the proxy env at a closed local port for the
// duration of the test.
//
// T-17-04-02. Four module files (osint/ip_info.go, subdomains/geo.go,
// web/wellknown.go, web/portscan.go) build their own http.Client and call out
// DIRECTLY — the arg-capturing backend never sees those, because they are not
// tool dispatches at all. Without this, driving all 97 Tasks would send real
// requests to ipinfo.io and shodan.io from `go test`.
//
// http.DefaultTransport honours ProxyFromEnvironment, so a proxy on a closed
// port turns every such call into an immediate connection refusal.
func blockNetworkEgress(t *testing.T) {
	t.Helper()

	// AN EMPTY PATH, and this is not belt-and-braces — it is load-bearing.
	//
	// FINDING (17-04, recorded not fixed): fourteen module files dispatch their
	// tool with exec.CommandContext DIRECTLY, bypassing backend.Runner:
	//
	//	web/{gxss,mantra,nomore403,shortscan,screenshot,jsa,hakoriginfinder,wordlistgen}.go
	//	vulns/{xss,ssrf,bypass4xx,spray}.go
	//	subdomains/reverseip.go  osint/github_repos.go
	//
	// The arg-capturing backend never sees those calls, so no layer of this
	// harness — not toolflags, not the drift detector, not this census — can
	// check their arg vectors. Worse, the first census run PROVED they start
	// real processes from `go test`: vulns.bypass4xx and web.nomore403 both
	// reported `err="signal: killed"`, meaning a binary ran and was killed by
	// the per-task deadline. On a provisioned box that is a unit test firing
	// real security tools.
	//
	// Emptying PATH makes exec.LookPath fail inside those Tasks, so they skip
	// instead of executing, and the census behaves IDENTICALLY on a bare CI
	// runner and on a fully provisioned box. That determinism is the property
	// this whole file depends on.
	t.Setenv("PATH", "")

	const dead = "http://127.0.0.1:1"
	t.Setenv("HTTP_PROXY", dead)
	t.Setenv("HTTPS_PROXY", dead)
	t.Setenv("http_proxy", dead)
	t.Setenv("https_proxy", dead)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")
	// Belt and braces: both ipinfo.io callers honour this override, so even a
	// proxy-ignoring client lands on a closed local port rather than a vendor.
	t.Setenv("RECONFTW_IPINFO_BASE_URL", "http://127.0.0.1:1")
}

// genericSeed populates a workspace with the artefacts and inputs Tasks
// commonly read, and enables the module gates.
//
// A Task that skips for want of input dispatches nothing, and a Task that
// dispatches nothing READS AS COVERAGE while asserting nothing. The seed is
// therefore deliberately generous.
func genericSeed(t *testing.T, workDir string, cfg *config.Config) {
	t.Helper()
	for _, d := range []string{"inputs", "artefacts", "raw", "logs", "osint", "out"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	in := func(p string) string { return filepath.Join(workDir, "inputs", p) }
	art := func(p string) string { return filepath.Join(workDir, "artefacts", p) }

	// Host / subdomain corpus.
	seedFile(t, in("resolved.merged.txt"), "api.example.com\nwww.example.com\n")
	seedFile(t, in("subdomains.txt"), "api.example.com\nwww.example.com\n")
	seedFile(t, in("httpx.hosts.txt"), "api.example.com\n")
	seedFile(t, art("subdomains.jsonl"), `{"subdomain":"api.example.com"}`+"\n")
	// LOCAL, CLOSED PORT — never a third-party host. Anything that escapes the
	// arg-capturing backend must land on 127.0.0.1:1.
	seedFile(t, art("hosts.jsonl"),
		`{"host":"api.example.com","url":"http://127.0.0.1:1","scheme":"http","port":"1","status":200,"ip":"127.0.0.1"}`+"\n")
	seedFile(t, art("ips.jsonl"), `{"ip":"127.0.0.1"}`+"\n")
	seedFile(t, in("urls.txt"), "http://127.0.0.1:1/api?x=1\n")
	seedFile(t, in("js.txt"), "http://127.0.0.1:1/app.js\n")
	seedFile(t, in("params.txt"), "http://127.0.0.1:1/api?x=1\n")

	// urls.jsonl carries a JS URL and a GraphQL endpoint. Six Tasks
	// (web.subjs, web.mantra, web.jsa, web.sourcemapper, web.wordlistgen,
	// osint.gqlspection) skip without them, and a skipping Task is not coverage.
	seedFile(t, art("urls.jsonl"),
		`{"url":"http://127.0.0.1:1/api?x=1"}`+"\n"+
			`{"url":"http://127.0.0.1:1/app.js"}`+"\n"+
			`{"url":"http://127.0.0.1:1/graphql"}`+"\n")
	seedFile(t, in("urls.katana.jsonl"), `{"url":"http://127.0.0.1:1/api?x=1"}`+"\n")
	seedFile(t, art("fuzz.jsonl"), `{"url":"http://127.0.0.1:1/admin","status":403}`+"\n")
	seedFile(t, in("passive.merged.txt"), "api.example.com\nwww.example.com\n")
	seedFile(t, filepath.Join(workDir, "raw", "sourcemaps", "app.js"), "var a=1;\n")
	seedFile(t, filepath.Join(workDir, "hosts", "portscan_active.gnmap"),
		"Host: 127.0.0.1 ()\tPorts: 22/open/tcp//ssh///\n")

	// gf pattern buckets — seven vulns Tasks gate on a non-empty bucket.
	for _, b := range []string{"xss", "sqli", "ssrf", "redirect", "lfi", "ssti", "rce", "idor", "ssti"} {
		seedFile(t, in(filepath.Join("gf", b+".txt")), "http://127.0.0.1:1/api?x=1\n")
	}

	// nuclei template tree, with the dast/ subdirectory three Tasks stat.
	templates := filepath.Join(workDir, "templates")
	seedFile(t, filepath.Join(templates, "dast", "x.yaml"), "id: x\n")
	seedFile(t, filepath.Join(templates, "x.yaml"), "id: x\n")
	cfg.Paths.NucleiTemplates = templates

	// A SYNTHETIC token file. Six OSINT Tasks skip without one, and every tool
	// they then reach for goes through the arg-capturing backend, so no process
	// starts and no request is made. The value is not a credential.
	tokens := in("github_tokens.txt")
	seedFile(t, tokens, "ghp_0000000000000000000000000000000000\n")
	cfg.Paths.GitHubTokens = tokens
	cfg.Paths.GitLabTokens = tokens

	// Wordlists and resolvers, as real files.
	wl := in("wordlist.txt")
	seedFile(t, wl, "www\napi\ndev\n")
	resolvers := in("resolvers.txt")
	seedFile(t, resolvers, resolverLines(12))

	// AN EMPTY TOOLS ROOT. resolveToolsDir() falls back to $HOME/Tools, and the
	// repo-clone Tasks that exec.Command an ABSOLUTE path (nomore403, bypass4xx,
	// jsa, wordlistgen) are not stopped by an empty PATH — the first census run
	// on this box ran the real nomore403 binary out of $HOME/Tools and killed it
	// on the deadline. Pointing DataDir at an empty directory makes os.Stat fail
	// and the Task skip, on any box.
	cfg.Paths.DataDir = filepath.Join(workDir, "tools-root")
	if err := os.MkdirAll(cfg.Paths.DataDir, 0o755); err != nil {
		t.Fatalf("mkdir tools-root: %v", err)
	}

	cfg.Paths.Resolvers = resolvers
	cfg.Paths.SubsWordlist = wl
	cfg.Paths.SubsWordlistBig = wl
	cfg.Paths.FuzzWordlist = wl
	cfg.Paths.LFIWordlist = wl
	cfg.Paths.SSTIWordlist = wl
	cfg.Paths.ResolversTrusted = resolvers
}

// countWorkspaceEntries counts files under root — the before/after check that
// keeps the sandbox honest (T-17-04-04).
func countWorkspaceEntries(t *testing.T, root string) int {
	t.Helper()
	n := 0
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() {
			n++
		}
		return nil
	})
	return n
}

// ---------------------------------------------------------------------------
// A registry that knows every tool
// ---------------------------------------------------------------------------

var (
	censusRegOnce sync.Once
	censusReg     *backend.ToolRegistry
	censusRegErr  error
)

// censusToolRegistry builds a ToolRegistry from tools.lock.
//
// Runner.Run returns "tool not registered" for an unknown name and never
// reaches the backend, so a registry with two tools in it would classify 95
// Tasks as dispatching nothing — a false green with the shape of coverage.
//
// tools.lock is parsed here rather than read off backend.Default because this
// package's Blocker-7 audit gate forbids *_test.go references to that
// singleton. Parsing the same file keeps default_args and timeout_seconds real.
func censusToolRegistry(t *testing.T) *backend.ToolRegistry {
	t.Helper()
	censusRegOnce.Do(func() {
		data, err := os.ReadFile("tools.lock")
		if err != nil {
			censusRegErr = err
			return
		}
		var lock struct {
			Tools []struct {
				Name           string   `toml:"name"`
				DefaultArgs    []string `toml:"default_args"`
				TimeoutSeconds int      `toml:"timeout_seconds"`
			} `toml:"tools"`
		}
		if err := tomlv2.Unmarshal(data, &lock); err != nil {
			censusRegErr = err
			return
		}
		reg := backend.NewToolRegistry()
		for _, tl := range lock.Tools {
			reg.Register(&backend.Tool{
				Name:        tl.Name,
				DefaultArgs: append([]string(nil), tl.DefaultArgs...),
				// Timeout deliberately NOT applied: tools.lock timeouts are
				// minutes-scale and the backend here never starts a process, so
				// honouring them would only slow the census. default_args DO
				// matter — they reach the argv this census asserts on.
			})
		}
		if len(lock.Tools) == 0 {
			censusRegErr = fmt.Errorf("tools.lock parsed to ZERO tools")
		}
		censusReg = reg
	})
	if censusRegErr != nil {
		t.Fatalf("census tool registry: %v", censusRegErr)
	}
	return censusReg
}

// TestCensusToolRegistryIsPopulated pins the registry the census drives
// through. An empty one would make every Task report "dispatched nothing".
func TestCensusToolRegistryIsPopulated(t *testing.T) {
	reg := censusToolRegistry(t)
	if n := len(reg.All()); n < 50 {
		t.Fatalf("census registry holds %d tools, expected the full tools.lock inventory (>=50). "+
			"A thin registry silently converts every dispatch into 'tool not registered', which this "+
			"census would then report as 'dispatched nothing' — coverage-shaped silence", n)
	}
}

// ---------------------------------------------------------------------------
// multiCapture
// ---------------------------------------------------------------------------

// multiCapture records every dispatch, with the TOOL NAME.
//
// argCapture records argv only, which is enough when the caller already knows
// the tool. The census does not: it drives a Task without knowing what that
// Task will reach for, and the tool name is what decides whether the argv can
// be checked at all.
type multiCapture struct {
	mu    sync.Mutex
	tools []string
	args  [][]string
}

func (c *multiCapture) record(tool string, args []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools = append(c.tools, tool)
	c.args = append(c.args, append([]string(nil), args...))
}

type dispatch struct {
	tool string
	args []string
}

// all returns every dispatch, in order.
func (c *multiCapture) all() []dispatch {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]dispatch, 0, len(c.tools))
	for i := range c.tools {
		out = append(out, dispatch{tool: c.tools[i], args: c.args[i]})
	}
	return out
}

// forTool returns the first dispatch to the named tool.
//
// The FIRST dispatch is not always the interesting one: osint.swagger reaches
// for SwaggerSpy before sj, and subdomains.scraping for favirecon before subjs.
// A capture that only ever kept the first would have asserted on the wrong tool
// for three of the six vectors this phase fixes.
func (c *multiCapture) forTool(name string) ([]string, bool) {
	for _, d := range c.all() {
		if d.tool == name {
			return d.args, true
		}
	}
	return nil, false
}

// syncBuffer is a mutex-guarded bytes.Buffer: the Task under drive may log from
// a goroutine of its own.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// firstLines trims a log dump to its first n lines for a readable census.
func firstLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, " | ")
}

func (c *multiCapture) Exec(_ context.Context, tl *backend.Tool, args []string) (*backend.Result, error) {
	c.record(tl.Name, args)
	return &backend.Result{ExitCode: 0}, nil
}

func (c *multiCapture) ExecEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return c.Exec(ctx, tl, args)
}

func (c *multiCapture) Stream(_ context.Context, tl *backend.Tool, args []string) (<-chan backend.Event, error) {
	c.record(tl.Name, args)
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (c *multiCapture) StreamEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return c.Stream(ctx, tl, args)
}

func (c *multiCapture) HealthCheck(_ context.Context) error { return nil }
func (c *multiCapture) Capacity() int                       { return 1 }
