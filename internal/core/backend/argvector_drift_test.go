// argvector_drift_test.go — drive real Tasks against an arg-capturing backend
// and check the argv they dispatch, hermetically.
//
// NO BUILD TAG AND NO BINARIES. This is the layer that runs on a CI runner with
// an empty PATH, which is what the two shipped flag bugs both got past: the only
// test that claimed to validate arg vectors sat behind //go:build realtools and
// nothing ran it.
//
// The assertion itself lives in toolflags_test.go (assertFlagsDefined); this
// file supplies the argv by running the Task the way the scheduler would.
//
// # THE PATTERN THIS GENERALISES
//
// internal/modules/subdomains/resolver_gate_test.go's TestSubActivePurednsFlagNames
// does exactly this for one Task and one tool, and it is the guard that closed
// the `puredns -rt` blocker. It was correct and mutation-proven, but it lived in
// one module package and covered one tool. This file lifts the harness so any
// registered Task can be driven from one place.
//
// # COVERAGE IS AN ASSERTED NUMBER, NOT AN IMPRESSION
//
// Some Tasks cannot be driven hermetically — they need network state, an
// external service, or a filesystem shape too costly to fake. Those are named on
// undrivableTasks WITH A REASON, and its size is asserted, because an unasserted
// exclusion list is how coverage drains away without a diff ever showing it.
//
// # DEFAULT ARGS
//
// The argv a Task really dispatches is tools.lock's DefaultArgs prepended to the
// Task's own args, applied in applyToolContract at the Runner seam. The harness
// therefore drives a real backend.Runner rather than calling the Task's arg
// builder, so a default_args entry is included exactly as production would see
// it. TestDriftHarnessIncludesDefaultArgs pins that.
package backend_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	// Blank imports register the Tasks. Without these the registry is empty and
	// every case below would skip — which would look exactly like passing.
	//
	// ALL FOUR MODULE PACKAGES, not two. With only subdomains and web, 41 of the
	// 97 registered Tasks are invisible to task.Default.All(), so every count the
	// coverage census prints would be a false green: it would report full coverage
	// of a registry two thirds of which had never been loaded.
	_ "github.com/six2dez/reconftw/internal/modules/osint"
	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
	_ "github.com/six2dez/reconftw/internal/modules/vulns"
	_ "github.com/six2dez/reconftw/internal/modules/web"
)

// driveCase is one Task driven for its argv.
type driveCase struct {
	taskName string
	tool     string
	// seed prepares the workdir and config so the Task reaches its tool call.
	seed func(t *testing.T, workDir string, cfg *config.Config)
}

// undrivableTasks names Tasks this harness deliberately does not drive, with the
// reason. Its size is asserted by TestUndrivableListIsPinned.
//
// This is the detector's COVERAGE LIMIT stated as a number. Growing it is a
// visible diff and needs a reason in the same commit.
var undrivableTasks = map[string]string{
	"subdomains.takeover.dnstake": "dnstake's argv depends on a resolved-host file the subzy case already covers for this tool class; adding it would duplicate coverage, not extend it",
	"web.nuclei":                  "runNucleiGroup fans out per host-group and per template path; a hermetic drive would pin one arbitrary group's argv and read as if it covered all of them",
	"web.portscan":                "dispatches naabu, nmap and smap from one Task through three branches selected by config and by prior-stage output; one drive covers one branch and would misreport as three",
}

const undrivableTasksSize = 3

// TestUndrivableListIsPinned keeps the exclusion list from growing unnoticed.
func TestUndrivableListIsPinned(t *testing.T) {
	if len(undrivableTasks) != undrivableTasksSize {
		t.Errorf("undrivableTasks has %d entries, constant says %d.\n"+
			"  This list IS the detector's coverage limit. If you added an entry, say why in the map\n"+
			"  and raise the constant in the same commit so the reduction in coverage is visible.",
			len(undrivableTasks), undrivableTasksSize)
	}
	for name, why := range undrivableTasks {
		if why == "" {
			t.Errorf("undrivableTasks[%q] has no reason — an unexplained exclusion is indistinguishable "+
				"from an oversight", name)
		}
	}
}

// driveCases are the Tasks driven for their argv. Scoped to the tools in
// knownToolFlags (see that file's scope criterion) — driving a Task whose tool
// has no flag table would capture argv nothing checks.
var driveCases = []driveCase{
	{
		taskName: "subdomains.takeover.subzy",
		tool:     "subzy",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"), "api.example.com\n")
			cfg.Subdomains.Takeover.Enabled = true
		},
	},
	{
		// CR-01 / 16-06 §6.3. The Task this harness could not see: before this
		// plan `subdomains.brute` was in NEITHER driveCases NOR undrivableTasks,
		// which is exactly why the puredns bruteforce vector shipped broken while
		// the guard built to catch that class stayed green.
		taskName: "subdomains.brute",
		tool:     "puredns",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			// Both gates in SubBruteTask.Run must be satisfied or the Task skips
			// LOUDLY and dispatches nothing — and a skipping Task reads as
			// coverage while asserting nothing at all.
			resolvers := filepath.Join(workDir, "inputs", "resolvers.txt")
			seedFile(t, resolvers, resolverLines(12))
			wordlist := filepath.Join(workDir, "inputs", "subs.txt")
			seedFile(t, wordlist, "www\napi\ndev\n")
			cfg.Subdomains.Brute.Enabled = true
			cfg.Subdomains.Brute.MinResolvers = 10
			cfg.Paths.Resolvers = resolvers
			cfg.Paths.SubsWordlist = wordlist
			// Production default (config.Defaults()) — the drive must mirror what
			// production dispatches, not a trimmed vector chosen to match a probe.
			cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit = 30
		},
	},
	{
		taskName: "subdomains.recursive.brute",
		tool:     "puredns",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"), "api.example.com\n")
			resolvers := filepath.Join(workDir, "inputs", "resolvers.txt")
			seedFile(t, resolvers, resolverLines(12))
			wordlist := filepath.Join(workDir, "inputs", "subs.txt")
			seedFile(t, wordlist, "www\napi\ndev\n")
			cfg.Paths.Resolvers = resolvers
			cfg.Paths.SubsWordlist = wordlist
			cfg.Subdomains.DNSResolve.PurednsWildcardtestLimit = 30
		},
	},
	{
		// Added 17-06 (CR-03). Before this plan the permutation stage dispatched
		// gotator with no -perm at all, and nothing in the tree captured its argv.
		taskName: "subdomains.permut",
		tool:     "gotator",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"),
				"api.example.com\nwww.example.com\n")
			// gotator v1.1 PANICS on an unreadable -perm, so the Task refuses to
			// dispatch without one. No wordlist here means no argv to check, and a
			// case that captures nothing asserts nothing.
			wl := filepath.Join(workDir, "inputs", "wordlists")
			seedFile(t, filepath.Join(wl, "permutations_list.txt"), "dev\nstage\nprod\n")
			seedFile(t, filepath.Join(wl, "permutations_list_short.txt"), "dev\nprod\n")
			cfg.Paths.WordlistsDir = wl
			cfg.Subdomains.Permut.Enabled = true
			cfg.Subdomains.Permut.WordlistMode = "auto"
			cfg.Subdomains.Permut.ShortThreshold = 100
			cfg.Subdomains.Permut.MinFreeMemGB = 0
		},
	},
	{
		// Added 17-06 (CR-04). Until now the regulator probe mirrored no Task, so
		// nothing compared the probe with what production dispatched — and the two
		// happened to agree only because the probe had been copied from the broken
		// module vector.
		taskName: "subdomains.permut.regex",
		tool:     "regulator",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"),
				"api.example.com\nwww.example.com\n")
			cfg.Subdomains.Permut.Enabled = true
			cfg.Subdomains.Permut.RegexEnabled = true
			cfg.Subdomains.Permut.MinFreeMemGB = 0
		},
	},
	{
		taskName: "web.httpx",
		tool:     "httpx",
		seed: func(t *testing.T, workDir string, cfg *config.Config) {
			t.Helper()
			seedFile(t, filepath.Join(workDir, "artefacts", "subdomains.jsonl"),
				"{\"subdomain\":\"api.example.com\"}\n")
			seedFile(t, filepath.Join(workDir, "inputs", "resolved.merged.txt"), "api.example.com\n")
			cfg.Web.Probe.Enabled = true
		},
	},
}

// TestTaskArgVectorFlagsAreDefined is the guard.
//
// It drives each Task exactly as the scheduler would — through a real
// backend.Runner, so tools.lock DefaultArgs are applied — captures the argv, and
// asserts every dash-prefixed token is a flag the tool defines.
func TestTaskArgVectorFlagsAreDefined(t *testing.T) {
	for _, tc := range driveCases {
		tc := tc
		t.Run(tc.taskName, func(t *testing.T) {
			if why, excluded := undrivableTasks[tc.taskName]; excluded {
				t.Fatalf("%s is both driven and on the undrivable list (%q) — one of the two is wrong",
					tc.taskName, why)
			}
			argv, ok := driveTaskForArgs(t, tc)
			if !ok {
				t.Fatalf("%s dispatched no tool invocation.\n"+
					"  The seed did not get the Task as far as its tool call, so this case asserts NOTHING\n"+
					"  while appearing to pass. Fix the seed, or move the Task to undrivableTasks with a\n"+
					"  reason.", tc.taskName)
			}
			t.Logf("%s -> %s %v", tc.taskName, tc.tool, argv)
			if !assertFlagsDefined(t, tc.tool, argv) {
				t.Fatalf("no flag table for %q — add one to knownToolFlags with its provenance, or drop "+
					"this case; a driven Task whose argv nothing checks is theatre", tc.tool)
			}
		})
	}
}

// TestDriftHarnessIncludesDefaultArgs proves the harness sees what production
// sees.
//
// If the harness called a Task's arg builder directly it would miss tools.lock's
// default_args, and a bad flag added there would be invisible to every case
// above. Driving a real Runner is what makes the coverage real, so it is pinned.
func TestDriftHarnessIncludesDefaultArgs(t *testing.T) {
	capture := &argCapture{}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "fixture-tool", DefaultArgs: []string{"--from-default-args"}})
	runner := backend.NewRunner(capture, reg, nil)

	if _, err := runner.Run(context.Background(), "fixture-tool", []string{"--from-caller"}); err != nil {
		t.Fatalf("run: %v", err)
	}
	want := []string{"--from-default-args", "--from-caller"}
	if len(capture.args) != len(want) {
		t.Fatalf("argv = %v, want %v — default_args did not reach the captured vector", capture.args, want)
	}
	for i := range want {
		if capture.args[i] != want[i] {
			t.Fatalf("argv = %v, want %v", capture.args, want)
		}
	}
}

// --- harness ----------------------------------------------------------------

// driveTaskForArgs runs one Task against an arg-capturing backend and returns
// the argv it dispatched.
func driveTaskForArgs(t *testing.T, tc driveCase) ([]string, bool) {
	t.Helper()

	workDir := t.TempDir()
	for _, d := range []string{"inputs", "artefacts", "raw", "logs"} {
		if err := os.MkdirAll(filepath.Join(workDir, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}

	cfg := &config.Config{}
	tc.seed(t, workDir, cfg)

	capture := &argCapture{}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: tc.tool})

	app := &appctx.AppContext{
		Tools:  backend.NewRunner(capture, reg, nil),
		Tree:   permissiveTree{},
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}

	tk, ok := task.Default.Lookup(tc.taskName)
	if !ok {
		var names []string
		for _, r := range task.Default.All() {
			names = append(names, r.Name())
		}
		sort.Strings(names)
		t.Fatalf("task %q is not registered — the entry is STALE.\n"+
			"  A renamed Task would otherwise leave this case silently checking nothing.\n"+
			"  registered: %v", tc.taskName, names)
	}

	// The Task's own error is not the subject: a mocked tool returning no output
	// makes many Tasks report skipped, and that is fine. The argv is the subject.
	_, _ = tk.Run(context.Background(), app)
	return capture.args, len(capture.args) > 0
}

// resolverLines builds a resolver file with n entries, so a Task's resolver
// health gate is satisfied by CONTENT rather than by lowering the gate.
func resolverLines(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "192.0.2.%d\n", i+1)
	}
	return b.String()
}

func seedFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("seed %s: %v", path, err)
	}
}

// argCapture records the argv of the first dispatch it sees.
type argCapture struct{ args []string }

func (c *argCapture) record(args []string) {
	if c.args == nil {
		c.args = append([]string(nil), args...)
	}
}

func (c *argCapture) Exec(_ context.Context, _ *backend.Tool, args []string) (*backend.Result, error) {
	c.record(args)
	return &backend.Result{ExitCode: 0}, nil
}

func (c *argCapture) ExecEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (*backend.Result, error) {
	return c.Exec(ctx, tl, args)
}

func (c *argCapture) Stream(_ context.Context, _ *backend.Tool, args []string) (<-chan backend.Event, error) {
	c.record(args)
	ch := make(chan backend.Event)
	close(ch)
	return ch, nil
}

func (c *argCapture) StreamEnv(ctx context.Context, tl *backend.Tool, args []string, _ []string) (<-chan backend.Event, error) {
	return c.Stream(ctx, tl, args)
}

func (c *argCapture) HealthCheck(_ context.Context) error { return nil }
func (c *argCapture) Capacity() int                       { return 1 }

// permissiveTree admits everything — scope is not what this file tests.
type permissiveTree struct{}

func (permissiveTree) Append(_ string, _ [][]byte) error { return nil }
func (permissiveTree) InScope(_ string) bool             { return true }

// --- probe-vs-Task drift ------------------------------------------------------

// TestProbeTableDeclaresMirrors makes an unfilled `mirrors` field impossible.
//
// The field exists so a probe can say which Task it copies. A blank one would be
// indistinguishable from an entry nobody got round to filling in, and the drift
// check would skip it silently — reproducing the exact hole this file closes.
func TestProbeTableDeclaresMirrors(t *testing.T) {
	if len(subdomainWebProbes) == 0 {
		t.Fatal("subdomainWebProbes is empty — the probe table checks nothing")
	}
	for i, p := range subdomainWebProbes {
		if p.mirrors == "" {
			t.Errorf("probe %d (%s %v) has a blank mirrors field.\n"+
				"  Name the Task it copies, or say probeMirrorsNoTask explicitly. A blank is not a\n"+
				"  declaration, it is an omission that this drift check would skip.", i, p.name, p.args)
		}
	}
}

// TestProbeTableMatchesTaskArgVectors is the drift detector.
//
// The probe table's own comment claims each entry "uses the EXACT arg vector
// from internal/modules/…". Nothing enforced that, so a module could change a
// flag and the probe would keep validating the old vector forever — the same
// failure class the probe exists to prevent, relocated from the tool to the test.
//
// FLAG-NAME SETS, NOT FULL ARGV. Full equality is unachievable: the probe
// substitutes throwaway paths and a synthetic domain, and a test that cannot
// pass gets deleted. Flag names are what broke twice, so flag names are what is
// compared.
func TestProbeTableMatchesTaskArgVectors(t *testing.T) {
	byTask := map[string]driveCase{}
	for _, dc := range driveCases {
		byTask[dc.taskName] = dc
	}

	checked := 0
	for _, p := range subdomainWebProbes {
		if p.mirrors == probeMirrorsNoTask {
			continue
		}
		p := p
		t.Run(p.name+"->"+p.mirrors, func(t *testing.T) {
			if _, ok := task.Default.Lookup(p.mirrors); !ok {
				t.Fatalf("probe %q names Task %q, which is NOT REGISTERED — the entry is STALE.\n"+
					"  A renamed Task would otherwise leave this probe checking a vector nothing dispatches.",
					p.name, p.mirrors)
			}
			dc, ok := byTask[p.mirrors]
			if !ok {
				t.Skipf("Task %q is named by a probe but is not in driveCases, so its argv cannot be "+
					"captured here; add a driveCase or move it to undrivableTasks", p.mirrors)
			}
			argv, got := driveTaskForArgs(t, dc)
			if !got {
				t.Fatalf("%s dispatched nothing — the seed did not reach the tool call", dc.taskName)
			}
			probeFlags := flagNamesOf(p.args)
			taskFlags := flagNamesOf(argv)
			if onlyProbe, onlyTask := symmetricDiff(probeFlags, taskFlags); len(onlyProbe)+len(onlyTask) > 0 {
				t.Errorf("DRIFT: probe %q and Task %q dispatch different flag names.\n"+
					"  probe flags: %v\n"+
					"  task  flags: %v\n"+
					"  only in probe: %v\n"+
					"  only in task:  %v\n"+
					"  The probe table is a hand-copied duplicate of the module's arg vector. One of the\n"+
					"  two changed and the other did not — fix the probe, or fix the module, but do not\n"+
					"  leave them disagreeing: the probe would keep validating a vector nothing dispatches.",
					p.name, p.mirrors, probeFlags, taskFlags, onlyProbe, onlyTask)
			}
			checked++
		})
	}

	// A drift detector that checked nothing would pass. Say what it covered.
	t.Logf("PROBE_DRIFT_COVERAGE checked=%d of %d probe entries; the rest declare probeMirrorsNoTask",
		checked, len(subdomainWebProbes))
}

// flagNamesOf returns the sorted, de-duplicated dash-prefixed tokens in argv.
// Negative numbers are values, not flags (see dashToken).
func flagNamesOf(argv []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range argv {
		if !dashToken.MatchString(a) || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

func symmetricDiff(a, b []string) (onlyA, onlyB []string) {
	inB := map[string]bool{}
	for _, x := range b {
		inB[x] = true
	}
	inA := map[string]bool{}
	for _, x := range a {
		inA[x] = true
		if !inB[x] {
			onlyA = append(onlyA, x)
		}
	}
	for _, x := range b {
		if !inA[x] {
			onlyB = append(onlyB, x)
		}
	}
	sort.Strings(onlyA)
	sort.Strings(onlyB)
	return onlyA, onlyB
}

// --- the six fixed vectors ----------------------------------------------------

// TestFixedArgVectorsMatchToolContracts asserts the SHAPE each real tool
// accepts, for the six vectors 17-04 fixes.
//
// # WHY SHAPE AND NOT FLAG NAMES
//
// assertFlagsDefined checks that a token IS a flag the tool defines. Four of
// these six bugs pass that check and are still broken, because the flag is
// defined and means something else:
//
//	puredns bruteforce -d X   `-d` is real. It names a FILE OF DOMAINS. Passing
//	                          a bare domain makes puredns try to open it:
//	                          `puredns error: open example.com: no such file`.
//	dnsx -d X (no -w)         `-d` is real. It is the BRUTEFORCE-domain input and
//	                          requires `-w`: `FTL missing wordlist(w) flag
//	                          required with domain(d) input`.
//	sj automate -u host       `-u` is real. It wants a URL, and a bare host gives
//	                          `unsupported protocol scheme ""`.
//	subjs -i -                `-i` is real. It names a FILE; subjs has no stdin
//	                          sentinel, so `-` gives
//	                          `Could not open input file: open -: no such file`.
//
// Only subzy's `--verify-ssl` is an undefined NAME, and that one the flag layer
// already caught in 16-04.
//
// # WHAT THE COMPANION REAL-TOOL CHECK PROVES, AND WHAT IT DOES NOT
//
// TestFixedArgVectorsAreAcceptedByRealTools runs each captured vector against
// the installed binary. It proves the tool ACCEPTS the invocation — which is
// exactly the property every one of these bugs destroyed. It does NOT prove the
// tool returns results: this box blocks outbound UDP/53, so puredns and dnsx
// cannot resolve here. Acceptance is provable, resolution is not, and the two
// are not the same claim.
func TestFixedArgVectorsMatchToolContracts(t *testing.T) {
	t.Run("subzy uses the underscore long flag", func(t *testing.T) {
		argv := captureFor(t, "subdomains.takeover.subzy", "subzy")
		if containsFlag(argv, "--verify-ssl") {
			t.Errorf("subzy is still dispatched with --verify-ssl (HYPHEN).\n"+
				"  subzy defines --verify_ssl with an UNDERSCORE and exits `unknown flag: --verify-ssl`\n"+
				"  on every invocation, so takeover detection produces zero results.\n  argv: %v", argv)
		}
		if !containsFlag(argv, "--verify_ssl") {
			t.Errorf("subzy is not dispatched with --verify_ssl.\n  argv: %v", argv)
		}
	})

	t.Run("puredns bruteforce takes the domain POSITIONALLY", func(t *testing.T) {
		for _, name := range []string{"subdomains.brute", "subdomains.recursive.brute"} {
			t.Run(name, func(t *testing.T) {
				argv := captureFor(t, name, "puredns")
				assertPurednsPositionalDomain(t, name, argv)
			})
		}
	})

	t.Run("sj is given a scheme-bearing URL", func(t *testing.T) {
		argv := captureFor(t, "osint.swagger", "sj")
		val, ok := flagValue(argv, "-u")
		if !ok {
			t.Fatalf("sj dispatched without -u.\n  argv: %v", argv)
		}
		u, err := url.Parse(val)
		if err != nil || u.Scheme == "" {
			t.Errorf("sj -u %q carries NO SCHEME.\n"+
				"  sj resolves the value as a URL and a bare host yields\n"+
				"  `Get \"api.example.com\": unsupported protocol scheme \"\"` — 100 of 100 invocations\n"+
				"  dead in the phase-16 parity run (16-06 §6.3).\n  argv: %v", val, argv)
		}
	})

	t.Run("dnsx record lookups use the LIST input, not the bruteforce-domain input", func(t *testing.T) {
		for _, name := range []string{"osint.ip_info", "osint.domain_info"} {
			t.Run(name, func(t *testing.T) {
				cap := driveTaskCapturing(t, name)
				dispatches := 0
				for _, d := range cap.all() {
					if d.tool != "dnsx" {
						continue
					}
					dispatches++
					assertDnsxListInput(t, name, d.args)
				}
				if dispatches == 0 {
					t.Fatalf("%s dispatched dnsx ZERO times — the seed did not reach the record "+
						"lookups, so this case asserts nothing while appearing to pass", name)
				}
				t.Logf("%s: %d dnsx invocation(s) checked", name, dispatches)
			})
		}
	})

	t.Run("subjs is given a real file, not a stdin sentinel", func(t *testing.T) {
		argv := captureFor(t, "subdomains.scraping", "subjs")
		val, ok := flagValue(argv, "-i")
		if !ok {
			t.Fatalf("subjs dispatched without -i.\n  argv: %v", argv)
		}
		if val == "-" {
			t.Errorf("subjs is dispatched with `-i -`.\n"+
				"  subjs has NO stdin sentinel — `-i` names a file, and `-` yields\n"+
				"  `Error running subjs: Could not open input file: open -: no such file or directory`.\n"+
				"  argv: %v", argv)
		}
		if _, err := os.Stat(val); err != nil {
			t.Errorf("subjs -i %q does not name an existing file: %v\n  argv: %v", val, err, argv)
		}
	})
}

// assertPurednsPositionalDomain pins the form `puredns bruteforce --help`
// documents: `puredns bruteforce <wordlist> domain [flags]`.
func assertPurednsPositionalDomain(t *testing.T, name string, argv []string) {
	t.Helper()
	if containsFlag(argv, "-d") || containsFlag(argv, "--domains") {
		t.Errorf("%s still passes the domain through puredns's -d/--domains flag.\n"+
			"  `-d, --domains string  text file containing domains to bruteforce` — it takes a FILE.\n"+
			"  With a bare domain puredns tries to OPEN it:\n"+
			"    $ puredns bruteforce wl.txt -d example.com -r res.txt --quiet\n"+
			"    puredns error: open example.com: no such file or directory   (exit 1)\n"+
			"  v1 passes it positionally (modules/utils.sh:1550), and so does `--help`:\n"+
			"    Usage: puredns bruteforce <wordlist> domain [flags]\n  argv: %v", name, argv)
		return
	}
	// argv[0] is the subcommand, argv[1] the wordlist, argv[2] the domain.
	if len(argv) < 3 || argv[0] != "bruteforce" {
		t.Fatalf("%s: argv is not a puredns bruteforce invocation: %v", name, argv)
	}
	if dashToken.MatchString(argv[2]) {
		t.Errorf("%s: the third token is %q, a flag — the POSITIONAL domain is missing.\n"+
			"  Expected `bruteforce <wordlist> <domain>`.\n  argv: %v", name, argv[2], argv)
	}
}

// assertDnsxListInput pins the single-name record-lookup form.
func assertDnsxListInput(t *testing.T, name string, argv []string) {
	t.Helper()
	if containsFlag(argv, "-d") || containsFlag(argv, "-domain") {
		t.Errorf("%s dispatches dnsx with -d and no wordlist.\n"+
			"  `-d, -domain` is the BRUTEFORCE-domain input and pairs with `-w`:\n"+
			"    $ dnsx -duc -silent -a -resp-only -d example.com\n"+
			"    [FTL] missing wordlist(w) flag required with domain(d) input   (exit 1)\n"+
			"  A single-name record lookup goes through the LIST input instead.\n  argv: %v", name, argv)
		return
	}
	val, ok := flagValue(argv, "-l")
	if !ok {
		t.Errorf("%s dispatches dnsx with neither -d nor -l — it has no input at all.\n  argv: %v", name, argv)
		return
	}
	if _, err := os.Stat(val); err != nil {
		t.Errorf("%s: dnsx -l %q does not name an existing file: %v\n  argv: %v", name, val, err, argv)
	}
}

// captureFor drives a Task under the generic seed and returns the argv of its
// first dispatch to the named tool.
func captureFor(t *testing.T, taskName, tool string) []string {
	t.Helper()
	argv, ok := driveTaskCapturing(t, taskName).forTool(tool)
	if !ok {
		t.Fatalf("%s dispatched %q ZERO times under the generic seed.\n"+
			"  The case therefore asserts NOTHING while appearing to pass — fix the seed rather than\n"+
			"  the assertion.", taskName, tool)
	}
	return argv
}

// driveTaskCapturing drives one registered Task under the census sandbox and
// returns every dispatch it made.
//
// It reuses genericSeed and the census sandbox deliberately: a second, divergent
// seeding path is a second thing to keep true, and the first one to rot.
func driveTaskCapturing(t *testing.T, taskName string) *multiCapture {
	t.Helper()
	blockNetworkEgress(t)

	tk, ok := task.Default.Lookup(taskName)
	if !ok {
		t.Fatalf("task %q is not registered — the case is STALE", taskName)
	}

	workDir := t.TempDir()
	cfg := config.Defaults()
	genericSeed(t, workDir, cfg)
	for _, dc := range driveCases {
		if dc.taskName == taskName && dc.seed != nil {
			dc.seed(t, workDir, cfg)
		}
	}

	capture := &multiCapture{}
	app := &appctx.AppContext{
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Tools:  backend.NewRunner(capture, censusToolRegistry(t), nil),
		Tree:   permissiveTree{},
		Cfg:    cfg,
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir, Scope: []string{"*.example.com"}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), censusTaskDeadline)
	defer cancel()
	_, _ = tk.Run(ctx, app)
	return capture
}

// flagValue returns the token following flag in argv.
func flagValue(argv []string, flag string) (string, bool) {
	for i, a := range argv {
		if a == flag && i+1 < len(argv) {
			return argv[i+1], true
		}
	}
	return "", false
}

// ExecOpts satisfies the backend.Backend options seam added in 18-01. It
// PRESERVES this fake's pre-18-01 dispatch exactly: Runner.Run used to call
// Backend.Exec and Runner.RunEnv used to call Backend.ExecEnv, and both now
// arrive here, so the env-set case forwards to ExecEnv and the zero case to Exec.
//
// It deliberately IGNORES opts.Stdin, opts.StdinPath and opts.Dir: this fake
// never receives them. A fake that needs to ASSERT on stdin must write its own
// ExecOpts instead of inheriting this forward — silently discarding the bytes is
// correct only because nothing here is testing them.
func (c *argCapture) ExecOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (*backend.Result, error) {
	if len(opts.Env) > 0 {
		return c.ExecEnv(ctx, t, args, opts.Env)
	}
	return c.Exec(ctx, t, args)
}

// StreamOpts satisfies the backend.Backend options seam (see ExecOpts).
func (c *argCapture) StreamOpts(ctx context.Context, t *backend.Tool, args []string, opts backend.ExecOptions) (<-chan backend.Event, error) {
	if len(opts.Env) > 0 {
		return c.StreamEnv(ctx, t, args, opts.Env)
	}
	return c.Stream(ctx, t, args)
}
