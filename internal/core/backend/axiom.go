// SPDX-License-Identifier: MIT
//
// AxiomBackend — real Phase 4 implementation replacing the Phase 3 compile stub.
//
// Key design decisions:
//   - Tool.InputFlag (not heuristic arg-scraping) identifies the input file for axiom-scan
//     fleet dispatch (REVIEWS finding #5 fix).
//   - moduleMap maps Tool.Name → axiom-scan module name; empty string = local fallback.
//   - HealthCheck detects "REMOTE HOST IDENTIFICATION HAS CHANGED" and repairs
//     known_hosts when cfg.Axiom.AutoFixHostkey=true (T-04-06-01 mitigation).
//   - Launch/Shutdown/resolversPropagation implement fleet lifecycle (AXIOM-05/06).
//   - NewAxiomBackendWithLocal is exported for test injection only (the internal
//     local backend is otherwise constructed by NewAxiomBackend).
package backend

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// defaultAxiomModuleMap returns the canonical Tool.Name → axiom-scan module mapping.
// An empty string means "no axiom module — use local fallback transparently".
func defaultAxiomModuleMap() map[string]string {
	return map[string]string{
		"puredns":   "puredns-resolve",
		"tlsx":      "tlsx",
		"dnsx":      "dnsx",
		"s3scanner": "s3scanner",
		"nuclei":    "nuclei",
		"subfinder": "", // API-bound — always local
		"dnstake":   "", // no official axiom module yet
	}
}

// axiomModulesNotPorted names every axiom-scan module the v1 bash tree dispatches
// that v2 does NOT, each with the reason it was left out.
//
// WHY THIS LIST IS IN THE CODE. v1 drives ~14 distinct axiom modules; v2's map
// above drives five. That is a real reduction in what a paid fleet does, and
// until this list existed it was recorded nowhere — a reader comparing the two
// trees had to grep the bash to discover it, and the difference was equally
// invisible at run time. TestAxiomModuleMapCoversV1Modules holds every `-m
// <module>` in modules/*.sh to being either mapped above or named here, so the
// gap can only ever shrink deliberately.
//
// PORTING ONE IS NOT A CODE-ONLY CHANGE. A module has to survive moduleArgsFor
// AND return output the v2 task's parser accepts; the canned axiom modules are
// minimal (dnsx is literally `cat input | dnsx -r <resolvers> -o output`) while
// v2's tasks parse specific shapes. Getting that wrong does not fail loudly —
// it returns text the parser reads as zero findings. So each entry stays here
// until it has been verified against a real fleet, not until it looks right.
// Reasons were checked against the Ax module definitions and axiom-scan's own
// source on 2026-09-04 (attacksurge/ax @ 06950c8), not inferred. Three facts
// from that reading shape the tiers below:
//
//   - add_extra_args() inserts forwarded args right after the module's binary,
//     so a tool flag v2 sends (httpx -json, katana -jc) lands inside the canned
//     command and takes effect; the txt variant merges by concatenation, which
//     is exactly right for JSONL.
//   - `-wL <local file>` uploads a local wordlist to every node and substitutes
//     the module's _wordlist_ placeholder. moduleArgsFor currently DROPS local
//     wordlist paths as unreachable; for these modules it should translate them
//     into -wL instead. That is the whole blocker for ffuf and puredns-single.
//   - A fleet split has no stdin, so anything v2 feeds through ExecOptions.Stdin
//     is refused by unsupportedOpt before it gets here (dalfox pipe mode).
var axiomModulesNotPorted = map[string]string{
	// Ready to port once a fleet run confirms them: the canned command already
	// matches what the v2 task sends, and v1 dispatched each of them this way.
	"httpx":   "canned txt variant + forwarded -json yields JSONL v2 parses (v1 did this); unverified on a fleet",
	"katana":  "canned per-_target_ variant + forwarded -jc/-kf/-d (v1 web.sh:1979 did this); unverified on a fleet",
	"wafw00f": "canned `wafw00f -i input -o output` is exactly v2's arg vector; unverified on a fleet",
	"subjs":   "canned pipe module; v2's -ua/-c forward cleanly; unverified on a fleet",
	"mantra":  "canned pipe module; unverified on a fleet",
	// Need a code change first.
	"ffuf":           "needs moduleArgsFor to turn the local wordlist into -wL (Ax uploads it and fills _wordlist_) instead of dropping it",
	"puredns-single": "the module exists (bruteforce, input = the WORDLIST split across nodes, domain forwarded — v1's model); needs extractInputFile to pick the wordlist for the bruteforce verb and the isLocalOnlyAxiomOp force lifted",
	"dalfox":         "v2 drives dalfox in pipe mode over ExecOptions.Stdin, which a fleet split cannot carry; port = rewrite to `file` mode with the reflected list as the input file",
	// Structurally different or absent in v2.
	"nmapx":              "v2 has no nmap-over-axiom task",
	"nuclei-screenshots": "output is a directory of PNGs content-addressed locally from a temp dir; needs the -oD dir merge, not the -o file path",
	"subfinder":          "API-bound; mapped to \"\" above so it is local by declaration, not by omission",
}

// Fleet-lifecycle timeouts. NONE of these calls is time-bounded by anything else:
// LocalBackend derives its deadline purely from the context (Tool.Timeout is not
// enforced there), and AxiomBackend calls it directly rather than through Runner.
// A live run proved the cost — `axiom-exec` blocked inside Launch for the FULL
// 120-minute scan budget, so the scan produced nothing and died on ctx cancel.
// Fleet management is best-effort setup; it must never be able to consume the
// scan's time budget.
const (
	axiomSelectTimeout    = 3 * time.Minute
	axiomDeployTimeout    = 15 * time.Minute
	axiomShutdownTimeout  = 5 * time.Minute
	axiomPropagateTimeout = 2 * time.Minute
)

// axiomDispatchTimeout caps ONE fleet dispatch, independently of the tool's own
// (much larger) local budget — dnsx is registered at 4h, puredns at 1h.
//
// Live fleets showed axiom-scan frequently never returning: it creates its
// ~/.axiom/tmp/<uid> directory, the remote work finishes, and the scan-side poll
// simply never completes. Without a cap of its own, one such dispatch burned 89
// minutes and (once dispatches were serialized) blocked every tool behind it.
//
// The point of distribution is to be FASTER than local. A dispatch still running
// after this long is not helping, so we treat it as an *AxiomFailure and let
// FailoverBackend re-run the tool locally with correct results.
const axiomDispatchTimeout = 10 * time.Minute

// axiomDispatchFailureLatch is how many dispatch failures in a row it takes to give
// up on the fleet for the rest of the run. A fleet that cannot return two dispatches
// will not return the next twenty, and each attempt costs axiomDispatchTimeout.
const axiomDispatchFailureLatch = 2

// isLocalOnlyAxiomOp returns true for tool operations that must run locally even
// under --axiom. The module map keys by tool name only, so it cannot see the
// sub-command: `puredns bruteforce` would be dispatched to "puredns-resolve", the
// wrong op, and silently yield zero brute candidates. A correct module DOES exist
// (Ax's "puredns-single": the wordlist is the input split across nodes, the
// domain a forwarded arg); wiring it needs extractInputFile to pick the wordlist
// for this verb — see axiomModulesNotPorted. Keep this in lockstep with
// defaultAxiomModuleMap.
func isLocalOnlyAxiomOp(tool string, args []string) bool {
	return tool == "puredns" && len(args) > 0 && args[0] == "bruteforce"
}

// AxiomBackend dispatches tools to an Axiom fleet via the axiom-scan CLI.
//
// Tools present in moduleMap (with a non-empty module name) are run via
// `axiom-scan <inputFile> -m <module> -o <outFile>` executed by the embedded
// LocalBackend. Tools with an empty moduleMap entry fall back to local execution
// transparently.
type AxiomBackend struct {
	cfg       *config.Config
	reg       *ToolRegistry
	log       *slog.Logger
	moduleMap map[string]string
	local     Backend // used to run axiom-scan or fallback local

	// disabled latches true once the fleet is known to be unusable (Launch could
	// not select any instance, or a dispatch came back with an empty selection).
	// Every later Exec/Stream then goes straight to local instead of paying the
	// SSH-preflight cost of an axiom-scan that will abort the same way.
	disabled atomic.Bool

	// dispatchSem (capacity 1) serializes fleet dispatches; lastDispatch is read and
	// written only while holding it. See dispatchGate for why both exist.
	dispatchSem  chan struct{}
	lastDispatch time.Time

	// distMu guards the two distribution ledgers below. They exist because a
	// fleet costs money and, before them, NOTHING anywhere told an operator what
	// the fleet actually did: an unmapped tool fell back to local silently, and
	// logs/tools.jsonl has no field naming the backend that ran an invocation.
	// "Did --axiom distribute anything?" was unanswerable after the fact.
	distMu     sync.Mutex
	dispatched map[string]int    // tool -> successful fleet dispatches
	ranLocally map[string]string // tool -> why it did NOT go to the fleet

	// dispatchFailures counts CONSECUTIVE failed dispatches; at
	// axiomDispatchFailureLatch the fleet is abandoned for the rest of the run.
	dispatchFailures atomic.Int32
}

// axiomUIDSeparation is the minimum gap between two dispatch starts.
//
// axiom-scan derives its scan identity as `uid="$module+$(date +%m-%d_%H-%M-%S-%1N)"`
// — module name plus a timestamp with ONE-DECISECOND resolution. Two dispatches of the
// same module inside the same 0.1s therefore share a uid, which means they share the
// remote /home/op/scan/<uid> directory AND the tmux session name on every node. A live
// run fired three dnsx dispatches 30ms apart: they collapsed into one axiom log dir,
// one returned in 5s, and the other two hung until their timeouts (89m).
const axiomUIDSeparation = 250 * time.Millisecond

// dispatchGate serializes fleet dispatches and spaces them past axiom-scan's uid
// granularity. It returns a release func, or an error if ctx ends while queuing.
//
// Serialization is also the semantically correct model: axiom-scan already splits its
// input across the WHOLE fleet, so several concurrent scans do not add throughput —
// they just contend for the same nodes.
func (a *AxiomBackend) dispatchGate(ctx context.Context) (func(), error) {
	if a.dispatchSem == nil { // defensive: zero-value backend, never built by New*
		return func() {}, nil
	}
	select {
	case a.dispatchSem <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if gap := axiomUIDSeparation - time.Since(a.lastDispatch); gap > 0 && !a.lastDispatch.IsZero() {
		timer := time.NewTimer(gap)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			<-a.dispatchSem
			return nil, ctx.Err()
		}
	}
	a.lastDispatch = time.Now()
	return func() { <-a.dispatchSem }, nil
}

// axiomLocalReason explains, in operator language, why a tool will NOT be sent to
// the fleet — or "" when it will be.
//
// The condition it replaces was written out three times (Exec, Stream and
// routesToFleet) and had to be kept in lockstep by hand. Naming the reason is the
// point: "ran locally" and "ran locally BECAUSE there is no axiom module for this
// tool" are different facts to someone deciding whether the fleet was worth it.
func (a *AxiomBackend) axiomLocalReason(t *Tool, args []string) string {
	module, ok := a.moduleMap[t.Name]
	switch {
	case !ok:
		return "no axiom module for this tool"
	case module == "":
		return "declared local-only in the module map"
	case isLocalOnlyAxiomOp(t.Name, args):
		return "this sub-command has no correct axiom module"
	case a.disabled.Load():
		return "fleet was abandoned earlier in this run"
	}
	return ""
}

// noteLocal records that a tool ran locally, and says so ONCE per tool.
//
// Once per tool, not once per call: a module that dispatches per host would
// otherwise bury the run's real output. Info, not Debug — an operator who paid
// for instances should not have to re-run at debug level to learn the fleet was
// idle for a given tool.
func (a *AxiomBackend) noteLocal(name, reason string) {
	a.distMu.Lock()
	if a.ranLocally == nil {
		a.ranLocally = make(map[string]string)
	}
	_, seen := a.ranLocally[name]
	a.ranLocally[name] = reason
	a.distMu.Unlock()
	if !seen && a.log != nil {
		a.log.Info("axiom_backend: running locally, not on the fleet",
			slog.String("tool", name), slog.String("reason", reason))
	}
}

// noteDispatch records one dispatch that actually returned fleet results.
func (a *AxiomBackend) noteDispatch(name string) {
	a.distMu.Lock()
	if a.dispatched == nil {
		a.dispatched = make(map[string]int)
	}
	a.dispatched[name]++
	a.distMu.Unlock()
}

// DistributionSummary reports what the fleet actually did this run: the tools it
// executed (with dispatch counts) and the tools it did not, each with its reason.
// Exported so a caller can surface it even when shutdown_on_end is false.
func (a *AxiomBackend) DistributionSummary() (dispatched map[string]int, local map[string]string) {
	a.distMu.Lock()
	defer a.distMu.Unlock()
	dispatched = make(map[string]int, len(a.dispatched))
	for k, v := range a.dispatched {
		dispatched[k] = v
	}
	local = make(map[string]string, len(a.ranLocally))
	for k, v := range a.ranLocally {
		local[k] = v
	}
	return dispatched, local
}

// logDistributionSummary emits the end-of-run accounting. A run in which the
// fleet executed NOTHING is reported at Warn: it means billable instances were
// provisioned and every tool still ran on the operator's own machine.
func (a *AxiomBackend) logDistributionSummary() {
	if a.log == nil {
		return
	}
	dispatched, local := a.DistributionSummary()
	total := 0
	tools := make([]string, 0, len(dispatched))
	for name, n := range dispatched {
		total += n
		tools = append(tools, name)
	}
	sort.Strings(tools)

	localTools := make([]string, 0, len(local))
	for name := range local {
		localTools = append(localTools, name)
	}
	sort.Strings(localTools)

	if total == 0 {
		a.log.Warn("axiom_backend: the fleet executed NOTHING this run — every tool ran locally",
			slog.Int("tools_run_locally", len(localTools)),
			slog.Any("local", localTools))
		return
	}
	a.log.Info("axiom_backend: distribution summary",
		slog.Int("dispatches", total),
		slog.Any("distributed", tools),
		slog.Any("ran_locally", localTools))
}

// NewAxiomBackend constructs the real AxiomBackend with cfg.Axiom.* settings.
// reg is used to look up the axiom-scan tool entry. logger may be nil (slog.Default used).
func NewAxiomBackend(cfg *config.Config, reg *ToolRegistry, logger *slog.Logger) *AxiomBackend {
	if logger == nil {
		logger = slog.Default()
	}
	return &AxiomBackend{
		cfg:         cfg,
		reg:         reg,
		log:         logger,
		moduleMap:   defaultAxiomModuleMap(),
		local:       NewLocalBackend(0), // default kill grace
		dispatchSem: make(chan struct{}, 1),
	}
}

// NewAxiomBackendWithLocal constructs an AxiomBackend with a test-injected local
// backend. This is the test-injection hook — production code uses NewAxiomBackend.
// Exported so the test package (backend_test) can inject fake backends.
func NewAxiomBackendWithLocal(cfg *config.Config, reg *ToolRegistry, logger *slog.Logger, local Backend) *AxiomBackend {
	if logger == nil {
		logger = slog.Default()
	}
	return &AxiomBackend{
		cfg:         cfg,
		reg:         reg,
		log:         logger,
		moduleMap:   defaultAxiomModuleMap(),
		local:       local,
		dispatchSem: make(chan struct{}, 1),
	}
}

// Exec dispatches toolName to axiom-scan (if in moduleMap) or falls back to
// local execution. Uses Tool.InputFlag to identify the input file — NOT a
// heuristic last-non-flag-arg scan (REVIEWS finding #5 fix).
func (a *AxiomBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
	if reason := a.axiomLocalReason(t, args); reason != "" {
		// Unmapped, explicitly local-only, an op with no correct axiom module
		// (puredns bruteforce — the map only has "puredns-resolve", the wrong op),
		// or a fleet already known to be unusable → transparent local fallback.
		// Transparent to the SCAN, but no longer invisible to the operator.
		a.noteLocal(t.Name, reason)
		return a.local.Exec(ctx, t, args)
	}
	module := a.moduleMap[t.Name]

	inputFile := extractInputFile(t, args)
	if inputFile == "" {
		// axiom-scan's whole model is splitting an input file across the fleet, so
		// with nothing to split there is no dispatch to make.
		a.noteLocal(t.Name, "no input file to split across the fleet")
		return a.local.Exec(ctx, t, args)
	}

	// Resolve axiom-scan tool entry from registry (may be nil if not registered).
	axiomTool := a.axiomScanTool()

	// Build the axiom-scan invocation:
	//   axiom-scan <inputFile> -m <module> <module args…> -o <outFile>
	//
	// The module args matter. axiom-scan's canned modules are minimal — dnsx is
	// literally `cat input | dnsx -r <remote resolvers> -o output` — while v2's
	// tasks build precise arg vectors and PARSE the matching output shape (dnsx
	// `-recon -json`, nuclei `-jsonl`, …). Dropping them, as this did, meant even a
	// perfectly healthy fleet returned output the task could not parse. axiom-scan
	// forwards any argument it does not recognise to the module command, which is
	// exactly how v1 drove it (modules/subdomains.sh: `-m nuclei -dast -nh -rl N …`).
	outFile := axiomOutFile(inputFile, t.Name)
	moduleArgs := moduleArgsFor(t, args, inputFile)
	axiomArgs := []string{inputFile, "-m", module}
	axiomArgs = append(axiomArgs, moduleArgs...)
	axiomArgs = append(axiomArgs, "-o", outFile)
	if a.cfg.Axiom.ExtraArgs != "" {
		axiomArgs = append(axiomArgs, strings.Fields(a.cfg.Axiom.ExtraArgs)...)
	}
	// Serialize + space out fleet dispatches (axiom-scan uid collision, see dispatchGate).
	// Done BEFORE the timeout clock starts so queueing never eats the tool's budget.
	release, gateErr := a.dispatchGate(ctx)
	if gateErr != nil {
		return nil, gateErr
	}
	defer release()

	// Logged AFTER the gate: this line means "an axiom-scan is starting NOW". Logging
	// it before made the live reports overcount — four "dispatching" lines when
	// serialization meant only one axiom-scan had actually run.
	if a.log != nil {
		a.log.Debug("axiom_backend: dispatching to fleet",
			slog.String("tool", t.Name), slog.String("module", module),
			slog.String("input", inputFile), slog.String("out", outFile),
			slog.Any("module_args", moduleArgs))
	}

	// Never let a leftover file from an earlier run masquerade as this run's results.
	_ = os.Remove(outFile)

	// Bound the dispatch by axiomDispatchTimeout, or by the tool's own registered
	// budget when that is SHORTER. Distribution must never buy a tool more wall-clock
	// than running it locally would, and a dispatch that outlives axiomDispatchTimeout
	// has already lost to simply running local.
	budget := axiomDispatchTimeout
	if t.Timeout > 0 && t.Timeout < budget {
		budget = t.Timeout
	}
	execCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	res, err := a.local.Exec(execCtx, axiomTool, axiomArgs)
	if err != nil {
		// A dispatch that ran out of OUR budget (not the caller's) is a fleet problem,
		// not a tool problem: report it as an AxiomFailure so the tool re-runs locally.
		if ctx.Err() == nil && execCtx.Err() != nil {
			a.recordDispatchFailure("dispatch exceeded " + budget.String())
			return nil, &coreerrors.AxiomFailure{
				Operation: "exec",
				Inner: fmt.Errorf("axiom-scan %s (module %s) did not return within %s — running locally instead",
					t.Name, module, budget),
			}
		}
		a.recordDispatchFailure("axiom-scan error")
		return nil, &coreerrors.AxiomFailure{
			Operation: "exec",
			Inner:     fmt.Errorf("axiom-scan %s: %w", t.Name, err),
		}
	}
	if res == nil {
		return nil, &coreerrors.AxiomFailure{
			Operation: "exec",
			Inner:     fmt.Errorf("axiom-scan %s: nil result", t.Name),
		}
	}

	// axiom-scan writes the fleet's aggregated tool output to outFile; its own stdout
	// is only progress/status noise (a large ASCII-art banner, then status lines).
	//
	// A MISSING outFile is the only reliable failure signal: axiom-scan aborts with
	// `exit` (no status) after printing e.g. "Unable to reach any instance selected",
	// so it exits 0 on a dead fleet. Surfacing its stdout in that case wrote the
	// BANNER TEXT into subdomains_dnsregs.json / resolved.*.txt as if it were tool
	// output — a silent data-poisoning bug. Returning *AxiomFailure instead lets
	// FailoverBackend immediately re-run the tool locally with correct results.
	out, rerr := os.ReadFile(outFile) //nolint:gosec // path derived from inputFile within the workspace
	if rerr != nil {
		diag := axiomScanDiagnostic(res)
		if isFleetUnreachable(diag) {
			// One dead fleet means every later dispatch dies the same way, each
			// paying a full SSH preflight. Latch local for the rest of the run.
			a.markDisabled("fleet unreachable: " + diag)
		}
		a.recordDispatchFailure("no output file")
		return nil, &coreerrors.AxiomFailure{
			Operation: "exec",
			Inner: fmt.Errorf("axiom-scan %s (module %s) produced no output file: %s",
				t.Name, module, diag),
		}
	}
	_ = os.Remove(outFile)
	res.Stdout = out
	a.dispatchFailures.Store(0) // a real result — the fleet is healthy again
	a.noteDispatch(t.Name)

	return res, nil
}

// axiomOutSeq numbers dispatch output files so concurrent dispatches never share one.
var axiomOutSeq atomic.Uint64

// axiomOutFile builds a unique `-o` path for one dispatch.
//
// It used to be `inputFile + ".axiom.out"`, derived solely from the input — but
// several tasks legitimately read the SAME input concurrently. A live run showed
// four dispatches (puredns-resolve + three dnsx variants) firing within 30ms, all
// pointed at inputs/passive.merged.txt.axiom.out: each one's pre-dispatch cleanup
// could delete another's finished results, and a read could pick up the wrong tool's
// output entirely. Per-dispatch names remove the race.
func axiomOutFile(inputFile, tool string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, tool)
	return fmt.Sprintf("%s.axiom.%s.%d.out", inputFile, safe, axiomOutSeq.Add(1))
}

// moduleArgsFor returns the tool's own arguments to forward to axiom-scan, which
// appends anything it does not recognise to the remote module command.
//
// Three classes are dropped:
//
//  1. The input file (and its flag) — axiom-scan splits and supplies it as the
//     module's `input` placeholder — plus a leading puredns sub-command verb, which
//     the module command already contains.
//  2. Flags axiom-scan owns (-m/-o/-oJ/…), which would fight the ones we set.
//  3. Arguments naming a path that exists on THIS machine (resolver lists, wordlists,
//     nuclei template dirs). Fleet nodes have their own copies at their own paths and
//     the module command already points at them; forwarding a local path makes the
//     remote tool fail. v1 handled this with a separate AXIOM_RESOLVERS_PATH setting;
//     the existence check generalises it — a path that is NOT local (already a remote
//     path) is forwarded untouched, matching v1's behaviour exactly.
func moduleArgsFor(t *Tool, args []string, inputFile string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]

		// (1) input file, its flag, and the positional sub-command verb.
		if t != nil && t.InputFlag != "" && arg == t.InputFlag {
			i++ // skip the value as well
			continue
		}
		if arg == inputFile || isPurednsVerb(arg) {
			continue
		}

		// (2) axiom-scan's own flags.
		if axiomScanOwnedFlags[arg] {
			if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
			}
			continue
		}

		// (3) local-only paths (drop the flag with its value).
		if strings.HasPrefix(arg, "-") && i+1 < len(args) && isExistingLocalPath(args[i+1]) {
			i++
			continue
		}
		if isExistingLocalPath(arg) {
			continue
		}

		out = append(out, arg)
	}
	return out
}

// axiomScanOwnedFlags are the output/module flags axiom-scan consumes itself.
// Forwarding a tool's own copy would collide with the -m/-o we set.
var axiomScanOwnedFlags = map[string]bool{
	"-m": true, "-o": true, "-oJ": true, "-oX": true, "-oD": true,
	"-csv": true, "-none": true, "--extra-args": true,
}

// isPurednsVerb reports whether arg is a puredns sub-command verb. The axiom
// puredns-resolve module command already starts with `puredns resolve`, so
// forwarding the verb again would corrupt the remote command line.
func isPurednsVerb(arg string) bool {
	return arg == "resolve" || arg == "bruteforce"
}

// isExistingLocalPath reports whether s looks like a filesystem path AND exists on
// this machine. The separator requirement keeps bare values ("3", "resolve") from
// accidentally matching a same-named file in the working directory.
func isExistingLocalPath(s string) bool {
	if s == "" || !strings.ContainsAny(s, "/\\") {
		return false
	}
	if _, err := os.Stat(s); err != nil {
		return false
	}
	return true
}

// axiomScanDiagnostic extracts a short, human-readable reason from axiom-scan's
// output. Its stdout leads with a multi-line ASCII-art banner, so this picks the
// last non-empty line (where the error lands) with ANSI escapes stripped.
func axiomScanDiagnostic(res *Result) string {
	if res == nil {
		return "no output"
	}
	for _, stream := range [][]byte{res.Stderr, res.Stdout} {
		lines := bytes.Split(stream, []byte("\n"))
		for i := len(lines) - 1; i >= 0; i-- {
			if line := strings.TrimSpace(stripANSI(string(lines[i]))); line != "" {
				return line
			}
		}
	}
	return "no output"
}

// stripANSI removes ANSI SGR escape sequences so diagnostics stay readable in
// JSON logs (axiom-scan colours its error lines).
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isFleetUnreachable matches axiom-scan's "no usable instances" abort, the
// condition that warrants latching local for the rest of the run.
func isFleetUnreachable(diag string) bool {
	d := strings.ToLower(diag)
	return strings.Contains(d, "unable to reach any instance") ||
		strings.Contains(d, "no instances selected")
}

// recordDispatchFailure counts a failed dispatch and abandons the fleet once
// axiomDispatchFailureLatch of them happen in a row. Without this, every remaining
// tool of the scan pays the full axiomDispatchTimeout before falling back.
func (a *AxiomBackend) recordDispatchFailure(reason string) {
	if a.dispatchFailures.Add(1) >= axiomDispatchFailureLatch {
		a.markDisabled(fmt.Sprintf("%d dispatches in a row failed (%s)", axiomDispatchFailureLatch, reason))
	}
}

// markDisabled latches the local-only fallback and logs why (once).
func (a *AxiomBackend) markDisabled(reason string) {
	if a.disabled.CompareAndSwap(false, true) && a.log != nil {
		a.log.Warn("axiom_backend: fleet unusable — running every remaining tool locally",
			slog.String("reason", reason), slog.String("fleet", a.cfg.Axiom.FleetName))
	}
}

// routesToFleet reports whether a dispatch for tool t with args would actually
// be sent to the axiom fleet, as opposed to being served by the transparent
// local fallback. It is the SAME condition Exec applies at its top, extracted so
// the option/env seams can consult routing BEFORE deciding to refuse.
//
// WHY THIS EXISTS (18-06 code review, CR-02). ExecOpts/StreamOpts/ExecEnv/
// StreamEnv used to refuse an unsupported option FIRST and consult routing never.
// For an UNMAPPED tool — which Exec would have delegated to a.local without ever
// touching the fleet — that turned a dispatch guaranteed to succeed locally into
// a typed *AxiomFailure. Before capability refusals were distinguished from
// infrastructure failures, FailoverBackend counted that type as evidence the
// fleet was unhealthy, so three such dispatches abandoned the fleet for the rest
// of the scan. 18-04/18-05 added ten option-carrying sites, two of which iterate
// per host or per repo, so three in a row is the normal path of any --vps run.
//
// A capability refusal is not evidence of an unhealthy fleet. Refusing loudly is
// still correct for a tool that WOULD have gone to the fleet (T-18-01-05) — that
// case is preserved below, unchanged.
func (a *AxiomBackend) routesToFleet(t *Tool, args []string) bool {
	// A nil local leg means there is nothing to delegate TO. A zero-valued
	// AxiomBackend (only constructed in tests — NewAxiomBackend always sets local)
	// would panic on the delegation below, and its Exec would panic on the very
	// same local-fallback arm, so the refusal is the only behaviour it can offer.
	// Reporting "routes to fleet" here keeps that path reachable and preserves the
	// T-18-01-05 refusal contract asserted by TestAxiomRefusesStdin.
	if a.local == nil {
		return true
	}
	if a.axiomLocalReason(t, args) != "" {
		return false
	}
	// V-02: Exec has a SECOND local-fallback arm — an unresolvable input file
	// (axiom.go, "no input file found, falling back to local"). The first version
	// of this helper mirrored only the first arm, so a MAPPED tool dispatched with
	// options and no resolvable input file would still be refused and still be
	// counted as a fleet failure: the exact CR-02 shape, one arm deeper. Not
	// reachable today — the mapped set is {puredns, tlsx, dnsx, s3scanner, nuclei}
	// and none of the option/env-carrying module sites dispatches any of them — but
	// "not reachable today" is what the FOUND-10 allowlist said too.
	return extractInputFile(t, args) != ""
}

// ExecEnv implements the Backend env seam. The axiom fleet split has NO env
// passthrough channel, so AxiomBackend does not support child-env injection: a
// non-empty env returns *AxiomFailure (not-supported). With a nil/empty env it
// delegates to Exec (identical behavior). OSINT tools that need GH_TOKEN run on
// LocalBackend per D-O1, so this restriction never blocks them.
func (a *AxiomBackend) ExecEnv(ctx context.Context, t *Tool, args []string, env []string) (*Result, error) {
	if !a.routesToFleet(t, args) {
		return a.local.ExecEnv(ctx, t, args, env)
	}
	if len(env) > 0 {
		return nil, &coreerrors.AxiomFailure{
			Operation:  "exec_env",
			Inner:      fmt.Errorf("axiom backend does not support child-env injection (tool %s); run env-requiring tools on LocalBackend", t.Name),
			Capability: true,
		}
	}
	return a.Exec(ctx, t, args)
}

// StreamEnv implements the Backend env seam for streaming. Same not-supported
// contract as ExecEnv: non-empty env returns *AxiomFailure; nil env delegates
// to Stream.
func (a *AxiomBackend) StreamEnv(ctx context.Context, t *Tool, args []string, env []string) (<-chan Event, error) {
	if !a.routesToFleet(t, args) {
		return a.local.StreamEnv(ctx, t, args, env)
	}
	if len(env) > 0 {
		return nil, &coreerrors.AxiomFailure{
			Operation:  "stream_env",
			Inner:      fmt.Errorf("axiom backend does not support child-env injection (tool %s); run env-requiring tools on LocalBackend", t.Name),
			Capability: true,
		}
	}
	return a.Stream(ctx, t, args)
}

// unsupportedOpt names the FIRST ExecOptions field the axiom fleet split cannot
// carry, or "" when the options are servable. Returning the NAME rather than a
// bare bool is the point: an operator reading logs/tools.jsonl has to be able to
// tell which capability was refused without reading this file.
func unsupportedOpt(t *Tool, opts ExecOptions) string {
	switch {
	case len(opts.Env) > 0:
		return "Env"
	case opts.Stdin != nil:
		return "Stdin"
	case opts.StdinPath != "":
		return "StdinPath"
	case opts.Dir != "":
		return "Dir"
	}
	// WR-01: a cwd or an interpreter prefix can arrive on the TOOL as well as on
	// the options, and after 18-02 Tool.WorkDir is the ONLY supported way to
	// express a clone's working directory — 18-05 routes nomore403 and bypass4xx
	// through it deliberately. Keying the refusal on the options struct alone meant
	// a tool whose requirement lived on the Tool was dispatched to the fleet with
	// that requirement silently dropped: precisely the "a wrapper forgets a
	// capability" hazard Option A was chosen to make a compile error, reintroduced
	// one layer down. ArgvPrefix is worse than useless on a fleet node — it carries
	// absolute LOCAL clone paths.
	if t != nil {
		switch {
		case t.WorkDir != "":
			return "Tool.WorkDir"
		case len(t.ArgvPrefix) > 0:
			return "Tool.ArgvPrefix"
		}
	}
	return ""
}

// ExecOpts implements the Backend options seam. A fleet split has no stdin
// channel, no cwd and no env channel, so AxiomBackend REFUSES a dispatch carrying
// any of them with a typed *AxiomFailure naming the offending field — it does not
// silently drop the option and run the tool anyway.
//
// Refusing loudly is the whole point (T-18-01-05): *AxiomFailure is the error type
// FailoverBackend keys on, so a stdin-carrying dispatch transparently lands on the
// local leg WITH its stdin intact, instead of running on the fleet with an empty
// standard input and reporting a clean zero-finding success.
func (a *AxiomBackend) ExecOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (*Result, error) {
	if !a.routesToFleet(t, args) {
		// Never going to the fleet — serve it locally WITH its options, exactly as
		// Exec's local-fallback arm already does. Refusing here would manufacture a
		// fleet failure out of a dispatch the fleet was never going to see (CR-02).
		return a.local.ExecOpts(ctx, t, args, opts)
	}
	if field := unsupportedOpt(t, opts); field != "" {
		return nil, &coreerrors.AxiomFailure{
			Operation:  "exec_opts",
			Inner:      fmt.Errorf("axiom backend does not support ExecOptions.%s (tool %s); run option-requiring tools on LocalBackend", field, t.Name),
			Capability: true,
		}
	}
	return a.Exec(ctx, t, args)
}

// StreamOpts is ExecOpts for the streaming mode; same refusal contract.
func (a *AxiomBackend) StreamOpts(ctx context.Context, t *Tool, args []string, opts ExecOptions) (<-chan Event, error) {
	if !a.routesToFleet(t, args) {
		return a.local.StreamOpts(ctx, t, args, opts)
	}
	if field := unsupportedOpt(t, opts); field != "" {
		return nil, &coreerrors.AxiomFailure{
			Operation:  "stream_opts",
			Inner:      fmt.Errorf("axiom backend does not support ExecOptions.%s (tool %s); run option-requiring tools on LocalBackend", field, t.Name),
			Capability: true,
		}
	}
	return a.Stream(ctx, t, args)
}

// extractInputFile returns the input file path from tool args using Tool.InputFlag.
//
// If Tool.InputFlag is non-empty (e.g. "-l"), returns the arg immediately
// following InputFlag in args. If InputFlag is empty, returns the last element of
// args (positional convention used by puredns, massdns, etc.).
// Returns "" if the flag is not found or args is empty.
func extractInputFile(t *Tool, args []string) string {
	if len(args) == 0 {
		return ""
	}
	if t.InputFlag != "" {
		// Find the arg immediately after InputFlag.
		for i, arg := range args {
			if arg == t.InputFlag && i+1 < len(args) {
				return args[i+1]
			}
		}
		return "" // flag not found
	}
	// InputFlag="" — positional. puredns (the only positional mapped tool) is invoked
	// verb-first: `puredns resolve <file> …` / `puredns bruteforce <wordlist> …`. Return
	// the FIRST non-flag arg, skipping a leading sub-command verb. The old "last element"
	// heuristic returned a trailing flag like "--quiet", so axiom-scan got a bogus input
	// path and the distributed run silently yielded nothing.
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") {
			continue // skip flags and their inline values are positional-independent here
		}
		if arg == "resolve" || arg == "bruteforce" {
			continue // skip the puredns sub-command verb
		}
		return arg
	}
	return ""
}

// axiomScanTool looks up the "axiom-scan" entry from the registry.
// If not found, returns a synthetic Tool entry so tests that don't seed
// the registry still work (they inject a fake local that ignores the Tool struct).
func (a *AxiomBackend) axiomScanTool() *Tool {
	if a.reg != nil {
		if t, ok := a.reg.Lookup("axiom-scan"); ok {
			return t
		}
	}
	return &Tool{Name: "axiom-scan", Path: "axiom-scan"}
}

// Stream dispatches the tool via axiom-scan (if mapped), buffers the result,
// and emits it over the returned channel. If the tool is unmapped, delegates
// to local.Stream transparently.
func (a *AxiomBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	if reason := a.axiomLocalReason(t, args); reason != "" {
		a.noteLocal(t.Name, reason)
		return a.local.Stream(ctx, t, args)
	}
	// Axiom: run Exec (buffer whole result), then pipe through a channel.
	res, err := a.Exec(ctx, t, args)
	if err != nil {
		return nil, err
	}
	out := make(chan Event, 1)
	go func() {
		defer close(out)
		for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			select {
			case out <- Event{Line: line, Source: t.Name}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// HealthCheck verifies the axiom fleet is reachable by running
// `axiom-exec "echo reconftw-axiom-probe"`. If the output contains
// "REMOTE HOST IDENTIFICATION HAS CHANGED", triggers repairKnownHosts
// when AutoFixHostkey=true; otherwise returns *AxiomFailure.
func (a *AxiomBackend) HealthCheck(ctx context.Context) error {
	pctx, cancel := context.WithTimeout(ctx, axiomSelectTimeout)
	defer cancel()
	probeResult, err := a.local.Exec(pctx, a.axiomScanTool(), []string{"echo", "reconftw-axiom-probe"})

	var stderrBytes []byte
	if probeResult != nil {
		stderrBytes = probeResult.Stderr
	}

	if err != nil || (probeResult != nil && probeResult.ExitCode != 0) {
		// Check for hostkey change in stderr.
		if bytes.Contains(stderrBytes, []byte("REMOTE HOST IDENTIFICATION HAS CHANGED")) {
			if a.cfg.Axiom.AutoFixHostkey {
				_ = a.repairKnownHosts(ctx, stderrBytes)
				return nil // attempt repair; best-effort
			}
			return &coreerrors.AxiomFailure{
				Operation: "healthcheck",
				Inner:     fmt.Errorf("SSH host key changed; set auto_fix_hostkey=true or run ssh-keygen -R <host>"),
			}
		}
		inner := err
		if inner == nil {
			inner = fmt.Errorf("axiom-exec probe exited with code %d", probeResult.ExitCode)
		}
		return &coreerrors.AxiomFailure{Operation: "healthcheck", Inner: inner}
	}
	return nil
}

// repairKnownHosts parses the offending hostname from SSH stderr and runs
// ssh-keygen -R <host> to remove the stale key (T-04-06-01 mitigation).
// Only called when AutoFixHostkey=true (explicit opt-in).
func (a *AxiomBackend) repairKnownHosts(ctx context.Context, errOutput []byte) error {
	// Parse offending host from SSH stderr pattern:
	// "Offending ECDSA key in /home/user/.ssh/known_hosts:42"
	// "Host key verification failed."
	host := parseOffendingHost(errOutput)

	sshKeygenTool := &Tool{Name: "ssh-keygen", Path: "ssh-keygen"}
	repairArgs := []string{"-R", host}
	if host == "" {
		repairArgs = []string{"-R", a.cfg.Axiom.FleetName}
	}
	kctx, cancel := context.WithTimeout(ctx, axiomPropagateTimeout)
	defer cancel()
	_, err := a.local.Exec(kctx, sshKeygenTool, repairArgs)
	if err != nil {
		a.log.Warn("axiom_backend: repairKnownHosts ssh-keygen failed",
			slog.String("host", host), slog.Any("err", err))
	} else {
		a.log.Info("axiom_backend: repaired known_hosts", slog.String("host", host))
	}
	return err
}

// parseOffendingHost extracts the hostname from SSH stderr output.
// Returns "" if the pattern is not found.
func parseOffendingHost(errOutput []byte) string {
	// Look for lines like: "Offending key in /home/.../.ssh/known_hosts:N"
	// or "@ WARNING: POSSIBLE DNS SPOOFING DETECTED! @" followed by fleet hostname.
	// Simplified: look for a hostname pattern after "Offending" on the same line.
	for _, line := range bytes.Split(errOutput, []byte("\n")) {
		if bytes.Contains(line, []byte("Offending")) {
			// Try to find host from context — look for IP or hostname patterns.
			// For the repair to work we use the fleet name as fallback.
			fields := bytes.Fields(line)
			for _, f := range fields {
				if bytes.Contains(f, []byte(".")) && !bytes.Contains(f, []byte("/")) {
					return string(f)
				}
			}
		}
	}
	return ""
}

// Capacity returns the configured fleet size (cfg.Axiom.FleetCount).
func (a *AxiomBackend) Capacity() int {
	return a.cfg.Axiom.FleetCount
}

// Launch provisions the axiom fleet, selects it, and propagates resolver files.
// Called by newSubsCmd before the first RunStage.
func (a *AxiomBackend) Launch(ctx context.Context) error {
	// If FleetLaunch is set, provision missing nodes FIRST — selecting before the
	// instances exist can only ever match nothing.
	if a.cfg.Axiom.FleetLaunch {
		fleet2Tool := &Tool{Name: "axiom-fleet2", Path: "axiom-fleet2"}
		fleetArgs := []string{
			"deploy", a.cfg.Axiom.FleetName,
			fmt.Sprintf("--count=%d", a.cfg.Axiom.FleetCount),
		}
		dctx, cancel := context.WithTimeout(ctx, axiomDeployTimeout)
		_, err := a.local.Exec(dctx, fleet2Tool, fleetArgs)
		cancel()
		if err != nil {
			a.log.Warn("axiom_backend: fleet2 deploy failed (non-fatal if fleet exists)",
				slog.String("fleet", a.cfg.Axiom.FleetName), slog.Any("err", err))
		}
	}

	// Select the fleet's instances. THE NAME MUST BE A PREFIX GLOB: axiom names a
	// fleet's members <fleet>01, <fleet>02, … so `axiom-select <fleet>` matches none
	// of them and writes an EMPTY selected.conf — after which every axiom-scan aborts
	// with "Unable to reach any instance selected" while still exiting 0. axiom-select's
	// own help documents the wildcard form (`axiom-select elion*`).
	axiomSelectTool := &Tool{Name: "axiom-select", Path: "axiom-select"}
	selector := fleetSelector(a.cfg.Axiom.FleetName)
	sctx, cancelSelect := context.WithTimeout(ctx, axiomSelectTimeout)
	res, err := a.local.Exec(sctx, axiomSelectTool, []string{selector})
	cancelSelect()
	if err != nil {
		a.markDisabled("axiom-select failed")
		return &coreerrors.AxiomFailure{
			Operation: "launch",
			Inner:     fmt.Errorf("axiom-select %s: %w", selector, err),
		}
	}
	// axiom-select exits 0 even when it matched nothing; its "Selected: [ … ]" line
	// is the only signal. Catch it here so the run degrades to local immediately
	// instead of after N failed dispatches.
	if res != nil && selectedNoInstances(res.Stdout) {
		a.markDisabled("axiom-select matched no instances for " + selector)
		return &coreerrors.AxiomFailure{
			Operation: "launch",
			Inner: fmt.Errorf("axiom-select %s matched no instances — is the fleet up? (axiom-ls)",
				selector),
		}
	}
	if a.log != nil {
		a.log.Info("axiom_backend: fleet selected", slog.String("selector", selector))
	}
	return a.resolversPropagation(ctx)
}

// fleetSelector turns a fleet name into the instance-matching glob axiom expects.
// Already-globbed names are passed through untouched.
func fleetSelector(fleetName string) string {
	if fleetName == "" || strings.ContainsAny(fleetName, "*?") {
		return fleetName
	}
	return fleetName + "*"
}

// selectedNoInstances reports whether axiom-select's output shows an empty
// selection — its final line is `Selected: [  <names…>  ]`.
func selectedNoInstances(stdout []byte) bool {
	text := stripANSI(string(stdout))
	idx := strings.LastIndex(text, "Selected:")
	if idx < 0 {
		return false // unrecognised output shape — don't guess, let dispatch decide
	}
	sel := text[idx+len("Selected:"):]
	sel = strings.TrimSpace(strings.Trim(strings.TrimSpace(sel), "[]"))
	return strings.TrimSpace(sel) == ""
}

// Shutdown removes the fleet when ShutdownOnEnd=true.
func (a *AxiomBackend) Shutdown(ctx context.Context) error {
	// BEFORE the ShutdownOnEnd gate: the accounting is about what the run did, and
	// an operator who keeps the fleet alive between scans needs it just as much as
	// one who tears it down.
	a.logDistributionSummary()

	if !a.cfg.Axiom.ShutdownOnEnd {
		return nil
	}
	// Same naming rule as Launch — and here it costs MONEY: `axiom-rm <fleet>` matches
	// no instance (they are <fleet>01, <fleet>02, …), so shutdown_on_end silently left
	// the paid droplets running. Delete by prefix glob.
	axiomRmTool := &Tool{Name: "axiom-rm", Path: "axiom-rm"}
	selector := fleetSelector(a.cfg.Axiom.FleetName)
	rctx, cancel := context.WithTimeout(ctx, axiomShutdownTimeout)
	defer cancel()
	if _, err := a.local.Exec(rctx, axiomRmTool, []string{selector, "--force"}); err != nil {
		return &coreerrors.AxiomFailure{
			Operation: "shutdown",
			Inner:     fmt.Errorf("axiom-rm %s: %w", selector, err),
		}
	}
	a.log.Info("axiom_backend: fleet shut down", slog.String("fleet", selector))
	return nil
}

// resolversPropagation copies the operator's resolver lists onto the fleet nodes
// (AXIOM-05), so distributed puredns/dnsx resolve against the same set as a local run.
//
// It previously shelled a heredoc through axiom-exec:
//
//	axiom-exec "cat > /tmp/resolvers.txt << 'EOF'\n$(cat <path>)\nEOF"
//
// which was wrong twice over. The `$(cat …)` expands on the REMOTE node, where that
// file is what we were trying to create; and it wrote /tmp/resolvers.txt, which no
// axiom module reads. Worse, on a live run that command HUNG — it burned the entire
// 120-minute scan budget inside Launch and the scan produced nothing. (It had never
// hung before only because the fleet-selection bug made axiom-exec abort instantly.)
//
// axiom-scp is the purpose-built transfer (`axiom-scp <local> 'fleet*':<remote>`) —
// no remote shell, no heredoc, no stdin. Per-file deadline and best-effort throughout:
// the axiom images already ship resolver lists, so a failed refresh must never be
// more than a warning.
//
// Source paths are the operator's LOCAL lists (cfg.Paths.*); destinations are the
// node-side paths (cfg.Advanced.Tools.Axiom.*Path, default /home/op/lists/*) that the
// axiom module commands read — the same split v1 used (AXIOM_RESOLVERS_PATH).
func (a *AxiomBackend) resolversPropagation(ctx context.Context) error {
	uploads := []struct{ local, remote string }{
		{a.cfg.Paths.Resolvers, a.cfg.Advanced.Tools.Axiom.ResolversPath},
		{a.cfg.Paths.ResolversTrusted, a.cfg.Advanced.Tools.Axiom.ResolversTrustedPath},
	}
	selector := fleetSelector(a.cfg.Axiom.FleetName)
	axiomScpTool := &Tool{Name: "axiom-scp", Path: "axiom-scp"}

	for _, up := range uploads {
		if up.local == "" || up.remote == "" {
			continue // nothing configured to send, or nowhere to send it
		}
		if _, err := os.Stat(up.local); err != nil {
			a.log.Debug("axiom_backend: resolver list not present locally — skipping upload",
				slog.String("file", up.local))
			continue
		}
		uctx, cancel := context.WithTimeout(ctx, axiomPropagateTimeout)
		_, err := a.local.Exec(uctx, axiomScpTool, []string{up.local, selector + ":" + up.remote})
		cancel()
		if err != nil {
			a.log.Warn("axiom_backend: resolver propagation failed (non-fatal — nodes keep their own lists)",
				slog.String("from", up.local), slog.String("to", up.remote), slog.Any("err", err))
			continue
		}
		a.log.Debug("axiom_backend: resolvers propagated to fleet",
			slog.String("from", up.local), slog.String("to", up.remote))
	}
	return nil
}
