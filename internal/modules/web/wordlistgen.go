// wordlistgen.go — WebWordlistGenTask: roboxtractor + getjswords wordlist
// generation (PAR-04). pydictor (leet) is DEFERRED to Phase 14.
//
// Name: "web.wordlistgen"  DependsOn: nil (sequential stage; reads web + JS corpus)
//
// Ports bash wordlist_gen_roboxtractor (web.sh:2691) + the jschecks getjswords
// step (web.sh:2343-2398): two independent, best-effort fuzzing-augmentation
// wordlist generators.
//
//	roboxtractor -m 1 -wb  < web targets   → webs/robots_wordlist.txt
//	getjswords.py <js-url> (per JS URL)     → webs/dict_words.txt
//
// cfg.Web.Wordlist.* (defaults.go:145) was previously unreferenced. Each
// generator degrades INDEPENDENTLY: a missing tool / empty input logs a warning
// and skips ONLY that generator — the task still returns StatusDone (T-13-04-02).
//
// pydictor (leet-password wordlists) is a Deferred Idea (niche, 13-CONTEXT.md
// "Deferred Ideas") → DEFERRED to Phase 14, documented below, and NOT invoked.
//
// SUBPROCESS NOTE (FOUND-10): roboxtractor is a stdin-only tool and getjswords is
// a repo Python script — neither routes through the name-keyed Backend/Runner
// registry (no stdin / cmd path injection). Like the sibling stdin wrappers
// (web/hakoriginfinder.go, web/gxss.go, subdomains/reverseip.go) this file uses
// direct, timeout-bounded exec.CommandContext behind overridable package-var
// runners, and is on the FOUND-10 allowlist. XCUT-07: no secrets on argv (URLs /
// paths only).
//
// Symbol hygiene (checker LOW #7): all unexported helpers are wordlistgen*-prefixed.
//
// Source: .planning/phases/13-domain-parity/13-04-PLAN.md Task 3.
package web

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// wordlistgenPydictorDeferred documents the pydictor deferral (13-CONTEXT.md
// Deferred Ideas). pydictor leet wordlists are niche; they are DEFERRED to
// Phase 14 and deliberately NOT invoked by this task.
const wordlistgenPydictorDeferred = "pydictor leet wordlists deferred to Phase 14 (niche, Deferred Idea)"

// Per-invocation timeouts (roboxtractor mirrors tools.lock; getjswords is a
// short per-URL fetch+parse).
const (
	wordlistgenRoboxTimeout  = 120 * time.Second
	wordlistgenGetJSWTimeout = 30 * time.Second
)

// wordlistgenRoboxtractorRunner runs `roboxtractor -m 1 -wb` with the web target
// URLs on stdin and returns raw stdout (robots-derived paths). Overridable in
// tests. Returns (nil, nil) when roboxtractor is not on PATH (graceful skip).
var wordlistgenRoboxtractorRunner = func(ctx context.Context, _ *appctx.AppContext, urls []string) ([]byte, error) {
	if len(urls) == 0 {
		return nil, nil
	}
	bin, err := exec.LookPath("roboxtractor")
	if err != nil {
		return nil, nil // not installed — graceful skip (D-O2)
	}
	cmdCtx, cancel := context.WithTimeout(ctx, wordlistgenRoboxTimeout)
	defer cancel()
	//nolint:gosec // bin from LookPath; stdin carries scope-derived web target URLs only (XCUT-07)
	cmd := exec.CommandContext(cmdCtx, bin, "-m", "1", "-wb")
	cmd.Stdin = strings.NewReader(strings.Join(urls, "\n") + "\n")
	var out bytes.Buffer
	cmd.Stdout = &out
	if runErr := cmd.Run(); runErr != nil {
		return out.Bytes(), runErr // partial output still parsed by caller
	}
	return out.Bytes(), nil
}

// wordlistgenGetJSWordsRunner runs getjswords.py (via cfg.Web.JS.GetJSWordsPython)
// once per JS URL and returns the aggregated stdout words. Overridable in tests.
// Returns (nil, nil) when python or the script is absent (graceful skip).
var wordlistgenGetJSWordsRunner = func(ctx context.Context, app *appctx.AppContext, jsURLs []string) ([]byte, error) {
	if len(jsURLs) == 0 {
		return nil, nil
	}
	python := app.Cfg.Web.JS.GetJSWordsPython
	if python == "" {
		python = "python3"
	}
	pyBin, err := exec.LookPath(python)
	if err != nil {
		return nil, nil // python absent — graceful skip (D-O2)
	}
	script := filepath.Join(resolveToolsDir(app.Cfg), "getjswords.py")
	if st, statErr := os.Stat(script); statErr != nil || st.IsDir() {
		return nil, nil // getjswords.py absent — graceful skip
	}
	var out bytes.Buffer
	for _, u := range jsURLs {
		cmdCtx, cancel := context.WithTimeout(ctx, wordlistgenGetJSWTimeout)
		//nolint:gosec // pyBin+script validated above; u is a scope-filtered JS URL (XCUT-07)
		cmd := exec.CommandContext(cmdCtx, pyBin, script, u)
		var buf bytes.Buffer
		cmd.Stdout = &buf
		_ = cmd.Run() // best-effort per URL — a single failure never aborts the batch
		cancel()
		if buf.Len() > 0 {
			out.Write(buf.Bytes())
			if buf.Bytes()[buf.Len()-1] != '\n' {
				out.WriteByte('\n')
			}
		}
	}
	return out.Bytes(), nil
}

// WebWordlistGenTask generates roboxtractor + getjswords fuzzing wordlists.
type WebWordlistGenTask struct{}

func (t *WebWordlistGenTask) Name() string   { return "web.wordlistgen" }
func (t *WebWordlistGenTask) Module() string { return "web" }
func (t *WebWordlistGenTask) Description() string {
	return "Wordlist generation (roboxtractor robots + getjswords JS words)"
}

// Enabled gates on cfg.Web.Wordlist.Enabled (bash WORDLIST, default true).
func (t *WebWordlistGenTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.Wordlist.Enabled
}

// DependsOn returns nil: wordlistgen is a sequential stage reading the web + JS
// corpus; plan 13-08 places it in the stage order.
func (t *WebWordlistGenTask) DependsOn() []string { return nil }

// Run drives the two independent best-effort generators (bash wordlist_gen).
// pydictor is deliberately NOT invoked (see wordlistgenPydictorDeferred).
func (t *WebWordlistGenTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	wl := app.Cfg.Web.Wordlist
	if !wl.Enabled {
		if app.Log != nil {
			app.Log.Info("web.wordlistgen: disabled (cfg.Web.Wordlist.Enabled=false) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	// bash guard: wordlist_gen is skipped for bare-IP targets (web.sh:2657).
	if app.Target != nil && app.Target.IsIP {
		if app.Log != nil {
			app.Log.Info("web.wordlistgen: IP-literal target — skipping (bash parity)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	websDir := filepath.Join(app.Target.WorkDir, "webs")
	if err := os.MkdirAll(websDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored}, err
	}

	robotsWords := wordlistgenRunRoboxtractor(ctx, app, websDir, wl)
	jsWords := wordlistgenRunGetJSWords(ctx, app, websDir)

	if app.Log != nil {
		app.Log.Debug("web.wordlistgen: completed",
			"robots_words", robotsWords, "js_words", jsWords,
			"pydictor", "deferred")
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"robots_words": robotsWords, "js_words": jsWords},
	}, nil
}

// wordlistgenRunRoboxtractor runs the roboxtractor generator independently and
// returns the number of new words written to webs/robots_wordlist.txt (0 when the
// tool/input is absent or it fails — a warning is logged, never an error).
func wordlistgenRunRoboxtractor(ctx context.Context, app *appctx.AppContext, websDir string, wl config.WebWordlist) int {
	if !wl.RobotsEnabled {
		return 0
	}
	urls, _ := readHostURLsFromJSONL(app)
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Debug("web.wordlistgen: no web targets for roboxtractor — skipping robots wordlist")
		}
		return 0
	}
	raw, err := wordlistgenRoboxtractorRunner(ctx, app, urls)
	if err != nil && app.Log != nil {
		app.Log.Info("web.wordlistgen: roboxtractor failed/absent — skipping robots wordlist", "err", err)
	}
	words := wordlistgenSplitLines(raw)
	if len(words) == 0 {
		return 0
	}
	return wordlistgenAnew(filepath.Join(websDir, "robots_wordlist.txt"), words)
}

// wordlistgenRunGetJSWords runs the getjswords generator independently and returns
// the number of new words written to webs/dict_words.txt (0 when absent/empty).
func wordlistgenRunGetJSWords(ctx context.Context, app *appctx.AppContext, websDir string) int {
	jsURLs, _ := readJSURLsFromJSONL(app)
	if len(jsURLs) == 0 {
		if app.Log != nil {
			app.Log.Debug("web.wordlistgen: no JS URLs for getjswords — skipping JS wordlist")
		}
		return 0
	}
	raw, err := wordlistgenGetJSWordsRunner(ctx, app, jsURLs)
	if err != nil && app.Log != nil {
		app.Log.Info("web.wordlistgen: getjswords failed/absent — skipping JS wordlist", "err", err)
	}
	words := wordlistgenSplitLines(raw)
	if len(words) == 0 {
		return 0
	}
	return wordlistgenAnew(filepath.Join(websDir, "dict_words.txt"), words)
}

// wordlistgenSplitLines splits raw tool output into trimmed, non-empty lines.
func wordlistgenSplitLines(raw []byte) []string {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		if s := strings.TrimSpace(line); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// wordlistgenAnew appends new unique lines to path (bash `anew -q`), deduplicating
// against existing content. Returns the number of newly added lines.
func wordlistgenAnew(path string, lines []string) int {
	existing := make(map[string]struct{})
	var buf bytes.Buffer
	if data, err := os.ReadFile(path); err == nil { //nolint:gosec // path within WorkDir
		buf.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			buf.WriteByte('\n')
		}
		for _, l := range strings.Split(string(data), "\n") {
			if s := strings.TrimSpace(l); s != "" {
				existing[s] = struct{}{}
			}
		}
	}
	added := 0
	for _, l := range lines {
		if _, ok := existing[l]; ok {
			continue
		}
		existing[l] = struct{}{}
		buf.WriteString(l + "\n")
		added++
	}
	if added > 0 {
		_ = os.WriteFile(path, buf.Bytes(), 0o644) //nolint:gosec,errcheck
	}
	return added
}

func init() { task.Register(&WebWordlistGenTask{}) }
