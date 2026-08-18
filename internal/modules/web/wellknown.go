// wellknown.go — WebWellKnownTask: .well-known metadata endpoint pivots (PAR-04).
//
// Name: "web.wellknown"  DependsOn: nil (sequential stage; reads the web targets)
//
// Ports bash well_known_pivots (modules/web.sh:2500): over the web target set it
// probes RFC 9116 security.txt (+ /security.txt), OpenID Connect discovery
// (/.well-known/openid-configuration) and OAuth AS metadata
// (/.well-known/oauth-authorization-server), extracts hostnames that match the
// target scope, and stages them as new host discoveries. cfg.Web.WellKnown
// (config.go:321) was previously unreferenced — DEFAULT-OFF (bash parity), so the
// task only runs when explicitly enabled.
//
// SSRF / scope guard (T-13-04-01): each web target URL is re-validated in-scope
// BEFORE any fetch — off-scope hosts and URLs carrying userinfo (user:pass@host)
// are rejected. Hostnames extracted from responses are filtered against the same
// scope before staging (bash DOMAIN_MATCH_REGEX equivalent). MaxTargets caps the
// number of probed URLs.
//
// This task uses native net/http (best-effort, short-timeout) — NOT a subprocess
// — so it is not on the FOUND-10 allowlist. Every HTTP error logs at Debug and
// continues; a fetch failure NEVER produces StatusErrored (bash best-effort).
//
// OUTPUT CONTRACT: discovered in-scope hostnames are written as HostRecord JSONL
// to inputs/hosts.wellknown.jsonl — the web "hosts" single-writer staging file
// (mirrors portscan.go's inputs/hosts.<producer>.jsonl). Plan 13-08 wires
// web.MergeStage(ctx, app, "hosts") to consolidate them into the store. This does
// NOT reintroduce bash Recon/*.txt as a primary contract.
//
// Symbol hygiene (checker LOW #7): all unexported helpers are wellknown*-prefixed.
//
// Source: .planning/phases/13-domain-parity/13-04-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
)

// wellknownPaths are the metadata endpoints probed per web target (bash
// web.sh:2523-2547). security.txt is plain text; the *-configuration /
// *-server endpoints are JSON (walked for string hostnames).
var wellknownPaths = []string{
	"/.well-known/security.txt",
	"/security.txt",
	"/.well-known/openid-configuration",
	"/.well-known/oauth-authorization-server",
}

// wellknownHostRE matches DNS hostnames in free text / JSON strings (bash
// grep -aoE '[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+'). The
// trailing (?:\.…)+ requires at least one dot so bare labels never match.
var wellknownHostRE = regexp.MustCompile(`[a-zA-Z0-9][-a-zA-Z0-9]*(?:\.[a-zA-Z0-9][-a-zA-Z0-9]*)+`)

// wellknownHTTPClient is the bounded client for the best-effort .well-known GETs
// (bash curl -m 5). A per-target timeout keeps a slow endpoint from stalling the
// pipeline.
//
// SSRF-pivot guard (CR-13-01): the per-target scope + userinfo check in Run
// validates only the INITIAL target URL. A default http.Client follows up to 10
// redirects with no per-hop check, so an in-scope but attacker-influenceable
// response (subdomain takeover, malicious app, or a plain 302) could redirect the
// scanner into internal space — cloud metadata (169.254.169.254), loopback
// services (127.0.0.1), or internal port probing. CheckRedirect refuses to follow
// ANY redirect, which closes that pivot for both internal and off-scope external
// targets. .well-known probing does not need redirects; bash's curl -L carries the
// same footgun but parity with a vulnerable default does not justify reproducing it.
var wellknownHTTPClient = &http.Client{
	Timeout: 8 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// wellknownGet fetches rawurl and returns up to 1 MiB of the response body. It is
// a package var so tests may inject a canned response without real network I/O
// (mirrors portscan.go's shodanInternetDBGet seam); the default impl performs a
// real GET, which the httptest-backed unit tests exercise.
var wellknownGet = func(ctx context.Context, rawurl string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return nil, err
	}
	resp, err := wellknownHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// WebWellKnownTask probes .well-known metadata endpoints for in-scope hostnames.
type WebWellKnownTask struct{}

func (t *WebWellKnownTask) Name() string   { return "web.wellknown" }
func (t *WebWellKnownTask) Module() string { return "web" }
func (t *WebWellKnownTask) Description() string {
	return "Well-known metadata endpoint pivots (security.txt + openid-configuration)"
}

// Enabled gates on cfg.Web.WellKnown.Enabled (bash WELLKNOWN_PIVOTS, default false).
func (t *WebWellKnownTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.WellKnown.Enabled
}

// DependsOn returns nil: wellknown is a sequential stage reading the web targets;
// plan 13-08 places it in the stage order.
func (t *WebWellKnownTask) DependsOn() []string { return nil }

// Run probes each in-scope web target's .well-known endpoints and stages the
// discovered in-scope hostnames (bash well_known_pivots, web.sh:2500).
func (t *WebWellKnownTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	wk := app.Cfg.Web.WellKnown
	// In-Run gate (default-off, bash parity) — also covers direct-Run unit tests.
	if !wk.Enabled {
		if app.Log != nil {
			app.Log.Info("web.wellknown: disabled (cfg.Web.WellKnown.Enabled=false) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	targets, _ := readHostURLsFromJSONL(app)
	if len(targets) == 0 {
		if app.Log != nil {
			app.Log.Info("web.wellknown: no web targets (hosts.jsonl empty) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Cap the probed targets (bash head -n WELLKNOWN_MAX_TARGETS).
	maxTargets := wk.MaxTargets
	if maxTargets <= 0 {
		maxTargets = 200
	}
	if len(targets) > maxTargets {
		targets = targets[:maxTargets]
	}

	// Single scope filter for BOTH the fetch guard (IsInScopeURL: userinfo +
	// off-scope rejection) and the discovered-hostname filter. Boot builds the
	// OutputTree scope from the same target.Scope, so a pre-filtered host is
	// never later rejected by app.Tree.Append (13-08).
	scopeFilter := &output.DefaultScopeFilter{Patterns: app.Target.Scope}

	discovered := newWellknownHostSet()
	probed := 0
	for _, target := range targets {
		target = strings.TrimSpace(target)
		if target == "" {
			continue
		}
		// SSRF / scope re-validation (T-13-04-01): reject userinfo + off-scope
		// URLs before any fetch.
		if !scopeFilter.IsInScopeURL(target) {
			if app.Log != nil {
				app.Log.Debug("web.wellknown: target rejected by scope/userinfo guard", "target", target)
			}
			continue
		}
		probed++
		base := strings.TrimRight(target, "/")
		for _, p := range wellknownPaths {
			body, err := wellknownGet(ctx, base+p)
			if err != nil {
				if app.Log != nil {
					app.Log.Debug("web.wellknown: fetch failed (non-fatal)", "url", base+p, "err", err)
				}
				continue
			}
			for _, host := range wellknownExtractHosts(body) {
				if wellknownInScopeHost(app, scopeFilter, host) {
					discovered.add(host)
				}
			}
		}
	}

	hosts := discovered.list()
	if len(hosts) == 0 && app.Log != nil {
		app.Log.Debug("web.wellknown: no in-scope hostnames discovered", "probed", probed)
	}

	// Stage discovered hostnames as HostRecord JSONL (web "hosts" single-writer
	// staging; consolidated to the store by web.MergeStage("hosts") in 13-08).
	//
	// F3 (phase 15): the old zero-host early return left a previous run's
	// inputs/hosts.wellknown.jsonl for the hosts merge to republish. This task
	// RAN (the no-targets path returns StatusSkipped above), so stage
	// unconditionally and let StageJSONL clear it.
	var lines [][]byte
	for _, h := range hosts {
		if b, err := json.Marshal(HostRecord{Host: h, Tech: []string{}}); err == nil {
			lines = append(lines, b)
		}
	}
	staging := filepath.Join(app.Target.WorkDir, "inputs", "hosts.wellknown.jsonl")
	if err := output.StageJSONL(staging, lines); err != nil && app.Log != nil {
		app.Log.Debug("web.wellknown: hosts staging write failed", "path", staging, "err", err)
	}

	if app.Log != nil {
		app.Log.Debug("web.wellknown: completed", "probed", probed, "hosts", len(hosts))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"wellknown_hosts": len(hosts)},
	}, nil
}

// wellknownExtractHosts returns the lowercased hostnames found in body. When body
// is valid JSON (OIDC / OAuth metadata) it walks all string values (bash
// jq -r '.. | strings'); otherwise it scans the raw text (security.txt).
func wellknownExtractHosts(body []byte) []string {
	var out []string
	var v any
	if json.Unmarshal(body, &v) == nil {
		wellknownWalkStrings(v, func(s string) {
			out = append(out, wellknownHostsInText(s)...)
		})
		return out
	}
	return wellknownHostsInText(string(body))
}

// wellknownHostsInText returns the lowercased regex hostname matches in s.
func wellknownHostsInText(s string) []string {
	matches := wellknownHostRE.FindAllString(s, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		out = append(out, strings.ToLower(m))
	}
	return out
}

// wellknownWalkStrings recursively visits every string value in a decoded JSON
// document (objects, arrays, and scalar strings) — the jq '.. | strings' walk.
func wellknownWalkStrings(v any, visit func(string)) {
	switch t := v.(type) {
	case string:
		visit(t)
	case []any:
		for _, e := range t {
			wellknownWalkStrings(e, visit)
		}
	case map[string]any:
		for _, e := range t {
			wellknownWalkStrings(e, visit)
		}
	}
}

// wellknownInScopeHost reports whether host is in scope for staging. It prefers
// app.Tree.InScope (the exact gate app.Tree.Append applies in 13-08) and falls
// back to the local scope filter when no Tree is wired (unit tests).
func wellknownInScopeHost(app *appctx.AppContext, scopeFilter *output.DefaultScopeFilter, host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		return false
	}
	if app.Tree != nil {
		return app.Tree.InScope(host)
	}
	return scopeFilter.IsInScope(host)
}

// wellknownHostSet is an insertion-ordered, deduplicated hostname set.
type wellknownHostSet struct {
	seen  map[string]struct{}
	order []string
}

func newWellknownHostSet() *wellknownHostSet {
	return &wellknownHostSet{seen: make(map[string]struct{})}
}

func (s *wellknownHostSet) add(host string) {
	if _, ok := s.seen[host]; ok {
		return
	}
	s.seen[host] = struct{}{}
	s.order = append(s.order, host)
}

func (s *wellknownHostSet) list() []string {
	out := append([]string(nil), s.order...)
	sort.Strings(out)
	return out
}

func init() { task.Register(&WebWellKnownTask{}) }
