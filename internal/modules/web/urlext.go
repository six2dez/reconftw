// urlext.go — WebURLExtTask: sensitive-extension URL bucketing (PAR-04).
//
// Name: "web.url_ext"  DependsOn: nil (sequential stage; reads the URL corpus)
//
// Ports bash url_ext (modules/web.sh:2144-2221): a pure awk transform that
// classifies the deduped URL corpus by a ~130-entry set of sensitive file
// extensions (.sql, .bak, .env, .config, …) and writes the matching URLs,
// grouped by extension, to webs/urls_by_ext.txt. Go produced no urls_by_ext.txt
// before this task — cfg.Web.URLs.ExtClassify (config.go:318, default true) was
// dead config.
//
// The bash reader is .tmp/url_extract_tmp.txt; the Go equivalent is the deduped
// URL corpus artefacts/urls.jsonl (urldedup.go is its sole writer, WEB-14). This
// task READS that corpus and WRITES the webs/urls_by_ext.txt contract artefact —
// it never writes the urls artefact.
//
// This is a pure in-process transform: it invokes NO external tool. It skips
// cleanly (StatusSkipped) when the target is an IP literal (bash guard,
// web.sh:2154) or the URL corpus is empty.
//
// WIRING NOTE: self-registered via init(); the stage-list placement (after
// urls-dedup) is added in plan 13-08. Unit tests exercise Run directly.
//
// Symbol hygiene (checker LOW #7): all unexported helpers are urlext*-prefixed so
// this file, wellknown.go, wordlistgen.go, and portscan.go (13-03) compile
// together without duplicate-symbol collisions.
//
// Source: .planning/phases/13-domain-parity/13-04-PLAN.md Task 1.
package web

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// urlextSensitiveExts is the bash url_ext extension set (modules/web.sh:2160),
// ported verbatim. Classification takes the URL's final dot-segment (after
// stripping query/fragment + trailing slash) and matches it case-insensitively
// against this set. The two-part "tar.gz" entry is kept for fidelity though the
// final-segment rule reduces it to "gz" in practice (bash awk parts[n] behaves
// identically).
var urlextSensitiveExts = map[string]struct{}{
	"7z": {}, "achee": {}, "action": {}, "adr": {}, "apk": {}, "arj": {},
	"ascx": {}, "asmx": {}, "asp": {}, "aspx": {}, "axd": {}, "backup": {},
	"bak": {}, "bat": {}, "bin": {}, "bkf": {}, "bkp": {}, "bok": {}, "cab": {},
	"cer": {}, "cfg": {}, "cfm": {}, "cnf": {}, "conf": {}, "config": {},
	"cpl": {}, "crt": {}, "csr": {}, "csv": {}, "dat": {}, "db": {}, "dbf": {},
	"deb": {}, "dmg": {}, "dmp": {}, "doc": {}, "docx": {}, "drv": {},
	"email": {}, "eml": {}, "emlx": {}, "env": {}, "exe": {}, "gadget": {},
	"gz": {}, "html": {}, "ica": {}, "inf": {}, "ini": {}, "iso": {}, "jar": {},
	"java": {}, "jhtml": {}, "json": {}, "jsp": {}, "key": {}, "log": {},
	"lst": {}, "mai": {}, "mbox": {}, "mbx": {}, "md": {}, "mdb": {}, "msg": {},
	"msi": {}, "nsf": {}, "ods": {}, "oft": {}, "old": {}, "ora": {}, "ost": {},
	"pac": {}, "passwd": {}, "pcf": {}, "pdf": {}, "pem": {}, "pgp": {},
	"php": {}, "php3": {}, "php4": {}, "php5": {}, "phtm": {}, "phtml": {},
	"pkg": {}, "pl": {}, "plist": {}, "pst": {}, "pwd": {}, "py": {}, "rar": {},
	"rb": {}, "rdp": {}, "reg": {}, "rpm": {}, "rtf": {}, "sav": {}, "sh": {},
	"shtm": {}, "shtml": {}, "skr": {}, "sql": {}, "swf": {}, "sys": {},
	"tar": {}, "tar.gz": {}, "tmp": {}, "toast": {}, "tpl": {}, "txt": {},
	"url": {}, "vcd": {}, "vcf": {}, "wml": {}, "wpd": {}, "wsdl": {}, "wsf": {},
	"xls": {}, "xlsm": {}, "xlsx": {}, "xml": {}, "xsd": {}, "yaml": {},
	"yml": {}, "z": {}, "zip": {},
}

// WebURLExtTask buckets the URL corpus by sensitive extension into
// webs/urls_by_ext.txt (bash url_ext parity). Pure transform, no external tool.
type WebURLExtTask struct{}

func (t *WebURLExtTask) Name() string   { return "web.url_ext" }
func (t *WebURLExtTask) Module() string { return "web" }
func (t *WebURLExtTask) Description() string {
	return "Sensitive-extension URL bucketing (url_ext → webs/urls_by_ext.txt)"
}

// Enabled gates on cfg.Web.URLs.ExtClassify (bash URL_EXT, default true).
func (t *WebURLExtTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.URLs.ExtClassify
}

// DependsOn returns nil: url_ext is a sequential stage that reads the deduped
// URL corpus; plan 13-08 places it after urls-dedup in the stage order.
func (t *WebURLExtTask) DependsOn() []string { return nil }

// Run classifies the URL corpus by sensitive extension and writes
// webs/urls_by_ext.txt (bash web.sh:2144-2221). Pure transform — no tool calls.
func (t *WebURLExtTask) Run(_ context.Context, app *appctx.AppContext) (task.Result, error) {
	// bash guard (web.sh:2154): url_ext is skipped for bare-IP targets.
	if app.Target != nil && app.Target.IsIP {
		if app.Log != nil {
			app.Log.Info("web.url_ext: IP-literal target — skipping (bash parity)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	urls := urlextReadURLCorpus(app)
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("web.url_ext: URL corpus empty (no artefacts/urls.jsonl) — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Classify: ext -> ordered-unique set of matching URLs.
	buckets := make(map[string]map[string]struct{})
	for _, u := range urls {
		ext := urlextExtOf(u)
		if ext == "" {
			continue
		}
		if _, ok := urlextSensitiveExts[ext]; !ok {
			continue
		}
		if buckets[ext] == nil {
			buckets[ext] = make(map[string]struct{})
		}
		buckets[ext][u] = struct{}{}
	}

	websDir := filepath.Join(app.Target.WorkDir, "webs")
	if err := os.MkdirAll(websDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.url_ext: mkdir webs/: %w", err)
	}
	outFile := filepath.Join(websDir, "urls_by_ext.txt")

	// Render grouped output (bash sort -k1,1 -k2,2 -u, then per-ext header block).
	var buf bytes.Buffer
	matched := 0
	for _, ext := range urlextSortedKeys(buckets) {
		urlSet := buckets[ext]
		sorted := make([]string, 0, len(urlSet))
		for u := range urlSet {
			sorted = append(sorted, u)
		}
		sort.Strings(sorted)
		// bash header block (web.sh:2194).
		fmt.Fprintf(&buf, "\n############################\n + %s + \n############################\n", ext)
		for _, u := range sorted {
			buf.WriteString(u)
			buf.WriteByte('\n')
			matched++
		}
	}

	// Always (re)write the contract artefact, even when empty — bash truncates it
	// unconditionally (web.sh:2163) so downstream consumers see a stable file.
	if err := os.WriteFile(outFile, buf.Bytes(), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.url_ext: write urls_by_ext.txt: %w", err)
	}

	if app.Log != nil {
		app.Log.Debug("web.url_ext: completed",
			"corpus_urls", len(urls), "extensions", len(buckets), "matched_urls", matched)
	}
	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{outFile},
		Stats:   map[string]int{"urls_by_ext": matched, "extensions": len(buckets)},
	}, nil
}

// urlextReadURLCorpus reads the deduped URL corpus (artefacts/urls.jsonl) and
// returns the url-field strings. Reuses extractURLStringsAndSources (urldedup.go)
// which is the canonical JSONL URL reader. Missing/empty corpus → nil.
func urlextReadURLCorpus(app *appctx.AppContext) []string {
	corpus := filepath.Join(app.Target.WorkDir, "artefacts", "urls.jsonl")
	data, err := os.ReadFile(corpus) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil
	}
	urls, _ := extractURLStringsAndSources(data)
	return urls
}

// urlextExtOf returns the lowercase final dot-segment of a URL after stripping
// query/fragment and a single trailing slash (bash awk: gsub /[?#].*/, gsub
// /\/$/, split on ".", tolower(parts[n])). Returns "" when there is no usable
// extension (no dot, or the final segment contains a path separator).
func urlextExtOf(rawurl string) string {
	u := strings.TrimSpace(rawurl)
	if u == "" {
		return ""
	}
	// Strip query + fragment (bash gsub /[?#].*/).
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	// Strip a single trailing slash (bash gsub /\/$/).
	u = strings.TrimSuffix(u, "/")
	idx := strings.LastIndexByte(u, '.')
	if idx < 0 || idx == len(u)-1 {
		return ""
	}
	seg := u[idx+1:]
	// A final segment spanning a path separator is not a file extension
	// (e.g. "example.com/path" → "com/path"); bash's parts[n] keeps the "/" so
	// it never matches an ext_map key. Reject it explicitly.
	if strings.ContainsAny(seg, "/\\") {
		return ""
	}
	return strings.ToLower(seg)
}

// urlextSortedKeys returns the bucket extensions in sorted order (bash sort -k1,1).
func urlextSortedKeys(buckets map[string]map[string]struct{}) []string {
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func init() { task.Register(&WebURLExtTask{}) }
