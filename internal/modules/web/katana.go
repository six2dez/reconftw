// katana.go — KatanaTask: web crawler (katana) → URL records in urls.jsonl.
//
// Name: "web.katana"  DependsOn: ["web.httpx"]
//
// KatanaTask crawls all probed hosts using katana, collects discovered URLs,
// and writes URLRecord entries to artefacts/urls.jsonl.
//
// ARG VECTOR (RESEARCH §katana — verbatim v1 form, web.sh:1940-1943):
//
//	katana -silent -list <targets_file> [-headless]
//	       -jc -kf all -c <threads> -d 2 (or 3 in DEEP mode) -fs rdn
//
// XCUT-09 (Pitfall 5): katana runs 3-4h; Backend.Stream is MANDATORY
// to deliver heartbeat events and avoid CI kill.
//
// T-05-15: out-of-scope URLs filtered by extract/urls.ExtractURLs domain check.
//
// [ASSUMED: -headless flag form unchanged; -fs rdn is current flag name.]
//
// Source: .planning/phases/05-web-pipeline-e2e/05-04-PLAN.md Task 2.
package web

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/task"
	urlsextract "github.com/six2dez/reconftw/internal/extract/urls"
)

// KatanaTask runs katana web crawler and writes URL records.
type KatanaTask struct{}

func (t *KatanaTask) Name() string        { return "web.katana" }
func (t *KatanaTask) Module() string      { return "web" }
func (t *KatanaTask) Description() string { return "Web crawler (katana → urls.jsonl)" }
func (t *KatanaTask) Enabled(cfg *config.Config) bool {
	return cfg.Web.URLs.ActiveEnabled
}
func (t *KatanaTask) DependsOn() []string { return []string{"web.httpx"} }

// Run executes katana against probed hosts and appends URL records to urls.jsonl.
func (t *KatanaTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "katana"
	cfg := app.Cfg

	// Read probed hosts from artefacts/hosts.jsonl.
	allURLs, err := readHostURLsFromJSONL(app)
	if err != nil || len(allURLs) == 0 {
		if app.Log != nil {
			app.Log.Info("web.katana: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Prepare directories.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.katana: mkdir inputs/: %w", err)
	}

	// Write katana target file.
	targetsFile := filepath.Join(inputsDir, "katana_targets.txt")
	if err := os.WriteFile(targetsFile, []byte(strings.Join(allURLs, "\n")+"\n"), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.katana: write targets file: %w", err)
	}

	// Resolve thread count (v1 default: AVAILABLE_CORES * 5).
	threads := cfg.Web.Katana.Threads
	if threads <= 0 {
		threads = runtime.NumCPU() * 5
	}

	// Crawl depth: 2 normally, 3 in deep mode (RESEARCH §katana).
	depth := 2
	if cfg.Advanced.Deep {
		depth = 3
	}

	// Build arg vector (RESEARCH §katana verbatim v1 form web.sh:1940-1943).
	args := []string{
		"-silent",
		"-list", targetsFile,
		"-jc",        // JS crawling
		"-kf", "all", // keep all forms
		"-c", strconv.Itoa(threads),
		"-d", strconv.Itoa(depth),
		"-fs", "rdn", // field scope: root domain name
	}

	// Headless mode: "smart" or "full" profile enables -headless.
	if cfg.Web.Katana.HeadlessProfile == "smart" || cfg.Web.Katana.HeadlessProfile == "full" {
		args = append(args, "-headless")
	}

	// XCUT-09: Backend.Stream is mandatory for katana (3-4h runtime; Pitfall 5).
	eventCh, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		if app.Log != nil {
			app.Log.Info("web.katana: binary absent or failed — skipping", "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Collect URL lines from streamed output.
	var urlLines []string
	for ev := range eventCh {
		if ev.IsErr {
			continue
		}
		line := strings.TrimSpace(string(ev.Line))
		if line != "" {
			urlLines = append(urlLines, line)
		}
	}

	// Extract and scope-filter URLs via extract/urls.
	var totalRecords int
	if len(urlLines) > 0 {
		rawText := []byte(strings.Join(urlLines, "\n"))
		records, _ := urlsextract.ExtractURLs(rawText, "katana", app.Target.Domain)
		totalRecords = len(records)

		var lines [][]byte
		for _, rec := range records {
			b, merr := json.Marshal(rec)
			if merr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			stagingPath := filepath.Join(app.Target.WorkDir, "inputs", "urls.katana.jsonl")
			if wErr := output.WriteJSONL(stagingPath, lines); wErr != nil && app.Log != nil {
				app.Log.Debug("web.katana: staging write failed",
					"path", stagingPath, "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Debug("web.katana: completed",
			"hosts", len(allURLs),
			"url_lines", len(urlLines),
			"in_scope_records", totalRecords)
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"urls_found": totalRecords},
	}, nil
}

func init() { task.Register(&KatanaTask{}) }
