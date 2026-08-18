// screenshot.go — ScreenshotTask: nuclei-headless screenshots → content-addressed PNGs.
//
// ScreenshotTask runs nuclei with -headless -id screenshot against probed hosts,
// then renames each produced PNG to raw/screenshots/<SHA-256-of-bytes>.png (D-W5).
//
// FAIL-SOFT (D-W6): if the nuclei binary or the nuclei-templates path is absent,
// the task logs an explicit SKIP message and returns StatusSkipped — it NEVER
// blocks the pipeline (best_effort policy, D-W12).
//
// ARG VECTOR (RESEARCH §nuclei screenshot — corrected WR-02):
//
//	nuclei -headless -id screenshot -V dir=<abs-temp-dir>
//	       -l <hosts_file>  (hosts file via -l flag, not stdin)
//
// D-W5 content-addressed rename: after nuclei writes PNGs to a temp dir,
// Walk the dir, compute sha256.Sum256 of each PNG's bytes, rename to
// raw/screenshots/<hex>.png.
//
// Source: .planning/phases/05-web-pipeline-e2e/05-02-PLAN.md Task 1.
package web

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// ScreenshotTask runs nuclei in headless mode to capture screenshots and
// stores them as content-addressed PNGs under raw/screenshots/.
//
// ARG VECTOR (corrected — WR-02): nuclei is invoked as:
//
//	nuclei -headless -id screenshot -V dir=<dir> -l <hosts_file>
//
// The -l flag is used for host-file input (not stdin as the original
// header claimed). Both code and doc now agree on -l.
type ScreenshotTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *ScreenshotTask) Name() string { return "web.screenshot" }

// Module returns the owning module group.
func (t *ScreenshotTask) Module() string { return "web" }

// Description returns a human-readable one-line description.
func (t *ScreenshotTask) Description() string {
	return "Screenshots via nuclei-headless → raw/screenshots/<sha256>.png"
}

// Enabled reports whether this task should run.
// Maps to cfg.Web.Screenshots.Enabled (WEBSCREENSHOT legacy alias per ADR §2).
func (t *ScreenshotTask) Enabled(cfg *config.Config) bool { return cfg.Web.Screenshots.Enabled }

// DependsOn returns the DAG edges for ScreenshotTask.
func (t *ScreenshotTask) DependsOn() []string { return []string{"web.httpx"} }

// Run captures screenshots using nuclei-headless and renames PNGs to
// raw/screenshots/<sha256hex>.png (D-W5 content-addressed storage).
func (t *ScreenshotTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "nuclei"
	cfg := app.Cfg

	// D-W6: check nuclei binary availability.
	if _, err := exec.LookPath(toolName); err != nil {
		if app.Log != nil {
			app.Log.Info("web.screenshot: nuclei binary not found — skipping (D-W6)",
				"err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// D-W6: check nuclei templates path.
	templatesPath := cfg.Web.Nuclei.TemplatesPath
	if templatesPath == "" {
		templatesPath = cfg.Paths.NucleiTemplates
	}
	if templatesPath == "" {
		if app.Log != nil {
			app.Log.Info("web.screenshot: nuclei templates path not configured — skipping (D-W6)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	if _, err := os.Stat(templatesPath); err != nil {
		if app.Log != nil {
			app.Log.Info("web.screenshot: nuclei templates path not accessible — skipping (D-W6)",
				"path", templatesPath, "err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Read probed hosts for screenshot input.
	allHosts, err := readScreenshotHosts(app)
	if err != nil || len(allHosts) == 0 {
		if app.Log != nil {
			app.Log.Info("web.screenshot: no hosts in hosts.jsonl — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Create a temp directory for nuclei's raw PNG output.
	tmpDir, err := os.MkdirTemp("", "reconftw-screenshot-*")
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.screenshot: create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck // cleanup on exit

	// Create the final raw/screenshots destination directory.
	rawScreenshotsDir := filepath.Join(app.Target.WorkDir, "raw", "screenshots")
	if err := os.MkdirAll(rawScreenshotsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.screenshot: mkdir raw/screenshots/: %w", err)
	}

	// Write hosts to stdin file for nuclei.
	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.screenshot: mkdir inputs/: %w", err)
	}
	hostsFile := filepath.Join(inputsDir, "screenshot.hosts.txt")
	content := strings.Join(allHosts, "\n") + "\n"
	if err := os.WriteFile(hostsFile, []byte(content), 0o644); err != nil { //nolint:gosec
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("web.screenshot: write hosts file: %w", err)
	}

	// Build arg vector (RESEARCH §nuclei screenshot — v1 web.sh:327).
	// -V dir=<abs-path> sets the nuclei variable for screenshot output directory.
	args := []string{
		"-headless",
		"-id", "screenshot",
		"-V", "dir=" + tmpDir,
		"-l", hostsFile,
		"-silent",
	}

	// Execute via Backend.Stream for XCUT-09 heartbeat (Pitfall 4 mitigation:
	// nuclei headless can be slow; stream gives progress visibility).
	eventCh, err := app.Tools.Stream(ctx, toolName, args)
	if err != nil {
		// Nuclei headless unavailable or returns error — treat as best_effort SKIP (D-W6).
		if app.Log != nil {
			app.Log.Info("web.screenshot: nuclei headless failed — skipping (D-W6)",
				"err", err)
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}
	// F6 (phase 15): consume the TERMINAL error. A nuclei headless run that dies
	// part way leaves a partial set of PNGs in tmpDir; content-addressing them
	// into raw/screenshots/ would publish an incomplete capture as a complete
	// one, and the count would silently understate what was not screenshotted.
	//
	// The D-W6 StatusSkipped above is deliberately untouched: it means nuclei
	// headless is UNAVAILABLE (dispatch), which must never become a failure.
	if drainErr := backend.Drain(eventCh); drainErr != nil {
		return task.Result{Status: task.StatusErrored},
			terminalStreamError(toolName, drainErr)
	}

	// Walk temp dir and content-address rename each PNG (D-W5).
	count, renameErr := contentAddressPNGs(tmpDir, rawScreenshotsDir)
	if renameErr != nil && app.Log != nil {
		app.Log.Debug("web.screenshot: some PNG renames failed", "err", renameErr)
	}

	// D-W6: if 0 PNGs produced (headless unavailable), return StatusSkipped — not fail.
	// WR-02: emit explicit Warn when hosts were non-empty to distinguish
	// "headless unavailable" from "wrong nuclei invocation".
	if count == 0 {
		if app.Log != nil {
			if len(allHosts) > 0 {
				app.Log.Warn("web.screenshot: no screenshots produced but hosts were non-empty — verify nuclei headless + templates",
					"hosts", len(allHosts))
			} else {
				app.Log.Info("web.screenshot: 0 PNGs produced (headless likely unavailable) — skipping (D-W6)")
			}
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	if app.Log != nil {
		app.Log.Debug("web.screenshot: completed",
			"screenshots", count,
			"dir", rawScreenshotsDir)
	}

	return task.Result{
		Status:  task.StatusDone,
		Outputs: []string{rawScreenshotsDir},
		Stats:   map[string]int{"screenshots": count},
	}, nil
}

// contentAddressPNGs walks srcDir for *.png files, computes SHA-256 of each,
// and renames them to dstDir/<hex>.png. Returns count of successful renames
// and the first rename error (if any). Non-fatal per D-W6.
func contentAddressPNGs(srcDir, dstDir string) (int, error) {
	var firstErr error
	count := 0

	walkErr := filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // skip unreadable entries
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(info.Name()), ".png") {
			return nil
		}

		data, readErr := os.ReadFile(path) //nolint:gosec // path from trusted Walk
		if readErr != nil {
			if firstErr == nil {
				firstErr = readErr
			}
			return nil
		}

		sum := sha256.Sum256(data)
		dstPath := filepath.Join(dstDir, fmt.Sprintf("%x.png", sum))

		if renameErr := os.Rename(path, dstPath); renameErr != nil {
			// Rename across filesystems can fail; fall back to copy+delete.
			if copyErr := copyFile(path, dstPath); copyErr != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("rename/copy %s → %s: %w", path, dstPath, copyErr)
				}
				return nil
			}
			os.Remove(path) //nolint:errcheck // best effort cleanup
		}
		count++
		return nil
	})

	if walkErr != nil && firstErr == nil {
		firstErr = walkErr
	}
	return count, firstErr
}

// copyFile copies src bytes to dst (used as fallback when os.Rename fails
// across filesystem boundaries).
func copyFile(src, dst string) error {
	data, err := os.ReadFile(src) //nolint:gosec
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644) //nolint:gosec
}

// readScreenshotHosts reads artefacts/hosts.jsonl and returns the URL list
// for screenshot input (url field from D-W11 HostRecord schema).
func readScreenshotHosts(app *appctx.AppContext) ([]string, error) {
	hostsPath := filepath.Join(app.Target.WorkDir, "artefacts", "hosts.jsonl")
	data, err := os.ReadFile(hostsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		return nil, fmt.Errorf("read hosts.jsonl for screenshot: %w", err)
	}
	var hosts []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			URL  string `json:"url"`
			Host string `json:"host"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		h := rec.URL
		if h == "" {
			h = rec.Host
		}
		if h != "" {
			hosts = append(hosts, h)
		}
	}
	return hosts, nil
}

// init self-registers ScreenshotTask with the Default task registry.
func init() { task.Register(&ScreenshotTask{}) }
