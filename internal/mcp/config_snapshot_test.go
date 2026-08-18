// config_snapshot_test.go — F7: the MCP server must run scans under the
// configuration the operator started it with.
//
// Before the snapshot, cmd/reconftw/mcp.go loaded the explicit --config file and
// then handed onward only cfg.MCP. RegisterTools discarded the rest
// (`_ = rdct; _ = cfg`), handlers.RunOptions.ConfigPath / SecretsPath /
// OutputDir / LogLevel were never populated, and every scan re-ran config.Load
// with NO explicit paths. A server started with --config therefore scanned into
// a different data dir, with a redactor that knew none of the operator's
// secrets. These tests assert the whole chain: startup config → RunOptions →
// ResolveRunPlan → the workspace that is actually created on disk.
package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	_ "modernc.org/sqlite" // checkpoint + store drivers used by BootReconApp

	"github.com/modelcontextprotocol/go-sdk/mcp"

	corelog "github.com/six2dez/reconftw/internal/core/log"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/ingest"
	"github.com/six2dez/reconftw/internal/core/output"
	"github.com/six2dez/reconftw/internal/core/scheduler"
	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

// writeTestConfig writes a minimal but VALID reconftw.toml whose data_dir is
// dataDir, and returns its path. extra is appended verbatim (used to add a
// second table in one test).
func writeTestConfig(t *testing.T, dataDir, extra string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "reconftw.toml")
	body := fmt.Sprintf(`[paths]
data_dir = %q

[output]
log_level = "warn"

[mcp]
enabled = true
api_key = "mcp-test-api-key-32-characters"
transport = "stdio"
port = 8765
%s`, dataDir, extra)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

// mustLoadConfig resolves a config exactly as runMCPServeCmd does.
func mustLoadConfig(t *testing.T, cfgPath string, secretsPath ...string) *config.Config {
	t.Helper()
	var secrets string
	if len(secretsPath) > 0 {
		secrets = secretsPath[0]
	}
	cfg, err := config.Load(config.LoadOptions{
		ExplicitConfigPath: cfgPath,
		SecretsPath:        secrets,
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// testSchedFactory mirrors the per-scan scheduler factory the entrypoint builds
// (heartbeat 0 so no heartbeat goroutine outlives the test).
func testSchedFactory() func() *scheduler.Scheduler {
	return func() *scheduler.Scheduler { return scheduler.NewScheduler(1, 0, nil, nil) }
}

// newTestServer loads cfgPath/secretsPath exactly as runMCPServeCmd does and
// builds an MCPServer from the result.
func newTestServer(t *testing.T, cfgPath, secretsPath string) *MCPServer {
	t.Helper()
	cfg := mustLoadConfig(t, cfgPath, secretsPath)
	srv := NewMCPServer(context.Background(), cfg, cfgPath, secretsPath, testSchedFactory(), &corelog.Redactor{}, "test")
	t.Cleanup(srv.Cancel)
	return srv
}

// TestScanToolCreatesTheWorkspaceUnderTheStartupDataDir is the observable proof
// that --config reaches the scan: the workspace the run actually creates lives
// under the config file's paths.data_dir, not under the default root.
//
// The fake run function stands in for RunSubsAsync and calls the very same
// BootReconApp the real handlers call, so the assertion is against a directory
// on disk rather than against a struct field.
func TestScanToolCreatesTheWorkspaceUnderTheStartupDataDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "wanted-data-dir")
	cfgPath := writeTestConfig(t, dataDir, "")
	srv := newTestServer(t, cfgPath, "")

	const target = "snapshot.example"
	type bootResult struct {
		opts    handlers.RunOptions
		workDir string
		err     error
	}
	done := make(chan bootResult, 1)

	fn := func(ctx context.Context, opts handlers.RunOptions) error {
		boot, err := handlers.BootReconApp(ctx, opts)
		if err != nil {
			done <- bootResult{opts: opts, err: err}
			return err
		}
		defer boot.Close() //nolint:errcheck // test cleanup
		done <- bootResult{opts: opts, workDir: boot.WorkDir}
		return nil
	}

	res, _, err := srv.tools.launch("sess-snapshot", target, false, "", fn)
	if err != nil {
		t.Fatalf("launch: %v", err)
	}
	if res.IsError {
		t.Fatalf("launch returned a tool error: %s", toolText(res))
	}

	var got bootResult
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan never booted")
	}
	if got.err != nil {
		t.Fatalf("BootReconApp: %v", got.err)
	}

	// The RunOptions the tool built carry the startup snapshot.
	if got.opts.ConfigPath != cfgPath {
		t.Errorf("RunOptions.ConfigPath = %q; want %q — the scan re-resolves config from the "+
			"path the server was started with", got.opts.ConfigPath, cfgPath)
	}
	if got.opts.OutputDir != dataDir {
		t.Errorf("RunOptions.OutputDir = %q; want %q", got.opts.OutputDir, dataDir)
	}
	if got.opts.LogLevel != "warn" {
		t.Errorf("RunOptions.LogLevel = %q; want %q (from the config file)", got.opts.LogLevel, "warn")
	}

	// The workspace that was actually created.
	id, err := output.CanonicalTargetID(target)
	if err != nil {
		t.Fatalf("CanonicalTargetID: %v", err)
	}
	want := filepath.Join(dataDir, id.Slug)
	if got.workDir != want {
		t.Fatalf("workspace = %q; want %q — the scan ran under a different configuration "+
			"than the one the server was started with (F7)", got.workDir, want)
	}
	if _, statErr := os.Stat(want); statErr != nil {
		t.Fatalf("workspace %q was not created: %v", want, statErr)
	}
}

// TestScanToolCarriesTheExplicitSecretsPath asserts a secret defined ONLY in the
// --secrets file is visible to the run's resolved config. The value is compared,
// never logged.
func TestScanToolCarriesTheExplicitSecretsPath(t *testing.T) {
	const shodanKey = "shodan-key-only-in-the-secrets-file"

	dataDir := filepath.Join(t.TempDir(), "data")
	cfgPath := writeTestConfig(t, dataDir, "")
	secretsPath := filepath.Join(t.TempDir(), "secrets.toml")
	secretsBody := fmt.Sprintf("[api_keys]\nshodan = %q\n", shodanKey)
	if err := os.WriteFile(secretsPath, []byte(secretsBody), 0o600); err != nil {
		t.Fatalf("write secrets: %v", err)
	}
	srv := newTestServer(t, cfgPath, secretsPath)

	type resolved struct {
		opts handlers.RunOptions
		plan handlers.RunPlan
		err  error
	}
	done := make(chan resolved, 1)
	fn := func(_ context.Context, opts handlers.RunOptions) error {
		plan, err := handlers.ResolveRunPlan(opts)
		done <- resolved{opts: opts, plan: plan, err: err}
		return err
	}

	if _, _, err := srv.tools.launch("sess-secrets", "secrets.example", true, "", fn); err != nil {
		t.Fatalf("launch: %v", err)
	}

	var got resolved
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("the scan never resolved its config")
	}
	if got.err != nil {
		t.Fatalf("ResolveRunPlan: %v", got.err)
	}
	if got.opts.SecretsPath != secretsPath {
		t.Errorf("RunOptions.SecretsPath = %q; want %q", got.opts.SecretsPath, secretsPath)
	}
	if string(got.plan.Cfg.APIKeys.Shodan) != shodanKey {
		t.Error("the run's resolved config does not carry the secret from the --secrets file; " +
			"a scan started through MCP would run without the operator's API keys (F7)")
	}
}

// TestConcurrentScansDoNotShareAMutableConfig is the T-15-15-08 proof: two runs
// with different ConfigTransforms must not observe each other's transform. The
// snapshot is the immutable PAIR OF PATHS plus a by-value RunOptions template;
// each run's ResolveRunPlan loads its own *config.Config and mutates only that.
//
// Run with -race -count=5.
func TestConcurrentScansDoNotShareAMutableConfig(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "data")
	cfgPath := writeTestConfig(t, dataDir, "")
	srv := newTestServer(t, cfgPath, "")

	snapshotJobsBefore := srv.cfg.Concurrency.MaxJobs

	run := func(maxJobs int) (int, string, error) {
		opts := srv.tools.runOptions("concurrent.example", true, "")
		opts.ConfigTransform = func(c *config.Config) { c.Concurrency.MaxJobs = maxJobs }
		plan, err := handlers.ResolveRunPlan(opts)
		if err != nil {
			return 0, "", err
		}
		return plan.Cfg.Concurrency.MaxJobs, plan.Cfg.Paths.DataDir, nil
	}

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		errs   []error
		result = map[int]int{}
	)
	for _, want := range []int{7, 23} {
		wg.Add(1)
		go func(want int) {
			defer wg.Done()
			got, gotDir, err := run(want)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			if gotDir != dataDir {
				errs = append(errs, fmt.Errorf("data dir = %q, want %q", gotDir, dataDir))
			}
			result[want] = got
		}(want)
	}
	wg.Wait()

	for _, err := range errs {
		t.Error(err)
	}
	for want, got := range result {
		if got != want {
			t.Errorf("a run that set MaxJobs=%d observed %d — the two runs shared one mutable "+
				"config (T-15-15-08)", want, got)
		}
	}
	if srv.cfg.Concurrency.MaxJobs != snapshotJobsBefore {
		t.Errorf("the server's config SNAPSHOT was mutated by a run (MaxJobs %d → %d); it must be "+
			"read-only for the lifetime of the server", snapshotJobsBefore, srv.cfg.Concurrency.MaxJobs)
	}
}

// TestReportToolHonoursTheStartupDataDir closes the gap plan 15-11 named: the
// report tool was handed cfg=nil behind a TODO, so an operator whose config sets
// paths.data_dir got "data" on the MCP report path while the CLI got it right.
func TestReportToolHonoursTheStartupDataDir(t *testing.T) {
	const target = "mcpreportsnapshot.example"
	dataDir := filepath.Join(t.TempDir(), "operator-data-dir")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	seedStoreForTarget(t, dataDir, target)

	cfgPath := writeTestConfig(t, dataDir, "")
	srv := newTestServer(t, cfgPath, "")

	res, _, err := srv.tools.report(context.Background(), "sess-report", ReportInput{Target: target})
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if res.IsError {
		t.Fatalf("report returned a tool error: %s", toolText(res))
	}

	var payload struct {
		Dir     string   `json:"dir"`
		ScanID  string   `json:"scan_id"`
		Reports []string `json:"reports"`
	}
	if err := json.Unmarshal([]byte(toolText(res)), &payload); err != nil {
		t.Fatalf("decode report response: %v (%s)", err, toolText(res))
	}
	if !strings.HasPrefix(payload.Dir, dataDir+string(os.PathSeparator)) {
		t.Fatalf("report dir = %q; want a directory under the operator's data dir %q — "+
			"the MCP report path ignored paths.data_dir (F7)", payload.Dir, dataDir)
	}
	if len(payload.Reports) == 0 {
		t.Error("the report tool rendered no files")
	}
}

// seedStoreForTarget ingests one scan for target into dataDir/store.db so the
// report renderer has something to render. Mirrors the handlers-package helper.
func seedStoreForTarget(t *testing.T, dataDir, target string) {
	t.Helper()
	workDir := filepath.Join(dataDir, "ws")
	artefacts := filepath.Join(workDir, "artefacts")
	if err := os.MkdirAll(artefacts, 0o755); err != nil {
		t.Fatalf("mkdir artefacts: %v", err)
	}
	hosts := `{"host":"api.` + target + `","ip":"1.1.1.1"}` + "\n"
	if err := os.WriteFile(filepath.Join(artefacts, "hosts.jsonl"), []byte(hosts), 0o600); err != nil {
		t.Fatalf("write hosts.jsonl: %v", err)
	}
	if _, err := ingest.ScanIntoStore(context.Background(), dataDir, workDir, target, "recon", nil); err != nil {
		t.Fatalf("seed ScanIntoStore: %v", err)
	}
}

// toolText concatenates the text content of a tool result.
func toolText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}
