// geo_zonetransfer_test.go — TDD RED tests for SubGeoTask and ZoneTransferTask.
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md
// Task 2 behavior tests.
//
// Test infrastructure reuses mockBackend, mockTree from scope_crosscheck_test.go.
package subdomains_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/backend"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"

	_ "github.com/six2dez/reconftw/internal/modules/subdomains"
)

// -------------------------------------------------------------------------
// buildGeoApp — minimal AppContext for geo task tests.
// ipinfoBaseURL overrides the ipinfo.io base URL (for test server injection).
// -------------------------------------------------------------------------

func buildGeoApp(t *testing.T, ipinfoBaseURL string) (*appctx.AppContext, string) {
	t.Helper()
	workDir := t.TempDir()

	// Create required directories.
	for _, dir := range []string{"inputs"} {
		if err := os.MkdirAll(filepath.Join(workDir, dir), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	// Write resolved.merged.txt.
	mergedFile := filepath.Join(workDir, "inputs", "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\n"), 0o644); err != nil {
		t.Fatalf("write resolved.merged.txt: %v", err)
	}

	// httpx mock returns IP address.
	httpxResult := &backend.Result{
		Stdout:   []byte(`{"host":"api.example.com","ip":"93.184.216.34"}` + "\n"),
		ExitCode: 0,
	}
	mockBe := &mockBackend{result: httpxResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "httpx"})
	runner := backend.NewRunner(mockBe, reg, nil)

	cfg := &config.Config{}
	cfg.Subdomains.Enabled = true
	cfg.APIKeys.PDCP = "test-pdcp-key-value"

	app := &appctx.AppContext{
		Tools:  runner,
		Tree:   &mockTree{},
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}

	// Inject ipinfo base URL via env var for test isolation.
	if ipinfoBaseURL != "" {
		t.Setenv("RECONFTW_IPINFO_BASE_URL", ipinfoBaseURL)
	}

	return app, workDir
}

// -------------------------------------------------------------------------
// Test 1: SubGeoTask.Enabled returns cfg.Subdomains.Enabled (no Geo struct)
// -------------------------------------------------------------------------

func TestSubGeoTaskEnabledUsesParentFlag(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.geo")
	if !ok {
		t.Fatal("subdomains.geo not registered")
	}

	cfg := &config.Config{}

	// Disabled via parent flag.
	cfg.Subdomains.Enabled = false
	if tsk.Enabled(cfg) {
		t.Errorf("SubGeoTask.Enabled(Subdomains.Enabled=false) = true, want false")
	}

	// Enabled via parent flag.
	cfg.Subdomains.Enabled = true
	if !tsk.Enabled(cfg) {
		t.Errorf("SubGeoTask.Enabled(Subdomains.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 2: SubGeoTask.Run returns HostRecord with non-empty City and Country
// -------------------------------------------------------------------------

func TestSubGeoTaskWritesHostRecordWithCityAndCountry(t *testing.T) {
	// Start test HTTP server simulating ipinfo.io.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":      "93.184.216.34",
			"city":    "Norwell",
			"country": "US",
			"org":     "AS15133 Edgecast Inc.",
		})
	}))
	defer srv.Close()

	app, workDir := buildGeoApp(t, srv.URL)
	mockTr := &mockTree{}
	app.Tree = mockTr

	tsk, ok := task.Default.Lookup("subdomains.geo")
	if !ok {
		t.Fatal("subdomains.geo not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubGeoTask.Run: unexpected error: %v", err)
	}
	if res.Status == task.StatusErrored {
		t.Errorf("SubGeoTask.Run returned StatusErrored")
	}

	// Tree.Append must have been called with host records.
	if !mockTr.appendCalled {
		t.Errorf("SubGeoTask.Run did NOT call Tree.Append for hosts artefact")
	}

	// Verify at least one line contains City and Country fields.
	found := false
	for _, line := range mockTr.appendLines {
		var rec struct {
			Host    string `json:"host"`
			IP      string `json:"ip"`
			City    string `json:"city"`
			Country string `json:"country"`
		}
		if err := json.Unmarshal(line, &rec); err != nil {
			continue
		}
		if rec.City != "" && rec.Country != "" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("SubGeoTask.Run: no HostRecord with non-empty City and Country found in Tree.Append output")
	}

	_ = workDir
}

// -------------------------------------------------------------------------
// Test 3: SubGeoTask.Run deduplicates IP lookups
// -------------------------------------------------------------------------

func TestSubGeoTaskDeduplicatesIPLookups(t *testing.T) {
	lookupCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lookupCount++
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":      "93.184.216.34",
			"city":    "Norwell",
			"country": "US",
			"org":     "AS15133 Edgecast Inc.",
		})
	}))
	defer srv.Close()

	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Two subdomains resolving to the SAME IP — should only query ipinfo once.
	mergedFile := filepath.Join(workDir, "inputs", "resolved.merged.txt")
	if err := os.WriteFile(mergedFile, []byte("api.example.com\nwww.example.com\n"), 0o644); err != nil {
		t.Fatalf("write merged: %v", err)
	}

	// httpx returns SAME IP for both subdomains.
	httpxResult := &backend.Result{
		Stdout: []byte(`{"host":"api.example.com","ip":"93.184.216.34"}` + "\n" +
			`{"host":"www.example.com","ip":"93.184.216.34"}` + "\n"),
		ExitCode: 0,
	}
	mockBe := &mockBackend{result: httpxResult}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "httpx"})
	runner := backend.NewRunner(mockBe, reg, nil)

	cfg := &config.Config{}
	cfg.Subdomains.Enabled = true

	app := &appctx.AppContext{
		Tools:  runner,
		Tree:   &mockTree{},
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}
	t.Setenv("RECONFTW_IPINFO_BASE_URL", srv.URL)

	tsk, ok := task.Default.Lookup("subdomains.geo")
	if !ok {
		t.Fatal("subdomains.geo not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubGeoTask.Run: %v", err)
	}

	// Should have queried ipinfo.io at most once for the same IP.
	if lookupCount > 1 {
		t.Errorf("SubGeoTask.Run made %d ipinfo lookups for the same IP, want ≤1 (dedup required)", lookupCount)
	}
}

// -------------------------------------------------------------------------
// Test 4: SubGeoTask.Run has DependsOn() == nil
// -------------------------------------------------------------------------

func TestSubGeoTaskDependsOnNil(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.geo")
	if !ok {
		t.Fatal("subdomains.geo not registered")
	}
	if deps := tsk.DependsOn(); deps != nil {
		t.Errorf("SubGeoTask.DependsOn() = %v, want nil", deps)
	}
}

// -------------------------------------------------------------------------
// Test 5: ZoneTransferTask.Run returns StatusSkipped when Enabled == false
// -------------------------------------------------------------------------

func TestZoneTransferRunReturnsSkippedWhenDisabled(t *testing.T) {
	workDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workDir, "inputs"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	mockBe := &mockBackend{result: &backend.Result{Stdout: []byte(""), ExitCode: 0}}
	reg := backend.NewToolRegistry()
	reg.Register(&backend.Tool{Name: "dnsx"})
	runner := backend.NewRunner(mockBe, reg, nil)

	cfg := &config.Config{}
	cfg.Subdomains.ZoneTransfer.Enabled = false // disabled

	app := &appctx.AppContext{
		Tools:  runner,
		Tree:   &mockTree{},
		Target: &appctx.Target{Domain: "example.com", WorkDir: workDir},
		Cfg:    cfg,
	}

	tsk, ok := task.Default.Lookup("subdomains.zonetransfer")
	if !ok {
		t.Fatal("subdomains.zonetransfer not registered")
	}

	res, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("ZoneTransferTask.Run: unexpected error: %v", err)
	}
	// Run() must return StatusSkipped even when ZoneTransfer.Enabled == false.
	// This is the REVIEWS finding #4 fix: Enabled() is NOT called by Scheduler.
	if res.Status != task.StatusSkipped {
		t.Errorf("ZoneTransferTask.Run(ZoneTransfer.Enabled=false) = %q, want skipped (in-Run gate required)", res.Status)
	}
}

// -------------------------------------------------------------------------
// Test 6: ZoneTransferTask.Enabled returns cfg.Subdomains.ZoneTransfer.Enabled
// -------------------------------------------------------------------------

func TestZoneTransferEnabledGate(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.zonetransfer")
	if !ok {
		t.Fatal("subdomains.zonetransfer not registered")
	}

	cfg := &config.Config{}
	cfg.Subdomains.ZoneTransfer.Enabled = false
	if tsk.Enabled(cfg) {
		t.Errorf("ZoneTransferTask.Enabled(ZoneTransfer.Enabled=false) = true, want false")
	}

	cfg.Subdomains.ZoneTransfer.Enabled = true
	if !tsk.Enabled(cfg) {
		t.Errorf("ZoneTransferTask.Enabled(ZoneTransfer.Enabled=true) = false, want true")
	}
}

// -------------------------------------------------------------------------
// Test 7: ZoneTransferTask has DependsOn() == nil
// -------------------------------------------------------------------------

func TestZoneTransferDependsOnNil(t *testing.T) {
	tsk, ok := task.Default.Lookup("subdomains.zonetransfer")
	if !ok {
		t.Fatal("subdomains.zonetransfer not registered")
	}
	if deps := tsk.DependsOn(); deps != nil {
		t.Errorf("ZoneTransferTask.DependsOn() = %v, want nil", deps)
	}
}

// -------------------------------------------------------------------------
// Test 8: SubGeoTask.Run calls Tree.Append("hosts", ...) — single writer
// -------------------------------------------------------------------------

func TestSubGeoTaskCallsTreeAppendHosts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"ip":      "93.184.216.34",
			"city":    "Norwell",
			"country": "US",
			"org":     "AS15133 Edgecast Inc.",
		})
	}))
	defer srv.Close()

	app, _ := buildGeoApp(t, srv.URL)
	mockTr := &mockTree{}
	app.Tree = mockTr

	tsk, ok := task.Default.Lookup("subdomains.geo")
	if !ok {
		t.Fatal("subdomains.geo not registered")
	}

	_, err := tsk.Run(context.Background(), app)
	if err != nil {
		t.Fatalf("SubGeoTask.Run: %v", err)
	}

	if !mockTr.appendCalled {
		t.Errorf("SubGeoTask.Run did NOT call Tree.Append — expected direct Append for hosts artefact (single writer)")
	}
}
