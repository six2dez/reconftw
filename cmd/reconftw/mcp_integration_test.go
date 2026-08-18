// mcp_integration_test.go — in-process MCP integration tests (Plan 08-05).
//
// Uses mcp.NewInMemoryTransports() to wire an in-process MCP client to the
// reconFTW MCPServer, exercising the public MCP API without requiring a real
// stdio or HTTP transport.
//
// Tests:
//   - TestMCPToolList: verifies all 8 tools are listed (MCP-01, MCP-02)
//   - TestMCPSubsToolAsyncReturn: verifies D-02 async pattern (run_id + resource keys)
//   - TestMCPScopeRejection: verifies D-06 hard-reject for out-of-scope targets
//   - TestMCPRedaction: verifies XCUT-07 — API key does not appear in logs
//
// External test package per project convention (package main_test).
package main_test

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/sync/semaphore"

	corelog "github.com/six2dez/reconftw/internal/core/log"
	mcpsrv "github.com/six2dez/reconftw/internal/mcp"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/scheduler"
)

// buildTestMCPServer constructs a ready-to-use MCPServer with test credentials.
// Each caller gets a fresh registry and scheduler — no shared state between tests.
//
// W4 — goroutine cleanup: registers t.Cleanup(srv.Cancel) so the server-level
// scan context is cancelled before the test exits. Any scan goroutines launched
// via CallTool will receive a cancellation signal and exit promptly.
func buildTestMCPServer(t *testing.T) *mcpsrv.MCPServer {
	t.Helper()
	cfg := config.Defaults()
	cfg.MCP = config.MCPConfig{
		Enabled:   true,
		APIKey:    corelog.Secret("test-api-key-16chars"),
		Transport: "stdio",
		Port:      8765,
	}
	rdct := &corelog.Redactor{}
	rdct.Register("test-api-key-16chars")
	// heartbeatSec=0 disables heartbeat goroutines — keeps test clean for goleak.
	// Per-scan scheduler factory sharing one global limiter (mirrors mcp.go).
	limiter := semaphore.NewWeighted(1)
	newSched := func() *scheduler.Scheduler {
		s := scheduler.NewScheduler(1, 0, nil, nil)
		s.Limiter = limiter
		return s
	}
	srv := mcpsrv.NewMCPServer(context.Background(), cfg, "", "", newSched, rdct, "test")
	// W4: cancel all scan goroutines when the test exits.
	t.Cleanup(srv.Cancel)
	return srv
}

// connectTestClient wires an in-process client to srv's SDK server.
// Returns a connected *mcp.ClientSession. Cleanup is registered via t.Cleanup.
//
// Pattern from sdk_assumptions_test.go (Plan 08-00 — A1/A2/A5 verified):
//   - server.Connect first (t1), then client.Connect (t2)
func connectTestClient(t *testing.T, srv *mcpsrv.MCPServer) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	t1, t2 := mcp.NewInMemoryTransports()
	ss, err := srv.SDKServer().Connect(ctx, t1, nil)
	if err != nil {
		t.Fatalf("server.Connect: %v", err)
	}

	client := mcp.NewClient(
		&mcp.Implementation{Name: "test-client", Version: "0.0.1"},
		nil,
	)
	cs, err := client.Connect(ctx, t2, nil)
	if err != nil {
		t.Fatalf("client.Connect: %v", err)
	}

	t.Cleanup(func() {
		_ = cs.Close()
		_ = ss.Wait()
	})
	return cs
}

// TestMCPToolList connects in-process and asserts exactly 8 tools are listed
// with the expected names: recon, subs, web, vulns, osint, monitor, report and
// cancel_scan.
//
// Acceptance gate for MCP-01 and MCP-02.
func TestMCPToolList(t *testing.T) {
	t.Parallel()

	srv := buildTestMCPServer(t)
	cs := connectTestClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	const wantCount = 8
	if len(result.Tools) != wantCount {
		t.Errorf("expected %d tools, got %d", wantCount, len(result.Tools))
	}

	wantNames := map[string]bool{
		"recon":       true,
		"subs":        true,
		"web":         true,
		"vulns":       true,
		"osint":       true,
		"monitor":     true,
		"report":      true,
		"cancel_scan": true,
	}
	gotNames := make(map[string]bool, len(result.Tools))
	for _, tool := range result.Tools {
		gotNames[tool.Name] = true
	}

	for name := range wantNames {
		if !gotNames[name] {
			t.Errorf("expected tool %q in list, but it was missing; got: %v", name, toolNames(result.Tools))
		}
	}
	for name := range gotNames {
		if !wantNames[name] {
			t.Errorf("unexpected tool %q in list", name)
		}
	}
}

// toolNames extracts tool names for error messages.
func toolNames(tools []*mcp.Tool) []string {
	names := make([]string, len(tools))
	for i, tool := range tools {
		names[i] = tool.Name
	}
	return names
}

// TestMCPSubsToolAsyncReturn verifies that the subs tool returns immediately
// with a JSON response containing "run_id" and "resource" keys (D-02 async).
//
// W4 goroutine cleanup: a 200ms context timeout acts as both the D-02 deadline
// and the scan goroutine's cancellation signal. The goroutine launched by
// launchScanAndNotify uses context.Background() by design (scan must outlive the
// tool call context). We register t.Cleanup(cancel) so the context is
// unconditionally cancelled before the test exits, ensuring any goroutine that
// polls ctx.Done() exits promptly. The 200ms window is sufficient for the
// async tool call to return, and the cancel() in t.Cleanup bounds goroutine
// lifetime.
func TestMCPSubsToolAsyncReturn(t *testing.T) {
	t.Parallel()

	srv := buildTestMCPServer(t)
	cs := connectTestClient(t, srv)

	// D-02 deadline: tool call must return within 200ms (non-blocking handler).
	// W4: cancel() registered in t.Cleanup to bound goroutine lifetime.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	t.Cleanup(cancel)

	// A2 fallback: first call sets "example.com" as the implicit session scope.
	result, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "subs",
		Arguments: map[string]any{"target": "example.com"},
	})
	if err != nil {
		t.Fatalf("CallTool(subs): %v", err)
	}
	if result.IsError {
		t.Fatalf("CallTool(subs) returned tool error: %v", extractText(result))
	}

	text := extractText(result)
	if !strings.Contains(text, "run_id") {
		t.Errorf("response missing 'run_id' key; got: %q", text)
	}
	if !strings.Contains(text, "resource") {
		t.Errorf("response missing 'resource' key; got: %q", text)
	}
}

// TestMCPScopeRejection verifies D-06: calling a tool with an out-of-scope target
// returns an error response (not a panic). Error text must contain scope-related
// rejection wording.
//
// A2 fallback path: the first call to subs with "example.com" captures the
// implicit session scope. A subsequent call with "evil.com" is rejected.
func TestMCPScopeRejection(t *testing.T) {
	t.Parallel()

	srv := buildTestMCPServer(t)
	cs := connectTestClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First call: sets implicit session scope to "example.com" (A2 fallback).
	first, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "subs",
		Arguments: map[string]any{"target": "example.com"},
	})
	if err != nil {
		t.Fatalf("first CallTool(subs, example.com): %v", err)
	}
	if first.IsError {
		t.Fatalf("first call (scope-setting) returned unexpected error: %q", extractText(first))
	}

	// Second call: different target — must be rejected by D-06.
	second, err := cs.CallTool(ctx, &mcp.CallToolParams{
		Name:      "subs",
		Arguments: map[string]any{"target": "evil.com"},
	})
	if err != nil {
		t.Fatalf("second CallTool(subs, evil.com) returned transport error: %v", err)
	}
	if !second.IsError {
		t.Fatalf("expected tool error for out-of-scope target, got success: %q", extractText(second))
	}

	errText := extractText(second)
	// The error text should reference scope rejection (D-06).
	if !strings.Contains(errText, "scope") && !strings.Contains(errText, "out_of_scope") {
		t.Errorf("expected scope-rejection text in error, got: %q", errText)
	}
}

// TestMCPRedaction verifies XCUT-07: the raw API key does NOT appear in any log
// output emitted during a ListTools call. The Redactor registered in
// buildTestMCPServer must scrub it before any log line is emitted.
func TestMCPRedaction(t *testing.T) {
	t.Parallel()

	const secretKey = "super-secret-key-32chars-ABCDEFG"

	// Build a server with a recognisable API key.
	cfg := config.Defaults()
	cfg.MCP = config.MCPConfig{
		Enabled:   true,
		APIKey:    corelog.Secret(secretKey),
		Transport: "stdio",
		Port:      8765,
	}
	rdct := &corelog.Redactor{}
	rdct.Register(secretKey)
	limiter := semaphore.NewWeighted(1)
	newSched := func() *scheduler.Scheduler {
		s := scheduler.NewScheduler(1, 0, nil, nil)
		s.Limiter = limiter
		return s
	}
	srv := mcpsrv.NewMCPServer(context.Background(), cfg, "", "", newSched, rdct, "test")
	// W4: cancel all scan goroutines when the test exits.
	t.Cleanup(srv.Cancel)

	// Redirect slog.Default() to a capturing buffer so we can inspect log output.
	var buf logCapture
	captureLogger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	prev := slog.Default()
	slog.SetDefault(captureLogger)
	t.Cleanup(func() { slog.SetDefault(prev) })

	cs := connectTestClient(t, srv)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}

	logOutput := buf.String()
	if strings.Contains(logOutput, secretKey) {
		t.Errorf("XCUT-07: raw API key %q appeared in log output: %q", secretKey, logOutput)
	}
}

// extractText returns the concatenated text content from a CallToolResult.
func extractText(r *mcp.CallToolResult) string {
	if r == nil {
		return ""
	}
	var parts []string
	for _, c := range r.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			parts = append(parts, tc.Text)
		}
	}
	return strings.Join(parts, "")
}

// logCapture is a minimal io.Writer that accumulates written bytes.
type logCapture struct {
	buf strings.Builder
}

func (l *logCapture) Write(p []byte) (int, error) {
	return l.buf.Write(p)
}

func (l *logCapture) String() string {
	return l.buf.String()
}
