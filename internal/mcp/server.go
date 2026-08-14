// Package mcp — MCPServer struct, constructor, and transport dispatch.
//
// MCPServer wraps the go-sdk *mcp.Server and exposes Start(ctx) to dispatch
// to either the stdio or HTTP/Streamable transport based on MCPConfig.Transport.
//
// HTTP transport (D-05): binds 127.0.0.1 only. Bearer auth middleware wraps the
// StreamableHTTPHandler at the net/http layer BEFORE the SDK sees the request
// (RESEARCH.md Pitfall 1 — cannot use AddReceivingMiddleware for Bearer auth).
//
// SDK landmines (from Wave-0 08-00-SUMMARY):
//   - A3: SubscribeHandler and UnsubscribeHandler MUST both be set in ServerOptions
//     or the SDK panics (server.go:172-176). Setting only one panics at NewServer.
//   - A6: NewMemoryEventStore(nil) is safe; nil options are accepted.
//   - A2: InitializedHandler is wired; ID()="" for in-memory transport — fallback
//     path in tools.go handles the first-tool-call scope capture.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/log"
	"github.com/six2dez/reconftw/internal/core/scheduler"
)

// MCPServer is the top-level MCP server component. It wraps the go-sdk
// *mcp.Server and owns the SessionRegistry, shared scheduler, and config.
//
// scanCtx / scanCancel: a server-lifetime context used by scan goroutines
// launched via launchScanAndNotify. When the server shuts down (or in tests
// when t.Cleanup calls Cancel()), all in-flight scan goroutines receive a
// cancellation signal and can exit promptly. This satisfies the W4 goroutine-
// cleanup requirement (Plan 08-05): use Cancel() in t.Cleanup to bound scan
// goroutine lifetime without needing test hooks or goleak.IgnoreTopFunction.
type MCPServer struct {
	srv        *mcp.Server
	cfg        *config.MCPConfig
	newSched   func() *scheduler.Scheduler
	rdct       *log.Redactor
	registry   *SessionRegistry
	scanCtx    context.Context    //nolint:containedctx // server owns scan goroutine lifetime
	scanCancel context.CancelFunc // called by Cancel() to stop all scan goroutines
}

// Cancel cancels the server-level context, signalling all in-flight scan
// goroutines to stop. Safe to call multiple times (idempotent via sync.Once
// semantics of context.CancelFunc).
//
// Tests register t.Cleanup(srv.Cancel) to bound scan goroutine lifetime (W4).
// Production code may also call this after Start() returns to ensure cleanup.
func (s *MCPServer) Cancel() {
	s.scanCancel()
}

// SDKServer returns the underlying go-sdk *mcp.Server. Used by integration
// tests (Plan 08-05) to connect in-memory transports without going through
// the HTTP/stdio layer.
func (s *MCPServer) SDKServer() *mcp.Server {
	return s.srv
}

// Registry returns the session registry. Used by integration tests and
// resource handlers to inspect scan state.
func (s *MCPServer) Registry() *SessionRegistry {
	return s.registry
}

// NewMCPServer constructs a ready-to-start MCPServer.
//
// It creates a SessionRegistry, builds the go-sdk *mcp.Server with
// SubscribeHandler + UnsubscribeHandler (both required by the SDK — A3),
// wires an InitializedHandler that sets session scope from client params
// (HTTP transport only; in-memory returns "" — A2 fallback in tools.go),
// registers all 7 tools, and registers the scan://… resource template.
//
// newSched is a factory that creates a fresh per-scan *scheduler.Scheduler for
// each tool invocation. Every scan gets its OWN scheduler (so the per-scan
// RunTask / Checkpoint / Hash fields wired by appctx.Boot never race across
// concurrent D-03 sessions), while all factory-produced schedulers share one
// process-wide Limiter so concurrent sessions cannot exceed PARALLEL_MAX_JOBS
// (MCP-05). The factory is supplied by runMCPServeCmd.
//
// version is embedded in the MCP Implementation.Version field.
func NewMCPServer(cfg *config.MCPConfig, newSched func() *scheduler.Scheduler, rdct *log.Redactor, version string) *MCPServer {
	registry := NewSessionRegistry()

	srv := mcp.NewServer(
		&mcp.Implementation{Name: "reconFTW", Version: version},
		&mcp.ServerOptions{
			// InitializedHandler: Set session scope from InitializeParams.
			// For HTTP transport, sess.ID() is a real random UUID.
			// For in-memory transports (tests), sess.ID() returns "" — see
			// A2 fallback in tools.go: first tool call captures scope via SetScope.
			InitializedHandler: func(ctx context.Context, req *mcp.InitializedRequest) {
				sess, ok := req.GetSession().(*mcp.ServerSession)
				if !ok || sess == nil {
					return
				}
				sessID := sess.ID()
				if sessID == "" {
					// A2 fallback path: ID="" for in-memory transport.
					// Scope will be captured on the first tool call in tools.go.
					return
				}
				// Pre-register the session so SetScope can find it.
				// Register with empty workdir and nil scope; scope will be set
				// when the first tool call arrives (A2 fallback), or here if
				// InitializeParams carries a target list in future extensions.
				//
				// For now, initialize with nil scope so the A2 fallback in
				// each tool handler captures it on first call.
				registry.Register(sessID, "", nil)
			},

			// A3 (08-00-SUMMARY): SubscribeHandler and UnsubscribeHandler MUST
			// both be set together. Setting only one causes a panic at NewServer.
			SubscribeHandler: func(ctx context.Context, req *mcp.SubscribeRequest) error {
				// Validate that the subscribing session has scope over the runID's target.
				// The runID is embedded in the URI: scan://<runID>/findings.
				runID := extractRunIDFromURI(req.Params.URI)
				if runID == "" {
					return fmt.Errorf("mcp: invalid subscription URI: %q", req.Params.URI)
				}
				// Verify the run exists AND belongs to the subscribing session.
				// Existence alone was checked before, so any client holding a
				// runID could stream another session's findings notifications.
				// Unknown and unauthorised share one error message so the
				// response does not confirm which runIDs exist.
				var subSessID string
				if sess, ok := req.GetSession().(*mcp.ServerSession); ok && sess != nil {
					subSessID = sess.ID()
				}
				if !registry.OwnedBy(runID, subSessID) {
					return fmt.Errorf("mcp: no such findings resource: %q", req.Params.URI)
				}
				return nil
			},
			UnsubscribeHandler: func(ctx context.Context, req *mcp.UnsubscribeRequest) error {
				// Allow all unsubscriptions.
				return nil
			},
		},
	)

	// Create the server-lifetime scan context. Scan goroutines use this context
	// so they can be cancelled when the server shuts down (or in tests via
	// t.Cleanup(srv.Cancel)). This satisfies W4 — no goroutine can outlive the
	// MCPServer's logical lifetime.
	scanCtx, scanCancel := context.WithCancel(context.Background())

	s := &MCPServer{
		srv:        srv,
		cfg:        cfg,
		newSched:   newSched,
		rdct:       rdct,
		registry:   registry,
		scanCtx:    scanCtx,
		scanCancel: scanCancel,
	}

	// Register all 7 MCP tools and the scan://…/findings resource template.
	// Pass s (MCPServer) so tool handlers can access the scan context.
	RegisterTools(srv, newSched, registry, rdct, cfg, s)
	RegisterResources(srv, registry)

	return s
}

// Start dispatches to either the HTTP or stdio transport based on cfg.Transport.
// Blocks until the context is cancelled or an error occurs.
func (s *MCPServer) Start(ctx context.Context) error {
	switch s.cfg.Transport {
	case "stdio":
		return runMCPServeStdio(ctx, s)
	default:
		// "http" and any unset value → HTTP transport (D-05).
		return runMCPServeHTTP(ctx, s)
	}
}

// runMCPServeStdio runs the MCP server using the stdin/stdout transport.
// The SDK's StdioTransport respects context cancellation (A5 — verified in
// sdk_assumptions_test.go: exits within 1s of cancel).
func runMCPServeStdio(ctx context.Context, s *MCPServer) error {
	if err := s.srv.Run(ctx, &mcp.StdioTransport{}); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("mcp: stdio server: %w", err)
	}
	return nil
}

// runMCPServeHTTP runs the MCP server using the streamable-HTTP transport.
//
// Security guarantees:
//   - T-08-04-01: Addr is always "127.0.0.1:<port>" (D-05 localhost-only binding).
//   - T-08-04-02: BearerAuthMiddleware wraps the entire mux before the MCP handler.
//   - Pitfall 5 (08-RESEARCH): MemoryEventStore(nil) replays events for reconnecting
//     clients (A6 — verified safe in sdk_assumptions_test.go).
func runMCPServeHTTP(ctx context.Context, s *MCPServer) error {
	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return s.srv },
		&mcp.StreamableHTTPOptions{
			// A6: nil options are safe (verified in sdk_assumptions_test.go).
			EventStore: mcp.NewMemoryEventStore(nil),
		},
	)

	mux := http.NewServeMux()
	// T-08-04-02: BearerAuthMiddleware wraps the MCP handler at the net/http layer.
	// Auth MUST be here, NOT inside the SDK (cannot read HTTP headers from go-sdk
	// middleware — see RESEARCH.md Pitfall 1).
	mux.Handle("/mcp", BearerAuthMiddleware(string(s.cfg.APIKey), mcpHandler))
	// T-08-04-04: OpenAPI schema served unauthenticated at /openapi.json.
	// The schema contains no secrets — only endpoint descriptions and input schemas.
	mux.HandleFunc("/openapi.json", serveOpenAPISchema)

	// T-08-04-01: D-05 localhost-only binding. Port from config (validated min=1024,max=65535).
	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.Port)
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Graceful shutdown when the context is cancelled.
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
	}()

	if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("mcp: http server: %w", err)
	}
	return nil
}

// extractRunIDFromURI parses a "scan://<runID>/findings" URI and returns the
// runID component. Returns "" for unrecognised URI shapes.
func extractRunIDFromURI(uri string) string {
	return extractRunIDFromSuffixedURI(uri, "/findings")
}

// extractRunIDFromSuffixedURI parses "scan://<runID><suffix>" and returns the
// runID, or "" when the URI does not have that shape. Generalised from the
// findings-only version when scan://<runID>/status was added, so both
// resources parse identically and a malformed URI is rejected the same way.
func extractRunIDFromSuffixedURI(uri, suffix string) string {
	const prefix = "scan://"
	if len(uri) <= len(prefix)+len(suffix) {
		return ""
	}
	if uri[:len(prefix)] != prefix {
		return ""
	}
	rest := uri[len(prefix):]
	if len(rest) <= len(suffix) {
		return ""
	}
	if rest[len(rest)-len(suffix):] != suffix {
		return ""
	}
	return rest[:len(rest)-len(suffix)]
}
