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
//   - A2: InitializedHandler is wired; ID()="" for in-memory transport. Either
//     way the first tool call captures the session scope through the registry's
//     atomic CaptureScopeIfUnset — there is one capture path, not two.
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
// launched via launchScanAndNotify. It is derived from the context handed to
// NewMCPServer (the entrypoint's cobra context) and additionally linked to the
// context Start receives, so transport shutdown or SIGINT cancels every
// in-flight scan (F9 / T-15-15-06). Tests call Cancel() from t.Cleanup to bound
// scan goroutine lifetime without test hooks or goleak.IgnoreTopFunction (W4).
//
// CONFIG SNAPSHOT (F7 / T-15-15-07, T-15-15-08). cfg, configPath and
// secretsPath are the configuration the operator STARTED THE SERVER WITH. They
// are written once, in NewMCPServer, and never mutated afterwards:
//
//   - cfg is the resolved *config.Config. It is only ever read (data dir, log
//     level, MCP transport/port/key) or handed to code that treats it as
//     read-only (the report renderer). It is NEVER handed to a scan, because
//     a scan's ConfigTransform MUTATES the config it is given and concurrent
//     scans would then race on one struct.
//   - configPath / secretsPath ARE the snapshot for scans: every run carries
//     them in handlers.RunOptions, so ResolveRunPlan re-loads config into its
//     OWN instance and applies its own transform to that instance. The paths
//     are immutable, so the snapshot is race-free by construction.
type MCPServer struct {
	srv *mcp.Server
	// cfg is the RESOLVED startup config. Read-only after construction.
	cfg *config.Config
	// configPath / secretsPath are the explicit --config / --secrets paths that
	// produced cfg (empty when the operator supplied none). They travel with
	// every scan so a run resolves the SAME configuration the server started
	// with instead of re-running config.Load with no explicit paths at all.
	configPath  string
	secretsPath string
	newSched    func() *scheduler.Scheduler
	rdct        *log.Redactor
	registry    *SessionRegistry
	// tools holds the wiring the tool closures use. Exposed on the struct so
	// tests can drive the exact code a tool call runs without fabricating an
	// *mcp.ServerSession with a chosen ID.
	tools      *toolDeps
	scanCtx    context.Context    //nolint:containedctx // server owns scan goroutine lifetime
	scanCancel context.CancelFunc // called by Cancel() to stop all scan goroutines
	// sweeperDone is closed when the terminal-entry sweeper goroutine exits.
	// Cancel() stops the sweeper; a test waits on this to prove it does not leak.
	sweeperDone chan struct{}
}

// eventStoreMaxBytes bounds the streamable-HTTP replay buffer. See the comment
// at its use site: the SDK bounds it too, but at a default we do not control.
const eventStoreMaxBytes = 8 << 20 // 8 MiB

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
// wires an InitializedHandler that pre-registers HTTP sessions with no scope
// (the first tool call captures it atomically via CaptureScopeIfUnset),
// registers the tools, and registers the scan://… resource templates.
//
// ctx is the scan root: every scan goroutine runs under a context derived from
// it, so cancelling ctx (SIGINT at the entrypoint) cancels in-flight scans.
// Start additionally links the context IT receives, and Cancel() cancels
// unconditionally. Passing a nil ctx is a programming error and panics in
// context.WithCancel, exactly as it would anywhere else.
//
// cfg is the RESOLVED configuration; configPath and secretsPath are the
// explicit --config / --secrets paths that produced it. All three are the
// immutable startup snapshot documented on MCPServer — before this, everything
// but cfg.MCP was discarded and each scan re-ran config.Load with no explicit
// paths, so a server started with --config silently scanned under a different
// configuration (F7).
//
// newSched is a factory that creates a fresh per-scan *scheduler.Scheduler for
// each tool invocation. Every scan gets its OWN scheduler (so the per-scan
// RunTask / Checkpoint / Hash fields wired by appctx.Boot never race across
// concurrent D-03 sessions), while all factory-produced schedulers share one
// process-wide Limiter so concurrent sessions cannot exceed PARALLEL_MAX_JOBS
// (MCP-05). The factory is supplied by runMCPServeCmd.
//
// version is embedded in the MCP Implementation.Version field.
func NewMCPServer(
	ctx context.Context,
	cfg *config.Config,
	configPath, secretsPath string,
	newSched func() *scheduler.Scheduler,
	rdct *log.Redactor,
	version string,
) *MCPServer {
	registry := NewSessionRegistry()

	srv := mcp.NewServer(
		&mcp.Implementation{Name: "reconFTW", Version: version},
		&mcp.ServerOptions{
			// InitializedHandler: pre-register the session. For HTTP transport
			// sess.ID() is a real random UUID; for in-memory transports (tests)
			// it is "". Scope is NOT set here — a session legitimately has no
			// target until its first tool call, which captures it atomically
			// via SessionRegistry.CaptureScopeIfUnset.
			InitializedHandler: func(_ context.Context, req *mcp.InitializedRequest) {
				sess, ok := req.GetSession().(*mcp.ServerSession)
				if !ok || sess == nil {
					return
				}
				sessID := sess.ID()
				if sessID == "" {
					// ID="" for in-memory transport. Nothing to pre-register;
					// the first tool call captures scope for the "" session
					// exactly as it does for a real one.
					return
				}
				// Register with an empty workdir and a NIL scope. That is not an
				// oversight: it is the honest statement that the session has not
				// named a target yet, and CheckScope stays fail-closed until the
				// first call captures one via CaptureScopeIfUnset.
				registry.Register(sessID, "", nil)
			},

			// A3 (08-00-SUMMARY): SubscribeHandler and UnsubscribeHandler MUST
			// both be set together. Setting only one causes a panic at NewServer.
			SubscribeHandler: func(_ context.Context, req *mcp.SubscribeRequest) error {
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
			UnsubscribeHandler: func(_ context.Context, _ *mcp.UnsubscribeRequest) error {
				// Allow all unsubscriptions.
				return nil
			},
		},
	)

	// Create the server-lifetime scan context. Scan goroutines run under it, so
	// cancelling the caller's ctx — or Cancel(), or the context Start receives —
	// stops every in-flight scan. It derives from the CALLER's context rather
	// than context.Background(): an orphaned scan keeps spawning external tool
	// processes long after the operator believes the server stopped (F9 /
	// T-15-15-06).
	scanCtx, scanCancel := context.WithCancel(ctx)

	s := &MCPServer{
		srv:         srv,
		cfg:         cfg,
		configPath:  configPath,
		secretsPath: secretsPath,
		newSched:    newSched,
		rdct:        rdct,
		registry:    registry,
		scanCtx:     scanCtx,
		scanCancel:  scanCancel,
		sweeperDone: make(chan struct{}),
	}

	// Register the MCP tools and the scan://… resource templates. Pass s
	// (MCPServer) so tool handlers can access the scan context and the config
	// snapshot.
	RegisterTools(srv, newSched, registry, rdct, cfg, configPath, secretsPath, s)
	RegisterResources(srv, registry, rdct)

	// Reclaim terminal registry entries so a long-lived server does not grow
	// without bound (T-15-15-05). The goroutine is owned by this server and
	// exits when the scan context is cancelled — Cancel() stops it, and
	// sweeperDone lets a test prove that it did.
	go s.sweepTerminalEntries()

	return s
}

// sweepTerminalEntries periodically reclaims terminal registry entries.
// It exits when the scan context is cancelled, closing sweeperDone on the way
// out so its lifetime is observable rather than assumed.
func (s *MCPServer) sweepTerminalEntries() {
	defer close(s.sweeperDone)

	ticker := time.NewTicker(terminalSweepInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.scanCtx.Done():
			return
		case now := <-ticker.C:
			s.registry.SweepTerminal(now.Add(-completedEntryTTL))
		}
	}
}

// linkShutdown ties ctx to the scan context: cancelling ctx cancels every
// in-flight scan. The returned stop function detaches the link (call it when
// the caller's context outlives the reason for linking).
//
// Split out of Start so the linkage can be asserted directly, without standing
// up a transport that reads os.Stdin or binds a port.
func (s *MCPServer) linkShutdown(ctx context.Context) (stop func() bool) {
	return context.AfterFunc(ctx, s.Cancel)
}

// Start dispatches to either the HTTP or stdio transport based on cfg.Transport.
// Blocks until the context is cancelled or an error occurs.
//
// Start owns the shutdown contract (F9 / T-15-15-06): cancelling ctx cancels
// every in-flight scan, and so does a transport that returns on its own (a
// listen error, a closed stdin). Scans used to run under a context derived from
// context.Background() with nothing cancelling it at shutdown, so an operator
// who stopped the server left scans spawning external tool processes behind it.
func (s *MCPServer) Start(ctx context.Context) error {
	stop := s.linkShutdown(ctx)
	defer stop()
	defer s.Cancel()

	switch s.cfg.MCP.Transport {
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
	// Event store bound (T-15-15-05). The SDK's MemoryEventStore already purges
	// oldest-first at MaxBytes — verified in the SDK source, default 10 MiB —
	// so it is not literally unbounded, but the bound was implicit and untuned.
	// Setting it explicitly makes the resident cost of a long-lived server a
	// stated number rather than an SDK default that can change under us.
	eventStore := mcp.NewMemoryEventStore(nil)
	eventStore.SetMaxBytes(eventStoreMaxBytes)

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(r *http.Request) *mcp.Server { return s.srv },
		&mcp.StreamableHTTPOptions{
			// A6: nil options are safe (verified in sdk_assumptions_test.go).
			EventStore: eventStore,
		},
	)

	mux := http.NewServeMux()
	// T-08-04-02: BearerAuthMiddleware wraps the MCP handler at the net/http layer.
	// Auth MUST be here, NOT inside the SDK (cannot read HTTP headers from go-sdk
	// middleware — see RESEARCH.md Pitfall 1).
	mux.Handle("/mcp", BearerAuthMiddleware(string(s.cfg.MCP.APIKey), mcpHandler))
	// T-08-04-04: OpenAPI schema served unauthenticated at /openapi.json.
	// The schema contains no secrets — only endpoint descriptions and input schemas.
	mux.HandleFunc("/openapi.json", serveOpenAPISchema)

	// T-08-04-01: D-05 localhost-only binding. Port from config (validated min=1024,max=65535).
	addr := fmt.Sprintf("127.0.0.1:%d", s.cfg.MCP.Port)
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
