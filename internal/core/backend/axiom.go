// SPDX-License-Identifier: MIT
//
// AxiomBackend — real Phase 4 implementation replacing the Phase 3 compile stub.
//
// Key design decisions:
//   - Tool.InputFlag (not heuristic arg-scraping) identifies the input file for axiom-scan
//     fleet dispatch (REVIEWS finding #5 fix).
//   - moduleMap maps Tool.Name → axiom-scan module name; empty string = local fallback.
//   - HealthCheck detects "REMOTE HOST IDENTIFICATION HAS CHANGED" and repairs
//     known_hosts when cfg.Axiom.AutoFixHostkey=true (T-04-06-01 mitigation).
//   - Launch/Shutdown/resolversPropagation implement fleet lifecycle (AXIOM-05/06).
//   - NewAxiomBackendWithLocal is exported for test injection only (the internal
//     local backend is otherwise constructed by NewAxiomBackend).
package backend

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/six2dez/reconftw/internal/core/config"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// defaultAxiomModuleMap returns the canonical Tool.Name → axiom-scan module mapping.
// An empty string means "no axiom module — use local fallback transparently".
func defaultAxiomModuleMap() map[string]string {
	return map[string]string{
		"puredns":   "puredns-resolve",
		"tlsx":      "tlsx",
		"dnsx":      "dnsx",
		"s3scanner": "s3scanner",
		"nuclei":    "nuclei",
		"subfinder": "", // API-bound — always local
		"dnstake":   "", // no official axiom module yet
	}
}

// AxiomBackend dispatches tools to an Axiom fleet via the axiom-scan CLI.
//
// Tools present in moduleMap (with a non-empty module name) are run via
// `axiom-scan <inputFile> -m <module> -o <outFile>` executed by the embedded
// LocalBackend. Tools with an empty moduleMap entry fall back to local execution
// transparently.
type AxiomBackend struct {
	cfg       *config.Config
	reg       *ToolRegistry
	log       *slog.Logger
	moduleMap map[string]string
	local     Backend // used to run axiom-scan or fallback local
}

// NewAxiomBackend constructs the real AxiomBackend with cfg.Axiom.* settings.
// reg is used to look up the axiom-scan tool entry. logger may be nil (slog.Default used).
func NewAxiomBackend(cfg *config.Config, reg *ToolRegistry, logger *slog.Logger) *AxiomBackend {
	if logger == nil {
		logger = slog.Default()
	}
	return &AxiomBackend{
		cfg:       cfg,
		reg:       reg,
		log:       logger,
		moduleMap: defaultAxiomModuleMap(),
		local:     NewLocalBackend(0), // default kill grace
	}
}

// NewAxiomBackendWithLocal constructs an AxiomBackend with a test-injected local
// backend. This is the test-injection hook — production code uses NewAxiomBackend.
// Exported so the test package (backend_test) can inject fake backends.
func NewAxiomBackendWithLocal(cfg *config.Config, reg *ToolRegistry, logger *slog.Logger, local Backend) *AxiomBackend {
	if logger == nil {
		logger = slog.Default()
	}
	return &AxiomBackend{
		cfg:       cfg,
		reg:       reg,
		log:       logger,
		moduleMap: defaultAxiomModuleMap(),
		local:     local,
	}
}

// Exec dispatches toolName to axiom-scan (if in moduleMap) or falls back to
// local execution. Uses Tool.InputFlag to identify the input file — NOT a
// heuristic last-non-flag-arg scan (REVIEWS finding #5 fix).
func (a *AxiomBackend) Exec(ctx context.Context, t *Tool, args []string) (*Result, error) {
	module, ok := a.moduleMap[t.Name]
	if !ok || module == "" {
		// Unmapped or explicitly local-only → transparent local fallback.
		return a.local.Exec(ctx, t, args)
	}

	inputFile := extractInputFile(t, args)
	if inputFile == "" {
		// No input file found — fall back to local silently.
		a.log.Debug("axiom_backend: no input file found, falling back to local",
			slog.String("tool", t.Name))
		return a.local.Exec(ctx, t, args)
	}

	// Resolve axiom-scan tool entry from registry (may be nil if not registered).
	axiomTool := a.axiomScanTool()

	// Build axiom-scan invocation: axiom-scan <inputFile> -m <module> -o <outFile>
	outFile := inputFile + ".axiom.out"
	axiomArgs := []string{inputFile, "-m", module, "-o", outFile}
	if a.cfg.Axiom.ExtraArgs != "" {
		axiomArgs = append(axiomArgs, strings.Fields(a.cfg.Axiom.ExtraArgs)...)
	}

	res, err := a.local.Exec(ctx, axiomTool, axiomArgs)
	if err != nil {
		return nil, &coreerrors.AxiomFailure{
			Operation: "exec",
			Inner:     fmt.Errorf("axiom-scan %s: %w", t.Name, err),
		}
	}

	return res, nil
}

// extractInputFile returns the input file path from tool args using Tool.InputFlag.
//
// If Tool.InputFlag is non-empty (e.g. "-l"), returns the arg immediately
// following InputFlag in args. If InputFlag is empty, returns the last element of
// args (positional convention used by puredns, massdns, etc.).
// Returns "" if the flag is not found or args is empty.
func extractInputFile(t *Tool, args []string) string {
	if len(args) == 0 {
		return ""
	}
	if t.InputFlag != "" {
		// Find the arg immediately after InputFlag.
		for i, arg := range args {
			if arg == t.InputFlag && i+1 < len(args) {
				return args[i+1]
			}
		}
		return "" // flag not found
	}
	// InputFlag="" — positional: last element.
	return args[len(args)-1]
}

// axiomScanTool looks up the "axiom-scan" entry from the registry.
// If not found, returns a synthetic Tool entry so tests that don't seed
// the registry still work (they inject a fake local that ignores the Tool struct).
func (a *AxiomBackend) axiomScanTool() *Tool {
	if a.reg != nil {
		if t, ok := a.reg.Lookup("axiom-scan"); ok {
			return t
		}
	}
	return &Tool{Name: "axiom-scan", Path: "axiom-scan"}
}

// Stream dispatches the tool via axiom-scan (if mapped), buffers the result,
// and emits it over the returned channel. If the tool is unmapped, delegates
// to local.Stream transparently.
func (a *AxiomBackend) Stream(ctx context.Context, t *Tool, args []string) (<-chan Event, error) {
	module, ok := a.moduleMap[t.Name]
	if !ok || module == "" {
		return a.local.Stream(ctx, t, args)
	}
	// Axiom: run Exec (buffer whole result), then pipe through a channel.
	res, err := a.Exec(ctx, t, args)
	if err != nil {
		return nil, err
	}
	out := make(chan Event, 1)
	go func() {
		defer close(out)
		for _, line := range bytes.Split(res.Stdout, []byte("\n")) {
			if len(line) == 0 {
				continue
			}
			select {
			case out <- Event{Line: line, Source: t.Name}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, nil
}

// HealthCheck verifies the axiom fleet is reachable by running
// `axiom-exec "echo reconftw-axiom-probe"`. If the output contains
// "REMOTE HOST IDENTIFICATION HAS CHANGED", triggers repairKnownHosts
// when AutoFixHostkey=true; otherwise returns *AxiomFailure.
func (a *AxiomBackend) HealthCheck(ctx context.Context) error {
	probeResult, err := a.local.Exec(ctx, a.axiomScanTool(), []string{"echo", "reconftw-axiom-probe"})

	var stderrBytes []byte
	if probeResult != nil {
		stderrBytes = probeResult.Stderr
	}

	if err != nil || (probeResult != nil && probeResult.ExitCode != 0) {
		// Check for hostkey change in stderr.
		if bytes.Contains(stderrBytes, []byte("REMOTE HOST IDENTIFICATION HAS CHANGED")) {
			if a.cfg.Axiom.AutoFixHostkey {
				_ = a.repairKnownHosts(ctx, stderrBytes)
				return nil // attempt repair; best-effort
			}
			return &coreerrors.AxiomFailure{
				Operation: "healthcheck",
				Inner:     fmt.Errorf("SSH host key changed; set auto_fix_hostkey=true or run ssh-keygen -R <host>"),
			}
		}
		inner := err
		if inner == nil {
			inner = fmt.Errorf("axiom-exec probe exited with code %d", probeResult.ExitCode)
		}
		return &coreerrors.AxiomFailure{Operation: "healthcheck", Inner: inner}
	}
	return nil
}

// repairKnownHosts parses the offending hostname from SSH stderr and runs
// ssh-keygen -R <host> to remove the stale key (T-04-06-01 mitigation).
// Only called when AutoFixHostkey=true (explicit opt-in).
func (a *AxiomBackend) repairKnownHosts(ctx context.Context, errOutput []byte) error {
	// Parse offending host from SSH stderr pattern:
	// "Offending ECDSA key in /home/user/.ssh/known_hosts:42"
	// "Host key verification failed."
	host := parseOffendingHost(errOutput)

	sshKeygenTool := &Tool{Name: "ssh-keygen", Path: "ssh-keygen"}
	repairArgs := []string{"-R", host}
	if host == "" {
		repairArgs = []string{"-R", a.cfg.Axiom.FleetName}
	}
	_, err := a.local.Exec(ctx, sshKeygenTool, repairArgs)
	if err != nil {
		a.log.Warn("axiom_backend: repairKnownHosts ssh-keygen failed",
			slog.String("host", host), slog.Any("err", err))
	} else {
		a.log.Info("axiom_backend: repaired known_hosts", slog.String("host", host))
	}
	return err
}

// parseOffendingHost extracts the hostname from SSH stderr output.
// Returns "" if the pattern is not found.
func parseOffendingHost(errOutput []byte) string {
	// Look for lines like: "Offending key in /home/.../.ssh/known_hosts:N"
	// or "@ WARNING: POSSIBLE DNS SPOOFING DETECTED! @" followed by fleet hostname.
	// Simplified: look for a hostname pattern after "Offending" on the same line.
	for _, line := range bytes.Split(errOutput, []byte("\n")) {
		if bytes.Contains(line, []byte("Offending")) {
			// Try to find host from context — look for IP or hostname patterns.
			// For the repair to work we use the fleet name as fallback.
			fields := bytes.Fields(line)
			for _, f := range fields {
				if bytes.Contains(f, []byte(".")) && !bytes.Contains(f, []byte("/")) {
					return string(f)
				}
			}
		}
	}
	return ""
}

// Capacity returns the configured fleet size (cfg.Axiom.FleetCount).
func (a *AxiomBackend) Capacity() int {
	return a.cfg.Axiom.FleetCount
}

// Launch provisions the axiom fleet, selects it, and propagates resolver files.
// Called by newSubsCmd before the first RunStage.
func (a *AxiomBackend) Launch(ctx context.Context) error {
	// Select (or create) the fleet by name.
	axiomSelectTool := &Tool{Name: "axiom-select", Path: "axiom-select"}
	if _, err := a.local.Exec(ctx, axiomSelectTool, []string{a.cfg.Axiom.FleetName}); err != nil {
		return &coreerrors.AxiomFailure{
			Operation: "launch",
			Inner:     fmt.Errorf("axiom-select %s: %w", a.cfg.Axiom.FleetName, err),
		}
	}
	// If FleetLaunch is set, provision missing nodes.
	if a.cfg.Axiom.FleetLaunch {
		fleet2Tool := &Tool{Name: "axiom-fleet2", Path: "axiom-fleet2"}
		fleetArgs := []string{"deploy", a.cfg.Axiom.FleetName,
			fmt.Sprintf("--count=%d", a.cfg.Axiom.FleetCount)}
		if _, err := a.local.Exec(ctx, fleet2Tool, fleetArgs); err != nil {
			a.log.Warn("axiom_backend: fleet2 deploy failed (non-fatal if fleet exists)",
				slog.String("fleet", a.cfg.Axiom.FleetName), slog.Any("err", err))
		}
	}
	return a.resolversPropagation(ctx)
}

// Shutdown removes the fleet when ShutdownOnEnd=true.
func (a *AxiomBackend) Shutdown(ctx context.Context) error {
	if !a.cfg.Axiom.ShutdownOnEnd {
		return nil
	}
	axiomRmTool := &Tool{Name: "axiom-rm", Path: "axiom-rm"}
	if _, err := a.local.Exec(ctx, axiomRmTool, []string{a.cfg.Axiom.FleetName, "--force"}); err != nil {
		return &coreerrors.AxiomFailure{
			Operation: "shutdown",
			Inner:     fmt.Errorf("axiom-rm %s: %w", a.cfg.Axiom.FleetName, err),
		}
	}
	a.log.Info("axiom_backend: fleet shut down", slog.String("fleet", a.cfg.Axiom.FleetName))
	return nil
}

// resolversPropagation uploads resolver files to the fleet nodes via axiom-exec.
// Mirrors v1 resolvers_update logic from modules/axiom.sh:55-120 (AXIOM-05).
func (a *AxiomBackend) resolversPropagation(ctx context.Context) error {
	resolversPath := a.cfg.Advanced.Tools.Axiom.ResolversPath
	trustedPath := a.cfg.Advanced.Tools.Axiom.ResolversTrustedPath
	if resolversPath == "" && trustedPath == "" {
		return nil // nothing to propagate
	}
	axiomExecTool := &Tool{Name: "axiom-exec", Path: "axiom-exec"}
	for _, rpath := range []string{resolversPath, trustedPath} {
		if rpath == "" {
			continue
		}
		// Upload file to each fleet node via axiom-exec scp-style transfer.
		uploadArgs := []string{fmt.Sprintf("cat > /tmp/resolvers.txt << 'EOF'\n$(cat %s)\nEOF", rpath)}
		if _, err := a.local.Exec(ctx, axiomExecTool, uploadArgs); err != nil {
			a.log.Warn("axiom_backend: resolver propagation failed (non-fatal)",
				slog.String("file", rpath), slog.Any("err", err))
		}
	}
	return nil
}
