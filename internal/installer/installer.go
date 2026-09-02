package installer

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	"github.com/six2dez/reconftw/internal/core/backend"
	coreerrors "github.com/six2dez/reconftw/internal/core/errors"
)

// Options configures an install/health-check run.
type Options struct {
	Profile        string                // "core" (critical tier only) or "full"/"" (everything)
	Without        []string              // tool names or kinds to skip
	NonInteractive bool                  // suppress spinners/prompts (required for the Docker builder stage)
	Registry       *backend.ToolRegistry // tool inventory; injected by the caller (the process-wide registry)
}

// Installer drives toolchain bootstrap + per-kind tool installation off the
// tools.lock inventory (Phase 11). It carries no Cobra/TTY dependency.
type Installer struct {
	Options
	pkgMgr         PkgMgr
	goInstaller    *GoToolInstaller
	pyInstaller    *PythonToolInstaller
	sysInstaller   *SystemToolInstaller
	cloneInstaller *CloneToolInstaller
	log            *slog.Logger
}

// New constructs an Installer from opts. The caller (cmd/reconftw/install.go)
// must supply opts.Registry — typically the process-wide tool registry; the
// installer package never references that global so it stays hermetically
// testable.
func New(opts Options) *Installer {
	logger := slog.Default()
	if opts.NonInteractive {
		// Honour the flag instead of merely storing it. This package has no
		// spinners or prompts to suppress, so --non-interactive was accepted,
		// carried all the way into Options, and then read by nothing — the
		// documented behaviour did not exist. What a CI or Docker-builder
		// caller actually wants is quiet progress, so drop the per-tool
		// install_tool_ok stream to Warn and keep failures visible.
		logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		}))
	}
	return &Installer{
		Options:        opts,
		goInstaller:    NewGoToolInstaller(),
		pyInstaller:    NewPythonToolInstaller(),
		cloneInstaller: NewCloneToolInstaller(),
		log:            logger,
	}
}

// detectPkgMgrFn is indirected so tests can simulate platforms without GOOS.
var detectPkgMgrFn = detectPkgMgr

// bootstrapConfigFn yields the bootstrap config; indirected for tests.
var newBootstrapConfig = func() *bootstrapConfig { return &bootstrapConfig{} }

// Run performs a full install: detect platform (INST-05/12), bootstrap Go + uv
// (D-02) plus Rust when a kind=rust tool is enabled (INST-09), then install each
// selected tool via its per-kind handler (INST-06/07/08). Non-critical tool
// failures are logged and the run continues (best-effort); a missing-and-
// critical failure aborts. Ends with a HealthCheck (INST-10).
func (i *Installer) Run(ctx context.Context) error {
	i.pkgMgr = detectPkgMgrFn()
	if i.pkgMgr == PkgMgrUnknown {
		return unsupportedPlatformErr()
	}
	i.sysInstaller = NewSystemToolInstaller(i.pkgMgr)

	tools := i.selectTools()
	bcfg := newBootstrapConfig()
	if err := bootstrapGo(ctx, bcfg); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if err := bootstrapUV(ctx, bcfg); err != nil {
		return fmt.Errorf("install: %w", err)
	}
	if anyKind(tools, "rust") {
		if err := bootstrapRust(ctx, bcfg); err != nil {
			return fmt.Errorf("install: %w", err)
		}
	}

	var failed []string
	for _, t := range tools {
		if err := i.installOne(ctx, t); err != nil {
			if t.Critical {
				return fmt.Errorf("install: critical tool %q failed: %w", t.Name, err)
			}
			i.log.Warn("install_tool_failed", "tool", t.Name, "kind", t.Kind, "err", err)
			failed = append(failed, t.Name)
			continue
		}
		i.log.Info("install_tool_ok", "tool", t.Name, "kind", t.Kind, "version", t.Version)
	}
	if len(failed) > 0 {
		i.log.Warn("install_completed_with_failures", "failed_count", len(failed), "failed", failed)
	}
	return i.HealthCheck(ctx)
}

// installOne dispatches a single tool to the handler for its kind.
func (i *Installer) installOne(ctx context.Context, t *backend.Tool) error {
	switch t.Kind {
	case "go":
		return i.goInstaller.Install(ctx, t)
	case "python":
		return i.pyInstaller.Install(ctx, t)
	case "system":
		return i.sysInstaller.Install(ctx, t)
	case "go_clone", "python_venv", "make_clone", "rust":
		return i.cloneInstaller.Install(ctx, t)
	default:
		return fmt.Errorf("unknown tool kind %q", t.Kind)
	}
}

// HealthCheck reports which tools are present on PATH (INST-10). Absent
// non-critical tools are reported (logged) but do NOT fail; an absent critical
// tool returns a non-nil error so callers can exit non-zero (FOUND-08 parity).
func (i *Installer) HealthCheck(ctx context.Context) error {
	var missing, missingCritical []string
	for _, t := range i.selectTools() {
		if _, err := lookPath(t.Name); err != nil {
			missing = append(missing, t.Name)
			if t.Critical {
				missingCritical = append(missingCritical, t.Name)
			}
		}
	}
	if len(missing) > 0 {
		i.log.Info("health_check_missing", "count", len(missing), "tools", missing)
	}
	if len(missingCritical) > 0 {
		return fmt.Errorf("health-check: %d critical tool(s) missing: %s",
			len(missingCritical), strings.Join(missingCritical, ", "))
	}
	return nil
}

// selectTools applies the Profile + Without filters to the registry inventory.
// A nil Registry yields no tools (the caller is responsible for injecting one).
func (i *Installer) selectTools() []*backend.Tool {
	if i.Registry == nil {
		return nil
	}
	skip := map[string]bool{}
	for _, w := range i.Without {
		skip[w] = true
	}
	var out []*backend.Tool
	for _, t := range i.Registry.All() {
		if i.Profile == "core" && !t.Critical {
			continue
		}
		if skip[t.Name] || skip[t.Kind] {
			continue
		}
		out = append(out, t)
	}
	return out
}

func anyKind(tools []*backend.Tool, kind string) bool {
	for _, t := range tools {
		if t.Kind == kind {
			return true
		}
	}
	return false
}

// unsupportedPlatformErr is the typed INST-12 error for an unrecognized host.
func unsupportedPlatformErr() error {
	return &coreerrors.ConfigError{
		Key:     "platform",
		Message: "unsupported platform: no known package manager (apt/yum/dnf/pacman/brew) detected",
	}
}

// runCmd executes a subprocess, capturing combined output so failures surface
// the tool's stderr. Indirected as a var so unit tests can stub it.
var runCmd = func(ctx context.Context, name string, args, env []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// runCmdDir is runCmd with a working directory. Indirected for tests.
var runCmdDir = func(ctx context.Context, dir, name string, args, env []string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s (in %s): %w (output: %s)", name, strings.Join(args, " "), dir, err, strings.TrimSpace(string(out)))
	}
	return nil
}
