package installer

import (
	"context"
	"fmt"
	"strings"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// PythonToolInstaller installs kind=python tools via `uv tool install` with
// per-tool isolation (INST-07, D-04 idempotency).
type PythonToolInstaller struct{}

// NewPythonToolInstaller constructs a PythonToolInstaller.
func NewPythonToolInstaller() *PythonToolInstaller { return &PythonToolInstaller{} }

// Install runs `uv tool install <spec>` unless the tool is already present at
// the pinned version. The install spec is `<pkg>==<version>` for PyPI packages
// and `<git+url>@<version>` for VCS installs (RESEARCH.md Pattern 3).
func (p *PythonToolInstaller) Install(ctx context.Context, tool *backend.Tool) error {
	if tool.PipPackage == "" {
		return fmt.Errorf("python tool %q: empty pip_package in tools.lock", tool.Name)
	}
	if installed, err := probeUVToolVersions(ctx); err == nil {
		if v, ok := installed[tool.Name]; ok {
			if tool.Version == "latest" || v == strings.TrimPrefix(tool.Version, "v") {
				return nil // present + satisfied — skip (INST-11)
			}
		}
	}
	spec := buildUVSpec(tool.PipPackage, tool.Version)
	if err := runCmd(ctx, "uv", []string{"tool", "install", spec}, nil); err != nil {
		return fmt.Errorf("uv tool install %s (tool %q): %w", spec, tool.Name, err)
	}
	return nil
}

// buildUVSpec assembles the `uv tool install` target. PyPI packages pin with
// `==`; VCS (git+https://) installs pin a tag/branch with `@`. An unset or
// "latest" version installs the default (no pin suffix).
func buildUVSpec(pipPackage, version string) string {
	isVCS := strings.HasPrefix(pipPackage, "git+") || strings.Contains(pipPackage, "://")
	if version == "" || version == "latest" {
		return pipPackage
	}
	if isVCS {
		return pipPackage + "@" + version
	}
	return pipPackage + "==" + strings.TrimPrefix(version, "v")
}
