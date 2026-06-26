package installer

import (
	"context"
	"fmt"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// GoToolInstaller installs kind=go tools via `go install <module>@<version>`
// with version-probe idempotency (INST-06, INST-11, D-04).
type GoToolInstaller struct{}

// NewGoToolInstaller constructs a GoToolInstaller.
func NewGoToolInstaller() *GoToolInstaller { return &GoToolInstaller{} }

// Install runs `go install <GoModule>@<Version>` unless the tool is already
// installed at the pinned version (INST-11). A "(devel)" probe (locally built,
// unknown provenance) always reinstalls. When the pin is the floating "latest"
// channel a present binary is treated as satisfied — there is no concrete tag
// to diff against, so reinstalling every run would violate idempotency.
func (g *GoToolInstaller) Install(ctx context.Context, tool *backend.Tool) error {
	if tool.GoModule == "" {
		return fmt.Errorf("go tool %q: empty go_module in tools.lock", tool.Name)
	}
	installed, err := probeGoToolVersion(ctx, tool.Name)
	if err == nil && installed != "(devel)" {
		if tool.Version == "latest" || installed == tool.Version {
			return nil // present + satisfied — skip (INST-11)
		}
	}
	spec := tool.GoModule + "@" + tool.Version
	env := []string{"GO111MODULE=on", "GOFLAGS=-mod=mod", "CGO_ENABLED=0"}
	if err := runCmd(ctx, "go", []string{"install", spec}, env); err != nil {
		return fmt.Errorf("go install %s (tool %q): %w", spec, tool.Name, err)
	}
	return nil
}
