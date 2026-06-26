package installer

import (
	"context"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// SystemToolInstaller installs kind=system tools via the host package manager
// (INST-08). It is idempotent: a tool already on PATH is skipped.
type SystemToolInstaller struct {
	pkgMgr PkgMgr
}

// NewSystemToolInstaller binds an installer to a detected package manager.
func NewSystemToolInstaller(pkgMgr PkgMgr) *SystemToolInstaller {
	return &SystemToolInstaller{pkgMgr: pkgMgr}
}

// Install installs the system package named after the tool when it is not
// already on PATH.
func (s *SystemToolInstaller) Install(ctx context.Context, tool *backend.Tool) error {
	if onPath(tool.Name) {
		return nil // already present (idempotent)
	}
	return InstallSystemPkg(ctx, s.pkgMgr, tool.Name)
}
