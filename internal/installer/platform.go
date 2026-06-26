// Package installer implements `reconftw install` — the Go replacement for the
// bash install.sh. It reads the embedded tools.lock inventory (via
// internal/core/backend) and installs every orchestrated tool through the
// appropriate native toolchain (`go install`, `uv tool install`, the platform
// package manager, or a repo clone+build), with SHA-256-verified toolchain
// bootstrap and version-probe idempotency.
//
// The package has NO Cobra or TTY dependency so it is fully unit-testable; the
// `reconftw install` Cobra adapter lives in cmd/reconftw/install.go (plan 11-03).
//
// Source: .planning/phases/11-installer-cross-platform-docker/11-02-PLAN.md.
package installer

import (
	"context"
	"os/exec"
	"runtime"
)

// PkgMgr identifies the host's system package manager (INST-05).
type PkgMgr int

const (
	PkgMgrUnknown PkgMgr = iota
	PkgMgrApt            // Debian/Ubuntu
	PkgMgrYum            // RHEL/Fedora/CentOS (yum or dnf)
	PkgMgrPacman         // Arch
	PkgMgrBrew           // macOS (Homebrew, Intel or Apple Silicon)
)

// String renders the package manager name for logs / health-check output.
func (p PkgMgr) String() string {
	switch p {
	case PkgMgrApt:
		return "apt"
	case PkgMgrYum:
		return "yum/dnf"
	case PkgMgrPacman:
		return "pacman"
	case PkgMgrBrew:
		return "brew"
	default:
		return "unknown"
	}
}

// lookPath is indirected so tests can stub PATH lookups deterministically.
var lookPath = exec.LookPath

// detectPkgMgr inspects GOOS + PATH to pick the system package manager
// (INST-05). macOS always maps to Homebrew (Intel + Apple Silicon both use
// `brew`). On Linux it probes for apt-get → dnf/yum → pacman in that order.
// Returns PkgMgrUnknown when no supported manager is found (INST-12).
func detectPkgMgr() PkgMgr { return detectPkgMgrFor(runtime.GOOS) }

// detectPkgMgrFor is the GOOS-parameterized core of detectPkgMgr, extracted so
// the Linux package-manager branches are unit-testable on any host.
func detectPkgMgrFor(goos string) PkgMgr {
	if goos == "darwin" {
		return PkgMgrBrew
	}
	if goos != "linux" {
		return PkgMgrUnknown
	}
	switch {
	case onPath("apt-get"):
		return PkgMgrApt
	case onPath("dnf"), onPath("yum"):
		return PkgMgrYum
	case onPath("pacman"):
		return PkgMgrPacman
	default:
		return PkgMgrUnknown
	}
}

func onPath(bin string) bool {
	_, err := lookPath(bin)
	return err == nil
}

// InstallSystemPkg installs a single OS package via the detected manager
// (INST-08). apt runs non-interactively (DEBIAN_FRONTEND=noninteractive); every
// invocation captures combined output so failures surface the manager's stderr.
func InstallSystemPkg(ctx context.Context, pkgMgr PkgMgr, pkgName string) error {
	var name string
	var args []string
	var env []string
	switch pkgMgr {
	case PkgMgrApt:
		name, args = "apt-get", []string{"install", "-y", pkgName}
		env = []string{"DEBIAN_FRONTEND=noninteractive"}
	case PkgMgrYum:
		mgr := "dnf"
		if !onPath("dnf") {
			mgr = "yum"
		}
		name, args = mgr, []string{"install", "-y", pkgName}
	case PkgMgrPacman:
		name, args = "pacman", []string{"-S", "--noconfirm", pkgName}
	case PkgMgrBrew:
		name, args = "brew", []string{"install", pkgName}
	default:
		return unsupportedPlatformErr()
	}
	return runCmd(ctx, name, args, env)
}
