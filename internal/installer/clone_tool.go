package installer

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/backend"
)

// CloneToolInstaller installs tools that are not available via a package index:
// kind=go_clone (git clone + go build), kind=python_venv (git clone + uv venv),
// and kind=rust (cargo install). Covers INST-06/07/09.
type CloneToolInstaller struct{}

// NewCloneToolInstaller constructs a CloneToolInstaller.
func NewCloneToolInstaller() *CloneToolInstaller { return &CloneToolInstaller{} }

// Install dispatches by tool.Kind to the appropriate clone/build flow.
func (c *CloneToolInstaller) Install(ctx context.Context, tool *backend.Tool) error {
	switch tool.Kind {
	case "go_clone":
		return c.installGoClone(ctx, tool)
	case "python_venv":
		return c.installPythonVenv(ctx, tool)
	case "rust":
		return c.installRust(ctx, tool)
	default:
		return fmt.Errorf("clone installer: unsupported kind %q for tool %q", tool.Kind, tool.Name)
	}
}

func (c *CloneToolInstaller) installGoClone(ctx context.Context, tool *backend.Tool) error {
	if onPath(tool.Name) && tool.Version == "latest" {
		return nil // present; latest has no pin to diff (INST-11)
	}
	if tool.RepoURL == "" {
		return fmt.Errorf("go_clone tool %q: empty repo_url", tool.Name)
	}
	dir, err := os.MkdirTemp("", "reconftw-clone-"+tool.Name+"-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := runCmd(ctx, "git", []string{"clone", "--depth", "1", tool.RepoURL, dir}, nil); err != nil {
		return fmt.Errorf("clone %s: %w", tool.Name, err)
	}
	out := filepath.Join(goBinDir(), tool.Name)
	if err := runCmdDir(ctx, dir, "go", []string{"build", "-o", out, "."}, []string{"CGO_ENABLED=0"}); err != nil {
		return fmt.Errorf("build %s: %w", tool.Name, err)
	}
	// Optional integrity check on the produced binary (INST-04). "PENDING"
	// means "hash not yet recorded" — log via the caller, don't hard-fail.
	if tool.Sha256 != "" && tool.Sha256 != "PENDING" {
		if err := verifyFile(ctx, out, tool.Sha256, tool.RepoURL); err != nil {
			return err
		}
	}
	return nil
}

func (c *CloneToolInstaller) installPythonVenv(ctx context.Context, tool *backend.Tool) error {
	if tool.RepoURL == "" {
		return fmt.Errorf("python_venv tool %q: empty repo_url", tool.Name)
	}
	dir := filepath.Join(toolsRepoDir(), tool.Name)
	if _, err := os.Stat(filepath.Join(dir, "venv")); err == nil {
		return nil // venv already provisioned (idempotent)
	}
	if err := runCmd(ctx, "git", []string{"clone", "--depth", "1", tool.RepoURL, dir}, nil); err != nil {
		return fmt.Errorf("clone %s: %w", tool.Name, err)
	}
	if err := runCmdDir(ctx, dir, "uv", []string{"venv", "venv"}, nil); err != nil {
		return fmt.Errorf("venv %s: %w", tool.Name, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		if err := runCmdDir(ctx, dir, "uv", []string{"pip", "install", "-r", "requirements.txt"}, nil); err != nil {
			return fmt.Errorf("pip install %s: %w", tool.Name, err)
		}
	}
	return nil
}

func (c *CloneToolInstaller) installRust(ctx context.Context, tool *backend.Tool) error {
	if onPath(tool.Name) && tool.Version == "latest" {
		return nil
	}
	crate := tool.CargoPackage
	if crate == "" {
		crate = tool.Name
	}
	if err := runCmd(ctx, "cargo", []string{"install", crate}, nil); err != nil {
		return fmt.Errorf("cargo install %s: %w", crate, err)
	}
	return nil
}

// goBinDir resolves the directory `go install` writes binaries to
// ($GOBIN, else $GOPATH/bin, else ~/go/bin).
func goBinDir() string {
	if b := os.Getenv("GOBIN"); b != "" {
		return b
	}
	gp := os.Getenv("GOPATH")
	if gp == "" {
		home, _ := os.UserHomeDir()
		gp = filepath.Join(home, "go")
	}
	return filepath.Join(strings.Split(gp, string(os.PathListSeparator))[0], "bin")
}

// toolsRepoDir is where repo-clone (python_venv) tools live.
func toolsRepoDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Tools")
}
