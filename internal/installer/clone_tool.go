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
// kind=make_clone (git clone + make) and kind=rust (cargo install).
// Covers INST-06/07/09.
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
	case "make_clone":
		return c.installMakeClone(ctx, tool)
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
	// Clone into the directory RESOLUTION will look in, not the tool's name.
	// The two differ whenever upstream capitalises differently from the name the
	// modules invoke (cmseek vs CMSeeK), and the registry resolves a clone tool
	// through CloneDir. Cloning to tool.Name there produces the worst outcome
	// available: the install succeeds, and the tool is still unresolvable.
	dir := filepath.Join(toolsRepoDir(), cloneTargetName(tool))
	if _, err := os.Stat(filepath.Join(dir, "venv")); err == nil {
		return nil // venv already provisioned (idempotent)
	}
	// A clone WITHOUT a venv is the wreckage of an earlier run that got past git
	// and died at `uv venv` — which is exactly what an absent uv used to cause,
	// for every python_venv tool at once. Re-cloning over it fails with "destination
	// path already exists", so the tool could never recover: the run that broke it
	// also made it permanently unfixable by re-running, while the installer
	// advertises itself as idempotent. Resume from the existing clone instead.
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		if pullErr := runCmdDir(ctx, dir, "git", []string{"pull", "--ff-only"}, nil); pullErr != nil {
			// A stale checkout is still buildable; only the refresh failed.
			_ = pullErr
		}
	} else if err := runCmd(ctx, "git", []string{"clone", "--depth", "1", tool.RepoURL, dir}, nil); err != nil {
		return fmt.Errorf("clone %s: %w", tool.Name, err)
	}
	if err := runCmdDir(ctx, dir, "uv", []string{"venv", "venv"}, nil); err != nil {
		return fmt.Errorf("venv %s: %w", tool.Name, err)
	}
	// requirements.txt is only ONE of the two shapes upstream uses. gato ships
	// pyproject.toml + setup.py and no requirements.txt, so this branch installed
	// nothing: the venv came out holding only its activate scripts, the declared
	// clone_entry `venv/bin/gato` was never created, and the tool resolved as
	// "INSTALLED BUT UNRESOLVABLE" — an install that reported success and left
	// the tool unusable. Installing the PACKAGE covers the packaged shape and, as
	// a side effect, its dependencies too.
	// --python venv/bin/python3 IS LOAD-BEARING, and its absence was invisible.
	// `uv pip install` with no target resolves an environment of its own choosing
	// — not the venv two lines above — so it printed "Installed 1 package" and
	// exited 0 while the venv stayed empty. Nothing failed, nothing was logged,
	// and the tool was simply unusable: verified on 2026-09-03, where
	// /root/Tools/gato/venv/bin held only activate scripts after a "successful"
	// install and gained the gato entry point the moment --python was passed.
	// v1 always passed it (install.sh: `uv pip install ... --python venv/bin/python3`).
	const venvPython = "venv/bin/python3"
	switch {
	case fileExists(filepath.Join(dir, "requirements.txt")):
		if err := runCmdDir(ctx, dir, "uv",
			[]string{"pip", "install", "-r", "requirements.txt", "--python", venvPython}, nil); err != nil {
			return fmt.Errorf("pip install %s: %w", tool.Name, err)
		}
	case fileExists(filepath.Join(dir, "pyproject.toml")), fileExists(filepath.Join(dir, "setup.py")):
		if err := runCmdDir(ctx, dir, "uv",
			[]string{"pip", "install", ".", "--python", venvPython}, nil); err != nil {
			return fmt.Errorf("pip install %s (packaged project): %w", tool.Name, err)
		}
	}
	return nil
}

// fileExists reports whether path is present. Named rather than inlined so the
// two-shape switch above reads as the decision it is.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
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

// installMakeClone builds a tool whose upstream is neither a Go module nor a
// Python package but a plain Makefile project — git clone, `make`, then place
// the produced binary on PATH under the name the registry (and exec.LookPath)
// expects.
//
// It exists because dnscewl was declared kind="go" with a go_module, and
// `go install github.com/codingo/dnscewl@latest` can never succeed: the repo is
// C++ (main.cpp + Makefile), so Go reports "module found but does not contain
// package" on every clean install. v1 never installed the tool at all, so there
// was no prior art to port — the entry was aspirational.
//
// THE NAME MISMATCH IS THE SUBTLE HALF. `make` produces `DNScewl`, while the
// registry, permut.go and exec.LookPath all say `dnscewl`. Building alone would
// therefore still leave the tool "not installed" on any case-sensitive
// filesystem, so the built artefact is resolved case-insensitively and copied to
// tool.Name — the binary is installed under the name that is looked up.
func (c *CloneToolInstaller) installMakeClone(ctx context.Context, tool *backend.Tool) error {
	if onPath(tool.Name) && tool.Version == "latest" {
		return nil // present; latest has no pin to diff (INST-11)
	}
	if tool.RepoURL == "" {
		return fmt.Errorf("make_clone tool %q: empty repo_url", tool.Name)
	}
	dir, err := os.MkdirTemp("", "reconftw-clone-"+tool.Name+"-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()

	if err := runCmd(ctx, "git", []string{"clone", "--depth", "1", tool.RepoURL, dir}, nil); err != nil {
		return fmt.Errorf("clone %s: %w", tool.Name, err)
	}
	if err := runCmdDir(ctx, dir, "make", nil, nil); err != nil {
		return fmt.Errorf("build %s (make): %w", tool.Name, err)
	}

	built, err := findBuiltBinary(dir, tool.Name)
	if err != nil {
		return fmt.Errorf("build %s: %w", tool.Name, err)
	}
	out := filepath.Join(goBinDir(), tool.Name)
	if err := copyExecutable(built, out); err != nil {
		return fmt.Errorf("install %s: %w", tool.Name, err)
	}
	if tool.Sha256 != "" && tool.Sha256 != "PENDING" {
		if err := verifyFile(ctx, out, tool.Sha256, tool.RepoURL); err != nil {
			return err
		}
	}
	return nil
}

// findBuiltBinary locates the executable `make` produced in dir. Upstream
// Makefiles rarely name the artefact exactly as the tool is invoked (DNSCewl's
// produces `DNScewl` for a tool looked up as `dnscewl`), so the match is
// case-insensitive on the file name and requires the file be executable.
func findBuiltBinary(dir, name string) (string, error) {
	// The clone root first, then bin/. Root-only was enough for dnscewl, whose
	// Makefile writes beside its sources, but it is NOT the common convention:
	// massdns's Makefile emits bin/massdns, so a root-only search reported "make
	// produced no executable" for a build that had in fact succeeded.
	for _, sub := range []string{"", "bin"} {
		search := dir
		if sub != "" {
			search = filepath.Join(dir, sub)
		}
		entries, err := os.ReadDir(search)
		if err != nil {
			continue // no such subdirectory — try the next candidate
		}
		for _, e := range entries {
			if e.IsDir() || !strings.EqualFold(e.Name(), name) {
				continue
			}
			info, statErr := e.Info()
			if statErr != nil {
				continue
			}
			if info.Mode()&0o111 == 0 {
				continue // matched by name but not executable — not the artefact
			}
			return filepath.Join(search, e.Name()), nil
		}
	}
	return "", fmt.Errorf("make produced no executable named %q (case-insensitive) "+
		"in the clone root or its bin/ subdirectory", name)
}

// copyExecutable copies src to dst with the executable bit set, replacing any
// previous build.
func copyExecutable(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
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

// cloneTargetName is the directory a clone tool is installed into, relative to
// the tools root. It is CloneDir when set and the tool name otherwise, because
// the two differ whenever upstream capitalises differently from the name the
// modules invoke — cmseek's clone_dir is "CMSeeK" — and the registry resolves a
// clone tool through CloneDir. Installing to tool.Name in that case produces the
// worst outcome available: the install succeeds and the tool is still
// unresolvable, which is the class of defect the tools.lock corrections of
// 2026-09-02 were fixing in the first place.
func cloneTargetName(tool *backend.Tool) string {
	if tool.CloneDir != "" {
		return tool.CloneDir
	}
	return tool.Name
}

// toolsRepoDir is where repo-clone (python_venv) tools live.
func toolsRepoDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Tools")
}
