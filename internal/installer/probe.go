package installer

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// runOutput is indirected so tests can stub subprocess output deterministically.
var runOutput = func(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	return string(out), err
}

// probeGoToolVersion returns the module version embedded in an installed Go
// binary by parsing `go version -m <bin>` (D-04). Returns ("", error) when the
// binary is not on PATH or carries no `mod` line. The version is the embedded
// module@version (e.g. "v2.14.0"), or "(devel)" for a locally-built binary.
func probeGoToolVersion(ctx context.Context, toolName string) (string, error) {
	bin, err := lookPath(toolName)
	if err != nil {
		return "", fmt.Errorf("probe %s: not on PATH: %w", toolName, err)
	}
	out, err := runOutput(ctx, "go", "version", "-m", bin)
	if err != nil {
		return "", fmt.Errorf("probe %s: go version -m: %w", toolName, err)
	}
	return parseGoVersionM(out)
}

// parseGoVersionM extracts the version field from the `mod` line of
// `go version -m` output. The mod line is tab/space separated:
//
//	mod  <module-path>  <version>  <hash>
func parseGoVersionM(output string) (string, error) {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "mod" {
			return fields[2], nil
		}
	}
	return "", fmt.Errorf("no mod line in `go version -m` output")
}

// probeUVToolVersions returns a map of uv-installed tool name → installed
// version by parsing `uv tool list` (D-04). Versions have the leading "v"
// stripped so they compare against tools.lock pins.
func probeUVToolVersions(ctx context.Context) (map[string]string, error) {
	out, err := runOutput(ctx, "uv", "tool", "list")
	if err != nil {
		return nil, fmt.Errorf("probe uv tool list: %w", err)
	}
	return parseUVToolList(out), nil
}

// parseUVToolList parses `uv tool list` output. Tool header lines look like
// "<name> v<version>"; executable sub-lines start with "-" and are ignored.
func parseUVToolList(output string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" || strings.HasPrefix(strings.TrimSpace(line), "-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			res[fields[0]] = strings.TrimPrefix(fields[1], "v")
		}
	}
	return res
}

// probePkgMgrVersion returns the installed version of a system package, or an
// error if the package is absent (D-04 for kind=system tools).
func probePkgMgrVersion(ctx context.Context, pkgMgr PkgMgr, name string) (string, error) {
	var cmd string
	var args []string
	switch pkgMgr {
	case PkgMgrApt:
		cmd, args = "dpkg-query", []string{"-W", "-f=${Version}", name}
	case PkgMgrYum:
		cmd, args = "rpm", []string{"-q", "--qf", "%{VERSION}", name}
	case PkgMgrPacman:
		cmd, args = "pacman", []string{"-Q", name}
	case PkgMgrBrew:
		cmd, args = "brew", []string{"list", "--versions", name}
	default:
		return "", unsupportedPlatformErr()
	}
	out, err := runOutput(ctx, cmd, args...)
	if err != nil {
		return "", fmt.Errorf("probe %s: %w", name, err)
	}
	return strings.TrimSpace(out), nil
}
