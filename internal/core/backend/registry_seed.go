// Source:
//   - .planning/phases/03-foundation-kernel/03-07-PLAN.md Task 2.
//   - .planning/phases/03-foundation-kernel/03-CONTEXT.md "Tools.lock
//     seeding in Phase 3" (Claude default (b): 5-10 tools for Phase 4).
//   - REQUIREMENTS.md FOUND-08 + Blocker 5 (Critical-tier).
//
// registry_seed.go embeds tools.lock at build time via //go:embed and
// auto-registers each entry with backend.Default in init().
//
// BLOCKER 7 NOTE: this is the only place in the kernel that mutates
// backend.Default at init() — Plan 04 unit tests use NewToolRegistry()
// per the audit gate, so Plan 04 tests are unaffected by what's
// registered here. Plan 07's registry_seed_test.go is the ONE test file
// allowed to reference backend.Default (Blocker 7 allowlist).
//
// Phase 11 (Installer) ships the full 70+ tool inventory plus SHA-256
// verification per INST-02..04. Until then, tools.lock contains only the
// 10 tools needed by Phase 4 plan-01.

package backend

import (
	_ "embed"
	"log/slog"
	"time"

	tomlv2 "github.com/pelletier/go-toml/v2"
)

//go:embed tools.lock
var toolsLockData []byte

// toolsLockSchema mirrors the TOML structure of tools.lock. Per-tool
// table inside the top-level `tools` array.
type toolsLockSchema struct {
	SchemaVersion string `toml:"schema_version"`
	GeneratedBy   string `toml:"generated_by"`
	GeneratedAt   string `toml:"generated_at"`
	Tools         []struct {
		Name           string   `toml:"name"`
		Kind           string   `toml:"kind"`
		GoModule       string   `toml:"go_module"`
		Description    string   `toml:"description"`
		DefaultArgs    []string `toml:"default_args"`
		TimeoutSeconds int      `toml:"timeout_seconds"`
		Critical       bool     `toml:"critical"`
		// Phase 11 install-metadata extensions (INST-02/03/04/06/07/08/09).
		PipPackage   string `toml:"pip_package"`
		RepoURL      string `toml:"repo_url"`
		CargoPackage string `toml:"cargo_package"`
		Version      string `toml:"version"`
		Sha256       string `toml:"sha256"`
		InputFlag    string `toml:"input_flag"`
		// 18-02 repo-clone coordinates (RS-B). All three are optional and
		// relative to the configured tools root. THREE PLACES MUST CHANGE
		// TOGETHER and a miss in any one of them is silent: this struct, the
		// copy block in init() below, and the Clone* fields on backend.Tool.
		// TestSeedCarriesCloneCoordinates is the guard against forgetting the
		// middle one, which would otherwise yield a tool with empty
		// coordinates that then reports "absent" while sitting on disk.
		CloneDir         string `toml:"clone_dir"`
		CloneEntry       string `toml:"clone_entry"`
		CloneInterpreter string `toml:"clone_interpreter"`
		CloneWorkDir     bool   `toml:"clone_workdir"`
	} `toml:"tools"`
}

// init parses the embedded tools.lock and registers each entry with
// Default. Errors are logged (slog.Default may be the bootstrap logger
// at this point — Phase 3 main.go installs it before any Backend call).
//
// If the TOML fails to parse, Default remains empty — Phase 4 plan-01
// would notice on the first `reconftw health-check` call. Logging the
// error gives operators a breadcrumb to the failure.
func init() {
	var lock toolsLockSchema
	if err := tomlv2.Unmarshal(toolsLockData, &lock); err != nil {
		slog.Error("tools_lock_parse_failed", "err", err)
		return
	}
	for _, t := range lock.Tools {
		tool := &Tool{
			Name:        t.Name,
			DefaultArgs: append([]string(nil), t.DefaultArgs...),
			Timeout:     time.Duration(t.TimeoutSeconds) * time.Second,
			Critical:    t.Critical, // Blocker 5 — Critical field per ADR §0 D-07 non-breaking
			// Phase 11 install metadata (INST-02..09) — lets the installer
			// resolve each tool's install coordinate off backend.Default.
			Kind:         t.Kind,
			GoModule:     t.GoModule,
			PipPackage:   t.PipPackage,
			RepoURL:      t.RepoURL,
			CargoPackage: t.CargoPackage,
			Version:      t.Version,
			Sha256:       t.Sha256,
			InputFlag:    t.InputFlag,
			// 18-02 repo-clone coordinates — see toolsLockSchema above.
			CloneDir:         t.CloneDir,
			CloneEntry:       t.CloneEntry,
			CloneInterpreter: t.CloneInterpreter,
			CloneWorkDir:     t.CloneWorkDir,
		}
		Default.Register(tool)
	}
	// Debug, not Info: this runs from package init, BEFORE main.run builds the real
	// logger, so at Info it printed a stray stdlib-formatted line above the output of
	// EVERY invocation — `reconftw --help`, `version`, shell completion, error paths.
	// Tool inventory is reported by `health-check`, which is where an operator looks.
	slog.Debug("tools_lock_loaded",
		"tool_count", len(lock.Tools),
		"schema_version", lock.SchemaVersion,
		"generated_by", lock.GeneratedBy,
	)
}
