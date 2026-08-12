// loglevel_test.go — regression guards for the --log-level / --quiet / --verbose
// flags being pure decoration.
//
// The live symptom: `reconftw all --target X --axiom --log-level debug` emitted ZERO
// DEBUG lines, so an axiom fleet outage could only be diagnosed by reading artefacts.
// main.run builds the logger at STEP 6 from cfg.Output.LogLevel, BEFORE cobra parses
// argv at STEP 10 — and nothing ever read the parsed flag back.
package main

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/six2dez/reconftw/internal/core/config"
)

// withCleanLogState isolates a subtest from the package-level CLI logger globals
// and from slog's process-wide default.
func withCleanLogState(t *testing.T) {
	t.Helper()
	prevLevel, prevLogger, prevDefault := cliLogLevel, cliLogger, slog.Default()
	cliLogLevel, cliLogger = "", nil
	t.Cleanup(func() {
		cliLogLevel, cliLogger = prevLevel, prevLogger
		slog.SetDefault(prevDefault)
	})
}

// runRootWithFlags executes a harmless subcommand so the root's PersistentPreRunE
// (the hook that consumes the log flags) runs exactly as it does in production.
func runRootWithFlags(t *testing.T, cfg *config.Config, args ...string) {
	t.Helper()
	root := newRootCmd(nil, cfg)
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs(append([]string{"version"}, args...))
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute %v: %v", args, err)
	}
}

func TestLogLevelFlagReachesConfigAndLogger(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		want  string
		level slog.Level
	}{
		{"log-level debug", []string{"--log-level", "debug"}, "debug", slog.LevelDebug},
		{"log-level warn", []string{"--log-level", "warn"}, "warn", slog.LevelWarn},
		{"quiet alias", []string{"--quiet"}, "error", slog.LevelError},
		{"verbose alias", []string{"--verbose"}, "debug", slog.LevelDebug},
		// --verbose is the debugging escape hatch: it wins over --quiet.
		{"verbose beats quiet", []string{"--quiet", "--verbose"}, "debug", slog.LevelDebug},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withCleanLogState(t)
			cfg := config.Defaults()
			runRootWithFlags(t, cfg, tc.args...)

			if cfg.Output.LogLevel != tc.want {
				t.Errorf("cfg.Output.LogLevel = %q, want %q\n"+
					"(the flag was declared but never read — `--log-level debug` was a no-op)",
					cfg.Output.LogLevel, tc.want)
			}
			// RunOptions.LogLevel is what carries the override into the composite
			// path, which re-loads config from scratch inside BootReconApp.
			if cliLogLevel != tc.want {
				t.Errorf("cliLogLevel = %q, want %q — composite modes re-load config and "+
					"would silently drop the override", cliLogLevel, tc.want)
			}
			if cliLogger == nil {
				t.Fatal("cliLogger is nil — AppContext + AxiomBackend would keep using slog.Default()")
			}
			if !cliLogger.Enabled(context.Background(), tc.level) {
				t.Errorf("rebuilt logger does not emit at %v", tc.level)
			}
			if !slog.Default().Enabled(context.Background(), tc.level) {
				t.Errorf("slog.Default() does not emit at %v", tc.level)
			}
		})
	}
}

// Without any of the three flags the config-file / env level must survive: the
// flag's own "info" default must not silently downgrade a debug config.
func TestLogLevelUnsetLeavesConfigUntouched(t *testing.T) {
	withCleanLogState(t)
	cfg := config.Defaults()
	cfg.Output.LogLevel = "debug"

	runRootWithFlags(t, cfg)

	if cfg.Output.LogLevel != "debug" {
		t.Errorf("cfg.Output.LogLevel = %q, want the configured \"debug\" preserved", cfg.Output.LogLevel)
	}
	if cliLogLevel != "" {
		t.Errorf("cliLogLevel = %q, want \"\" when no flag was supplied", cliLogLevel)
	}
}

// An unrecognised value is config-validation's business, not this hook's: it must
// not corrupt the config or tear down the working logger.
func TestLogLevelIgnoresUnknownValue(t *testing.T) {
	withCleanLogState(t)
	cfg := config.Defaults()
	cfg.Output.LogLevel = "info"

	runRootWithFlags(t, cfg, "--log-level", "chatty")

	if cfg.Output.LogLevel != "info" {
		t.Errorf("cfg.Output.LogLevel = %q, want \"info\" (unknown value ignored)", cfg.Output.LogLevel)
	}
	if cliLogLevel != "" {
		t.Errorf("cliLogLevel = %q, want \"\" for an unrecognised level", cliLogLevel)
	}
}
