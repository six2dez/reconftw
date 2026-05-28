// Source: ADR 0002 §10.3 lines 2528-2563 — the init-order requirement names
// the call shape log.New(cfg, redactor) returning *slog.Logger. Plan 03-01
// ships this with a local *Config placeholder; Plan 03-02 swaps the pointer
// type to *config.Config when the koanf loader lands (no signature change
// beyond the pointer type — the call site `slog.New(...)` stays).
//
// The handler chain assembled here is:
//
//	slog.JSONHandler|TextHandler  (inner; honors cfg.Level)
//	    ↓ wrapped by
//	RedactingHandler              (Layer 2 secret-substring scrubbing)
//	    ↓ returned by slog.New(_)
//	*slog.Logger                  (process-wide default after slog.SetDefault)
//
// All log records that flow through this Logger pass through the Redactor
// before hitting the inner handler — this is the foundation of XCUT-07.

package log

import (
	"io"
	"log/slog"
	"os"
)

// Config is the minimal logging configuration needed to build the logger
// chain. Plan 03-01 ships this local placeholder; Plan 03-02 will replace
// the *Config pointer type with the real *config.Config once the koanf
// loader is live (no caller change beyond the pointer type — `log.New`
// signature still takes a pointer to a struct with Level/Format/Output).
type Config struct {
	// Level is the inner handler's minimum slog.Level. Default: slog.LevelInfo.
	Level slog.Level
	// Format is "json" (default) or "text". Empty string defaults to "json".
	Format string
	// Output is where log records get written. Default: os.Stderr.
	Output io.Writer
}

// New is the logger factory called from cmd/reconftw/main.go per ADR §10.3
// init order. It returns a *slog.Logger whose handler chain is
// [JSON|Text]Handler → RedactingHandler so every emitted record passes
// through the Redactor before hitting the inner handler.
//
// Phase 2 of Plan 03-02 will replace *Config with *config.Config from the
// koanf loader (no signature change beyond the pointer type).
func New(cfg *Config, redactor *Redactor) *slog.Logger {
	out := cfg.Output
	if out == nil {
		out = os.Stderr
	}
	opts := &slog.HandlerOptions{Level: cfg.Level}

	var inner slog.Handler
	switch cfg.Format {
	case "text":
		inner = slog.NewTextHandler(out, opts)
	case "json", "":
		inner = slog.NewJSONHandler(out, opts)
	default:
		// Unknown format → fall back to JSON (defensive; avoids panic at boot).
		inner = slog.NewJSONHandler(out, opts)
	}

	return slog.New(NewRedactingHandler(inner, redactor))
}
