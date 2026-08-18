// Tests for the monitor subcommand's flag resolution (F13).
//
// The CLI used to hardcode `--interval "6h"` as the flag default, which meant
// monitor.interval_minutes could never win: an operator who set it in the config
// file saw it silently ignored. The chain is now explicit flag →
// cfg.Monitor.IntervalMinutes → the package default, floored at one minute, and
// this file asserts each link.
package main

import (
	"testing"
	"time"

	"github.com/six2dez/reconftw/internal/mcp/handlers"
)

func TestParseMonitorIntervalFlag(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in      string
		want    time.Duration
		wantErr bool
	}{
		{"", 0, false},    // unset — defer to config
		{"   ", 0, false}, // whitespace is unset too
		{"30m", 30 * time.Minute, false},
		{"1h30m", 90 * time.Minute, false},
		{"banana", 0, true},
	}
	for _, c := range cases {
		got, err := parseMonitorIntervalFlag(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseMonitorIntervalFlag(%q) returned nil error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseMonitorIntervalFlag(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseMonitorIntervalFlag(%q) = %s, want %s", c.in, got, c.want)
		}
	}
}

// TestMonitorIntervalResolutionChain composes the two halves the CLI actually
// uses: the flag parser, then handlers.ResolveMonitorInterval against the
// configured monitor.interval_minutes.
func TestMonitorIntervalResolutionChain(t *testing.T) {
	t.Parallel()

	const cfgMinutes = 45

	// Flag not given → the config value is used.
	flagVal, err := parseMonitorIntervalFlag("")
	if err != nil {
		t.Fatalf("parse empty flag: %v", err)
	}
	if got := handlers.ResolveMonitorInterval(flagVal, cfgMinutes); got != cfgMinutes*time.Minute {
		t.Fatalf("with no --interval, resolved %s, want %s (monitor.interval_minutes)",
			got, cfgMinutes*time.Minute)
	}

	// Flag given → it wins over the config value.
	flagVal, err = parseMonitorIntervalFlag("2h")
	if err != nil {
		t.Fatalf("parse explicit flag: %v", err)
	}
	if got := handlers.ResolveMonitorInterval(flagVal, cfgMinutes); got != 2*time.Hour {
		t.Fatalf("with --interval 2h, resolved %s, want 2h", got)
	}

	// Neither → the package default, never zero.
	if got := handlers.ResolveMonitorInterval(0, 0); got <= 0 {
		t.Fatalf("with neither source, resolved %s — a non-positive interval is a "+
			"continuous scan loop", got)
	}

	// A misconfigured sub-minute value from either source is floored.
	if got := handlers.ResolveMonitorInterval(time.Second, 0); got < time.Minute {
		t.Fatalf("an explicit 1s interval resolved to %s, below the safety floor", got)
	}
}

// TestMonitorFlagDefaultsAreUnset guards the specific regression: a non-empty
// --interval default makes the config setting unreachable.
func TestMonitorFlagDefaultsAreUnset(t *testing.T) {
	t.Parallel()

	cmd := newMonitorCmd()
	f := cmd.Flags().Lookup("interval")
	if f == nil {
		t.Fatal("monitor command has no --interval flag")
	}
	if f.DefValue != "" {
		t.Fatalf("--interval default is %q, want \"\" — a literal default outranks "+
			"monitor.interval_minutes and makes it unreachable", f.DefValue)
	}
	c := cmd.Flags().Lookup("monitor-cycles")
	if c == nil {
		t.Fatal("monitor command has no --monitor-cycles flag")
	}
	if c.DefValue != "0" {
		t.Fatalf("--monitor-cycles default is %q, want \"0\" (unset → monitor.max_cycles)", c.DefValue)
	}
}
