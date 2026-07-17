// Tests for the real `reconftw migrate` subcommand (Phase 14 plan 14-01).
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func runMigrate(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newMigrateCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), errb.String(), err
}

// TestMigrateCmdDryRunWritesNothing — --dry-run prints the disposition table and
// creates NO output file (CUT-05).
func TestMigrateCmdDryRunWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "reconftw.cfg")
	if err := os.WriteFile(cfg, []byte("OSINT=true\nWAYMORE_TIMEOUT=30m\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out.toml")

	out, _, err := runMigrate(t, "--dry-run", "--from-bash", cfg, "--to", target)
	if err != nil {
		t.Fatalf("migrate --dry-run returned error: %v", err)
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Errorf("--dry-run must not create the target file %s", target)
	}
	if !strings.Contains(out, "V1 KEY") || !strings.Contains(out, "Summary:") {
		t.Errorf("dry-run should print the disposition table; got:\n%s", out)
	}
}

// TestMigrateCmdWritesFile — a normal run writes the v2 TOML atomically.
func TestMigrateCmdWritesFile(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "reconftw.cfg")
	if err := os.WriteFile(cfg, []byte("OSINT=true\nNUCLEI_SEVERITY=\"info,low\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "out.toml")

	if _, _, err := runMigrate(t, "--from-bash", cfg, "--to", target); err != nil {
		t.Fatalf("migrate write returned error: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read migrated file: %v", err)
	}
	if !strings.Contains(string(data), "enabled = true  # was OSINT") {
		t.Errorf("migrated file missing expected osint key; got:\n%s", string(data))
	}
	if strings.Contains(string(data), "[legacy]") {
		t.Errorf("migrated file must NOT contain a [legacy] block")
	}
}

// TestMigrateCmdMissingInput — a missing input file is a hard failure (exit 1).
func TestMigrateCmdMissingInput(t *testing.T) {
	_, _, err := runMigrate(t, "--from-bash", filepath.Join(t.TempDir(), "nope.cfg"), "--dry-run")
	if err == nil {
		t.Fatal("expected an error for a missing input file")
	}
	var ec *exitCodeError
	if !asExitCode(err, &ec) || ec.code != 1 {
		t.Errorf("expected *exitCodeError{code:1}, got %T: %v", err, err)
	}
}

// TestMigrateCmdSecretRedaction — secrets are redacted in --dry-run output but
// written verbatim to the target file (threat T-14-02).
func TestMigrateCmdSecretRedaction(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "reconftw.cfg")
	token := "deadbeefdeadbeefdeadbeef"
	if err := os.WriteFile(cfg, []byte("SHODAN_API_KEY="+token+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// --dry-run: neither stdout nor stderr may contain the raw token.
	out, errb, err := runMigrate(t, "--dry-run", "--from-bash", cfg, "--to", filepath.Join(dir, "dry.toml"))
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	combined := out + errb
	if strings.Contains(combined, token) {
		t.Errorf("dry-run output leaked the raw secret token; got:\n%s", combined)
	}
	if !strings.Contains(combined, "***") {
		t.Errorf("dry-run output should redact the secret to ***; got:\n%s", combined)
	}

	// Normal run: the written file MUST contain the real token.
	realToml := filepath.Join(dir, "real.toml")
	if _, _, err := runMigrate(t, "--from-bash", cfg, "--to", realToml); err != nil {
		t.Fatalf("migrate write: %v", err)
	}
	data, err := os.ReadFile(realToml)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(data), token) {
		t.Errorf("migrated file MUST contain the real secret value; got:\n%s", string(data))
	}
}

// asExitCode is a tiny errors.As wrapper kept local to avoid an extra import in
// the table above.
func asExitCode(err error, target **exitCodeError) bool {
	for err != nil {
		if ec, ok := err.(*exitCodeError); ok {
			*target = ec
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}
