// Internal-package tests for non-public helpers (covers coerceAndSet branches,
// toSnake fallback, DefaultConfigDir). Internal because these are
// package-private utilities — public tests live in *_test.go (package
// config_test).
package config

import (
	"os"
	"reflect"
	"testing"

	"github.com/go-playground/validator/v10"
)

func TestCoerceAndSetIntFromString(t *testing.T) {
	t.Parallel()
	var dst int
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, "42"); err != nil {
		t.Fatalf("coerce string -> int: %v", err)
	}
	if dst != 42 {
		t.Errorf("got %d; want 42", dst)
	}
}

func TestCoerceAndSetIntFromInt64(t *testing.T) {
	t.Parallel()
	var dst int
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, int64(99)); err != nil {
		t.Fatalf("coerce int64 -> int: %v", err)
	}
	if dst != 99 {
		t.Errorf("got %d; want 99", dst)
	}
}

func TestCoerceAndSetIntFromFloat(t *testing.T) {
	t.Parallel()
	var dst int64
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, 7.0); err != nil {
		t.Fatalf("coerce float64 -> int64: %v", err)
	}
	if dst != 7 {
		t.Errorf("got %d; want 7", dst)
	}
}

func TestCoerceAndSetIntFromBadString(t *testing.T) {
	t.Parallel()
	var dst int
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, "not-an-int"); err == nil {
		t.Fatal("expected error coercing non-numeric string to int")
	}
}

func TestCoerceAndSetBoolFromString(t *testing.T) {
	t.Parallel()
	var dst bool
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, "true"); err != nil {
		t.Fatalf("coerce string -> bool: %v", err)
	}
	if !dst {
		t.Error("expected true")
	}
}

func TestCoerceAndSetBoolFromBadValue(t *testing.T) {
	t.Parallel()
	var dst bool
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, 42); err == nil {
		t.Fatal("expected error coercing int to bool")
	}
	if err := coerceAndSet(rv, "not-a-bool"); err == nil {
		t.Fatal("expected error coercing non-bool string to bool")
	}
}

func TestCoerceAndSetStringFromInt(t *testing.T) {
	t.Parallel()
	var dst string
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, 42); err != nil {
		t.Fatalf("coerce int -> string: %v", err)
	}
	if dst != "42" {
		t.Errorf("got %q; want %q", dst, "42")
	}
}

func TestCoerceAndSetFloatFromInt(t *testing.T) {
	t.Parallel()
	var dst float64
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, 5); err != nil {
		t.Fatalf("coerce int -> float64: %v", err)
	}
	if dst != 5.0 {
		t.Errorf("got %v; want 5.0", dst)
	}
}

func TestCoerceAndSetFloatFromString(t *testing.T) {
	t.Parallel()
	var dst float64
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, "0.5"); err != nil {
		t.Fatalf("coerce string -> float64: %v", err)
	}
	if dst != 0.5 {
		t.Errorf("got %v; want 0.5", dst)
	}
}

func TestCoerceAndSetFloatFromBadString(t *testing.T) {
	t.Parallel()
	var dst float64
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, "nope"); err == nil {
		t.Fatal("expected error coercing non-numeric string to float")
	}
}

func TestCoerceAndSetFloatFromBadType(t *testing.T) {
	t.Parallel()
	var dst float64
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, true); err == nil {
		t.Fatal("expected error coercing bool to float")
	}
}

func TestCoerceAndSetUnsupported(t *testing.T) {
	t.Parallel()
	var dst []byte
	rv := reflect.ValueOf(&dst).Elem()
	if err := coerceAndSet(rv, 42); err == nil {
		t.Fatal("expected error for unsupported destination kind")
	}
}

func TestCoerceAndSetUnsettable(t *testing.T) {
	t.Parallel()
	// reflect.Value of a struct field accessed by index returns a settable
	// value only when the parent is addressable. A bare reflect.ValueOf(int)
	// is NOT addressable, so CanSet returns false.
	dst := 5
	rv := reflect.ValueOf(dst) // not addressable
	if err := coerceAndSet(rv, 99); err == nil {
		t.Fatal("expected error for unsettable destination")
	}
}

// toSnake is package-private; cover all branches.
func TestToSnake(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"MaxJobs", "max_jobs"},
		{"FleetCount", "fleet_count"},
		{"", ""},
		{"x", "x"},
		{"AlreadyLower", "already_lower"},
	}
	for _, c := range cases {
		got := toSnake(c.in)
		if got != c.want {
			t.Errorf("toSnake(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// DefaultConfigDir — XDG path branch.
func TestDefaultConfigDirXDG(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/custom/xdg")
	got := DefaultConfigDir()
	want := "/custom/xdg/reconftw/config.toml"
	if got != want {
		t.Errorf("DefaultConfigDir() = %q; want %q", got, want)
	}
}

// DefaultConfigDir — HOME path branch when XDG is unset.
func TestDefaultConfigDirHome(t *testing.T) {
	// Save + restore.
	prev := os.Getenv("XDG_CONFIG_HOME")
	if err := os.Unsetenv("XDG_CONFIG_HOME"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	defer func() { _ = os.Setenv("XDG_CONFIG_HOME", prev) }()
	got := DefaultConfigDir()
	if got == "" {
		t.Skip("HOME-based fallback returned empty; environment isolated")
	}
	// Must contain ".config/reconftw/config.toml".
	if !contains(got, ".config/reconftw/config.toml") {
		t.Errorf("DefaultConfigDir() = %q; expected to contain .config/reconftw/config.toml", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ReadBytes on the structs provider — koanf's Load() prefers Read() but the
// Provider contract requires ReadBytes to exist. Document the no-op behavior.
func TestStructsProviderReadBytes(t *testing.T) {
	t.Parallel()
	p := structsProvider(Defaults())
	b, err := p.ReadBytes()
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}
	if b != nil {
		t.Errorf("ReadBytes should be nil for non-parser provider; got %d bytes", len(b))
	}
}

// mustRegister — happy path is covered by init(); cover the panic path by
// invoking RegisterValidation directly on an invalid tag name (only empty
// tag name causes the underlying call to error in validator/v10).
func TestMustRegisterPanicOnError(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r == nil {
			t.Error("mustRegister did not panic on bad tag")
		}
	}()
	// Empty tag is rejected by go-playground/validator.
	mustRegister("", func(_ validator.FieldLevel) bool { return true })
}
