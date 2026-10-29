// scope_lists_test.go — the v1 -i / -x include/exclude lists on the scope
// filter (subdomains.scope.include_file / exclude_file).
package output_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/six2dez/reconftw/v5/internal/core/output"
)

func TestScopeExcludeListDropsAtTheFilter(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{
		Patterns: []string{"*.example.com", "10.0.0.0/8"},
		Exclude:  []string{"legacy.example.com", "*.staging.example.com", "10.1.0.0/16", "10.2.3.4"},
	}
	cases := []struct {
		value string
		want  bool
	}{
		{"api.example.com", true},
		{"legacy.example.com", false},           // exact exclude
		{"www.legacy.example.com", true},        // exact exclude is not a wildcard
		{"staging.example.com", false},          // wildcard exclude matches apex
		{"db.staging.example.com", false},       // wildcard exclude matches subdomain
		{"notstaging.example.com", true},        // anchored: no substring match
		{"10.0.5.5", true},                      // in patterns, not excluded
		{"10.1.200.1", false},                   // CIDR exclude
		{"10.2.3.4", false},                     // IP literal exclude
		{"10.2.3.5", true},                      // IP literal exclude is exact
		{"http://legacy.example.com/x", false},  // via IsInScopeURL
		{"https://api.example.com/login", true}, // via IsInScopeURL
		{"evil.com", false},                     // never in patterns
		{"legacy.example.com.evil.com", false},  // not in patterns at all
		{"LEGACY.EXAMPLE.COM", false},           // case-insensitive
	}
	for _, c := range cases {
		var got bool
		if strings.Contains(c.value, "://") {
			got = f.IsInScopeURL(c.value)
		} else {
			got = f.IsInScope(c.value)
		}
		if got != c.want {
			t.Errorf("IsInScope(%q) = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestScopeIncludeListNarrowsButNeverWidens(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{
		Patterns: []string{"*.example.com"},
		Include:  []string{"api.example.com", "*.shop.example.com", "*.other.org"},
	}
	cases := []struct {
		value string
		want  bool
	}{
		{"api.example.com", true},
		{"www.example.com", false},   // in patterns, not in include → dropped
		{"example.com", false},       // apex in patterns, not in include
		{"a.shop.example.com", true}, // wildcard include
		{"shop.example.com", true},   // wildcard include matches its apex
		{"x.other.org", false},       // include entry outside Patterns cannot widen
		{"api.example.com.evil.org", false},
	}
	for _, c := range cases {
		if got := f.IsInScope(c.value); got != c.want {
			t.Errorf("IsInScope(%q) = %v, want %v", c.value, got, c.want)
		}
	}
}

func TestScopeExcludeBeatsInclude(t *testing.T) {
	t.Parallel()
	f := &output.DefaultScopeFilter{
		Patterns: []string{"*.example.com"},
		Include:  []string{"*.example.com"},
		Exclude:  []string{"admin.example.com"},
	}
	if f.IsInScope("admin.example.com") {
		t.Fatal("exclude must win over include")
	}
	if !f.IsInScope("api.example.com") {
		t.Fatal("non-excluded host inside include must pass")
	}
}

func TestScopeEmptyListsChangeNothing(t *testing.T) {
	t.Parallel()
	base := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}}
	withLists := &output.DefaultScopeFilter{Patterns: []string{"*.example.com"}, Include: nil, Exclude: []string{}}
	for _, v := range []string{"example.com", "a.example.com", "evil.com", "10.0.0.1", ""} {
		if base.IsInScope(v) != withLists.IsInScope(v) {
			t.Errorf("empty include/exclude changed the verdict for %q", v)
		}
	}
}

func TestParseScopeListSkipsCommentsAndBlankLines(t *testing.T) {
	t.Parallel()
	got := output.ParseScopeList("# header\n\n  API.Example.com  \n*.staging.example.com # trailing\n10.0.0.0/8\n\t\n")
	want := []string{"api.example.com", "*.staging.example.com", "10.0.0.0/8"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ParseScopeList = %v, want %v", got, want)
	}
	if out := output.ParseScopeList(""); len(out) != 0 {
		t.Fatalf("empty content → %v, want none", out)
	}
}

func TestNewScopeFilterLoadsFilesAndRejectsMissing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inc := filepath.Join(dir, "in.txt")
	exc := filepath.Join(dir, "out.txt")
	if err := os.WriteFile(inc, []byte("api.example.com\n*.shop.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exc, []byte("# never\nold.shop.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f, err := output.NewScopeFilter([]string{"*.example.com"}, inc, exc)
	if err != nil {
		t.Fatalf("NewScopeFilter: %v", err)
	}
	if len(f.Include) != 2 || len(f.Exclude) != 1 {
		t.Fatalf("lists not loaded: include=%v exclude=%v", f.Include, f.Exclude)
	}
	if !f.IsInScope("new.shop.example.com") || f.IsInScope("old.shop.example.com") || f.IsInScope("www.example.com") {
		t.Fatal("loaded lists not applied")
	}

	// No lists → plain pattern filter.
	plain, err := output.NewScopeFilter([]string{"*.example.com"}, "", "")
	if err != nil || plain.Include != nil || plain.Exclude != nil {
		t.Fatalf("empty paths: err=%v include=%v exclude=%v", err, plain.Include, plain.Exclude)
	}

	// Missing file is an error, never a silent empty list.
	if _, err := output.NewScopeFilter(nil, filepath.Join(dir, "missing.txt"), ""); err == nil {
		t.Fatal("missing include file must error")
	}
	if _, err := output.NewScopeFilter(nil, "", filepath.Join(dir, "missing.txt")); err == nil {
		t.Fatal("missing exclude file must error")
	}
}

// TestTreeAppendHonoursExcludeList proves the write boundary — not just the
// filter — drops an excluded host: FilterInScope over a Tree built with the
// list-aware filter.
func TestTreeAppendHonoursExcludeList(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := &output.DefaultScopeFilter{
		Patterns: []string{"*.example.com"},
		Exclude:  []string{"*.staging.example.com"},
	}
	tree, err := output.NewTree(dir, f)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	lines := [][]byte{
		[]byte(`{"subdomain":"api.example.com"}`),
		[]byte(`{"subdomain":"db.staging.example.com"}`),
	}
	kept, dropped := output.FilterInScope(tree, "subdomains", lines)
	if len(kept) != 1 || dropped != 1 {
		t.Fatalf("FilterInScope kept=%d dropped=%d, want 1/1", len(kept), dropped)
	}
	if err := tree.Append("subdomains", lines[1:]); err == nil {
		t.Fatal("Append of an excluded host must be rejected at the write boundary")
	}
}
