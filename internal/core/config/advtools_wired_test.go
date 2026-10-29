package config

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

// TestAdvToolFieldsAreWired walks every koanf leaf of AdvancedTools by
// reflection and asserts that production code OUTSIDE internal/core/config
// reads it through its selector (e.g. `.Tools.Gotator.Flags`).
//
// Why: fourteen advanced.tools.* fields were declared, defaulted, migrated from
// v1 by legacy_aliases.go — and read by nothing. An operator who set
// GOTATOR_FLAGS or TLSX_THREADS got a config that loaded cleanly and changed
// nothing. Build/vet/`go test` cannot see an unread struct field; this guard
// can. A new AdvTool* field must be consumed by the task that dispatches the
// tool, or it must not exist.
func TestAdvToolFieldsAreWired(t *testing.T) {
	t.Parallel()

	root := filepath.Join("..", "..", "..")
	sources := collectProductionGoSources(t, root)
	if len(sources) == 0 {
		t.Fatal("no production Go sources found outside internal/core/config")
	}

	var missing []string
	walkKoanfLeaves(reflect.TypeOf(AdvancedTools{}), "Tools", func(selector, koanfPath string) {
		// `.Tools.FFUF.Flags` followed by a non-identifier character.
		re := regexp.MustCompile(`\.` + regexp.QuoteMeta(selector) + `\b`)
		for _, src := range sources {
			if re.MatchString(src) {
				return
			}
		}
		missing = append(missing, selector+" (advanced."+koanfPath+")")
	})
	if len(missing) > 0 {
		t.Fatalf("advanced.tools fields declared but read by no production code "+
			"(wire them into the dispatching task or delete them):\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// walkKoanfLeaves calls fn for every leaf (non-struct) field reachable from
// typ, with the Go selector chain (prefix.Field.Sub) and the koanf dotted path.
func walkKoanfLeaves(typ reflect.Type, prefix string, fn func(selector, koanfPath string)) {
	walkKoanfLeavesRec(typ, prefix, "tools", fn)
}

func walkKoanfLeavesRec(typ reflect.Type, selPrefix, koanfPrefix string, fn func(selector, koanfPath string)) {
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := f.Tag.Get("koanf")
		if tag == "" || tag == "-" {
			continue
		}
		sel := selPrefix + "." + f.Name
		kp := koanfPrefix + "." + tag
		if f.Type.Kind() == reflect.Struct {
			walkKoanfLeavesRec(f.Type, sel, kp, fn)
			continue
		}
		fn(sel, kp)
	}
}

// collectProductionGoSources returns the contents of every non-test .go file
// under root, excluding this package, testdata trees, vendored/planning dirs.
func collectProductionGoSources(t *testing.T, root string) []string {
	t.Helper()
	skipDirs := map[string]bool{
		".git": true, ".planning": true, "testdata": true, "vendor": true,
		"node_modules": true, "reconftw-web": true,
	}
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			rel, _ := filepath.Rel(root, path)
			if filepath.ToSlash(rel) == "internal/core/config" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path) //nolint:gosec // test walks the repo tree
		if rerr != nil {
			return rerr
		}
		out = append(out, string(b))
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// TestAdvToolGuardSeesKnownWiredField is the mutation check for the guard
// above: a field that IS read (FFUF.Flags, consumed by web.fuzz) must be found,
// otherwise the walker or the regexp is broken and the guard is a false green.
func TestAdvToolGuardSeesKnownWiredField(t *testing.T) {
	t.Parallel()
	sources := collectProductionGoSources(t, filepath.Join("..", "..", ".."))
	re := regexp.MustCompile(`\.Tools\.FFUF\.Flags\b`)
	for _, src := range sources {
		if re.MatchString(src) {
			return
		}
	}
	t.Fatal("guard cannot see .Tools.FFUF.Flags, which web.fuzz reads — walker/regexp broken")
}
