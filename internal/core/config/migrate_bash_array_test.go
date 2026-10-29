package config

import (
	"strings"
	"testing"
)

// TestEvaluateValueBashArray: v1 now declares GOTATOR_FLAGS / NUCLEI_EXTRA_ARGS /
// NUCLEI_DAST_EXTRA_ARGS / AXIOM_EXTRA_ARGS as bash arrays. Their v2 homes are
// flag strings split with strings.Fields, so the migrator must join the
// elements — not emit the literal "(-depth 1 … -md)" as the value.
func TestEvaluateValueBashArray(t *testing.T) {
	t.Parallel()
	cases := []struct {
		raw, want string
		shell     bool
	}{
		{`(-depth 1 -numbers 3 -mindup -adv -md) # Flags for gotator`, "-depth 1 -numbers 3 -mindup -adv -md", false},
		{`()`, "", false},
		{`() # empty`, "", false},
		{`(-etags openssh,ssl -eid a,b)`, "-etags openssh,ssl -eid a,b", false},
		{`(--rm-logs)`, "--rm-logs", false},
		{`(-H "User-Agent: x y" -t 5)`, "-H User-Agent: x y -t 5", false},
		{`('a b' c)`, "a b c", false},
		{`(-p "$HOME/x")`, "-p $HOME/x", true}, // unresolved expansion → Case B
	}
	for _, c := range cases {
		got := evaluateValue(c.raw)
		if got.value != c.want || got.shell != c.shell {
			t.Errorf("evaluateValue(%q) = {%q, shell=%v}, want {%q, shell=%v}",
				c.raw, got.value, got.shell, c.want, c.shell)
		}
	}
}

// TestMigrateGotatorArrayLandsAsFlagString runs the whole migrator over the
// array form and checks the emitted TOML value.
func TestMigrateGotatorArrayLandsAsFlagString(t *testing.T) {
	t.Parallel()
	in := "GOTATOR_FLAGS=(-depth 1 -numbers 3 -mindup -adv -md) # Flags for gotator\nNUCLEI_EXTRA_ARGS=()\n"
	res, err := Migrate(strings.NewReader(in), MigrateOptions{})
	if err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	out := string(res.TOML)
	if !strings.Contains(out, `flags = "-depth 1 -numbers 3 -mindup -adv -md"`) {
		t.Errorf("gotator flags not joined; TOML:\n%s", out)
	}
	if strings.Contains(out, `"()"`) || strings.Contains(out, `"(-depth`) {
		t.Errorf("array literal leaked into TOML:\n%s", out)
	}
}
