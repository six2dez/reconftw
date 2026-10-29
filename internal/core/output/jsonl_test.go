package output

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type jsonlRec struct {
	Host string `json:"host"`
	N    int    `json:"n"`
}

func writeJSONLFixture(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "recs.jsonl")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return p
}

func TestReadJSONLSkipsBlankLinesAndDecodes(t *testing.T) {
	p := writeJSONLFixture(t, "{\"host\":\"a\",\"n\":1}\n\n   \n{\"host\":\"b\",\"n\":2}\n")
	got, err := ReadJSONL[jsonlRec](p)
	if err != nil {
		t.Fatalf("ReadJSONL: %v", err)
	}
	if len(got) != 2 || got[0].Host != "a" || got[1].N != 2 {
		t.Fatalf("ReadJSONL = %+v, want [a:1 b:2]", got)
	}
}

func TestReadJSONLMissingFileIsEmptyNil(t *testing.T) {
	got, err := ReadJSONL[jsonlRec](filepath.Join(t.TempDir(), "absent.jsonl"))
	if err != nil {
		t.Fatalf("missing file must be (nil, nil), got err %v", err)
	}
	if got != nil {
		t.Fatalf("missing file must be nil slice, got %v", got)
	}
	called := false
	if err := ForEachJSONL(filepath.Join(t.TempDir(), "absent.jsonl"), func(jsonlRec) error {
		called = true
		return nil
	}); err != nil || called {
		t.Fatalf("ForEachJSONL on a missing file: err=%v called=%v", err, called)
	}
}

func TestForEachJSONLMalformedLineIsTypedWithLineNumber(t *testing.T) {
	// Line 3 is physical: a blank line 2 must still count.
	p := writeJSONLFixture(t, "{\"host\":\"a\"}\n\n{not json}\n{\"host\":\"c\"}\n")
	var seen []string
	err := ForEachJSONL(p, func(r jsonlRec) error {
		seen = append(seen, r.Host)
		return nil
	})
	var je *JSONLError
	if !errors.As(err, &je) {
		t.Fatalf("malformed line must surface as *JSONLError, got %T %v", err, err)
	}
	if je.Line != 3 || je.Path != p {
		t.Errorf("JSONLError = %+v, want Line 3 at %s", je, p)
	}
	if !strings.Contains(err.Error(), ":3:") {
		t.Errorf("Error() = %q, want the line number in it", err.Error())
	}
	if len(seen) != 1 || seen[0] != "a" {
		t.Errorf("records before the bad line = %v, want [a] (the walk stops AT the error)", seen)
	}
}

func TestForEachJSONLOneMiBLineIsAccepted(t *testing.T) {
	big := strings.Repeat("x", 1<<20)
	p := writeJSONLFixture(t, "{\"host\":\""+big+"\",\"n\":7}\n{\"host\":\"tail\"}\n")
	got, err := ReadJSONL[jsonlRec](p)
	if err != nil {
		t.Fatalf("a 1 MiB line is within the 4 MiB cap and must decode: %v", err)
	}
	if len(got) != 2 || len(got[0].Host) != 1<<20 || got[1].Host != "tail" {
		t.Fatalf("got %d records; first host len %d", len(got), len(got[0].Host))
	}
}

func TestForEachJSONLLineOverCapIsAnErrorNotASilentStop(t *testing.T) {
	// A line past the cap must be REPORTED, not swallowed: the old per-module
	// scanners ended the walk silently here.
	p := writeJSONLFixture(t, "{\"host\":\"a\"}\n{\"host\":\""+strings.Repeat("y", 5<<20)+"\"}\n")
	err := ForEachJSONLLine(p, 0, func([]byte) error { return nil })
	var je *JSONLError
	if !errors.As(err, &je) || !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("over-cap line: err = %v (%T), want *JSONLError wrapping bufio.ErrTooLong", err, err)
	}
	if je.Line != 2 {
		t.Errorf("over-cap line reported at %d, want 2", je.Line)
	}
	// A larger explicit cap accepts it.
	if err := ForEachJSONLLine(p, 8<<20, func([]byte) error { return nil }); err != nil {
		t.Errorf("with an 8 MiB cap the same file must read cleanly: %v", err)
	}
}

func TestForEachJSONLCallbackErrorIsReturnedUnwrapped(t *testing.T) {
	p := writeJSONLFixture(t, "{\"host\":\"a\"}\n{\"host\":\"b\"}\n")
	stop := errors.New("stop here")
	n := 0
	err := ForEachJSONL(p, func(jsonlRec) error {
		n++
		return stop
	})
	if !errors.Is(err, stop) || n != 1 {
		t.Fatalf("callback error: err=%v n=%d, want the sentinel after one call", err, n)
	}
}
