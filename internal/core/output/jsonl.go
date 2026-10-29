// jsonl.go — the one JSONL reader.
//
// Every module that consumed an artefact (urls.jsonl, hosts.jsonl,
// findings.*.jsonl) carried its own bufio.Scanner with the same 64 KiB initial /
// 4 MiB maximum buffer, the same blank-line skip and the same silent `continue`
// on a line that failed to decode. A record that did not parse vanished without
// a trace, and a line past the buffer cap ended the scan early with no error:
// both are the "did not look" failure that is indistinguishable from "found
// nothing". The readers here return a typed error that names the file and the
// line instead.
//
// A missing file is NOT an error for these readers: an absent artefact means
// the pipeline that writes it did not run, which every consumer already treats
// as "no input". Callers that need to distinguish the two use os.Stat.
package output

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

const (
	// JSONLInitialBuffer is the scanner's starting buffer, the size the module
	// readers have always used.
	JSONLInitialBuffer = 64 << 10
	// JSONLMaxLine is the largest single record the readers accept. A longer
	// line is reported as a *JSONLError wrapping bufio.ErrTooLong, not skipped.
	JSONLMaxLine = 4 << 20
)

// JSONLError reports a line that could not be read or decoded. Line is 1-based
// and counts every line in the file, blank ones included, so it can be pasted
// into `sed -n`.
type JSONLError struct {
	Path string
	Line int
	Err  error
}

func (e *JSONLError) Error() string {
	return fmt.Sprintf("%s:%d: %v", e.Path, e.Line, e.Err)
}

func (e *JSONLError) Unwrap() error { return e.Err }

// ForEachJSONLLine calls fn with the raw bytes of every non-blank line of path.
// maxLine bounds a single line; 0 means JSONLMaxLine. The slice handed to fn is
// a copy, so fn may retain it.
//
// A missing file returns nil without calling fn. fn's first non-nil error stops
// the walk and is returned unwrapped (so callers can use their own sentinels);
// a read failure is returned as a *JSONLError.
func ForEachJSONLLine(path string, maxLine int, fn func(line []byte) error) error {
	return walkJSONL(path, maxLine, func(_ int, line []byte) error { return fn(line) })
}

// walkJSONL is the single scanner behind the exported readers; lineNo is the
// 1-based PHYSICAL line (blank lines count) so an error points at the file.
func walkJSONL(path string, maxLine int, fn func(lineNo int, line []byte) error) error {
	if maxLine <= 0 {
		maxLine = JSONLMaxLine
	}
	f, err := os.Open(path) //nolint:gosec // artefact path under the workspace
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return &JSONLError{Path: path, Err: err}
	}
	defer f.Close() //nolint:errcheck // read-only handle

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, JSONLInitialBuffer), maxLine)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		cp := make([]byte, len(line))
		copy(cp, line)
		if err := fn(lineNo, cp); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		// The scanner stops AT the offending line: the one after the last it
		// delivered.
		return &JSONLError{Path: path, Line: lineNo + 1, Err: err}
	}
	return nil
}

// ForEachJSONL decodes every non-blank line of path into a T and calls fn with
// it. A line that does not decode is returned as a *JSONLError carrying the
// line number; fn's own error is returned as-is. A missing file is empty, nil.
func ForEachJSONL[T any](path string, fn func(T) error) error {
	return walkJSONL(path, 0, func(lineNo int, line []byte) error {
		var v T
		if err := json.Unmarshal(line, &v); err != nil {
			return &JSONLError{Path: path, Line: lineNo, Err: err}
		}
		return fn(v)
	})
}

// ReadJSONL decodes the whole of path into a slice. Same contract as
// ForEachJSONL: a missing file is (nil, nil); a bad line is a *JSONLError.
func ReadJSONL[T any](path string) ([]T, error) {
	var out []T
	err := ForEachJSONL(path, func(v T) error {
		out = append(out, v)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
