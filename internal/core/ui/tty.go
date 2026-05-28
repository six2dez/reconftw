// Source: lib/ui.sh — _UI_IS_TTY detection (ports the bash `[[ -t 1 ]]`
// check). Phase 3 Plan 5 Task 2.

package ui

import (
	"io"
	"os"
)

// IsTTY reports whether w is an interactive terminal. Returns true for an
// *os.File whose stat reports ModeCharDevice; false for io.Writers (e.g.
// *bytes.Buffer in tests) and for files redirected from /dev/null.
//
// Mirrors v1 lib/ui.sh _UI_IS_TTY semantics.
func IsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
