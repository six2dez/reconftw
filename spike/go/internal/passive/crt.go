// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §1.1
// Bash reference: modules/subdomains.sh:sub_passive() (lines 507-553)
package passive

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/six2dez/reconftw/spike/go/internal/proc"
	"github.com/six2dez/reconftw/spike/go/internal/ui"
)

// crtOutput is one entry in the JSON array from crt -json.
// crt.sh returns a JSON ARRAY (not NDJSON) — different from subfinder.
// This exercises the "buffered" parse pattern (opposite of subfinder's streaming NDJSON).
type crtOutput struct {
	Subdomain string `json:"subdomain"`
}

// crtRun invokes the crt binary via proc.Run and collects subdomains.
// Output format: JSON array (buffered) — single blob, not streaming.
// This is the OPPOSITE of subfinder's NDJSON; per RESEARCH.md §1.1 this exercises
// the "JSON-array buffered" source axis.
// Command: crt -s -json -l 200 <target>
func crtRun(ctx context.Context, target string, collect func(subdomain, source string)) error {
	ui.Info("crt: starting for " + target)

	args := []string{"-s", "-json", "-l", "200", target}

	// Buffer all stdout (crt emits a JSON array in one shot, not line-by-line).
	var buf bytes.Buffer
	err := proc.Run(ctx, "crt", args, func(line []byte) error {
		buf.Write(line)
		buf.WriteByte('\n')
		return nil
	})
	if err != nil {
		ui.Warn("crt: exited with error: " + err.Error())
		// Non-fatal.
		return nil
	}

	// Parse the accumulated JSON array (crt outputs [] or [{...},{...},...]).
	data := bytes.TrimSpace(buf.Bytes())
	if len(data) == 0 || bytes.Equal(data, []byte("null")) || bytes.Equal(data, []byte("[]")) {
		ui.Info("crt: no results for " + target)
		return nil
	}

	var entries []crtOutput
	if err := json.Unmarshal(data, &entries); err != nil {
		// crt may output a single JSON object or malformed JSON on error.
		ui.Warn("crt: JSON parse error: " + err.Error())
		return nil
	}

	count := 0
	for _, e := range entries {
		if e.Subdomain != "" {
			collect(e.Subdomain, "crt")
			count++
		}
	}

	ui.Info("crt: collected " + itoa(count) + " subdomains")
	return nil
}
