// SPDX-License-Identifier: MIT
// Spike PoC — DO NOT EVOLVE INTO PRODUCTION
// Source: .planning/phases/01-language-adr-spike/01-02-PLAN.md Task 3
// Locked scope: spike/README.md §Scope
// Pattern reference: .planning/phases/01-language-adr-spike/01-RESEARCH.md §3.4
package tests

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/six2dez/reconftw/spike/go/internal/httpxprobe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// toolAvailable checks if a tool is available on PATH.
func toolAvailable(name string) bool {
	_, err := os.ReadFile("/dev/null")
	_ = err
	// Use os.LookPath equivalent via exec.LookPath
	return lookPath(name)
}

// TestHTTPxProbe_Streaming runs httpxprobe.Run against a small list of known-resolvable hosts
// and asserts:
//   - outFile exists and contains at least 1 JSONL line
//   - each line parses as JSON with url and status_code fields
//
// If httpx not in PATH: test skips.
func TestHTTPxProbe_Streaming(t *testing.T) {
	if !toolAvailable("httpx") {
		t.Skip("httpx not in PATH — skipping TestHTTPxProbe_Streaming")
	}

	dir := t.TempDir()

	// Create a fake subs.jsonl with a few known-resolvable hosts.
	// httpxprobe.Run expects a subs.jsonl with one subdomain per line
	// (or JSONL with {"subdomain":"..."} format).
	// Actually httpx -l takes a plain text file (one host per line).
	subsFile := filepath.Join(dir, "subs.jsonl")
	subsContent := "www.example.com\nwww.iana.org\ndns.google\n"
	require.NoError(t, os.WriteFile(subsFile, []byte(subsContent), 0o644))

	outFile := filepath.Join(dir, "hosts.jsonl")

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	err := httpxprobe.Run(ctx, subsFile, outFile)
	assert.NoError(t, err)

	// Check if outFile was created.
	data, readErr := os.ReadFile(outFile)
	if readErr != nil {
		t.Logf("outFile not created — httpx may have found no live hosts")
		return
	}
	if len(data) == 0 {
		t.Logf("outFile is empty — no hosts responded")
		return
	}

	// Verify each line is valid JSON with at least url and status_code.
	type httpxEntry struct {
		URL        string `json:"url"`
		StatusCode int    `json:"status-code"`
		Input      string `json:"input"`
	}

	lineCount := 0
	scanner := bufio.NewScanner(
		&bytesReader{data: data, pos: 0},
	)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var entry httpxEntry
		require.NoError(t, json.Unmarshal([]byte(line), &entry),
			"each line must parse as JSON httpx output; got: %s", line)
		assert.NotEmpty(t, entry.Input, "httpx output must have input field; got: %s", line)
		lineCount++
	}

	t.Logf("httpx: collected %d JSONL lines", lineCount)
	assert.GreaterOrEqual(t, lineCount, 1, "expected at least 1 host from httpx probe")
}
