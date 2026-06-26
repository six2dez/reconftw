// Package mcp — MCP resource registrations.
//
// RegisterResources adds the scan://{runID}/findings resource template to the
// go-sdk server. The read handler streams the raw JSONL from the scan workspace's
// artefacts/findings.jsonl file.
//
// SARIF serialization: the raw JSONL returned here maps to SarifResult via
// internal/core/findings.BuildSarifLog. Phase 10 REPORT-07 calls BuildSarifLog
// to reuse the canonical schema (D-04). This handler intentionally returns raw
// JSONL for live streaming efficiency.
//
// NotifyFindingsUpdated is called from the scan goroutine (tools.go
// launchScanAndNotify) after each stage completes. It broadcasts a
// resources/updated notification to all subscribed sessions via the SDK's
// fan-out mechanism (A3 — verified in sdk_assumptions_test.go).
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// RegisterResources adds the scan://{runID}/findings resource template to srv.
//
// Read handler:
//   - Extracts runID from the URI "scan://<runID>/findings".
//   - Looks up the work directory for that runID in registry.
//   - Reads artefacts/findings.jsonl and returns raw JSONL as text/x-ndjson.
//   - Returns an empty result (not an error) if the file doesn't exist yet —
//     the scan may be early in its pipeline.
func RegisterResources(srv *mcp.Server, registry *SessionRegistry) {
	srv.AddResourceTemplate(
		&mcp.ResourceTemplate{
			URITemplate: "scan://{runID}/findings",
			Name:        "Scan findings",
			MIMEType:    "application/x-ndjson",
			Description: "Live JSONL findings for a running or completed scan. Subscribe for real-time updates.",
		},
		func(ctx context.Context, req *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			// SARIF serialization: the raw JSONL returned here maps to SarifResult via
			// internal/core/findings.BuildSarifLog for Phase 10 REPORT-07 reuse (D-04).
			// This handler intentionally returns raw JSONL for live streaming efficiency.

			runID := extractRunIDFromURI(req.Params.URI)
			if runID == "" {
				return nil, fmt.Errorf("mcp: invalid findings URI: %q", req.Params.URI)
			}

			workDir := registry.WorkDir(runID)
			if workDir == "" {
				// Run not yet started or workdir not set — return empty content.
				return &mcp.ReadResourceResult{
					Contents: []*mcp.ResourceContents{
						{URI: req.Params.URI, MIMEType: "application/x-ndjson", Text: ""},
					},
				}, nil
			}

			findingsPath := filepath.Join(workDir, "artefacts", "findings.jsonl")
			lines, err := readFindingsJSONL(findingsPath)
			if err != nil {
				// File may not exist yet (early in pipeline). Return empty content.
				return &mcp.ReadResourceResult{
					Contents: []*mcp.ResourceContents{
						{URI: req.Params.URI, MIMEType: "application/x-ndjson", Text: ""},
					},
				}, nil
			}

			// Join lines with newline to form the raw JSONL response.
			var sb strings.Builder
			for i, line := range lines {
				sb.Write(line)
				if i < len(lines)-1 {
					sb.WriteByte('\n')
				}
			}

			return &mcp.ReadResourceResult{
				Contents: []*mcp.ResourceContents{
					{
						URI:      req.Params.URI,
						MIMEType: "application/x-ndjson",
						Text:     sb.String(),
					},
				},
			}, nil
		},
	)
}

// NotifyFindingsUpdated sends a resources/updated notification for the given
// runID's findings URI to all subscribed sessions. The SDK fans out to all
// subscribers (A3 — verified in sdk_assumptions_test.go: 2 subscribers both
// received the notification).
//
// Returns any error from the SDK (non-fatal in the scan goroutine — the caller
// in launchScanAndNotify logs and continues on error).
func NotifyFindingsUpdated(ctx context.Context, srv *mcp.Server, runID string) error {
	return srv.ResourceUpdated(ctx, &mcp.ResourceUpdatedNotificationParams{
		URI: "scan://" + runID + "/findings",
	})
}

// readFindingsJSONL reads a JSONL file and returns each non-empty line as a
// []byte slice. Pattern from 08-PATTERNS.md §"internal/mcp/resources.go" and
// internal/mcp/handlers/common.go:readJSONLLines.
//
// Returns an error if the file does not exist or cannot be read. The caller
// should treat a missing file as "no findings yet" (not an error condition).
func readFindingsJSONL(path string) ([][]byte, error) {
	f, err := os.Open(path) //nolint:gosec // path derived from validated WorkDir + const suffix
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var lines [][]byte
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		line := make([]byte, len(b))
		copy(line, b)
		lines = append(lines, line)
	}
	return lines, sc.Err()
}
