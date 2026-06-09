// graphql.go — GraphQLTask: gqlspection-based GraphQL introspection scanner (D-V3).
//
// GraphQLTask is a D-V3 fold-in from web.sh graphql_scan(), routed to the
// vulns pipeline per plan 06-08 (VULN-14 parity completeness gate).
//
// INPUT: artefacts/urls.jsonl — URL corpus from Phase 5.
//        Empty → StatusSkipped (best_effort per D-V7).
//
// ARG VECTOR (v1 web.sh graphql_scan verbatim, gqlspection variant):
//
//	gqlspection -t <url> -o <tmpFile.json>
//
// Per-URL invocation; each URL probed independently.
// Non-zero exit per URL → log.Debug + continue (best_effort per-host, ADR §7).
//
// OUTPUT: artefacts/graphql.jsonl — single-writer; direct app.Tree.Append OK
// (doc.go: single-writer artefacts do NOT go through the staging+merge pipeline).
//
// PAYLOAD REDACTION (XCUT-07):
// GraphQL schema (field names, types) is the recon OUTPUT — no redaction needed
// for schema structure. No secret values in the introspection output path.
// (T-06-08-01: accept disposition — GraphQL introspection data is not a secret.)
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-08-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// GraphQLTask runs gqlspection against each URL in the corpus to discover
// GraphQL introspection endpoints (D-V3, VULN-14 parity completeness).
type GraphQLTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GraphQLTask) Name() string { return "vulns.graphql" }

// Module returns the owning module group.
func (t *GraphQLTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *GraphQLTask) Description() string {
	return "GraphQL introspection scanner (gqlspection)"
}

// Enabled reads cfg.Vulns.GraphQL.Enabled.
func (t *GraphQLTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.GraphQL.Enabled }

// DependsOn declares GFTask as the DAG root dependency.
// GraphQLTask consumes artefacts/urls.jsonl; the gf dependency ensures the
// vulns pipeline scaffold is initialized before these probes run.
func (t *GraphQLTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes gqlspection against the URL corpus.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract URL strings — StatusSkipped if empty.
//  2. For each URL: run gqlspection -t <url> -o <tmpFile.json>.
//     On error → log.Debug + continue (best_effort per-host).
//  3. Parse each tmpFile.json for introspection results.
//  4. Aggregate records; write to artefacts/graphql.jsonl via app.Tree.Append.
func (t *GraphQLTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "gqlspection"

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	urls, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.graphql: read URL corpus error (best_effort)", "err", err)
	}
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.graphql: no URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Temp dir for per-URL output files.
	tmpDir, err := os.MkdirTemp("", "reconftw-graphql-*")
	if err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("vulns.graphql: mkdirtemp: %w", err)
	}
	defer os.RemoveAll(tmpDir) //nolint:errcheck

	var allRecords []graphqlRecord
	found := 0

	// Step 2 & 3: Per-URL gqlspection invocation.
	for i, u := range urls {
		// Context cancellation check between URLs.
		select {
		case <-ctx.Done():
			return task.Result{Status: task.StatusCancelled},
				fmt.Errorf("vulns.graphql: cancelled: %w", ctx.Err())
		default:
		}

		tmpFile := filepath.Join(tmpDir, fmt.Sprintf("gql_%d.json", i))
		// gqlspection -t <url> -o <tmpFile.json>
		args := []string{"-t", u, "-o", tmpFile}

		res, runErr := app.Tools.Run(ctx, toolName, args)
		if runErr != nil {
			if app.Log != nil {
				app.Log.Debug("vulns.graphql: gqlspection error (best_effort — continuing)",
					"url", u, "err", runErr)
			}
			continue
		}

		// Parse the output file if it was produced.
		recs := parseGQLSpectionOutput(tmpFile, res.Stdout, u)
		allRecords = append(allRecords, recs...)
		found += len(recs)
	}

	// Step 4: Write artefacts/graphql.jsonl via direct app.Tree.Append (single-writer).
	if len(allRecords) > 0 {
		var lines [][]byte
		for _, rec := range allRecords {
			b, mErr := json.Marshal(rec)
			if mErr != nil {
				continue
			}
			lines = append(lines, b)
		}
		if len(lines) > 0 {
			if wErr := app.Tree.Append("graphql", lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.graphql: Tree.Append failed",
					"records", len(lines), "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.graphql: completed", "endpoints", found)
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"endpoints": found},
	}, nil
}

// graphqlRecord is the artefacts/graphql.jsonl schema for a discovered
// GraphQL introspection endpoint (T-06-08-01: schema structure is the recon
// output; no redaction needed).
type graphqlRecord struct {
	URL    string `json:"url"`
	Target string `json:"target"`
	Type   string `json:"type"` // "graphql-endpoint"
}

// parseGQLSpectionOutput parses a gqlspection JSON output file, falling back
// to stdout if the file is absent or empty. Returns records for each
// introspection-capable endpoint found.
func parseGQLSpectionOutput(tmpFile string, stdout []byte, srcURL string) []graphqlRecord {
	// Try the output file first.
	data, err := os.ReadFile(tmpFile) //nolint:gosec // tmpFile is within mkdirtemp
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		// Fall back to stdout content.
		data = bytes.TrimSpace(stdout)
	}
	if len(data) == 0 {
		return nil
	}

	// gqlspection output is either a JSON object or a JSON array.
	// If it parses as valid JSON (non-empty), the endpoint is introspectable.
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		// Non-JSON output — try treating non-empty output as a positive signal.
		if len(bytes.TrimSpace(data)) > 10 {
			return []graphqlRecord{{
				URL:    srcURL,
				Target: extractHostFromURL(srcURL),
				Type:   "graphql-endpoint",
			}}
		}
		return nil
	}

	// Valid JSON output from gqlspection — endpoint supports introspection.
	return []graphqlRecord{{
		URL:    srcURL,
		Target: extractHostFromURL(srcURL),
		Type:   "graphql-endpoint",
	}}
}

// readURLsJSONL reads artefacts/urls.jsonl and returns URL strings.
// Each line may be a plain URL string or a JSON object with a "url" field.
// Returns nil when absent or empty (non-fatal for Task).
func readURLsJSONL(workDir string) ([]string, error) {
	urlsPath := filepath.Join(workDir, "artefacts", "urls.jsonl")
	data, err := os.ReadFile(urlsPath) //nolint:gosec // path within WorkDir
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}

	var urls []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		// Try JSON object with "url" field first.
		var rec struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal(line, &rec); err == nil && rec.URL != "" {
			urls = append(urls, rec.URL)
			continue
		}
		// Fall back to treating the line itself as a URL string.
		u := strings.TrimSpace(string(line))
		if u != "" && (strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) {
			urls = append(urls, u)
		}
	}
	return urls, sc.Err()
}

// extractHostFromURL extracts the hostname from a URL string.
// Returns the full URL when parsing fails (safe fallback for record metadata).
func extractHostFromURL(rawURL string) string {
	// Simple host extraction — avoid importing net/url for this helper.
	after := rawURL
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		after = rawURL[idx+3:]
	}
	if idx := strings.IndexByte(after, '/'); idx >= 0 {
		after = after[:idx]
	}
	if after == "" {
		return rawURL
	}
	return after
}

// init self-registers GraphQLTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&GraphQLTask{}) }
