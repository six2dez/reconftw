// gqlspection.go — GQLSpectionTask: GraphQL introspection via gqlspection (OSINT-13).
//
// GQLSpectionTask runs gqlspection over the discovered GraphQL endpoints (v1
// modules/web.sh:1256: gqlspection -t <ep> -o <out>) to perform deep schema
// introspection on each reachable GraphQL endpoint — surfacing the exposed types,
// queries, and mutations. Each introspected endpoint becomes an informational
// OSINTFindingRecord (D-O4, Category graphql-introspection).
//
// OPPORTUNISTIC ENRICHMENT (D-O2): gqlspection is a v1 web.sh function (URL-corpus
// seeded — it runs only on endpoints another stage discovered). It reads candidate
// GraphQL endpoint URLs from the workspace artefacts (artefacts/urls.jsonl or
// artefacts/hosts.jsonl) IF present. When NO workspace URLs exist it logs an Info
// note and returns StatusSkipped — it NEVER fails or bootstraps subs/web
// (best_effort, D-O1/D-O2). URLs are scope-filtered by Phase 5 (T-07-05-05).
//
// SEEDING (D-O1): no DependsOn edges — the workspace-URL enrichment is
// opportunistic, not a DAG edge.
// FAILURE POLICY (D-O8, ARCH-09): best_effort.
//
// Source: .planning/phases/07-osint-e2e/07-05-PLAN.md Task 2.
package osint

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// gqlMaxEndpoints bounds the opportunistic per-URL gqlspection loop (D-O8
// conservative cap against attacker-influenced workspace URLs — T-07-05-05).
const gqlMaxEndpoints = 100

// GQLSpectionTask runs gqlspection for OSINT-13 (GraphQL introspection).
type GQLSpectionTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GQLSpectionTask) Name() string { return "osint.gqlspection" }

// Module returns the owning module group.
func (t *GQLSpectionTask) Module() string { return "osint" }

// Description returns a human-readable one-line description.
func (t *GQLSpectionTask) Description() string {
	return "GraphQL introspection (gqlspection, OSINT-13)"
}

// Enabled reports whether GraphQL introspection is configured.
func (t *GQLSpectionTask) Enabled(cfg *config.Config) bool {
	return cfg.OSINT.GraphQL.Enabled
}

// DependsOn returns nil — the workspace-URL enrichment (D-O2) is OPPORTUNISTIC,
// not a DAG edge.
func (t *GQLSpectionTask) DependsOn() []string { return nil }

// Run executes gqlspection per workspace GraphQL endpoint (D-O2 opportunistic).
//
// Steps:
//  1. D-O2: read candidate GraphQL endpoint URLs from workspace artefacts IF
//     present; absent → log Info + StatusSkipped (best_effort, NO fail/bootstrap).
//  2. Loop gqlspection per endpoint (LITERAL web.sh:1256 arg vector -t <ep> -o).
//  3. Parse introspection output into informational records.
//  4. Write inputs/findings.gqlspection.jsonl (multi-writer staging).
func (t *GQLSpectionTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	// Step 1: D-O2 opportunistic URL read, filtered to likely GraphQL endpoints.
	urls := graphqlEndpoints(readWorkspaceHosts(app.Target.WorkDir))
	if len(urls) == 0 {
		// D-O2: log-skip when absent — best_effort, NOT an error/bootstrap.
		if app.Log != nil {
			app.Log.Info("osint.gqlspection: no workspace GraphQL endpoints (artefacts/urls.jsonl|hosts.jsonl) — skipping (D-O2)")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	inputsDir := filepath.Join(app.Target.WorkDir, "inputs")
	if err := os.MkdirAll(inputsDir, 0o755); err != nil {
		return task.Result{Status: task.StatusErrored},
			fmt.Errorf("osint.gqlspection: mkdir inputs/: %w", err)
	}
	osintDir := filepath.Join(app.Target.WorkDir, "osint", "graphql")
	_ = os.MkdirAll(osintDir, 0o755) //nolint:errcheck // best_effort

	if len(urls) > gqlMaxEndpoints {
		urls = urls[:gqlMaxEndpoints] // conservative cap (D-O8)
	}

	var records []OSINTFindingRecord
	// gqlRan records whether AT LEAST ONE endpoint was actually probed, and
	// cancelled records an interrupted loop. Neither an absent gqlspection nor a
	// cancelled run observed the corpus, so neither may clear a previous run's
	// staging (F3 did-not-run — see writeOSINTStaging).
	gqlRan := false
	cancelled := false
	for i, ep := range urls {
		if ctx.Err() != nil {
			cancelled = true
			break
		}
		// LITERAL v1 gqlspection arg vector (web.sh:1256): gqlspection -t <ep> -o <out>.
		outFile := filepath.Join(osintDir, fmt.Sprintf("introspection_%d.json", i))
		res, err := app.Tools.Run(ctx, "gqlspection", []string{"-t", ep, "-o", outFile})
		if err != nil {
			if app.Log != nil {
				app.Log.Debug("osint.gqlspection: gqlspection run failed (best_effort)", "endpoint", ep, "err", err)
			}
			continue
		}
		gqlRan = true
		// Introspection succeeded if the tool produced a non-empty schema file or
		// any stdout. The endpoint + a short marker are the OSINT finding.
		if introspectionSucceeded(outFile, res.Stdout) {
			records = append(records, OSINTFindingRecord{
				Severity:    "informational",
				Class:       "osint",
				Source:      "gqlspection",
				Category:    "graphql-introspection",
				PoCRedacted: ep, // GraphQL endpoint — non-secret OSINT value
			})
		}
	}

	// Step 4: write staging JSONL (multi-writer contract).
	// F3: a run in which no endpoint answered introspection REMOVES the staging
	// file rather than republishing an endpoint that has since been locked down.
	if gqlRan && !cancelled {
		writeOSINTStaging(app, inputsDir, "findings.gqlspection.jsonl", records)
	} else if app.Log != nil {
		app.Log.Debug("osint.gqlspection: gqlspection did not probe the endpoints — staging preserved (F3 did-not-run)")
	}

	if app.Log != nil {
		app.Log.Info("osint.gqlspection: completed", "findings", len(records), "endpoints", len(urls))
	}
	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"findings": len(records), "endpoints": len(urls)},
	}, nil
}

// graphqlEndpoints filters workspace URLs to those that look like GraphQL
// endpoints (path contains "graphql" / "graphiql" / "gql"), mirroring v1's
// reliance on nuclei graphql-detect to seed .tmp/graphql_endpoints.txt. Returns a
// deduped list. Non-URL host entries are excluded (gqlspection needs a full URL).
func graphqlEndpoints(candidates []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if !strings.HasPrefix(strings.ToLower(c), "http") {
			continue
		}
		lower := strings.ToLower(c)
		if !strings.Contains(lower, "graphql") &&
			!strings.Contains(lower, "graphiql") &&
			!strings.Contains(lower, "/gql") {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	return out
}

// introspectionSucceeded reports whether gqlspection produced introspection
// output for an endpoint — a non-empty -o schema file, or non-empty stdout.
func introspectionSucceeded(outFile string, stdout []byte) bool {
	if data, err := os.ReadFile(outFile); err == nil && len(bytes.TrimSpace(data)) > 0 { //nolint:gosec // within WorkDir
		return true
	}
	return len(bytes.TrimSpace(stdout)) > 0
}

// init self-registers GQLSpectionTask with the Default task registry.
func init() { task.Register(&GQLSpectionTask{}) }
