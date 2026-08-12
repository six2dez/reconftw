// grpc.go — GRPCTask: grpcurl reflection scanner (D-V3).
//
// GRPCTask is a D-V3 fold-in from web.sh grpc_reflection(), routed to the
// vulns pipeline per plan 06-08 (VULN-14 parity completeness gate).
//
// INPUT: artefacts/urls.jsonl — URL corpus from Phase 5.
//
//	Empty → StatusSkipped (best_effort per D-V7).
//
// ARG VECTOR (v1 web.sh grpc_reflection verbatim):
//
//	grpcurl -plaintext -max-msg-sz 10485760 -d '{}' <host:port> list
//
// Probes common plaintext gRPC ports (50051, 50052) per host.
// Non-zero exit per host:port → log.Debug + continue (best_effort per-host, ADR §7).
// Exit 0 + non-empty stdout → gRPC service found.
//
// OUTPUT: artefacts/grpc.jsonl — single-writer; direct app.Tree.Append OK
// (doc.go: single-writer artefacts do NOT go through the staging+merge pipeline).
//
// Source: .planning/phases/06-vulnerability-scanning-e2e/06-08-PLAN.md Task 1.
package vulns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// grpcPorts are the common plaintext gRPC port numbers probed per host.
// Mirrors v1 grpc_reflection() which iterates 50051 50052.
var grpcPorts = []string{"50051", "50052"}

// GRPCTask runs grpcurl reflection probing against each host in the corpus
// (D-V3, VULN-14 parity completeness).
type GRPCTask struct{}

// Name returns the globally unique dot-namespaced task identifier.
func (t *GRPCTask) Name() string { return "vulns.grpc" }

// Module returns the owning module group.
func (t *GRPCTask) Module() string { return "vulns" }

// Description returns a human-readable one-line description.
func (t *GRPCTask) Description() string {
	return "gRPC reflection scanner (grpcurl)"
}

// Enabled reads cfg.Vulns.GRPC.Enabled.
func (t *GRPCTask) Enabled(cfg *config.Config) bool { return cfg.Vulns.GRPC.Enabled }

// DependsOn declares GFTask as the DAG root dependency.
func (t *GRPCTask) DependsOn() []string { return []string{"vulns.gf"} }

// Run executes grpcurl reflection probing.
//
// Steps:
//  1. Read artefacts/urls.jsonl; extract unique hosts — StatusSkipped if empty.
//  2. For each host × port: run grpcurl -plaintext -max-msg-sz 10485760 -d '{}' <host:port> list.
//     On error → log.Debug + continue (best_effort per-host).
//     Exit 0 + non-empty stdout → gRPC service found.
//  3. Aggregate records; write to artefacts/grpc.jsonl via app.Tree.Append.
func (t *GRPCTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "grpcurl"

	// Step 1: Resolve URL corpus via D-V5 precedence (--urls ctx > artefacts/urls.jsonl).
	urls, err := readURLsWithCtx(ctx, app)
	if err != nil && app.Log != nil {
		app.Log.Debug("vulns.grpc: read URL corpus error (best_effort)", "err", err)
	}
	if len(urls) == 0 {
		if app.Log != nil {
			app.Log.Info("vulns.grpc: no URLs in URL corpus — skipping")
		}
		return task.Result{Status: task.StatusSkipped}, nil
	}

	// Deduplicate hosts from URLs.
	hosts := dedupeHosts(urls)

	var allRecords []grpcRecord
	found := 0

	// Step 2: Per-host × port grpcurl invocation.
	for _, host := range hosts {
		for _, port := range grpcPorts {
			// Context cancellation check.
			select {
			case <-ctx.Done():
				return task.Result{Status: task.StatusCancelled},
					fmt.Errorf("vulns.grpc: cancelled: %w", ctx.Err())
			default:
			}

			target := host + ":" + port
			// v1 arg vector: grpcurl -plaintext -max-msg-sz 10485760 -d '{}' <target> list
			args := []string{"-plaintext", "-max-msg-sz", "10485760", "-d", "{}", target, "list"}

			res, runErr := app.Tools.Run(ctx, toolName, args)
			if runErr != nil {
				if app.Log != nil {
					app.Log.Debug("vulns.grpc: grpcurl error (best_effort — continuing)",
						"target", target, "err", runErr)
				}
				continue
			}

			// Exit 0 + non-empty stdout → gRPC reflection enabled.
			if len(bytes.TrimSpace(res.Stdout)) == 0 {
				continue
			}

			// Parse service names from stdout (one per line).
			services := parseGRPCServices(res.Stdout)
			if len(services) == 0 {
				continue
			}

			allRecords = append(allRecords, grpcRecord{
				Host:     host,
				Port:     port,
				Target:   target,
				Services: services,
				Type:     "grpc-reflection",
			})
			found++
		}
	}

	// Step 3: Write artefacts/grpc.jsonl via direct app.Tree.Append (single-writer).
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
			if wErr := app.Tree.Append("grpc", lines); wErr != nil && app.Log != nil {
				app.Log.Debug("vulns.grpc: Tree.Append failed",
					"records", len(lines), "err", wErr)
			}
		}
	}

	if app.Log != nil {
		app.Log.Info("vulns.grpc: completed", "grpc_hosts", found)
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"grpc_hosts": found},
	}, nil
}

// grpcRecord is the artefacts/grpc.jsonl schema for a discovered gRPC service.
type grpcRecord struct {
	Host     string   `json:"host"`
	Port     string   `json:"port"`
	Target   string   `json:"target"`
	Services []string `json:"services"`
	Type     string   `json:"type"` // "grpc-reflection"
}

// parseGRPCServices reads grpcurl "list" stdout (one service name per line)
// and returns the service names.
func parseGRPCServices(data []byte) []string {
	if len(data) == 0 {
		return nil
	}
	var services []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			services = append(services, line)
		}
	}
	return services
}

// dedupeHosts extracts unique hostnames from URL strings. It strips scheme and
// path components so that "https://example.com/foo" and "http://example.com/bar"
// both produce "example.com".
func dedupeHosts(urls []string) []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, u := range urls {
		h := extractHostFromURL(u)
		if h == "" {
			continue
		}
		if _, exists := seen[h]; !exists {
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	return hosts
}

// init self-registers GRPCTask with the Default task registry.
// cmd/reconftw/modules.go blank-imports this package to trigger registration.
func init() { task.Register(&GRPCTask{}) }
