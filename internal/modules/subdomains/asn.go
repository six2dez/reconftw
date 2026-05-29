// asn.go — SubASNTask: ASN/CIDR mapping via asnmap.
//
// SINGLE-WRITER CONTRACT: SubASNTask is the ONLY writer for the "asns"
// artefact. Since no concurrent Task writes to "asns", direct
// app.Tree.Append is safe (no REPLACE-overwrite race).
//
// Source: .planning/phases/04-subdomains-e2e-axiom-integration/04-05-PLAN.md Task 1.
package subdomains

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/six2dez/reconftw/internal/core/appctx"
	"github.com/six2dez/reconftw/internal/core/config"
	"github.com/six2dez/reconftw/internal/core/task"
)

// SubASNTask maps the target domain to ASN numbers and CIDR ranges via asnmap.
// Writes ASNRecord JSONL to artefacts/asns.jsonl via single direct Append.
type SubASNTask struct{}

// Name returns the task identifier.
func (SubASNTask) Name() string { return "subdomains.asn" }

// Module returns the owning module.
func (SubASNTask) Module() string { return "subdomains" }

// Description returns a short description.
func (SubASNTask) Description() string {
	return "ASN-to-CIDR mapping via asnmap for passive network enumeration"
}

// Enabled returns true when cfg.Subdomains.ASN.Enabled is set.
func (SubASNTask) Enabled(cfg *config.Config) bool {
	return cfg.Subdomains.ASN.Enabled
}

// DependsOn returns nil — sequential RunStage ordering in command layer.
func (SubASNTask) DependsOn() []string { return nil }

// Run executes asnmap -d <domain> -json, parses the JSONL output into
// ASNRecord entries, and appends them directly to the "asns" artefact.
// This is safe because SubASNTask is the sole writer for "asns".
func (SubASNTask) Run(ctx context.Context, app *appctx.AppContext) (task.Result, error) {
	const toolName = "asnmap"

	args := []string{"-d", app.Target.Domain, "-json", "-silent"}

	res, err := app.Tools.Run(ctx, toolName, args)
	if err != nil {
		if app.Log != nil {
			app.Log.Debug("asnmap run failed or tool not registered",
				"tool", toolName, "err", err.Error())
		}
		return task.Result{
			Status: task.StatusDone,
			Stats:  map[string]int{"asns_found": 0},
		}, nil
	}

	// Parse asnmap JSON output. asnmap -json emits one JSON object per line:
	// {"as_number":"AS15133","as_name":"Edgecast Inc.","as_country":"US",
	//  "as_range":["93.184.216.0/24"]}
	var records [][]byte
	scanner := bufio.NewScanner(bytes.NewReader(res.Stdout))
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var entry struct {
			ASNumber string   `json:"as_number"`
			ASName   string   `json:"as_name"`
			ASRange  []string `json:"as_range"`
			// Alternative field names used by some asnmap versions.
			ASN  string   `json:"asn"`
			Org  string   `json:"org"`
			CIDR []string `json:"cidrs"`
		}
		if err := json.Unmarshal(line, &entry); err != nil {
			continue
		}

		// Normalise field variants.
		asn := entry.ASNumber
		if asn == "" {
			asn = entry.ASN
		}
		org := entry.ASName
		if org == "" {
			org = entry.Org
		}
		cidrs := entry.ASRange
		if len(cidrs) == 0 {
			cidrs = entry.CIDR
		}

		if asn == "" {
			continue
		}

		rec := ASNRecord{
			ASN:   asn,
			Org:   org,
			CIDRs: cidrs,
		}
		encoded, encErr := json.Marshal(rec)
		if encErr != nil {
			continue
		}
		records = append(records, encoded)
	}

	if len(records) > 0 {
		if err := app.Tree.Append("asns", records); err != nil {
			if app.Log != nil {
				app.Log.Debug("asnmap: Tree.Append(asns) failed",
					"err", err.Error(), "records", len(records))
			}
			return task.Result{Status: task.StatusErrored},
				fmt.Errorf("asnmap: Tree.Append(asns): %w", err)
		}
	}

	return task.Result{
		Status: task.StatusDone,
		Stats:  map[string]int{"asns_found": len(records)},
	}, nil
}

// -------------------------------------------------------------------------
// init() — Task self-registration
// -------------------------------------------------------------------------

func init() { task.Register(SubASNTask{}) }
