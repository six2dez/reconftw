package findings

import (
    "strings"

    sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// MapSeverity maps a store.Finding Severity string to a SARIF level string.
// "critical" and "high" map to "error"; "medium" maps to "warning";
// "low", "info", and any unrecognised value (including empty) map to "note".
// The comparison is case-insensitive.
func MapSeverity(severity string) string {
    switch strings.ToLower(severity) {
    case "critical", "high":
        return "error"
    case "medium":
        return "warning"
    default: // "low", "info", "", or anything else
        return "note"
    }
}

// MapStoreFinding converts a *sqlcgen.Finding to a SarifResult.
//
// Field mapping:
//
//   - TemplateSignature → RuleID
//   - Severity          → Level (via MapSeverity)
//   - Title + Description → Message.Text ("Title: Description")
//   - MatchedAt         → Locations[0].PhysicalLocation.ArtifactLocation.URI
//     (only when MatchedAt is non-empty; otherwise Locations is nil)
//
// NOTE: Evidence is intentionally excluded from Message.Text (T-08-01-01: may
// contain raw tool output including secrets).
func MapStoreFinding(f *sqlcgen.Finding) SarifResult {
    result := SarifResult{
        RuleID:  f.TemplateSignature,
        Level:   MapSeverity(f.Severity),
        Message: SarifMessage{Text: f.Title + ": " + f.Description},
    }
    if f.MatchedAt != "" {
        result.Locations = []SarifLocation{
            {
                PhysicalLocation: SarifPhysicalLocation{
                    ArtifactLocation: SarifArtifactLocation{URI: f.MatchedAt},
                },
            },
        }
    }
    return result
}

// BuildSarifLog builds a SarifLog from a slice of *sqlcgen.Finding.
//
// All findings are placed in a single SarifRun whose driver is named toolName
// with the given version. Rules are deduplicated by TemplateSignature.
// A nil or empty findings slice produces a valid SarifLog with an empty
// Results slice (not nil).
func BuildSarifLog(toolName, version string, findings []*sqlcgen.Finding) SarifLog {
    results := make([]SarifResult, 0, len(findings))
    rules := make([]SarifRule, 0)
    seen := make(map[string]bool)

    for _, f := range findings {
        results = append(results, MapStoreFinding(f))

        if !seen[f.TemplateSignature] {
            seen[f.TemplateSignature] = true
            rules = append(rules, SarifRule{
                ID:   f.TemplateSignature,
                Name: f.Title,
                DefaultConfig: &SarifRuleConfig{
                    Level: MapSeverity(f.Severity),
                },
            })
        }
    }

    run := SarifRun{
        Tool: SarifTool{
            Driver: SarifDriver{
                Name:    toolName,
                Version: version,
                Rules:   rules,
            },
        },
        Results: results,
    }

    return SarifLog{
        Version: "2.1.0",
        Runs:    []SarifRun{run},
    }
}
