// Tests for the findings SARIF mapper (MapSeverity, MapStoreFinding, BuildSarifLog).
//
// External test package per project convention.
package findings_test

import (
    "testing"

    "github.com/six2dez/reconftw/internal/core/findings"
    sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// TestMapSeverity verifies the severity → SARIF level mapping table.
func TestMapSeverity(t *testing.T) {
    t.Parallel()

    cases := []struct {
        name  string
        input string
        want  string
    }{
        {name: "critical_lower", input: "critical", want: "error"},
        {name: "high_lower", input: "high", want: "error"},
        {name: "medium_lower", input: "medium", want: "warning"},
        {name: "low_lower", input: "low", want: "note"},
        {name: "info_lower", input: "info", want: "note"},
        {name: "empty", input: "", want: "note"},
        {name: "CRITICAL_upper", input: "CRITICAL", want: "error"},
        {name: "unknown", input: "unknownvalue", want: "note"},
        {name: "HIGH_mixed", input: "High", want: "error"},
        {name: "MEDIUM_upper", input: "MEDIUM", want: "warning"},
    }

    for _, tc := range cases {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            got := findings.MapSeverity(tc.input)
            if got != tc.want {
                t.Errorf("MapSeverity(%q) = %q; want %q", tc.input, got, tc.want)
            }
        })
    }
}

// TestMapStoreFinding verifies that store.Finding fields map to the correct SarifResult fields.
func TestMapStoreFinding(t *testing.T) {
    t.Parallel()

    cases := []struct {
        name             string
        finding          *sqlcgen.Finding
        wantRuleID       string
        wantLevel        string
        wantMessageText  string
        wantLocationsLen int
        wantURI          string
    }{
        {
            name: "full_finding_with_matched_at",
            finding: &sqlcgen.Finding{
                TemplateSignature: "nuclei/high/cve-2021-44228",
                Severity:          "high",
                Title:             "Log4Shell RCE",
                Description:       "Apache Log4j2 RCE via JNDI",
                MatchedAt:         "https://sub.example.com/app",
                Evidence:          "secret-tool-output", // must NOT appear in message
            },
            wantRuleID:       "nuclei/high/cve-2021-44228",
            wantLevel:        "error",
            wantMessageText:  "Log4Shell RCE: Apache Log4j2 RCE via JNDI",
            wantLocationsLen: 1,
            wantURI:          "https://sub.example.com/app",
        },
        {
            name: "empty_matched_at_produces_nil_locations",
            finding: &sqlcgen.Finding{
                TemplateSignature: "nuclei/medium/xss",
                Severity:          "medium",
                Title:             "XSS",
                Description:       "Cross-site scripting",
                MatchedAt:         "",
            },
            wantRuleID:       "nuclei/medium/xss",
            wantLevel:        "warning",
            wantMessageText:  "XSS: Cross-site scripting",
            wantLocationsLen: 0,
            wantURI:          "",
        },
        {
            name: "empty_title_and_description",
            finding: &sqlcgen.Finding{
                TemplateSignature: "generic/info/test",
                Severity:          "info",
                Title:             "",
                Description:       "",
                MatchedAt:         "https://example.com",
            },
            wantRuleID:       "generic/info/test",
            wantLevel:        "note",
            wantMessageText:  ": ",
            wantLocationsLen: 1,
            wantURI:          "https://example.com",
        },
    }

    for _, tc := range cases {
        tc := tc
        t.Run(tc.name, func(t *testing.T) {
            t.Parallel()
            got := findings.MapStoreFinding(tc.finding)

            if got.RuleID != tc.wantRuleID {
                t.Errorf("RuleID = %q; want %q", got.RuleID, tc.wantRuleID)
            }
            if got.Level != tc.wantLevel {
                t.Errorf("Level = %q; want %q", got.Level, tc.wantLevel)
            }
            if got.Message.Text != tc.wantMessageText {
                t.Errorf("Message.Text = %q; want %q", got.Message.Text, tc.wantMessageText)
            }
            if len(got.Locations) != tc.wantLocationsLen {
                t.Errorf("len(Locations) = %d; want %d", len(got.Locations), tc.wantLocationsLen)
            }
            if tc.wantLocationsLen > 0 {
                uri := got.Locations[0].PhysicalLocation.ArtifactLocation.URI
                if uri != tc.wantURI {
                    t.Errorf("Locations[0].URI = %q; want %q", uri, tc.wantURI)
                }
            }
        })
    }
}

// TestBuildSarifLog verifies grouping, deduplication, and edge cases.
func TestBuildSarifLog(t *testing.T) {
    t.Parallel()

    t.Run("nil_findings_produces_valid_log", func(t *testing.T) {
        t.Parallel()
        log := findings.BuildSarifLog("reconFTW", "2.0.0", nil)
        if log.Version != "2.1.0" {
            t.Errorf("Version = %q; want %q", log.Version, "2.1.0")
        }
        if len(log.Runs) != 1 {
            t.Fatalf("len(Runs) = %d; want 1", len(log.Runs))
        }
        if len(log.Runs[0].Results) != 0 {
            t.Errorf("len(Results) = %d; want 0", len(log.Runs[0].Results))
        }
        if log.Runs[0].Tool.Driver.Name != "reconFTW" {
            t.Errorf("Driver.Name = %q; want %q", log.Runs[0].Tool.Driver.Name, "reconFTW")
        }
    })

    t.Run("single_finding", func(t *testing.T) {
        t.Parallel()
        f := &sqlcgen.Finding{
            TemplateSignature: "nuclei/high/cve-2021-44228",
            Severity:          "high",
            Title:             "Log4Shell",
            Description:       "RCE via JNDI",
            MatchedAt:         "https://example.com",
            Tool:              "nuclei",
        }
        log := findings.BuildSarifLog("reconFTW", "2.0.0", []*sqlcgen.Finding{f})
        if log.Version != "2.1.0" {
            t.Errorf("Version = %q; want %q", log.Version, "2.1.0")
        }
        if len(log.Runs) != 1 {
            t.Fatalf("len(Runs) = %d; want 1", len(log.Runs))
        }
        run := log.Runs[0]
        if len(run.Results) != 1 {
            t.Errorf("len(Results) = %d; want 1", len(run.Results))
        }
        if len(run.Tool.Driver.Rules) != 1 {
            t.Errorf("len(Rules) = %d; want 1", len(run.Tool.Driver.Rules))
        }
        if run.Tool.Driver.Rules[0].ID != "nuclei/high/cve-2021-44228" {
            t.Errorf("Rules[0].ID = %q; want %q", run.Tool.Driver.Rules[0].ID, "nuclei/high/cve-2021-44228")
        }
    })

    t.Run("duplicate_template_signatures_deduplicated", func(t *testing.T) {
        t.Parallel()
        f1 := &sqlcgen.Finding{
            TemplateSignature: "nuclei/high/cve-2021-44228",
            Severity:          "high",
            Title:             "Log4Shell",
            Description:       "RCE via JNDI",
            MatchedAt:         "https://host1.example.com",
            Tool:              "nuclei",
        }
        f2 := &sqlcgen.Finding{
            TemplateSignature: "nuclei/high/cve-2021-44228", // same template
            Severity:          "high",
            Title:             "Log4Shell",
            Description:       "RCE via JNDI",
            MatchedAt:         "https://host2.example.com",
            Tool:              "nuclei",
        }
        log := findings.BuildSarifLog("reconFTW", "2.0.0", []*sqlcgen.Finding{f1, f2})
        run := log.Runs[0]
        if len(run.Results) != 2 {
            t.Errorf("len(Results) = %d; want 2 (one per finding)", len(run.Results))
        }
        if len(run.Tool.Driver.Rules) != 1 {
            t.Errorf("len(Rules) = %d; want 1 (deduplicated)", len(run.Tool.Driver.Rules))
        }
    })

    t.Run("multiple_different_templates", func(t *testing.T) {
        t.Parallel()
        findings_ := []*sqlcgen.Finding{
            {
                TemplateSignature: "nuclei/high/cve-2021-44228",
                Severity:          "high",
                Title:             "Log4Shell",
                Description:       "RCE",
                MatchedAt:         "https://host1.example.com",
                Tool:              "nuclei",
            },
            {
                TemplateSignature: "nuclei/medium/xss",
                Severity:          "medium",
                Title:             "XSS",
                Description:       "Cross-site scripting",
                MatchedAt:         "https://host2.example.com",
                Tool:              "nuclei",
            },
            {
                TemplateSignature: "nuclei/low/info-disclosure",
                Severity:          "low",
                Title:             "Info Disclosure",
                Description:       "Path disclosure",
                MatchedAt:         "https://host3.example.com",
                Tool:              "nuclei",
            },
        }
        log := findings.BuildSarifLog("reconFTW", "2.0.0", findings_)
        run := log.Runs[0]
        if len(run.Results) != 3 {
            t.Errorf("len(Results) = %d; want 3", len(run.Results))
        }
        if len(run.Tool.Driver.Rules) != 3 {
            t.Errorf("len(Rules) = %d; want 3 (one per unique template)", len(run.Tool.Driver.Rules))
        }
    })

    t.Run("version_set_on_driver", func(t *testing.T) {
        t.Parallel()
        log := findings.BuildSarifLog("nuclei", "3.1.0", []*sqlcgen.Finding{
            {
                TemplateSignature: "t/high/cve",
                Severity:          "high",
                Title:             "Test",
                Description:       "test",
            },
        })
        if log.Runs[0].Tool.Driver.Version != "3.1.0" {
            t.Errorf("Driver.Version = %q; want %q", log.Runs[0].Tool.Driver.Version, "3.1.0")
        }
        if log.Runs[0].Tool.Driver.Name != "nuclei" {
            t.Errorf("Driver.Name = %q; want %q", log.Runs[0].Tool.Driver.Name, "nuclei")
        }
    })
}
