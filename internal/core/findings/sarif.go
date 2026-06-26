// Package findings provides SARIF 2.1.0 types and mappers from reconFTW internal finding records.
package findings

// SarifLog is the top-level SARIF 2.1.0 document.
type SarifLog struct {
    Version string     `json:"version"` // must be "2.1.0"
    Schema  string     `json:"$schema,omitempty"`
    Runs    []SarifRun `json:"runs"`
}

// SarifRun represents a single analysis run within a SARIF log.
type SarifRun struct {
    Tool    SarifTool    `json:"tool"`
    Results []SarifResult `json:"results"`
}

// SarifTool describes the analysis tool that produced the run.
type SarifTool struct {
    Driver SarifDriver `json:"driver"`
}

// SarifDriver describes the primary analysis tool component (driver).
type SarifDriver struct {
    Name    string      `json:"name"`
    Version string      `json:"version,omitempty"`
    Rules   []SarifRule `json:"rules,omitempty"`
}

// SarifRule describes a reportable condition (rule / checker).
type SarifRule struct {
    ID               string           `json:"id"`
    Name             string           `json:"name,omitempty"`
    ShortDescription *SarifMessage    `json:"shortDescription,omitempty"`
    DefaultConfig    *SarifRuleConfig `json:"defaultConfiguration,omitempty"`
}

// SarifRuleConfig holds the default configuration for a rule.
type SarifRuleConfig struct {
    Level string `json:"level"` // "none" | "note" | "warning" | "error"
}

// SarifResult represents a single finding produced by the analysis.
type SarifResult struct {
    RuleID    string          `json:"ruleId,omitempty"`
    Level     string          `json:"level,omitempty"` // "none" | "note" | "warning" | "error"
    Message   SarifMessage    `json:"message"`
    Locations []SarifLocation `json:"locations,omitempty"`
}

// SarifMessage is a human-readable string used in results and rules.
type SarifMessage struct {
    Text string `json:"text"`
}

// SarifLocation specifies a location in an artefact.
type SarifLocation struct {
    PhysicalLocation SarifPhysicalLocation `json:"physicalLocation"`
}

// SarifPhysicalLocation identifies an artefact and optionally a region within it.
type SarifPhysicalLocation struct {
    ArtifactLocation SarifArtifactLocation `json:"artifactLocation"`
}

// SarifArtifactLocation specifies the location of an artefact via a URI.
type SarifArtifactLocation struct {
    URI string `json:"uri"`
}
