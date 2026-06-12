package report

import (
	"encoding/json"
	"fmt"

	"github.com/six2dez/reconftw/internal/core/findings"
	"github.com/six2dez/reconftw/internal/core/output"
	sqlcgen "github.com/six2dez/reconftw/internal/store/sqlc"
)

// WriteSARIF wires findings.BuildSarifLog to output.WriteFile.
// All writes use the 4-step atomic writer (ADR §3.5 / FOUND-04).
//
// The evidence field is already excluded from SARIF output by
// findings.MapStoreFinding (see mapper.go T-08-01-01 comment).
func WriteSARIF(destPath, toolVersion string, fs []*sqlcgen.Finding) error {
	sarifLog := findings.BuildSarifLog("reconftw", toolVersion, fs)
	data, err := json.MarshalIndent(sarifLog, "", "  ")
	if err != nil {
		return fmt.Errorf("report/sarif: marshal: %w", err)
	}
	return output.WriteFile(destPath, data, 0o644)
}
