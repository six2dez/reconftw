// Package stagingcontract holds COMPILED-OUT fixture sources for the
// staging-contract detector in internal/modules/staging_contract_test.go.
//
// This directory is named testdata, so the go tool never builds it and the
// detector's own walker skips any directory named testdata when scanning the
// real tree. The sources exist only to be PARSED.
//
// One function per shape. The *OK functions pin the categories that must stay
// OUT of scope — without them a future contributor could quietly re-broaden the
// rule from staging-glob-triggered back to path- or write-triggered and nothing
// would fail until plan 15-14 hit ~35 tool-input writes with no sanctioned exit.
// The *Bad functions pin the categories that must stay IN.
package stagingcontract

import (
	"os"
	"path/filepath"

	"github.com/six2dez/reconftw/internal/core/output"
)

// ─── PASSING SHAPES ─────────────────────────────────────────────────────────

// stageJSONLOK — a migrated JSONL producer.
func stageJSONLOK(workDir string, lines [][]byte) error {
	return output.StageJSONL(filepath.Join(workDir, "inputs", "findings.nuclei.jsonl"), lines)
}

// stageLinesOK — a migrated plain-text producer.
func stageLinesOK(workDir string, hosts []string) error {
	return output.StageLines(filepath.Join(workDir, "inputs", "passive.subfinder.txt"), hosts)
}

// readerOnlyOK — builds an inputs path and only READS it. A reader has nothing
// to stage; a path-triggered rule would flag it and could never reach zero.
func readerOnlyOK(workDir string) ([]byte, error) {
	p := filepath.Join(workDir, "inputs", "urls.katana.jsonl")
	return os.ReadFile(p)
}

// writesArtefactOK — writes an artefacts/ path, not an inputs/ path.
func writesArtefactOK(workDir string, lines [][]byte) error {
	return output.WriteJSONL(filepath.Join(workDir, "artefacts", "findings.jsonl"), lines)
}

// toolInputWriteOK — mirrors internal/modules/web/katana.go exactly: ONE
// function, TWO inputs/ writes. inputs/katana_targets.txt is the tool-input list
// handed to katana (2 dot-parts, no merger globs it) and the staging write is
// already migrated. This fixture pins the tool-input category open.
func toolInputWriteOK(workDir string, targets []byte, lines [][]byte) error {
	if err := os.WriteFile(filepath.Join(workDir, "inputs", "katana_targets.txt"), targets, 0o644); err != nil {
		return err
	}
	return output.StageJSONL(filepath.Join(workDir, "inputs", "urls.katana.jsonl"), lines)
}

// scratchTxtWriteOK — mirrors internal/modules/web/wafw00f.go: THREE dot-parts
// and a .txt extension, but "wafw00f" is not a subdomains staging stage. Pins
// the "3 parts is not enough — part[0] must be a real stage" half of the rule,
// which a naive implementation gets wrong.
func scratchTxtWriteOK(workDir string, hosts []byte) error {
	return os.WriteFile(filepath.Join(workDir, "inputs", "wafw00f.hosts.txt"), hosts, 0o644)
}

// subdirWriteOK — mirrors internal/modules/vulns/gf.go: a TWO-level join.
// Transitive tracking must resolve gfDir → bucketFile, and the resolved path
// must then be recognised as a SUBDIRECTORY and dropped. filepath.Glob's `*`
// does not cross `/`, so no merger glob can reach it.
func subdirWriteOK(workDir, class string, urls []byte) error {
	gfDir := filepath.Join(workDir, "inputs", "gf")
	if err := os.MkdirAll(gfDir, 0o755); err != nil {
		return err
	}
	bucketFile := filepath.Join(gfDir, class+".txt")
	return os.WriteFile(bucketFile, urls, 0o644)
}

// derivedExemptOK — writes a derived <stage>.merged.txt intermediate and IS
// listed in the fixture exemption map with that literal.
func derivedExemptOK(workDir, stage string, body []byte) error {
	merged := filepath.Join(workDir, "inputs", stage+".merged.txt")
	return os.WriteFile(merged, body, 0o644)
}

// helperArgLiteralOK — passes a staging FILENAME literal to a package-local
// helper that is itself MIGRATED. The caller must not be double-reported.
func helperArgLiteralOK(workDir string, lines [][]byte) error {
	inputsDir := filepath.Join(workDir, "inputs")
	return migratedStagingHelper(inputsDir, "findings.tool.jsonl", lines)
}

func migratedStagingHelper(inputsDir, fileName string, lines [][]byte) error {
	return output.StageJSONL(filepath.Join(inputsDir, fileName), lines)
}

// ─── FAILING SHAPES ─────────────────────────────────────────────────────────

// guardedRawWriteBad — the exact F3 bug shape: the staging file is written only
// when there is data, so a run that found nothing leaves the previous run's file
// on disk for the merger to republish.
func guardedRawWriteBad(workDir string, lines [][]byte) error {
	inputsPath := filepath.Join(workDir, "inputs", "findings.nuclei.jsonl")
	if len(lines) > 0 {
		return output.WriteJSONL(inputsPath, lines)
	}
	return nil
}

// osWriteFileBad — same violation through os.WriteFile.
func osWriteFileBad(workDir string, body []byte) error {
	return os.WriteFile(filepath.Join(workDir, "inputs", "waf.wafw00f.jsonl"), body, 0o644)
}

// osCreateBad — same violation through os.Create. A producer must not be able to
// leave the guard by swapping its write primitive.
func osCreateBad(workDir string) error {
	f, err := os.Create(filepath.Join(workDir, "inputs", "hosts.portscan.jsonl"))
	if err != nil {
		return err
	}
	return f.Close()
}

// osOpenFileBad — same violation through os.OpenFile.
func osOpenFileBad(workDir string) error {
	f, err := os.OpenFile(filepath.Join(workDir, "inputs", "urls.waymore.jsonl"),
		os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}

// derivedTxtBad — a TWO-level transitive resolution that lands on a
// GLOB-MATCHING single component. Proves transitive tracking still catches real
// staging rather than only subdirectories.
func derivedTxtBad(workDir, tool string, body []byte) error {
	inputsDir := filepath.Join(workDir, "inputs")
	return os.WriteFile(filepath.Join(inputsDir, "resolved."+tool+".txt"), body, 0o644)
}

// helperWriteBad — calls a package-local path-writer helper, itself unmigrated,
// with a fully-resolved staging path. Without the helper-call arm a producer
// could move its write one function down and pass the guard while nothing
// changed. The CALLER is the reported site here: it holds the staging path.
func helperWriteBad(workDir string, body []byte) error {
	p := filepath.Join(workDir, "inputs", "findings.shortscan.jsonl")
	return rawWriteHelper(p, body)
}

func rawWriteHelper(path string, body []byte) error {
	return os.WriteFile(path, body, 0o644)
}

// helperArgLiteralBad — an unmigrated helper whose path comes from its own
// PARAMETERS, reachable only by argument-literal propagation from the
// "passive.tool.txt" call site below. This is the shape of
// osint/domain_info.go writeOSINTStaging and subdomains/takeover.go
// writeTakeoverStagingFile: without this rule the detector reports ZERO osint
// violations and 20 producers leave the guard silently. The HELPER is the
// reported site — the fix goes there, once — and its callers are not.
func helperArgLiteralBad(inputsDir, fileName string, body []byte) error {
	return os.WriteFile(filepath.Join(inputsDir, fileName), body, 0o644)
}

func helperArgLiteralCaller(workDir string, body []byte) error {
	inputsDir := filepath.Join(workDir, "inputs")
	const stagingName = "passive.tool.txt"
	return helperArgLiteralBad(inputsDir, stagingName, body)
}

// derivedNotExemptBad — listed in the fixture exemption map with the
// ".merged.txt" literal, and it DOES write that file. But it ALSO writes
// inputs/findings.x.jsonl, which carries no exempt literal and must still be
// reported. Proves the exemption is scoped to its declared path literal, not to
// the whole function, so a future producer cannot smuggle a staging write into
// an exempted function.
func derivedNotExemptBad(workDir, stage string, body []byte) error {
	if err := os.WriteFile(filepath.Join(workDir, "inputs", stage+".merged.txt"), body, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(workDir, "inputs", "findings.x.jsonl"), body, 0o644)
}
