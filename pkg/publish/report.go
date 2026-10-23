// Package publish holds the mode handlers that turn a plan or verified
// batches into output: report (enriched SARIF and a JSON summary) today;
// pr, review and local in later phases.
package publish

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rossedman/sarifix/pkg/plan"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// Report output file names inside the report directory.
const (
	ReportSARIF   = "sarifix.sarif"
	ReportSummary = "summary.json"
)

// ReportFiles are the paths Report wrote.
type ReportFiles struct {
	SARIF   string `json:"sarif"`
	Summary string `json:"summary"`
}

// Report writes the enriched SARIF (every input run, each finding carrying
// properties.sarifix) and the JSON summary into dir. It makes no edits.
func Report(dir string, log *sarif.Log, p *plan.Plan) (ReportFiles, error) {
	files := ReportFiles{SARIF: filepath.Join(dir, ReportSARIF), Summary: filepath.Join(dir, ReportSummary)}
	p.Annotate()
	if err := log.WriteFile(files.SARIF); err != nil {
		return files, fmt.Errorf("write enriched SARIF: %w", err)
	}
	data, err := json.MarshalIndent(p.Summarize(), "", "  ")
	if err != nil {
		return files, err
	}
	if err := os.WriteFile(files.Summary, append(data, '\n'), 0o644); err != nil {
		return files, fmt.Errorf("write summary: %w", err)
	}
	return files, nil
}
