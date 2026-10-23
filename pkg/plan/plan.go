// Package plan runs the read-only half of the pipeline: filter findings
// through policy, group the fixable ones into batches, and record a status
// for every finding. Plan mode prints it; report mode writes it out.
package plan

import (
	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/group"
	"github.com/rossedman/sarifix/pkg/policy"
	"github.com/rossedman/sarifix/pkg/sarif"
)

// Statuses a finding can have in a plan.
const (
	// StatusBatched findings are in a batch this run would attempt.
	StatusBatched = "batched"
	// StatusDeferred findings are fixable but their batch is over
	// limits.batches_per_run; a later run picks them up.
	StatusDeferred = "deferred"
	// StatusSkipped findings are not fixable; Reason says why.
	StatusSkipped = "skipped"
)

// Options select what a run works on.
type Options struct {
	// Rules keeps only rule keys matching these globs (--rule).
	Rules []string
	// Campaign keeps only this campaign's findings (--campaign).
	Campaign string
	// Baseline findings are skipped as pre-existing (--baseline).
	Baseline []finding.Finding
}

// Status is one finding's outcome, written to properties.sarifix in
// enriched SARIF.
type Status struct {
	Status      string `json:"status"`
	Reason      string `json:"reason,omitempty"`
	Detail      string `json:"detail,omitempty"`
	Scanner     string `json:"scanner,omitempty"`
	RuleKey     string `json:"ruleKey"`
	Campaign    string `json:"campaign,omitempty"`
	Batch       string `json:"batch,omitempty"`
	Branch      string `json:"branch,omitempty"`
	Fingerprint string `json:"fingerprint"`
}

// Entry pairs an item with its status.
type Entry struct {
	policy.Item
	Status Status
}

// Plan is the full outcome for one set of findings.
type Plan struct {
	Entries      []Entry
	Batches      group.Result
	BranchPrefix string
}

// Build judges findings against cfg and groups the fixable ones.
func Build(cfg *config.Config, fs []finding.Finding, opts Options) *Plan {
	var base map[string]int
	if len(opts.Baseline) > 0 {
		base = make(map[string]int, len(opts.Baseline))
		for _, f := range opts.Baseline {
			base[f.Fingerprint]++
		}
	}
	items := policy.New(cfg, policy.Options{Rules: opts.Rules, Campaign: opts.Campaign, Baseline: base}).Apply(fs)
	p := &Plan{Batches: group.Batches(items, cfg.Limits), BranchPrefix: cfg.Publish.PR.BranchPrefix}

	type where struct {
		batch, branch, status string
	}
	placed := map[itemID]where{}
	for status, bs := range map[string][]group.Batch{StatusBatched: p.Batches.Run, StatusDeferred: p.Batches.Deferred} {
		for _, b := range bs {
			for _, it := range b.Findings {
				placed[idOf(it.Finding)] = where{b.ID(), b.Branch(p.BranchPrefix), status}
			}
		}
	}
	p.Entries = make([]Entry, len(items))
	for i, it := range items {
		st := Status{
			Status: StatusSkipped, Reason: string(it.Skip), Detail: it.Detail,
			Scanner: it.Scanner, RuleKey: it.Key(), Campaign: it.Campaign, Fingerprint: it.Fingerprint,
		}
		if w, ok := placed[idOf(it.Finding)]; ok {
			st.Status, st.Batch, st.Branch = w.status, w.batch, w.branch
		}
		p.Entries[i] = Entry{Item: it, Status: st}
	}
	return p
}

// itemID identifies a finding across copies: its SARIF result when known,
// plus its fingerprint (which is unique within a run).
type itemID struct {
	run *sarif.SourcedRun
	idx int
	fp  string
}

// idOf returns f's identity.
func idOf(f finding.Finding) itemID {
	return itemID{run: f.Run, idx: f.ResultIndex, fp: f.Fingerprint}
}

// Annotate records each entry's status on its SARIF result as
// properties.sarifix, so the log can be written out as enriched SARIF.
func (p *Plan) Annotate() {
	for _, e := range p.Entries {
		if e.Run != nil {
			e.Run.SetResultProperty(e.ResultIndex, "sarifix", e.Status)
		}
	}
}

// BatchSummary describes one batch in the JSON summary.
type BatchSummary struct {
	ID       string   `json:"id"`
	Key      string   `json:"key"`
	Branch   string   `json:"branch"`
	Scanner  string   `json:"scanner"`
	RuleID   string   `json:"ruleId,omitempty"`
	Campaign string   `json:"campaign,omitempty"`
	File     string   `json:"file,omitempty"`
	Rules    []string `json:"rules"`
	Level    string   `json:"level"`
	Findings int      `json:"findings"`
	Files    []string `json:"files"`
}

// Summary is the JSON summary of a plan.
type Summary struct {
	Findings int            `json:"findings"`
	Batched  int            `json:"batched"`
	Deferred int            `json:"deferred"`
	Skipped  map[string]int `json:"skipped"`
	// Run lists the batches this run would attempt, in order.
	Run []BatchSummary `json:"batches"`
	// Later lists batches over the per-run cap.
	Later []BatchSummary `json:"deferredBatches"`
}

// Summarize counts statuses and lists batches.
func (p *Plan) Summarize() Summary {
	s := Summary{Findings: len(p.Entries), Skipped: map[string]int{}, Run: []BatchSummary{}, Later: []BatchSummary{}}
	for _, e := range p.Entries {
		switch e.Status.Status {
		case StatusBatched:
			s.Batched++
		case StatusDeferred:
			s.Deferred++
		default:
			s.Skipped[e.Status.Reason]++
		}
	}
	for _, b := range p.Batches.Run {
		s.Run = append(s.Run, p.batchSummary(b))
	}
	for _, b := range p.Batches.Deferred {
		s.Later = append(s.Later, p.batchSummary(b))
	}
	return s
}

// batchSummary converts a batch for the summary.
func (p *Plan) batchSummary(b group.Batch) BatchSummary {
	return BatchSummary{
		ID: b.ID(), Key: b.Key, Branch: b.Branch(p.BranchPrefix), Scanner: b.Scanner, RuleID: b.RuleID,
		Campaign: b.Campaign, File: b.File, Rules: b.Rules, Level: b.Level, Findings: len(b.Findings), Files: b.Files,
	}
}

// SkipCount is one skip reason with its count, for ordered display.
type SkipCount struct {
	Reason string
	Count  int
}

// SkipCounts returns non-zero skip counts in the order checks run.
func (s Summary) SkipCounts() []SkipCount {
	var out []SkipCount
	for _, r := range policy.Reasons {
		if n := s.Skipped[string(r)]; n > 0 {
			out = append(out, SkipCount{string(r), n})
		}
	}
	return out
}
