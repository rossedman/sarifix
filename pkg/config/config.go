// Package config defines sarifix.yaml: its schema, defaults, layering and
// validation.
package config

import (
	"fmt"
	"time"

	"go.yaml.in/yaml/v3"
)

// CurrentVersion is the only config schema version.
const CurrentVersion = 1

// DefaultFile is the config file name looked up in the repo root.
const DefaultFile = "sarifix.yaml"

// Scopes a scanner can rescan during verify.
const (
	ScopeChanged = "changed"
	ScopeDir     = "dir"
	ScopeRepo    = "repo"
)

// Config is the whole sarifix.yaml file.
type Config struct {
	Version   int        `yaml:"version" json:"version" doc:"Schema version. Must be 1."`
	Scanners  []Scanner  `yaml:"scanners" json:"scanners" doc:"SARIF-emitting tools sarifix can run and route findings to."`
	Rules     Rules      `yaml:"rules" json:"rules" doc:"Which rules may be fixed."`
	Paths     Paths      `yaml:"paths" json:"paths" doc:"Which files may be changed."`
	Campaigns []Campaign `yaml:"campaigns" json:"campaigns" doc:"Named migrations tracked across repos."`
	Limits    Limits     `yaml:"limits" json:"limits" doc:"Batch grouping and sizes, retries and time limits."`
	Verify    Verify     `yaml:"verify" json:"verify" doc:"How a fix is proven before it is published."`
	Agent     Agent      `yaml:"agent" json:"agent" doc:"The AI agent that writes fixes."`
	Publish   Publish    `yaml:"publish" json:"publish" doc:"How verified fixes are published."`
}

// Scanner is one SARIF-emitting tool.
type Scanner struct {
	Name    string            `yaml:"name" json:"name" doc:"Unique ID, used in rule keys and branch names." required:"true"`
	Match   []string          `yaml:"match" json:"match" doc:"SARIF tool.driver.name values routed to this scanner (case-insensitive)." default:"[name]"`
	Command []string          `yaml:"command" json:"command" doc:"argv to run, no shell. Placeholders are expanded per element. Leave it out for an imported scanner, whose findings come from code scanning (sarifix alerts export) instead, such as CodeQL."`
	Output  string            `yaml:"output" json:"output" doc:"Where the SARIF lands, for tools that choose their own file name." default:"{out}"`
	Workdir string            `yaml:"workdir" json:"workdir" doc:"Working directory for the command." default:"{repo}"`
	Env     map[string]string `yaml:"env" json:"env,omitempty" doc:"Extra environment variables."`
	Scope   string            `yaml:"scope" json:"scope" doc:"Rescan scope during verify: changed, dir or repo." default:"dir"`
	Timeout Duration          `yaml:"timeout" json:"timeout" doc:"Time limit per invocation." default:"5m"`
	Offline bool              `yaml:"offline" json:"offline" doc:"Run verify rescans with the network disabled." default:"false"`
}

// Rules selects which findings are fixable, by "<scanner>/<ruleId>" glob.
type Rules struct {
	Allow    []string `yaml:"allow" json:"allow" doc:"Rule-key globs that may be fixed. Empty allows nothing."`
	Deny     []string `yaml:"deny" json:"deny" doc:"Rule-key globs that are never fixed; wins over allow."`
	MinLevel string   `yaml:"min_level" json:"min_level" doc:"Lowest SARIF level to fix: error, warning, note or none." default:"warning"`
}

// Paths limits which files may be edited.
type Paths struct {
	Deny []string `yaml:"deny" json:"deny" doc:"Path globs (** allowed) that are never edited. .github/workflows/** is always added." default:"[.github/workflows/**]"`
}

// Campaign groups a migration's rules under one ID.
type Campaign struct {
	ID      string   `yaml:"id" json:"id" doc:"Campaign ID, used as the batch key." required:"true"`
	Scanner string   `yaml:"scanner" json:"scanner" doc:"Name of the scanner that finds the old pattern." required:"true"`
	Rules   []string `yaml:"rules" json:"rules" doc:"Rule-key globs in this campaign."`
	PRTitle string   `yaml:"pr_title" json:"pr_title" doc:"Title for the campaign's PRs."`
	Labels  []string `yaml:"labels" json:"labels" doc:"Extra labels for the campaign's PRs."`
}

// Ways findings are grouped into batches (limits.group_by).
const (
	GroupByRule = "rule"
	GroupByFile = "file"
	GroupByAuto = "auto"
)

// Limits caps the work done per batch and per run.
type Limits struct {
	GroupBy          string   `yaml:"group_by" json:"group_by" doc:"How findings become batches: rule (one per rule), file (one per scanner and file) or auto (one per rule, except that rules a scanner reports in only one file share a batch per file)." default:"rule"`
	FilesPerBatch    int      `yaml:"files_per_batch" json:"files_per_batch" doc:"Most files one batch may touch." default:"10"`
	FindingsPerBatch int      `yaml:"findings_per_batch" json:"findings_per_batch" doc:"Most findings in one batch." default:"25"`
	BatchesPerRun    int      `yaml:"batches_per_run" json:"batches_per_run" doc:"Most batches one run attempts." default:"5"`
	Retries          int      `yaml:"retries" json:"retries" doc:"Extra attempts after a failed verify." default:"2"`
	MaxDiffLines     int      `yaml:"max_diff_lines" json:"max_diff_lines" doc:"Largest diff the diff guard accepts." default:"400"`
	AgentTimeout     Duration `yaml:"agent_timeout" json:"agent_timeout" doc:"Time limit for one agent call." default:"10m"`
}

// Verify configures the checks a fix must pass.
type Verify struct {
	Commands             [][]string `yaml:"commands" json:"commands" doc:"argv lists that must each exit 0, such as [[make, test]]."`
	RequireNoNewFindings bool       `yaml:"require_no_new_findings" json:"require_no_new_findings" doc:"Fail when the rescan finds anything new." default:"true"`
}

// Agent picks the fixing agent.
type Agent struct {
	Provider          string `yaml:"provider" json:"provider" doc:"Agent implementation. v1 supports claude-code." default:"claude-code"`
	Model             string `yaml:"model" json:"model" doc:"Model name; empty uses the provider default."`
	ExtraInstructions string `yaml:"extra_instructions" json:"extra_instructions" doc:"Repo file with conventions added to every prompt."`
}

// Publish configures the mode handlers.
type Publish struct {
	PR     PRPublish     `yaml:"pr" json:"pr" doc:"Settings for --mode pr."`
	Review ReviewPublish `yaml:"review" json:"review" doc:"Settings for --mode review."`
	Issues IssuesPublish `yaml:"issues" json:"issues" doc:"Settings for --mode issues."`
}

// PRPublish configures pull requests.
type PRPublish struct {
	BranchPrefix  string   `yaml:"branch_prefix" json:"branch_prefix" doc:"Prefix for fix branches: <prefix>/<scanner>/<rule>." default:"sarifix"`
	Draft         bool     `yaml:"draft" json:"draft" doc:"Open PRs as drafts." default:"false"`
	Labels        []string `yaml:"labels" json:"labels" doc:"Labels added to every PR." default:"[sarifix]"`
	ReviewersFrom string   `yaml:"reviewers_from" json:"reviewers_from" doc:"Where reviewers come from: codeowners or none." default:"codeowners"`
}

// ReviewPublish configures review comments.
type ReviewPublish struct {
	MaxSuggestions int `yaml:"max_suggestions" json:"max_suggestions" doc:"Most suggested changes in one review." default:"20"`
}

// IssuesPublish configures one GitHub issue per batch.
type IssuesPublish struct {
	Label      string `yaml:"label" json:"label" doc:"Label on every batch issue; sarifix only manages issues that carry it." default:"sarifix"`
	MaxOpen    int    `yaml:"max_open" json:"max_open" doc:"Most batch issues open at once, the most severe batches first." default:"10"`
	Queue      int    `yaml:"queue" json:"queue" doc:"How many issues to keep labeled queue_label for an agent; 0 queues none." default:"0"`
	QueueLabel string `yaml:"queue_label" json:"queue_label" doc:"Label that hands an issue to an agent queue." default:"agent-ready"`
}

// Default returns a config with every default filled in and no scanners.
func Default() *Config {
	return &Config{
		Version: CurrentVersion,
		Rules:   Rules{MinLevel: "warning"},
		Paths:   Paths{Deny: []string{".github/workflows/**"}},
		Limits: Limits{
			GroupBy:          GroupByRule,
			FilesPerBatch:    10,
			FindingsPerBatch: 25,
			BatchesPerRun:    5,
			Retries:          2,
			MaxDiffLines:     400,
			AgentTimeout:     Duration(10 * time.Minute),
		},
		Verify: Verify{RequireNoNewFindings: true},
		Agent:  Agent{Provider: "claude-code"},
		Publish: Publish{
			PR:     PRPublish{BranchPrefix: "sarifix", Labels: []string{"sarifix"}, ReviewersFrom: "codeowners"},
			Review: ReviewPublish{MaxSuggestions: 20},
			Issues: IssuesPublish{Label: "sarifix", MaxOpen: 10, QueueLabel: "agent-ready"},
		},
	}
}

// applyScannerDefaults fills per-scanner defaults in place.
func (c *Config) applyScannerDefaults() {
	for i := range c.Scanners {
		s := &c.Scanners[i]
		if len(s.Match) == 0 && s.Name != "" {
			s.Match = []string{s.Name}
		}
		if s.Output == "" {
			s.Output = "{out}"
		}
		if s.Workdir == "" {
			s.Workdir = "{repo}"
		}
		if s.Scope == "" {
			s.Scope = ScopeDir
		}
		if s.Timeout == 0 {
			s.Timeout = Duration(5 * time.Minute)
		}
	}
}

// Imported reports whether s has no command: sarifix never runs it, and its
// findings come from elsewhere, such as code scanning alerts.
func (s Scanner) Imported() bool {
	return len(s.Command) == 0
}

// Runnable returns the scanners sarifix runs: those with a command.
func (c *Config) Runnable() []Scanner {
	var out []Scanner
	for _, s := range c.Scanners {
		if !s.Imported() {
			out = append(out, s)
		}
	}
	return out
}

// Scanner returns the scanner with the given name.
func (c *Config) Scanner(name string) (*Scanner, bool) {
	for i := range c.Scanners {
		if c.Scanners[i].Name == name {
			return &c.Scanners[i], true
		}
	}
	return nil, false
}

// Duration is a time.Duration written as a Go duration string ("5m").
type Duration time.Duration

// Std returns the value as a time.Duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// String formats the duration like time.Duration.
func (d Duration) String() string { return time.Duration(d).String() }

// UnmarshalYAML parses a duration string.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("duration must be a string like 5m: %w", err)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q", s)
	}
	if v < 0 {
		return fmt.Errorf("duration %q is negative", s)
	}
	*d = Duration(v)
	return nil
}

// MarshalYAML writes the duration as a string.
func (d Duration) MarshalYAML() (any, error) { return d.String(), nil }

// MarshalText writes the duration as a string (used by JSON).
func (d Duration) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

// UnmarshalText parses a duration string (used by JSON).
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return fmt.Errorf("invalid duration %q", b)
	}
	*d = Duration(v)
	return nil
}
