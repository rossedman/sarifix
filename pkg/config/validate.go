package config

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/rossedman/sarifix/pkg/glob"
	"github.com/rossedman/sarifix/pkg/placeholder"
)

// nameRE limits scanner names and campaign IDs to characters that are safe
// in branch names and rule keys.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// Levels accepted by rules.min_level.
var validLevels = []string{"error", "warning", "note", "none"}

// Providers accepted by agent.provider.
var validProviders = []string{"claude-code"}

// ValidateOptions tunes validation.
type ValidateOptions struct {
	// Strict also rejects rules.allow entries that cannot match any
	// configured scanner.
	Strict bool
}

// validator accumulates errors located in the source files.
type validator struct {
	l    *Loaded
	errs []*Error
}

// Validate checks the resolved config. It returns *Errors, or nil.
func (l *Loaded) Validate(opts ValidateOptions) error {
	v := &validator{l: l}
	v.version()
	v.scanners()
	v.rules(opts.Strict)
	v.paths()
	v.campaigns()
	v.limits()
	v.verify()
	v.agent()
	v.publish()
	if len(v.errs) == 0 {
		return nil
	}
	return &Errors{List: v.errs}
}

// add records an error at path p.
func (v *validator) add(p, format string, args ...any) {
	file, line := v.l.where(p)
	v.errs = append(v.errs, &Error{File: file, Path: p, Line: line, Msg: fmt.Sprintf(format, args...)})
}

// version checks the schema version.
func (v *validator) version() {
	if v.l.Version != CurrentVersion {
		v.add("version", "must be %d, got %d", CurrentVersion, v.l.Version)
	}
}

// scanners checks every scanner entry and cross-scanner rules.
func (v *validator) scanners() {
	owner := map[string]string{} // lower-cased match value -> scanner name
	seen := map[string]bool{}
	for i, s := range v.l.Scanners {
		p := "scanners[" + strconv.Itoa(i) + "]"
		switch {
		case s.Name == "":
			v.add(p+".name", "is required")
		case !nameRE.MatchString(s.Name):
			v.add(p+".name", "%q may only contain letters, digits, '.', '_' and '-'", s.Name)
		case seen[s.Name]:
			v.add(p+".name", "duplicate scanner name %q", s.Name)
		}
		seen[s.Name] = true

		if len(s.Command) > 0 && s.Command[0] == "" {
			v.add(p+".command", "must not be empty")
		}
		for j, a := range s.Command {
			v.placeholders(fmt.Sprintf("%s.command[%d]", p, j), a)
		}
		v.placeholders(p+".output", s.Output)
		v.placeholders(p+".workdir", s.Workdir)
		for k, val := range s.Env {
			v.placeholders(p+".env."+k, val)
		}
		switch s.GroupBy {
		case "", GroupByRule, GroupByFile, GroupByAuto:
		default:
			v.add(p+".group_by", "must be rule, file or auto, got %q", s.GroupBy)
		}
		switch s.Scope {
		case ScopeChanged, ScopeDir, ScopeRepo:
		default:
			v.add(p+".scope", "must be changed, dir or repo, got %q", s.Scope)
		}
		for j, m := range s.Match {
			mp := fmt.Sprintf("%s.match[%d]", p, j)
			if m == "" {
				v.add(mp, "must not be empty")
				continue
			}
			key := strings.ToLower(m)
			if other, ok := owner[key]; ok && other != s.Name {
				v.add(mp, "%q is already matched by scanner %q", m, other)
				continue
			}
			owner[key] = s.Name
		}
	}
}

// placeholders reports unknown placeholders in a templated string.
func (v *validator) placeholders(p, s string) {
	for _, n := range placeholder.Unknown(s) {
		v.add(p, "unknown placeholder {%s} (known: {%s})", n, strings.Join(placeholder.Names, "}, {"))
	}
}

// rules checks allow/deny globs and the level floor.
func (v *validator) rules(strict bool) {
	r := v.l.Rules
	for i, g := range r.Allow {
		p := fmt.Sprintf("rules.allow[%d]", i)
		if !v.keyGlob(p, g) {
			continue
		}
		if strict && !v.matchesAnyScanner(g) {
			v.add(p, "%q matches no configured scanner", g)
		}
	}
	for i, g := range r.Deny {
		v.keyGlob(fmt.Sprintf("rules.deny[%d]", i), g)
	}
	if !contains(validLevels, r.MinLevel) {
		v.add("rules.min_level", "must be one of %s, got %q", strings.Join(validLevels, ", "), r.MinLevel)
	}
}

// keyGlob validates a "<scanner>/<rule>" glob and reports whether it is ok.
func (v *validator) keyGlob(p, g string) bool {
	if !strings.Contains(g, "/") {
		v.add(p, "%q must look like <scanner>/<ruleId>", g)
		return false
	}
	if err := glob.ValidateKey(g); err != nil {
		v.add(p, "bad glob %q: %v", g, err)
		return false
	}
	return true
}

// matchesAnyScanner reports whether the scanner part of a rule glob can
// match a configured scanner name.
func (v *validator) matchesAnyScanner(g string) bool {
	scannerPart := g[:strings.Index(g, "/")]
	for _, s := range v.l.Scanners {
		if glob.MatchKey(scannerPart, s.Name) {
			return true
		}
	}
	return false
}

// paths checks path deny globs.
func (v *validator) paths() {
	for i, g := range v.l.Paths.Deny {
		if err := glob.ValidatePath(g); err != nil {
			v.add(fmt.Sprintf("paths.deny[%d]", i), "bad glob %q: %v", g, err)
		}
	}
}

// campaigns checks campaign IDs, scanners and rule globs.
func (v *validator) campaigns() {
	seen := map[string]bool{}
	for i, c := range v.l.Campaigns {
		p := "campaigns[" + strconv.Itoa(i) + "]"
		switch {
		case c.ID == "":
			v.add(p+".id", "is required")
		case !nameRE.MatchString(c.ID):
			v.add(p+".id", "%q may only contain letters, digits, '.', '_' and '-'", c.ID)
		case seen[c.ID]:
			v.add(p+".id", "duplicate campaign id %q", c.ID)
		}
		seen[c.ID] = true
		if c.Scanner == "" {
			v.add(p+".scanner", "is required")
		} else if _, ok := v.l.Scanner(c.Scanner); !ok {
			v.add(p+".scanner", "unknown scanner %q", c.Scanner)
		}
		if len(c.Rules) == 0 {
			v.add(p+".rules", "must list at least one rule glob")
		}
		for j, g := range c.Rules {
			v.keyGlob(fmt.Sprintf("%s.rules[%d]", p, j), g)
		}
	}
}

// limits checks that every limit is in range.
func (v *validator) limits() {
	lm := v.l.Limits
	switch lm.GroupBy {
	case GroupByRule, GroupByFile, GroupByAuto:
	default:
		v.add("limits.group_by", "must be rule, file or auto, got %q", lm.GroupBy)
	}
	for _, x := range []struct {
		name string
		val  int
	}{
		{"files_per_batch", lm.FilesPerBatch},
		{"findings_per_batch", lm.FindingsPerBatch},
		{"batches_per_run", lm.BatchesPerRun},
		{"max_diff_lines", lm.MaxDiffLines},
	} {
		if x.val < 1 {
			v.add("limits."+x.name, "must be at least 1, got %d", x.val)
		}
	}
	if lm.Retries < 0 {
		v.add("limits.retries", "must not be negative, got %d", lm.Retries)
	}
	if lm.AgentTimeout <= 0 {
		v.add("limits.agent_timeout", "must be positive")
	}
}

// verify checks verify commands.
func (v *validator) verify() {
	for i, c := range v.l.Verify.Commands {
		if len(c) == 0 || c[0] == "" {
			v.add(fmt.Sprintf("verify.commands[%d]", i), "must not be empty")
		}
	}
}

// agent checks the agent provider.
func (v *validator) agent() {
	if !contains(validProviders, v.l.Agent.Provider) {
		v.add("agent.provider", "must be one of %s, got %q", strings.Join(validProviders, ", "), v.l.Agent.Provider)
	}
}

// publish checks publish settings.
func (v *validator) publish() {
	pr := v.l.Publish.PR
	if !nameRE.MatchString(pr.BranchPrefix) {
		v.add("publish.pr.branch_prefix", "%q is not a valid branch name component", pr.BranchPrefix)
	}
	if pr.ReviewersFrom != "codeowners" && pr.ReviewersFrom != "none" {
		v.add("publish.pr.reviewers_from", "must be codeowners or none, got %q", pr.ReviewersFrom)
	}
	if v.l.Publish.Review.MaxSuggestions < 0 {
		v.add("publish.review.max_suggestions", "must not be negative")
	}
	is := v.l.Publish.Issues
	for _, l := range []struct{ key, name string }{{"publish.issues.label", is.Label}, {"publish.issues.queue_label", is.QueueLabel}} {
		if strings.TrimSpace(l.name) == "" || strings.Contains(l.name, ",") || len(l.name) > 50 {
			v.add(l.key, "must be a GitHub label name (1 to 50 characters, no commas), got %q", l.name)
		}
	}
	if is.Label == is.QueueLabel {
		v.add("publish.issues.queue_label", "must differ from publish.issues.label")
	}
	if is.MaxOpen < 1 {
		v.add("publish.issues.max_open", "must be at least 1")
	}
	if is.Queue < 0 || is.Queue > is.MaxOpen {
		v.add("publish.issues.queue", "must be between 0 and max_open (%d), got %d", is.MaxOpen, is.Queue)
	}
}

// listIndex matches a leading "scanners[N]" or "campaigns[N]".
var listIndex = regexp.MustCompile(`^(scanners|campaigns)\[(\d+)\]`)

// where maps a path in the merged config to the file and line that set it.
// Paths that no file sets (defaults) report the last file and line 0.
func (l *Loaded) where(p string) (string, int) {
	if len(l.Files) == 0 {
		return "", 0
	}
	if m := listIndex.FindStringSubmatch(p); m != nil {
		i, _ := strconv.Atoi(m[2])
		from := l.scannerFrom
		if m[1] == "campaigns" {
			from = l.campaignFrom
		}
		if i < len(from) {
			f := l.Files[from[i].file]
			local := m[1] + "[" + strconv.Itoa(from[i].index) + "]" + p[len(m[0]):]
			return f.Name, f.Line(local)
		}
	}
	for i := len(l.Files) - 1; i >= 0; i-- {
		if line, ok := l.Files[i].lines[p]; ok {
			return l.Files[i].Name, line
		}
	}
	last := l.Files[len(l.Files)-1]
	return last.Name, last.Line(p)
}
