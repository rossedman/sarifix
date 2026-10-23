// Package group batches fixable findings into small single-rule units of
// work, each of which becomes one branch and one PR.
package group

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/policy"
)

// Batch is a set of findings for one rule (or one campaign) that is fixed,
// verified and published together.
type Batch struct {
	// Key is "<scanner>/<ruleId>", or the campaign ID for campaign batches.
	Key      string `json:"key"`
	Scanner  string `json:"scanner"`
	RuleID   string `json:"ruleId,omitempty"`
	Campaign string `json:"campaign,omitempty"`
	// Part numbers the batches a key was split into, from 1.
	Part int `json:"part"`
	// Level is the most severe level among the findings.
	Level    string        `json:"level"`
	Files    []string      `json:"files"`
	Findings []policy.Item `json:"findings"`
}

// ID is Key plus "#<part>" when the key was split into several batches.
func (b Batch) ID() string {
	if b.Part > 1 {
		return fmt.Sprintf("%s#%d", b.Key, b.Part)
	}
	return b.Key
}

// Branch is the batch's fix branch: <prefix>/<scanner>/<rule-slug>, or
// <prefix>/campaign/<id> for campaigns, with "-<part>" for later parts.
// Re-running on the same input yields the same branch names.
func (b Batch) Branch(prefix string) string {
	var name string
	if b.Campaign != "" {
		name = prefix + "/campaign/" + Slug(b.Campaign)
	} else {
		name = prefix + "/" + Slug(b.Scanner) + "/" + Slug(b.RuleID)
	}
	if b.Part > 1 {
		name += fmt.Sprintf("-%d", b.Part)
	}
	return name
}

// Result is the outcome of grouping.
type Result struct {
	// Run are the batches this run attempts, at most limits.batches_per_run.
	Run []Batch `json:"run"`
	// Deferred are batches over the per-run cap, in priority order.
	Deferred []Batch `json:"deferred"`
}

// Batches groups fixable items by rule (or campaign), splits groups to fit
// files_per_batch and findings_per_batch, orders them by the group's
// severity then size (keeping a group's parts together and in order), and
// caps the run at batches_per_run.
func Batches(items []policy.Item, lim config.Limits) Result {
	type groupT struct {
		key, scanner, rule, campaign string
		items                        []policy.Item
	}
	var order []string
	groups := map[string]*groupT{}
	for _, it := range items {
		if it.Skip != "" {
			continue
		}
		g := &groupT{key: it.Key(), scanner: it.Scanner, rule: it.RuleID}
		if it.Campaign != "" {
			g = &groupT{key: it.Campaign, scanner: it.Scanner, campaign: it.Campaign}
		}
		if existing, ok := groups[g.key]; ok {
			g = existing
		} else {
			groups[g.key] = g
			order = append(order, g.key)
		}
		g.items = append(g.items, it)
	}

	var all []Batch
	for _, k := range order {
		g := groups[k]
		for i, part := range split(g.items, lim.FilesPerBatch, lim.FindingsPerBatch) {
			b := Batch{Key: g.key, Scanner: g.scanner, RuleID: g.rule, Campaign: g.campaign, Part: i + 1, Findings: part}
			b.Files, b.Level = summarize(part)
			all = append(all, b)
		}
	}
	// Rank keys by their most severe finding, then total size; a key's parts
	// stay together and in order.
	type rank struct{ level, size int }
	ranks := map[string]rank{}
	for _, b := range all {
		r := ranks[b.Key]
		r.level = max(r.level, finding.LevelRank(b.Level))
		r.size += len(b.Findings)
		ranks[b.Key] = r
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, b := all[i], all[j]
		ra, rb := ranks[a.Key], ranks[b.Key]
		if ra.level != rb.level {
			return ra.level > rb.level
		}
		if ra.size != rb.size {
			return ra.size > rb.size
		}
		if a.Key != b.Key {
			return a.Key < b.Key
		}
		return a.Part < b.Part
	})
	n := min(max(lim.BatchesPerRun, 0), len(all))
	return Result{Run: all[:n], Deferred: all[n:]}
}

// split orders items by file and line, then cuts them into parts holding at
// most maxFiles distinct files and maxFindings findings. A file never spans
// two parts unless it alone has more than maxFindings findings.
func split(items []policy.Item, maxFiles, maxFindings int) [][]policy.Item {
	maxFiles, maxFindings = max(maxFiles, 1), max(maxFindings, 1)
	sorted := slices.Clone(items)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Path != sorted[j].Path {
			return sorted[i].Path < sorted[j].Path
		}
		return sorted[i].StartLine < sorted[j].StartLine
	})
	// Bucket by file so whole files move between parts.
	var files [][]policy.Item
	for _, it := range sorted {
		if n := len(files); n > 0 && files[n-1][0].Path == it.Path {
			files[n-1] = append(files[n-1], it)
			continue
		}
		files = append(files, []policy.Item{it})
	}
	var parts [][]policy.Item
	var cur []policy.Item
	curFiles := 0
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, cur)
		}
		cur, curFiles = nil, 0
	}
	for _, f := range files {
		if len(cur) > 0 && (curFiles+1 > maxFiles || len(cur)+len(f) > maxFindings) {
			flush()
		}
		for len(f) > maxFindings {
			// One file with too many findings: give it parts of its own.
			flush()
			parts = append(parts, f[:maxFindings])
			f = f[maxFindings:]
		}
		cur = append(cur, f...)
		curFiles++
	}
	flush()
	return parts
}

// summarize returns a part's sorted file list and its highest level.
func summarize(items []policy.Item) ([]string, string) {
	seen := map[string]bool{}
	var files []string
	level := finding.LevelNone
	for _, it := range items {
		if !seen[it.Path] {
			seen[it.Path] = true
			files = append(files, it.Path)
		}
		if finding.LevelRank(it.Level) > finding.LevelRank(level) {
			level = it.Level
		}
	}
	sort.Strings(files)
	return files, level
}

// slugUnsafe matches runs of characters not allowed in a slug.
var slugUnsafe = regexp.MustCompile(`[^a-z0-9._-]+`)

// maxSlug bounds a slug's length so branch names stay readable.
const maxSlug = 60

// Slug makes s safe for a git branch name component: lower case, runs of
// other characters become "-". When that does more than change case, or the
// result is truncated, a short hash of the original is appended so distinct
// IDs don't share a slug. (IDs differing only in case do share one.) An
// empty result, or one ending in ".lock" (which git refuses), also gets the
// hash.
func Slug(s string) string {
	out := strings.Trim(slugUnsafe.ReplaceAllString(strings.ToLower(s), "-"), "-.")
	for strings.Contains(out, "..") {
		out = strings.ReplaceAll(out, "..", ".")
	}
	if out != "" && out == strings.ToLower(s) && len(out) <= maxSlug && !strings.HasSuffix(out, ".lock") {
		return out
	}
	if len(out) > maxSlug {
		out = strings.TrimRight(out[:maxSlug], "-.")
	}
	sum := sha256.Sum256([]byte(s))
	h := hex.EncodeToString(sum[:])[:6]
	if out == "" {
		return h
	}
	return out + "-" + h
}
