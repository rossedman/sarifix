// Package policy decides which findings sarifix may fix. Every finding it
// drops gets a reason, so plans and reports can say why nothing happened.
package policy

import (
	"strings"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
	"github.com/rossedman/sarifix/pkg/glob"
)

// Reason says why a finding was skipped.
type Reason string

// Skip reasons, in the order checks run.
const (
	ReasonUnrouted      Reason = "unrouted"        // no scanner matches tool.driver.name
	ReasonNoLocation    Reason = "no_location"     // no physical file location in the repo
	ReasonInBaseline    Reason = "in_baseline"     // also present in the --baseline scan
	ReasonBelowMinLevel Reason = "below_min_level" // level under rules.min_level
	ReasonRuleDenied    Reason = "rule_denied"     // matches rules.deny
	ReasonNotAllowed    Reason = "rule_not_allowed"
	ReasonPathDenied    Reason = "path_denied"  // file matches paths.deny
	ReasonNotSelected   Reason = "not_selected" // excluded by --rule or --campaign
)

// Reasons lists every skip reason in check order.
var Reasons = []Reason{
	ReasonUnrouted, ReasonNoLocation, ReasonInBaseline, ReasonBelowMinLevel,
	ReasonRuleDenied, ReasonNotAllowed, ReasonPathDenied, ReasonNotSelected,
}

// Item is a finding with the policy's verdict on it.
type Item struct {
	finding.Finding
	// Scanner is the configured scanner that owns the finding, or "" when
	// unrouted.
	Scanner string `json:"scanner,omitempty"`
	// Campaign is the campaign ID the finding belongs to, if any.
	Campaign string `json:"campaign,omitempty"`
	// Skip is empty for fixable findings.
	Skip Reason `json:"skip,omitempty"`
	// Detail explains the skip, such as the glob that denied it.
	Detail string `json:"detail,omitempty"`
}

// Key is the item's rule key, "<scanner>/<ruleId>". Unrouted findings use
// the SARIF tool name instead.
func (it Item) Key() string {
	if it.Scanner == "" {
		return finding.RuleKey(it.Tool, it.RuleID)
	}
	return finding.RuleKey(it.Scanner, it.RuleID)
}

// Options narrow what one run works on, beyond the config.
type Options struct {
	// Rules keeps only rule keys matching one of these globs (--rule).
	Rules []string
	// Campaign keeps only findings in this campaign (--campaign).
	Campaign string
	// Baseline holds fingerprints of findings that existed before; those are
	// skipped (--baseline).
	Baseline map[string]int
	// IgnoreAllow skips the rules.allow check. rules.allow says what sarifix
	// may fix on its own; feedback on a change (sarifix check) covers every
	// rule that isn't denied.
	IgnoreAllow bool
}

// Policy applies a config's rules to findings.
type Policy struct {
	cfg  *config.Config
	opts Options
}

// New returns a Policy for cfg.
func New(cfg *config.Config, opts Options) *Policy {
	return &Policy{cfg: cfg, opts: opts}
}

// Route returns the configured scanner name for a SARIF tool.driver.name,
// matched case-insensitively.
func (p *Policy) Route(driver string) (string, bool) {
	for _, s := range p.cfg.Scanners {
		for _, m := range s.Match {
			if strings.EqualFold(m, driver) {
				return s.Name, true
			}
		}
	}
	return "", false
}

// campaign returns the ID of the first campaign covering key, if any.
func (p *Policy) campaign(scanner, key string) string {
	for _, c := range p.cfg.Campaigns {
		if c.Scanner != scanner {
			continue
		}
		for _, g := range c.Rules {
			if glob.MatchKey(g, key) {
				return c.ID
			}
		}
	}
	return ""
}

// Apply judges every finding and returns one Item per finding, in order.
// Fixable items have an empty Skip.
func (p *Policy) Apply(fs []finding.Finding) []Item {
	baseline := make(map[string]int, len(p.opts.Baseline))
	for k, v := range p.opts.Baseline {
		baseline[k] = v
	}
	out := make([]Item, len(fs))
	for i, f := range fs {
		out[i] = p.judge(f, baseline)
	}
	return out
}

// judge applies the checks to one finding. baseline is consumed as a
// multiset so two identical new findings aren't hidden by one old one.
func (p *Policy) judge(f finding.Finding, baseline map[string]int) Item {
	it := Item{Finding: f}
	scanner, ok := p.Route(f.Tool)
	if !ok {
		return it.skip(ReasonUnrouted, "no scanner matches tool "+f.Tool)
	}
	it.Scanner = scanner
	key := it.Key()
	it.Campaign = p.campaign(scanner, key)

	if !f.Located() {
		return it.skip(ReasonNoLocation, "")
	}
	if baseline[f.Fingerprint] > 0 {
		baseline[f.Fingerprint]--
		return it.skip(ReasonInBaseline, "")
	}
	if finding.LevelRank(f.Level) < finding.LevelRank(p.cfg.Rules.MinLevel) {
		return it.skip(ReasonBelowMinLevel, f.Level+" < "+p.cfg.Rules.MinLevel)
	}
	if g, ok := firstKeyMatch(p.cfg.Rules.Deny, key); ok {
		return it.skip(ReasonRuleDenied, g)
	}
	// A campaign's rules are allowed by being in the campaign.
	if it.Campaign == "" && !p.opts.IgnoreAllow {
		if _, ok := firstKeyMatch(p.cfg.Rules.Allow, key); !ok {
			return it.skip(ReasonNotAllowed, "")
		}
	}
	if g, ok := firstPathMatch(p.cfg.Paths.Deny, f.Path); ok {
		return it.skip(ReasonPathDenied, g)
	}
	if len(p.opts.Rules) > 0 {
		if _, ok := firstKeyMatch(p.opts.Rules, key); !ok {
			return it.skip(ReasonNotSelected, "--rule")
		}
	}
	if p.opts.Campaign != "" && it.Campaign != p.opts.Campaign {
		return it.skip(ReasonNotSelected, "--campaign "+p.opts.Campaign)
	}
	return it
}

// skip marks the item skipped.
func (it Item) skip(r Reason, detail string) Item {
	it.Skip, it.Detail = r, detail
	return it
}

// firstKeyMatch returns the first rule-key glob matching key.
func firstKeyMatch(globs []string, key string) (string, bool) {
	for _, g := range globs {
		if glob.MatchKey(g, key) {
			return g, true
		}
	}
	return "", false
}

// firstPathMatch returns the first path glob matching path.
func firstPathMatch(globs []string, path string) (string, bool) {
	for _, g := range globs {
		if glob.MatchPath(g, path) {
			return g, true
		}
	}
	return "", false
}

// Fixable returns the items with no skip reason.
func Fixable(items []Item) []Item {
	var out []Item
	for _, it := range items {
		if it.Skip == "" {
			out = append(out, it)
		}
	}
	return out
}
