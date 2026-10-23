package policy

import (
	"testing"

	"github.com/rossedman/sarifix/pkg/config"
	"github.com/rossedman/sarifix/pkg/finding"
)

// cfg returns a config exercising every check.
func cfg() *config.Config {
	c := config.Default()
	c.Scanners = []config.Scanner{
		{Name: "trivy", Match: []string{"Trivy"}},
		{Name: "migrate", Match: []string{"image-migrate"}},
	}
	c.Rules.Allow = []string{"trivy/*"}
	c.Rules.Deny = []string{"*/secret-*"}
	c.Paths.Deny = []string{".github/workflows/**", "vendor/**"}
	c.Campaigns = []config.Campaign{{ID: "base-v4", Scanner: "migrate", Rules: []string{"migrate/OLD_*"}}}
	return c
}

// f builds a located finding.
func f(tool, rule, level, path, fp string) finding.Finding {
	return finding.Finding{Tool: tool, RuleID: rule, Level: level, Path: path, StartLine: 1, Fingerprint: fp}
}

func TestApply(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		f        finding.Finding
		opts     Options
		want     Reason
		detail   string
		campaign string
	}{
		{"fixable", f("Trivy", "DS-1", "error", "Dockerfile", "a"), Options{}, "", "", ""},
		{"case-insensitive route", f("TRIVY", "DS-1", "error", "Dockerfile", "a"), Options{}, "", "", ""},
		{"unrouted", f("checkov", "C1", "error", "x.tf", "a"), Options{}, ReasonUnrouted, "no scanner matches tool checkov", ""},
		{"no location", f("Trivy", "DS-1", "error", "", "a"), Options{}, ReasonNoLocation, "", ""},
		{"baseline", f("Trivy", "DS-1", "error", "Dockerfile", "old"), Options{Baseline: map[string]int{"old": 1}}, ReasonInBaseline, "", ""},
		{"below level", f("Trivy", "DS-1", "note", "Dockerfile", "a"), Options{}, ReasonBelowMinLevel, "note < warning", ""},
		{"none level", f("Trivy", "DS-1", "none", "Dockerfile", "a"), Options{}, ReasonBelowMinLevel, "none < warning", ""},
		{"denied", f("Trivy", "secret-aws", "error", "a.env", "a"), Options{}, ReasonRuleDenied, "*/secret-*", ""},
		{"not allowed", f("image-migrate", "OTHER", "error", "Dockerfile", "a"), Options{}, ReasonNotAllowed, "", ""},
		{"allow ignored", f("image-migrate", "OTHER", "error", "Dockerfile", "a"), Options{IgnoreAllow: true}, "", "", ""},
		{"deny still applies", f("Trivy", "secret-aws", "error", "a.env", "a"), Options{IgnoreAllow: true}, ReasonRuleDenied, "*/secret-*", ""},
		{"campaign implies allow", f("image-migrate", "OLD_BASE", "warning", "Dockerfile", "a"), Options{}, "", "", "base-v4"},
		{"workflow denied", f("Trivy", "DS-1", "error", ".github/workflows/ci.yml", "a"), Options{}, ReasonPathDenied, ".github/workflows/**", ""},
		{"vendor denied", f("Trivy", "DS-1", "error", "vendor/x/Dockerfile", "a"), Options{}, ReasonPathDenied, "vendor/**", ""},
		{"rule selected", f("Trivy", "DS-1", "error", "Dockerfile", "a"), Options{Rules: []string{"trivy/DS-*"}}, "", "", ""},
		{"rule not selected", f("Trivy", "DS-1", "error", "Dockerfile", "a"), Options{Rules: []string{"trivy/AWS-*"}}, ReasonNotSelected, "--rule", ""},
		{"campaign selected", f("image-migrate", "OLD_BASE", "warning", "Dockerfile", "a"), Options{Campaign: "base-v4"}, "", "", "base-v4"},
		{"not in campaign", f("Trivy", "DS-1", "error", "Dockerfile", "a"), Options{Campaign: "base-v4"}, ReasonNotSelected, "--campaign base-v4", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := New(cfg(), tt.opts).Apply([]finding.Finding{tt.f})[0]
			if got.Skip != tt.want || got.Detail != tt.detail || got.Campaign != tt.campaign {
				t.Errorf("got skip=%q detail=%q campaign=%q", got.Skip, got.Detail, got.Campaign)
			}
		})
	}
}

func TestBaselineIsAMultiset(t *testing.T) {
	t.Parallel()
	base := map[string]int{"x": 1}
	p := New(cfg(), Options{Baseline: base})
	items := p.Apply([]finding.Finding{f("Trivy", "R", "error", "a", "x"), f("Trivy", "R", "error", "a", "x")})
	if items[0].Skip != ReasonInBaseline || items[1].Skip != "" {
		t.Errorf("got %q %q", items[0].Skip, items[1].Skip)
	}
	if base["x"] != 1 {
		t.Error("Apply consumed the caller's baseline map")
	}
	// A second Apply starts from the full baseline again.
	if again := p.Apply([]finding.Finding{f("Trivy", "R", "error", "a", "x")}); again[0].Skip != ReasonInBaseline {
		t.Error("baseline not reset between calls")
	}
}

func TestKeyAndFixable(t *testing.T) {
	t.Parallel()
	items := New(cfg(), Options{}).Apply([]finding.Finding{
		f("Trivy", "DS-1", "error", "Dockerfile", "a"),
		f("checkov", "C1", "error", "x.tf", "b"),
	})
	if items[0].Key() != "trivy/DS-1" || items[1].Key() != "checkov/C1" {
		t.Errorf("keys %q %q", items[0].Key(), items[1].Key())
	}
	if got := Fixable(items); len(got) != 1 || got[0].RuleID != "DS-1" {
		t.Errorf("Fixable = %+v", got)
	}
	if len(Reasons) != 8 {
		t.Errorf("Reasons has %d entries", len(Reasons))
	}
}

func BenchmarkApply(b *testing.B) {
	fs := make([]finding.Finding, 10_000)
	for i := range fs {
		fs[i] = f("Trivy", "DS-1", "error", "modules/m/main.tf", "fp")
	}
	p := New(cfg(), Options{Rules: []string{"trivy/*"}})
	b.ReportAllocs()
	for b.Loop() {
		p.Apply(fs)
	}
}
