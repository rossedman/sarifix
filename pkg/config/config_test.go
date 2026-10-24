package config

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadExample(t *testing.T) {
	t.Parallel()
	l, err := Load(filepath.Join("..", "..", "examples", "sarifix.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Validate(ValidateOptions{Strict: true}); err != nil {
		t.Fatal(err)
	}
	if len(l.Scanners) != 4 {
		t.Fatalf("got %d scanners", len(l.Scanners))
	}
	gl, _ := l.Scanner("golangci-lint")
	if !slices.Equal(gl.Match, []string{"golangci-lint"}) || gl.Output != "{out}" || gl.Timeout.Std() != 5*time.Minute {
		t.Errorf("defaults not applied: %+v", gl)
	}
	tr, _ := l.Scanner("trivy")
	if tr.Workdir != "{repo}" || tr.Scope != ScopeDir || !tr.Offline {
		t.Errorf("trivy: %+v", tr)
	}
	if l.Limits.AgentTimeout.Std() != 10*time.Minute || l.Publish.Review.MaxSuggestions != 20 {
		t.Errorf("limits/publish: %+v %+v", l.Limits, l.Publish)
	}
	if _, ok := l.Scanner("nope"); ok {
		t.Error("found unknown scanner")
	}
}

func TestDefaultsWithEmptyFile(t *testing.T) {
	t.Parallel()
	l, err := Parse("empty.yaml", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Validate(ValidateOptions{}); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l.Paths.Deny, AlwaysDeniedPaths) || !l.Verify.RequireNoNewFindings || l.Rules.MinLevel != "warning" {
		t.Errorf("defaults: %+v", l.Config)
	}
}

func TestWorkflowsAlwaysDenied(t *testing.T) {
	t.Parallel()
	l, err := Parse("x.yaml", []byte("version: 1\npaths:\n  deny: [vendor/**]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l.Paths.Deny, []string{".github/workflows/**", "vendor/**"}) {
		t.Errorf("deny = %v", l.Paths.Deny)
	}
}

func TestLayered(t *testing.T) {
	t.Parallel()
	l, err := LoadLayered(filepath.Join("testdata", "org.yaml"), filepath.Join("testdata", "repo.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range l.Scanners {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"trivy", "checkov", "golangci-lint"}) {
		t.Fatalf("scanners = %v", names)
	}
	tr, _ := l.Scanner("trivy")
	if tr.Command[1] != "fs" || tr.Timeout.Std() != 2*time.Minute {
		t.Errorf("repo trivy did not win: %+v", tr)
	}
	if !slices.Equal(l.Rules.Allow, []string{"golangci-lint/errcheck"}) {
		t.Errorf("allow = %v, want repo list", l.Rules.Allow)
	}
	if l.Limits.Retries != 1 {
		t.Errorf("retries = %d, want org value 1", l.Limits.Retries)
	}
	if len(l.Files) != 2 {
		t.Errorf("files = %d", len(l.Files))
	}
}

func TestLayeredErrorsPointAtSourceFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	org := write(t, dir, "org.yaml", "version: 1\nscanners:\n  - name: a\n    command: [a, \"{bogus}\"]\n")
	repo := write(t, dir, "repo.yaml", "version: 1\nscanners:\n  - name: b\n    command: []\n")
	l, err := LoadLayered(org, repo)
	if err != nil {
		t.Fatal(err)
	}
	got := l.Validate(ValidateOptions{}).Error()
	for _, want := range []string{
		org + ":4: scanners[0].command[1]: unknown placeholder {bogus}",
		repo + ":4: scanners[1].command: must not be empty",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
}

func TestValidateErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, yaml string
		strict     bool
		want       []string
	}{
		{"unknown placeholder", `
version: 1
scanners:
  - name: t
    command: ["t", "-o", "{output}"]
    output: "{outdir}/{nope}"
`, false, []string{
			"x.yaml:5: scanners[0].command[2]: unknown placeholder {output}",
			"x.yaml:6: scanners[0].output: unknown placeholder {nope}",
		}},
		{"duplicate names", `
version: 1
scanners:
  - name: t
    command: [t]
  - name: t
    command: [t]
`, false, []string{`x.yaml:6: scanners[1].name: duplicate scanner name "t"`}},
		{"overlapping match", `
version: 1
scanners:
  - name: a
    match: [Trivy]
    command: [a]
  - name: b
    match: [trivy]
    command: [b]
`, false, []string{`x.yaml:8: scanners[1].match[0]: "trivy" is already matched by scanner "a"`}},
		{"empty command", `
version: 1
scanners:
  - name: a
    command: []
  - name: b
    command: [""]
`, false, []string{"x.yaml:5: scanners[0].command: must not be empty", "x.yaml:7: scanners[1].command: must not be empty"}},
		{"issues labels", `
version: 1
publish:
  issues:
    label: "a,b"
    queue_label: "a,b"
    max_open: 0
    queue: 2
`, false, []string{
			`publish.issues.label: must be a GitHub label name (1 to 50 characters, no commas), got "a,b"`,
			`publish.issues.queue_label: must be a GitHub label name`,
			"publish.issues.queue_label: must differ from publish.issues.label",
			"publish.issues.max_open: must be at least 1",
			"publish.issues.queue: must be between 0 and max_open (0), got 2",
		}},
		{"issues blank label and negative queue", `
version: 1
publish:
  issues:
    label: " "
    queue: -1
`, false, []string{
			`publish.issues.label: must be a GitHub label name (1 to 50 characters, no commas), got " "`,
			"publish.issues.queue: must be between 0 and max_open (10), got -1",
		}},
		{"unknown campaign scanner", `
version: 1
campaigns:
  - id: c1
    scanner: ghost
    rules: [ghost/X]
`, false, []string{`x.yaml:5: campaigns[0].scanner: unknown scanner "ghost"`}},
		{"strict allow", `
version: 1
scanners:
  - name: trivy
    command: [trivy]
rules:
  allow: [trivy/DS-0002, checkov/CKV_1, "*/x"]
`, true, []string{`x.yaml:7: rules.allow[1]: "checkov/CKV_1" matches no configured scanner`}},
		{"bad values", `
version: 2
scanners:
  - name: "bad name"
    command: [x]
    scope: everywhere
    match: [""]
rules:
  allow: [nokey, "a/["]
  deny: ["b/["]
  min_level: critical
paths:
  deny: ["a**"]
campaigns:
  - id: ""
    scanner: ""
  - id: c
    scanner: x
    rules: [x/a]
  - id: c
    scanner: x
    rules: [x/a]
limits:
  group_by: folder
  files_per_batch: 0
  retries: -1
  agent_timeout: 0s
verify:
  commands: [[]]
agent:
  provider: other
publish:
  pr:
    branch_prefix: "a b"
    reviewers_from: team
  review:
    max_suggestions: -1
`, false, []string{
			"x.yaml:2: version: must be 1, got 2",
			`scanners[0].name: "bad name" may only contain`,
			`scanners[0].scope: must be changed, dir or repo, got "everywhere"`,
			"scanners[0].match[0]: must not be empty",
			`rules.allow[0]: "nokey" must look like`,
			`rules.allow[1]: bad glob`,
			`rules.deny[0]: bad glob`,
			`rules.min_level: must be one of`,
			`paths.deny[1]: bad glob "a**"`,
			"campaigns[0].id: is required",
			"campaigns[0].scanner: is required",
			"campaigns[0].rules: must list",
			`campaigns[2].id: duplicate campaign id "c"`,
			`campaigns[1].scanner: unknown scanner "x"`,
			`x.yaml:21: campaigns[2].scanner: unknown scanner "x"`,
			`limits.group_by: must be rule, file or auto, got "folder"`,
			"limits.files_per_batch: must be at least 1",
			"limits.retries: must not be negative",
			"limits.agent_timeout: must be positive",
			"verify.commands[0]: must not be empty",
			`agent.provider: must be one of claude-code, got "other"`,
			`publish.pr.branch_prefix: "a b"`,
			`publish.pr.reviewers_from: must be codeowners or none`,
			"publish.review.max_suggestions: must not be negative",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			l, err := Parse("x.yaml", []byte(tt.yaml))
			if err != nil {
				t.Fatal(err)
			}
			err = l.Validate(ValidateOptions{Strict: tt.strict})
			var es *Errors
			if !errors.As(err, &es) {
				t.Fatalf("want *Errors, got %v", err)
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("missing %q in:\n%s", w, err)
				}
			}
			if len(es.List) != len(tt.want) {
				t.Errorf("got %d errors, want %d:\n%s", len(es.List), len(tt.want), err)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct{ name, yaml, want string }{
		{"unknown field", "version: 1\nscaners: []\n", "x.yaml:2: field scaners not found"},
		{"bad duration", "version: 1\nlimits:\n  agent_timeout: soon\n", `invalid duration "soon"`},
		{"negative duration", "version: 1\nlimits:\n  agent_timeout: -1m\n", `is negative`},
		{"duration type", "version: 1\nlimits:\n  agent_timeout: [1]\n", "x.yaml:3: cannot unmarshal"},
		{"syntax", "version: [1\n", "x.yaml"},
		{"wrong type", "version: 1\nscanners: {}\n", "x.yaml:2: cannot unmarshal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse("x.yaml", []byte(tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("got %v, want %q", err, tt.want)
			}
		})
	}
	if _, err := Load(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("missing file accepted")
	}
}

func TestErrorFormat(t *testing.T) {
	t.Parallel()
	e := &Error{File: "f", Msg: "m"}
	if e.Error() != "f: m" {
		t.Errorf("got %q", e.Error())
	}
	if got := Duration(90 * time.Second).String(); got != "1m30s" {
		t.Errorf("duration = %q", got)
	}
	b, _ := Duration(time.Second).MarshalText()
	y, _ := Duration(time.Second).MarshalYAML()
	if string(b) != "1s" || y != "1s" {
		t.Errorf("marshal = %q %v", b, y)
	}
	var d Duration
	if err := d.UnmarshalText([]byte("2m")); err != nil || d.Std() != 2*time.Minute {
		t.Errorf("unmarshal text: %v %v", d, err)
	}
	if err := d.UnmarshalText([]byte("x")); err == nil {
		t.Error("bad text duration accepted")
	}
}

// write creates a file in dir and returns its path.
func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestRecursiveAliasTerminates guards against a self-referencing alias
// sending the line indexer into infinite recursion.
func TestRecursiveAliasTerminates(t *testing.T) {
	t.Parallel()
	for _, doc := range []string{"a: &x [*x]\n", "version: 1\nrules: &r\n  allow: *r\n"} {
		if _, err := Parse("x.yaml", []byte(doc)); err == nil {
			t.Errorf("%q: want an error", doc)
		}
	}
}
