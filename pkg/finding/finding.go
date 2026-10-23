// Package finding turns SARIF results into normalized Findings with stable
// fingerprints and rule keys.
package finding

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/rossedman/sarifix/pkg/sarif"
)

// Levels in SARIF order of severity, highest first.
const (
	LevelError   = "error"
	LevelWarning = "warning"
	LevelNote    = "note"
	LevelNone    = "none"
)

// FingerprintKey is the partialFingerprints key sarifix writes for its own
// snippet hash, so a later run can match a finding without file access.
const FingerprintKey = "sarifix/v1"

// primaryKey is the GitHub code scanning line-hash fingerprint.
const primaryKey = "primaryLocationLineHash"

// Finding is one SARIF result, normalized. Message and HelpText come from the
// scanner and must be treated as untrusted.
type Finding struct {
	Tool      string `json:"tool"`
	RuleID    string `json:"ruleId"`
	Level     string `json:"level"`
	Message   string `json:"message"`
	Path      string `json:"path,omitempty"`
	StartLine int    `json:"startLine,omitempty"`
	EndLine   int    `json:"endLine,omitempty"`
	Snippet   string `json:"-"`
	// SnippetFromFile is set when Snippet was read from the repo rather
	// than taken from the SARIF, so it may come from a different checkout
	// than the one scanned.
	SnippetFromFile bool   `json:"-"`
	Fingerprint     string `json:"fingerprint"`
	HelpText        string `json:"-"`
	Source          string `json:"source"`

	Raw *sarif.Result `json:"-"`
	// Run and ResultIndex locate Raw in its log, so sarifix can annotate it.
	Run         *sarif.SourcedRun `json:"-"`
	ResultIndex int               `json:"-"`
}

// RuleKey is "<scanner>/<ruleId>", the key used by policy globs and batches.
func RuleKey(scanner, ruleID string) string {
	return scanner + "/" + ruleID
}

// Located reports whether the finding has a physical file location.
func (f Finding) Located() bool {
	return f.Path != ""
}

// LevelRank orders levels: error 3, warning 2, note 1, none and unknown 0.
func LevelRank(level string) int {
	switch level {
	case LevelError:
		return 3
	case LevelWarning:
		return 2
	case LevelNote:
		return 1
	}
	return 0
}

// Extractor converts runs into findings.
type Extractor struct {
	// Normalizer maps SARIF URIs to repo-relative paths.
	Normalizer *sarif.Normalizer
	// ReadFile reads a repo-relative file to recover snippets. Nil disables
	// file access; findings then fingerprint from the SARIF alone.
	ReadFile func(rel string) ([]byte, error)

	cache map[string][]string
}

// NewExtractor returns an Extractor reading files under root.
func NewExtractor(root string) (*Extractor, error) {
	n, err := sarif.NewNormalizer(root)
	if err != nil {
		return nil, err
	}
	return &Extractor{
		Normalizer: n,
		ReadFile: func(rel string) ([]byte, error) {
			return os.ReadFile(filepath.Join(n.Root, filepath.FromSlash(rel)))
		},
	}, nil
}

// Extract returns the findings in every run of log, in input order.
func (e *Extractor) Extract(log *sarif.Log) []Finding {
	var out []Finding
	for _, r := range log.Runs {
		out = append(out, e.ExtractRun(r)...)
	}
	return out
}

// ExtractRun returns the findings in one run. Results whose kind is not
// "fail" (pass, notApplicable, informational...) are not findings.
func (e *Extractor) ExtractRun(sr *sarif.SourcedRun) []Finding {
	run := sr.Run
	tool := sr.Driver()
	var out []Finding
	for i, res := range run.Results {
		if res == nil || (res.Kind != "" && res.Kind != "fail") {
			continue
		}
		f := Finding{Tool: tool, Source: sr.Source, Raw: res, Run: sr, ResultIndex: i}
		rule := lookupRule(run, res)
		f.RuleID = ruleID(res, rule)
		f.Level = level(res, rule)
		f.Message = messageText(res, rule)
		f.HelpText = helpText(rule)
		e.locate(&f, run, res)
		out = append(out, f)
	}
	assignFingerprints(out)
	return out
}

// locate fills Path, lines and Snippet from the first physical location.
func (e *Extractor) locate(f *Finding, run *sarif.Run, res *sarif.Result) {
	for _, loc := range res.Locations {
		if loc == nil || loc.PhysicalLocation == nil {
			continue
		}
		pl := loc.PhysicalLocation
		p, ok := e.Normalizer.Path(run, pl.ArtifactLocation)
		if !ok {
			continue
		}
		f.Path = p
		if r := pl.Region; r != nil {
			if r.StartLine != nil {
				f.StartLine = *r.StartLine
			}
			f.EndLine = f.StartLine
			if r.EndLine != nil && *r.EndLine >= f.StartLine {
				f.EndLine = *r.EndLine
			}
			if r.Snippet != nil && r.Snippet.Text != nil {
				f.Snippet = *r.Snippet.Text
			}
		}
		if f.Snippet == "" && f.StartLine > 0 {
			f.Snippet = e.lines(p, f.StartLine, f.EndLine)
			f.SnippetFromFile = f.Snippet != ""
		}
		return
	}
}

// maxSnippetLines caps how much of a file a region may pull into a snippet.
const maxSnippetLines = 200

// lines returns lines start..end (1-based, inclusive) of a repo file.
func (e *Extractor) lines(rel string, start, end int) string {
	if e.ReadFile == nil {
		return ""
	}
	if e.cache == nil {
		e.cache = map[string][]string{}
	}
	ls, ok := e.cache[rel]
	if !ok {
		data, err := e.ReadFile(rel)
		if err == nil {
			sc := bufio.NewScanner(bytes.NewReader(data))
			sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
			for sc.Scan() {
				ls = append(ls, sc.Text())
			}
		}
		e.cache[rel] = ls
	}
	if start > len(ls) {
		return ""
	}
	if end > len(ls) {
		end = len(ls)
	}
	if end-start >= maxSnippetLines {
		end = start + maxSnippetLines - 1
	}
	return strings.Join(ls[start-1:end], "\n")
}

// lookupRule finds the rule descriptor for res. go-sarif decodes a missing
// ruleIndex as 0, so the indexed rule is used only when its id agrees with
// the result's ruleId; otherwise rules are searched by id.
func lookupRule(run *sarif.Run, res *sarif.Result) *sarif.ReportingDescriptor {
	if run.Tool == nil || run.Tool.Driver == nil {
		return nil
	}
	rules := run.Tool.Driver.Rules
	id := ""
	if res.RuleID != nil {
		id = *res.RuleID
	} else if res.Rule != nil && res.Rule.ID != nil {
		id = *res.Rule.ID
	}
	if i := res.RuleIndex; i >= 0 && i < len(rules) && rules[i] != nil {
		if id == "" || strVal(rules[i].ID) == id {
			return rules[i]
		}
	}
	if id == "" {
		return nil
	}
	for _, r := range rules {
		if r != nil && strVal(r.ID) == id {
			return r
		}
	}
	return nil
}

// strVal dereferences an optional string.
func strVal(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// ruleID prefers result.ruleId, then result.rule.id, then the descriptor.
func ruleID(res *sarif.Result, rule *sarif.ReportingDescriptor) string {
	switch {
	case res.RuleID != nil && *res.RuleID != "":
		return *res.RuleID
	case res.Rule != nil && res.Rule.ID != nil:
		return *res.Rule.ID
	case rule != nil:
		return strVal(rule.ID)
	}
	return ""
}

// level applies SARIF defaulting: result.level, then the rule's default
// configuration, then "warning".
func level(res *sarif.Result, rule *sarif.ReportingDescriptor) string {
	if res.Level != "" {
		return res.Level
	}
	if rule != nil && rule.DefaultConfiguration != nil && rule.DefaultConfiguration.Level != "" {
		return rule.DefaultConfiguration.Level
	}
	return LevelWarning
}

// messageText returns the result message, falling back to the rule's
// short description.
func messageText(res *sarif.Result, rule *sarif.ReportingDescriptor) string {
	if m := res.Message; m != nil {
		if m.Text != nil && *m.Text != "" {
			return *m.Text
		}
		if m.Markdown != nil && *m.Markdown != "" {
			return *m.Markdown
		}
	}
	if rule != nil && rule.ShortDescription != nil && rule.ShortDescription.Text != nil {
		return *rule.ShortDescription.Text
	}
	return ""
}

// helpText returns the rule's help, falling back to its full description.
func helpText(rule *sarif.ReportingDescriptor) string {
	if rule == nil {
		return ""
	}
	if h := rule.Help; h != nil {
		if h.Markdown != nil && *h.Markdown != "" {
			return *h.Markdown
		}
		if h.Text != nil && *h.Text != "" {
			return *h.Text
		}
	}
	if d := rule.FullDescription; d != nil && d.Text != nil {
		return *d.Text
	}
	return ""
}

// assignFingerprints sets Fingerprint on each finding. Identical findings in
// the same run (same tool, rule, path and snippet) are numbered in order of
// appearance so each still gets a distinct fingerprint.
func assignFingerprints(fs []Finding) {
	seen := map[string]int{}
	for i := range fs {
		base := baseFingerprint(&fs[i])
		seen[base]++
		fs[i].Fingerprint = base + ":" + strconv.Itoa(seen[base])
	}
}

// baseFingerprint picks the strongest identity available for f, without the
// occurrence suffix. Line numbers never contribute.
func baseFingerprint(f *Finding) string {
	if f.Raw != nil {
		if pf := f.Raw.PartialFingerprints; len(pf) > 0 {
			if v := pf[primaryKey]; v != "" {
				return hashParts(f.Tool, f.RuleID, primaryKey, stripOccurrence(v))
			}
			if s := toolFingerprints(pf); s != "" {
				return hashParts(f.Tool, f.RuleID, "partial", s)
			}
		}
	}
	// A snippet the tool wrote is the truth about the scanned code.
	if hasContent(f.Snippet) && !f.SnippetFromFile {
		return SnippetHash(f.Tool, f.RuleID, f.Path, f.Snippet)
	}
	// sarifix/v1 was computed by `sarifix scan` from the checkout that was
	// scanned, so it beats lines read now from files that may have changed
	// since (a baseline scan of an older commit, read in a newer checkout).
	if f.Raw != nil {
		if v := f.Raw.PartialFingerprints[FingerprintKey]; v != "" {
			return v
		}
	}
	if hasContent(f.Snippet) {
		return SnippetHash(f.Tool, f.RuleID, f.Path, f.Snippet)
	}
	// No snippet anywhere: the message is the best line-independent content.
	return SnippetHash(f.Tool, f.RuleID, f.Path, "\x01"+f.Message)
}

// Annotate records each finding's snippet hash on its SARIF result under
// partialFingerprints["sarifix/v1"], written out with the run. A later run
// that cannot read the files (for example a diff against a scan of another
// commit) then still gets the same fingerprint. Findings with no snippet, or
// not tied to a loaded run, are left alone.
func Annotate(fs []Finding) {
	for _, f := range fs {
		if f.Run == nil || !hasContent(f.Snippet) {
			continue
		}
		f.Run.AddPartialFingerprint(f.ResultIndex, FingerprintKey, SnippetHash(f.Tool, f.RuleID, f.Path, f.Snippet))
	}
}

// toolFingerprints joins a tool's own partial fingerprints (not sarifix's)
// in key order.
func toolFingerprints(pf map[string]string) string {
	keys := make([]string, 0, len(pf))
	for k := range pf {
		if k != FingerprintKey {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(pf[k])
		b.WriteByte(0)
	}
	return b.String()
}

// stripOccurrence removes GitHub's ":N" occurrence suffix, since sarifix
// numbers occurrences itself.
func stripOccurrence(v string) string {
	if i := strings.LastIndexByte(v, ':'); i > 0 {
		if _, err := strconv.Atoi(v[i+1:]); err == nil {
			return v[:i]
		}
	}
	return v
}

// SnippetHash is the computed fingerprint: sha256 over tool, rule, path and
// the snippet with all whitespace runs collapsed to one space.
func SnippetHash(tool, ruleID, path, snippet string) string {
	return hashParts(tool, ruleID, path, CollapseSpace(snippet))
}

// hashParts hashes NUL-separated parts and returns hex.
func hashParts(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// hasContent reports whether a snippet has any non-space text.
func hasContent(s string) bool {
	return strings.TrimFunc(s, unicode.IsSpace) != ""
}

// CollapseSpace trims s and replaces every whitespace run with one space.
func CollapseSpace(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = true
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}
