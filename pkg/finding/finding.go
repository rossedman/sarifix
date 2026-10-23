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
	// Anchor is the text that identifies the finding: the flagged line for
	// a one-line region, and for a block (a Terraform resource, a
	// Kubernetes object) the shortest run of lines from the block's start
	// that is unique in the file. Edits inside the block below the anchor
	// don't change it.
	Anchor      string `json:"-"`
	Fingerprint string `json:"fingerprint"`
	HelpText    string `json:"-"`
	// HelpURI is the rule's documentation link (rules[].helpUri), if any.
	HelpURI string `json:"-"`
	Source  string `json:"source"`

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

	cache map[string]*file
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
		if rule != nil {
			f.HelpURI = strVal(rule.HelpURI)
		}
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
		e.anchorFinding(f)
		return
	}
}

// anchorFinding sets Anchor, and Snippet when the SARIF has none. The file
// is used only when it holds the lines the tool scanned: if the SARIF
// carries a snippet that disagrees with the file, the file is another
// checkout and only the snippet is trusted.
func (e *Extractor) anchorFinding(f *Finding) {
	if f.StartLine <= 0 {
		return
	}
	fromFile := e.lines(f.Path, f.StartLine, f.EndLine)
	toolSnippet := f.Snippet
	if toolSnippet == "" {
		f.Snippet = fromFile
	}
	if fromFile != "" && (toolSnippet == "" || CollapseSpace(toolSnippet) == CollapseSpace(fromFile)) {
		f.Anchor = e.anchor(f.Path, f.StartLine, f.EndLine)
		return
	}
	// No usable file: the first non-blank line of the tool's snippet.
	for _, line := range strings.Split(toolSnippet, "\n") {
		if c := CollapseSpace(line); c != "" {
			f.Anchor = c
			return
		}
	}
}

// maxSnippetLines caps how much of a file a region may pull into a snippet.
const maxSnippetLines = 200

// file holds a repo file's lines, whitespace-collapsed, with an index from
// line text to the positions it occurs at.
type file struct {
	raw       []string
	collapsed []string
	at        map[string][]int
}

// file reads and indexes a repo-relative file once; nil if unreadable.
func (e *Extractor) file(rel string) *file {
	if e.ReadFile == nil {
		return nil
	}
	if e.cache == nil {
		e.cache = map[string]*file{}
	}
	if f, ok := e.cache[rel]; ok {
		return f
	}
	var f *file
	if data, err := e.ReadFile(rel); err == nil {
		f = &file{at: map[string][]int{}}
		sc := bufio.NewScanner(bytes.NewReader(data))
		sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
		for sc.Scan() {
			c := CollapseSpace(sc.Text())
			f.at[c] = append(f.at[c], len(f.raw))
			f.raw = append(f.raw, sc.Text())
			f.collapsed = append(f.collapsed, c)
		}
	}
	e.cache[rel] = f
	return f
}

// span clamps a 1-based inclusive region to the file and the snippet cap,
// returning 0-based [lo, hi) or ok=false when it starts past the end.
func span(f *file, start, end int) (int, int, bool) {
	if f == nil || start < 1 || start > len(f.raw) {
		return 0, 0, false
	}
	end = min(end, len(f.raw), start+maxSnippetLines-1)
	return start - 1, end, true
}

// lines returns lines start..end (1-based, inclusive) of a repo file.
func (e *Extractor) lines(rel string, start, end int) string {
	f := e.file(rel)
	lo, hi, ok := span(f, start, end)
	if !ok {
		return ""
	}
	return strings.Join(f.raw[lo:hi], "\n")
}

// anchor returns the region's identifying text: starting at its first
// non-blank line, the fewest lines that occur nowhere else in the file (or
// the whole region if no prefix is unique), whitespace-collapsed.
func (e *Extractor) anchor(rel string, start, end int) string {
	f := e.file(rel)
	lo, hi, ok := span(f, start, end)
	if !ok {
		return ""
	}
	for lo < hi && f.collapsed[lo] == "" {
		lo++
	}
	if lo == hi {
		return ""
	}
	others := f.at[f.collapsed[lo]]
	k := 1
	for ; lo+k < hi; k++ {
		if unique(f, lo, k, others) {
			break
		}
	}
	return strings.Join(f.collapsed[lo:lo+k], "\n")
}

// unique reports whether the k lines at lo occur at no other start
// position in candidates.
func unique(f *file, lo, k int, candidates []int) bool {
	for _, j := range candidates {
		if j == lo || j+k > len(f.collapsed) {
			continue
		}
		same := true
		for i := 1; i < k && same; i++ {
			same = f.collapsed[j+i] == f.collapsed[lo+i]
		}
		if same {
			return false
		}
	}
	return true
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
	// sarifix/v1 was computed by `sarifix scan` with the scanned checkout
	// at hand, so it beats anything recomputed now from files that may have
	// changed since (a baseline scan of an older commit, read in a newer
	// checkout).
	if f.Raw != nil {
		if v := f.Raw.PartialFingerprints[FingerprintKey]; v != "" {
			return v
		}
	}
	if hasContent(f.Anchor) {
		return SnippetHash(f.Tool, f.RuleID, f.Path, f.Anchor)
	}
	// No anchor anywhere: the message is the best line-independent content.
	return SnippetHash(f.Tool, f.RuleID, f.Path, "\x01"+f.Message)
}

// Annotate records each finding's snippet hash on its SARIF result under
// partialFingerprints["sarifix/v1"], written out with the run. A later run
// that cannot read the files (for example a diff against a scan of another
// commit) then still gets the same fingerprint. Findings with no snippet, or
// not tied to a loaded run, are left alone.
func Annotate(fs []Finding) {
	for _, f := range fs {
		if f.Run == nil || !hasContent(f.Anchor) {
			continue
		}
		f.Run.AddPartialFingerprint(f.ResultIndex, FingerprintKey, SnippetHash(f.Tool, f.RuleID, f.Path, f.Anchor))
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
