package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

// AlwaysDeniedPaths can never be edited, whatever paths.deny says.
var AlwaysDeniedPaths = []string{".github/workflows/**"}

// File is one parsed config file, kept so validation errors can name lines.
type File struct {
	Name  string
	lines map[string]int
}

// Line returns the line of the node at a dotted path such as
// "scanners[1].command", falling back to the nearest parent, or 0.
func (f *File) Line(p string) int {
	for p != "" {
		if l, ok := f.lines[p]; ok {
			return l
		}
		p = parentPath(p)
	}
	return 0
}

// parentPath drops the last element of a dotted path.
func parentPath(p string) string {
	i := strings.LastIndexAny(p, ".[")
	if i < 0 {
		return ""
	}
	return p[:i]
}

// Loaded is a resolved config plus the files it came from.
type Loaded struct {
	*Config
	// Files lists the layers in load order (org default first).
	Files []*File

	// scannerFrom and campaignFrom record which file and index each merged
	// entry came from, so errors point at the right line.
	scannerFrom  []origin
	campaignFrom []origin
}

// origin locates a merged list entry in its source file.
type origin struct {
	file  int
	index int
}

// Load reads one config file over the defaults.
func Load(path string) (*Loaded, error) {
	return LoadLayered("", path)
}

// LoadLayered reads an optional org default file and then the repo file
// over it. Scalars and lists in the repo file replace the org values;
// scanners and campaigns are merged by name and ID, with the repo winning.
// Either path may be empty to skip that layer.
func LoadLayered(orgPath, repoPath string) (*Loaded, error) {
	l := &Loaded{Config: Default()}
	for _, p := range []string{orgPath, repoPath} {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, &Errors{List: []*Error{{File: p, Msg: err.Error()}}}
		}
		if err := l.decode(p, data); err != nil {
			return nil, err
		}
	}
	l.finish()
	return l, nil
}

// Parse decodes a single config document over the defaults.
func Parse(name string, data []byte) (*Loaded, error) {
	l := &Loaded{Config: Default()}
	if err := l.decode(name, data); err != nil {
		return nil, err
	}
	l.finish()
	return l, nil
}

// finish applies defaults that depend on the decoded values.
func (l *Loaded) finish() {
	l.applyScannerDefaults()
	for _, p := range AlwaysDeniedPaths {
		if !contains(l.Paths.Deny, p) {
			l.Paths.Deny = append([]string{p}, l.Paths.Deny...)
		}
	}
}

// decode layers one YAML document onto l.
func (l *Loaded) decode(name string, data []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return yamlError(name, err)
	}
	f := &File{Name: name, lines: map[string]int{}}
	if len(root.Content) > 0 {
		indexLines(root.Content[0], "", f.lines)
	}
	l.Files = append(l.Files, f)

	// Decode scanners and campaigns separately so they merge by key.
	prevScanners, prevCampaigns := l.Scanners, l.Campaigns
	l.Scanners, l.Campaigns = nil, nil
	if len(bytes.TrimSpace(data)) > 0 {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		if err := dec.Decode(l.Config); err != nil && !errors.Is(err, io.EOF) {
			return yamlError(name, err)
		}
	}
	fi := len(l.Files) - 1
	l.Scanners, l.scannerFrom = merge(prevScanners, l.scannerFrom, l.Scanners, fi, func(s Scanner) string { return s.Name })
	l.Campaigns, l.campaignFrom = merge(prevCampaigns, l.campaignFrom, l.Campaigns, fi, func(c Campaign) string { return c.ID })
	return nil
}

// merge overlays entries by key, keeping first-seen order, and tracks where
// each resulting entry was defined. Only entries from earlier layers are
// replaced: duplicates inside one file are kept so validation reports them.
// Entries with an empty key never merge.
func merge[T any](base []T, baseFrom []origin, over []T, file int, key func(T) string) ([]T, []origin) {
	out := append([]T(nil), base...)
	from := append([]origin(nil), baseFrom...)
	for i, v := range over {
		o := origin{file: file, index: i}
		replaced := false
		if k := key(v); k != "" {
			for j := range base {
				if key(out[j]) == k {
					out[j], from[j], replaced = v, o, true
					break
				}
			}
		}
		if !replaced {
			out = append(out, v)
			from = append(from, o)
		}
	}
	return out, from
}

// indexLines records the line of every mapping value and sequence item.
// Aliases are not followed: an alias can refer to its own ancestor, and the
// anchor's own lines are already indexed where it is defined.
func indexLines(n *yaml.Node, p string, out map[string]int) {
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			cp := k.Value
			if p != "" {
				cp = p + "." + k.Value
			}
			out[cp] = k.Line
			indexLines(v, cp, out)
		}
	case yaml.SequenceNode:
		for i, v := range n.Content {
			cp := p + "[" + strconv.Itoa(i) + "]"
			out[cp] = v.Line
			indexLines(v, cp, out)
		}
	}
}

// yamlLine pulls "line N" out of yaml.v3 error text.
var yamlLine = regexp.MustCompile(`^(?:yaml: )?line (\d+): (.*)$`)

// yamlError converts a yaml.v3 error into Errors with line numbers.
func yamlError(name string, err error) error {
	var msgs []string
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	} else {
		msgs = []string{err.Error()}
	}
	es := &Errors{}
	for _, m := range msgs {
		e := &Error{File: name, Msg: strings.TrimPrefix(m, "yaml: ")}
		if sm := yamlLine.FindStringSubmatch(m); sm != nil {
			e.Line, _ = strconv.Atoi(sm[1])
			e.Msg = sm[2]
		}
		es.List = append(es.List, e)
	}
	return es
}

// contains reports whether list has s.
func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// Error is one config problem, located as precisely as possible.
type Error struct {
	File string
	Path string
	Line int
	Msg  string
}

// Error formats as "file:line: path: msg".
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(e.File)
	if e.Line > 0 {
		fmt.Fprintf(&b, ":%d", e.Line)
	}
	b.WriteString(": ")
	if e.Path != "" {
		b.WriteString(e.Path)
		b.WriteString(": ")
	}
	b.WriteString(e.Msg)
	return b.String()
}

// Errors is a list of config problems. It is the error type returned by
// loading and validation, so callers can map it to exit code 2.
type Errors struct {
	List []*Error
}

// Error joins every problem on its own line.
func (e *Errors) Error() string {
	parts := make([]string, len(e.List))
	for i, x := range e.List {
		parts[i] = x.Error()
	}
	return strings.Join(parts, "\n")
}
