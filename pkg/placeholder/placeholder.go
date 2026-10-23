// Package placeholder expands {name} placeholders in scanner argv templates.
//
// A placeholder is a brace-wrapped identifier such as {out}. Any other brace
// is literal text, so arguments like '{"a":1}' pass through unchanged. The
// {paths} placeholder is special: when it is an entire argv element it expands
// to one element per path; inside a larger element the paths are joined with
// spaces.
package placeholder

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// Known placeholder names.
const (
	Out    = "out"
	OutDir = "outdir"
	Dir    = "dir"
	Paths  = "paths"
	Repo   = "repo"
)

// Names lists every placeholder sarifix understands, sorted.
var Names = []string{Dir, Out, OutDir, Paths, Repo}

// pattern matches one placeholder token.
var pattern = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Vars holds the values substituted for placeholders.
type Vars struct {
	Out    string
	OutDir string
	Dir    string
	Repo   string
	Paths  []string
}

// Find returns the placeholder names used in s, in order of appearance.
func Find(s string) []string {
	var names []string
	for _, m := range pattern.FindAllStringSubmatch(s, -1) {
		names = append(names, m[1])
	}
	return names
}

// Unknown returns the placeholder names in s that sarifix does not know.
func Unknown(s string) []string {
	var bad []string
	for _, n := range Find(s) {
		if !slices.Contains(Names, n) {
			bad = append(bad, n)
		}
	}
	return bad
}

// ExpandArgs expands every element of args. An element that is exactly
// "{paths}" becomes one element per path (zero elements if there are none).
func ExpandArgs(args []string, v Vars) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, a := range args {
		if a == "{"+Paths+"}" {
			out = append(out, v.Paths...)
			continue
		}
		s, err := Expand(a, v)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, nil
}

// Expand replaces the placeholders in a single string. {paths} is joined with
// spaces. Unknown placeholders are an error.
func Expand(s string, v Vars) (string, error) {
	var err error
	res := pattern.ReplaceAllStringFunc(s, func(tok string) string {
		name := tok[1 : len(tok)-1]
		switch name {
		case Out:
			return v.Out
		case OutDir:
			return v.OutDir
		case Dir:
			return v.Dir
		case Repo:
			return v.Repo
		case Paths:
			return strings.Join(v.Paths, " ")
		}
		if err == nil {
			err = fmt.Errorf("unknown placeholder {%s} (known: %s)", name, list())
		}
		return tok
	})
	if err != nil {
		return "", err
	}
	return res, nil
}

// list formats Names for error messages.
func list() string {
	parts := make([]string, len(Names))
	for i, n := range Names {
		parts[i] = "{" + n + "}"
	}
	return strings.Join(parts, ", ")
}
