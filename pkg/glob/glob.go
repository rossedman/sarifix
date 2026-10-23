// Package glob matches the two kinds of patterns sarifix config uses.
//
// Path patterns match repo-relative slash paths: "*", "?" and "[...]" stay
// inside one path segment (unlike path.Match, where a negated class can match
// "/"), and "**" as a whole segment matches zero or more segments.
//
// Key patterns match rule keys such as "checkov/CKV_AWS_20": "*" matches any
// run of characters, including "/", because rule IDs may contain slashes.
package glob

import (
	"errors"
	"path"
	"strings"
)

// ErrBadPattern reports a malformed pattern.
var ErrBadPattern = errors.New("syntax error in pattern")

// ValidatePath reports whether p is a well-formed path pattern.
func ValidatePath(p string) error {
	if p == "" {
		return ErrBadPattern
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "**" {
			continue
		}
		if strings.Contains(seg, "**") {
			return errors.New(`"**" must be a whole path segment`)
		}
		if _, err := path.Match(seg, ""); err != nil {
			return ErrBadPattern
		}
	}
	return nil
}

// MatchPath reports whether the slash path name matches the path pattern.
// A malformed pattern never matches.
func MatchPath(pattern, name string) bool {
	if ValidatePath(pattern) != nil {
		return false
	}
	return matchSegs(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

// matchSegs matches pattern segments against name segments.
func matchSegs(ps, ns []string) bool {
	for len(ps) > 0 {
		if ps[0] == "**" {
			// Collapse repeated ** and try every split point.
			for len(ps) > 0 && ps[0] == "**" {
				ps = ps[1:]
			}
			if len(ps) == 0 {
				return true
			}
			for i := range ns {
				if matchSegs(ps, ns[i:]) {
					return true
				}
			}
			return false
		}
		if len(ns) == 0 {
			return false
		}
		if ok, _ := path.Match(ps[0], ns[0]); !ok {
			return false
		}
		ps, ns = ps[1:], ns[1:]
	}
	return len(ns) == 0
}

// ValidateKey reports whether p is a well-formed key pattern.
func ValidateKey(p string) error {
	if p == "" {
		return ErrBadPattern
	}
	if _, err := path.Match(keyToPath(p), ""); err != nil {
		return ErrBadPattern
	}
	return nil
}

// MatchKey reports whether key matches the key pattern. A malformed pattern
// never matches.
func MatchKey(pattern, key string) bool {
	if ValidateKey(pattern) != nil {
		return false
	}
	// path.Match's "*" stops at "/", so swap "/" for a byte that can't occur
	// in config text before matching.
	ok, _ := path.Match(keyToPath(pattern), strings.ReplaceAll(key, "/", sep))
	return ok
}

// sep stands in for "/" when matching keys.
const sep = "\x00"

// keyToPath rewrites a key pattern for path.Match, keeping escapes intact.
func keyToPath(p string) string {
	return strings.ReplaceAll(p, "/", sep)
}
