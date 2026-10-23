// Package baseline compares two finding sets by fingerprint.
package baseline

import "github.com/rossedman/sarifix/pkg/finding"

// Diff is the result of comparing a base and a head finding set.
type Diff struct {
	// New findings are in head but not in base.
	New []finding.Finding `json:"new"`
	// Fixed findings are in base but not in head.
	Fixed []finding.Finding `json:"fixed"`
	// Unchanged findings are in both; the head copy is kept, so lines are
	// current.
	Unchanged []finding.Finding `json:"unchanged"`
}

// Compare diffs base against head. Fingerprints are compared as a multiset:
// two identical findings in head and one in base give one unchanged and one
// new. Order follows the input.
func Compare(base, head []finding.Finding) Diff {
	remaining := make(map[string]int, len(base))
	for _, f := range base {
		remaining[f.Fingerprint]++
	}
	var d Diff
	for _, f := range head {
		if remaining[f.Fingerprint] > 0 {
			remaining[f.Fingerprint]--
			d.Unchanged = append(d.Unchanged, f)
			continue
		}
		d.New = append(d.New, f)
	}
	for _, f := range base {
		if remaining[f.Fingerprint] > 0 {
			remaining[f.Fingerprint]--
			d.Fixed = append(d.Fixed, f)
		}
	}
	return d
}

// NewOnly returns the head findings whose fingerprint is absent from base,
// the filter used by --baseline.
func NewOnly(base, head []finding.Finding) []finding.Finding {
	return Compare(base, head).New
}
