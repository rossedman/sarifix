package github

import (
	"context"
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strconv"
)

// Alert is the part of a code scanning alert sarifix reads.
type Alert struct {
	Number  int    `json:"number"`
	HTMLURL string `json:"html_url"`
	Rule    struct {
		ID          string `json:"id"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		HelpURI     string `json:"help_uri"`
	} `json:"rule"`
	Tool struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
	Instance struct {
		Message struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
		} `json:"location"`
	} `json:"most_recent_instance"`
}

// Alerts returns the open code scanning alerts on ref (the default branch
// when ref is empty). Reading them needs security-events read.
func (c *Client) Alerts(ctx context.Context, ref string) ([]Alert, error) {
	var out []Alert
	for page := 1; ; page++ {
		q := url.Values{"state": {"open"}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
		if ref != "" {
			q.Set("ref", ref)
		}
		var batch []Alert
		if err := c.do(ctx, "GET", c.repoPath("code-scanning", "alerts")+"?"+q.Encode(), nil, &batch); err != nil {
			return nil, err
		}
		out = append(out, batch...)
		if len(batch) < 100 {
			return out, nil
		}
	}
}

// AlertRun is one tool's alerts, written as one SARIF run. A run with no
// alerts still says the tool was read, so its fixed issues can close.
type AlertRun struct {
	Tool    string
	Version string
	Alerts  []Alert
}

// The SARIF written for alerts. sarifix's go-sarif structs would write
// zero values (such as "enabled": false on rules), so these carry only
// what is set.
type (
	// alertLog is a SARIF 2.1.0 log.
	alertLog struct {
		Schema  string     `json:"$schema"`
		Version string     `json:"version"`
		Runs    []alertRun `json:"runs"`
	}
	// alertRun is one tool's run.
	alertRun struct {
		Tool struct {
			Driver alertDriver `json:"driver"`
		} `json:"tool"`
		Results []alertResult `json:"results"`
	}
	// alertDriver names the tool and its rules.
	alertDriver struct {
		Name    string      `json:"name"`
		Version string      `json:"version,omitempty"`
		Rules   []alertRule `json:"rules,omitempty"`
	}
	// alertRule is one rule's description and help link.
	alertRule struct {
		ID               string        `json:"id"`
		ShortDescription *alertMessage `json:"shortDescription,omitempty"`
		HelpURI          string        `json:"helpUri,omitempty"`
	}
	// alertMessage is SARIF's message object.
	alertMessage struct {
		Text string `json:"text"`
	}
	// alertResult is one alert.
	alertResult struct {
		RuleID     string          `json:"ruleId"`
		Level      string          `json:"level"`
		Message    alertMessage    `json:"message"`
		Locations  []alertLocation `json:"locations,omitempty"`
		Properties map[string]any  `json:"properties"`
	}
	// alertLocation is a file and line range.
	alertLocation struct {
		Physical struct {
			Artifact struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region *alertRegion `json:"region,omitempty"`
		} `json:"physicalLocation"`
	}
	// alertRegion is a line range.
	alertRegion struct {
		StartLine int `json:"startLine"`
		EndLine   int `json:"endLine,omitempty"`
	}
)

// alertLevels maps a rule's severity to a SARIF level.
var alertLevels = map[string]string{"error": "error", "warning": "warning", "note": "note", "none": "none"}

// WriteSARIF writes runs as a SARIF 2.1.0 log, one run per tool. Each
// result keeps its alert's number and URL in its properties.
func WriteSARIF(w io.Writer, runs []AlertRun) error {
	doc := alertLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []alertRun{}}
	for _, r := range runs {
		var run alertRun
		run.Tool.Driver = alertDriver{Name: r.Tool, Version: r.Version}
		run.Results = []alertResult{}
		rules := map[string]alertRule{}
		for _, a := range r.Alerts {
			if _, ok := rules[a.Rule.ID]; !ok {
				rule := alertRule{ID: a.Rule.ID, HelpURI: a.Rule.HelpURI}
				if a.Rule.Description != "" {
					rule.ShortDescription = &alertMessage{Text: a.Rule.Description}
				}
				rules[a.Rule.ID] = rule
			}
			level, ok := alertLevels[a.Rule.Severity]
			if !ok {
				level = "warning"
			}
			msg := a.Instance.Message.Text
			if msg == "" {
				msg = a.Rule.Description
			}
			res := alertResult{RuleID: a.Rule.ID, Level: level, Message: alertMessage{Text: msg},
				Properties: map[string]any{"githubAlert": a.Number, "githubAlertURL": a.HTMLURL}}
			if loc := a.Instance.Location; loc.Path != "" {
				var l alertLocation
				l.Physical.Artifact.URI = loc.Path
				if loc.StartLine > 0 {
					l.Physical.Region = &alertRegion{StartLine: loc.StartLine}
					if loc.EndLine >= loc.StartLine {
						l.Physical.Region.EndLine = loc.EndLine
					}
				}
				res.Locations = []alertLocation{l}
			}
			run.Results = append(run.Results, res)
		}
		for _, rule := range rules {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
		}
		sort.Slice(run.Tool.Driver.Rules, func(i, j int) bool { return run.Tool.Driver.Rules[i].ID < run.Tool.Driver.Rules[j].ID })
		doc.Runs = append(doc.Runs, run)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
