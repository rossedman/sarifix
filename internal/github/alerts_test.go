package github

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/rossedman/sarifix/pkg/sarif"
)

// alert builds an API alert.
func alert(n int, tool, rule, severity, path string, line int) Alert {
	var a Alert
	a.Number, a.HTMLURL = n, "https://github.com/o/r/security/code-scanning/"+strings.Repeat("1", n%3+1)
	a.Tool.Name, a.Tool.Version = tool, "2.20.0"
	a.Rule.ID, a.Rule.Severity, a.Rule.Description = rule, severity, "Rule "+rule
	a.Instance.Message.Text = "Problem " + rule
	a.Instance.Location.Path, a.Instance.Location.StartLine, a.Instance.Location.EndLine = path, line, line+1
	return a
}

func TestAlertsPages(t *testing.T) {
	t.Parallel()
	c, calls := fakeAPI(t, func(cl call) (int, any) {
		if strings.Contains(cl.Query, "page=1&") || strings.HasSuffix(cl.Query, "page=1") {
			page := make([]Alert, 100)
			for i := range page {
				page[i] = alert(i+1, "CodeQL", "go/x", "error", "a.go", i+1)
			}
			return 200, page
		}
		return 200, []Alert{alert(101, "CodeQL", "go/y", "warning", "b.go", 3)}
	})
	got, err := c.Alerts(context.Background(), "refs/heads/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 101 || got[100].Rule.ID != "go/y" || got[100].Instance.Location.Path != "b.go" {
		t.Fatalf("got %d alerts, last %+v", len(got), got[len(got)-1])
	}
	if len(*calls) != 2 || (*calls)[0].Path != "/repos/o/r/code-scanning/alerts" ||
		!strings.Contains((*calls)[0].Query, "state=open") || !strings.Contains((*calls)[0].Query, "ref=refs%2Fheads%2Fmain") {
		t.Errorf("calls = %+v", *calls)
	}

	failing, _ := fakeAPI(t, func(call) (int, any) {
		return 403, map[string]string{"message": "Advanced Security must be enabled"}
	})
	if _, err := failing.Alerts(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "403 Advanced Security") {
		t.Errorf("err = %v", err)
	}
}

func TestWriteSARIF(t *testing.T) {
	t.Parallel()
	noLoc := alert(3, "CodeQL", "go/z", "", "", 0)
	noLoc.Instance.Message.Text = ""
	noLine := alert(4, "CodeQL", "go/x", "note", "c.go", 0)
	runs := []AlertRun{
		{Tool: "CodeQL", Version: "2.20.0", Alerts: []Alert{alert(1, "CodeQL", "go/x", "error", "a.go", 5), noLoc, noLine}},
		{Tool: "Snyk"},
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, runs); err != nil {
		t.Fatal(err)
	}
	if err := sarif.Validate(buf.Bytes()); err != nil {
		t.Fatalf("invalid SARIF: %v\n%s", err, buf.String())
	}
	log, warns, err := sarif.Parse(buf.Bytes(), "alerts.sarif", sarif.Options{})
	if err != nil || len(warns) != 0 || len(log.Runs) != 2 {
		t.Fatalf("parse: %v %v %d runs", err, warns, len(log.Runs))
	}
	if log.Runs[0].Driver() != "CodeQL" || log.Runs[1].Driver() != "Snyk" || len(log.Runs[1].Run.Results) != 0 {
		t.Errorf("drivers %q %q", log.Runs[0].Driver(), log.Runs[1].Driver())
	}
	var doc struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Rules []struct {
						ID string `json:"id"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	r := doc.Runs[0]
	if len(r.Tool.Driver.Rules) != 2 || r.Tool.Driver.Rules[0].ID != "go/x" || r.Tool.Driver.Rules[1].ID != "go/z" {
		t.Errorf("rules = %+v", r.Tool.Driver.Rules)
	}
	first, _ := json.Marshal(r.Results[0])
	for _, want := range []string{`"level":"error"`, `"uri":"a.go"`, `"startLine":5`, `"endLine":6`, `"githubAlert":1`} {
		if !strings.Contains(string(first), want) {
			t.Errorf("first result missing %s: %s", want, first)
		}
	}
	// No severity is a warning; no message falls back to the rule's
	// description; no path means no location; no line means no region.
	second, _ := json.Marshal(r.Results[1])
	if !strings.Contains(string(second), `"level":"warning"`) || !strings.Contains(string(second), `"text":"Rule go/z"`) || strings.Contains(string(second), "locations") {
		t.Errorf("second result: %s", second)
	}
	third, _ := json.Marshal(r.Results[2])
	if !strings.Contains(string(third), `"level":"note"`) || strings.Contains(string(third), "region") {
		t.Errorf("third result: %s", third)
	}
}
