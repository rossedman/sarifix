package cli

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// fakeGitHub is an in-memory GitHub issues API for one repo.
type fakeGitHub struct {
	mu     sync.Mutex
	issues []map[string]any
	labels []string
	fail   bool
}

// ServeHTTP handles list, create, edit, comment, label and label-create calls.
func (g *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
		return
	}
	var in map[string]any
	_ = json.NewDecoder(r.Body).Decode(&in)
	path := strings.TrimPrefix(r.URL.Path, "/repos/acme/infra/")
	parts := strings.Split(path, "/")
	switch {
	case r.Method == http.MethodPost && path == "labels":
		g.labels = append(g.labels, in["name"].(string))
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "{}")
	case r.Method == http.MethodGet && path == "issues":
		var open []map[string]any
		for _, is := range g.issues {
			if is["state"] == "open" {
				open = append(open, is)
			}
		}
		_ = json.NewEncoder(w).Encode(open)
	case r.Method == http.MethodPost && path == "issues":
		in["number"] = len(g.issues) + 1
		in["state"] = "open"
		var labels []map[string]any
		for _, l := range in["labels"].([]any) {
			labels = append(labels, map[string]any{"name": l})
		}
		in["labels"] = labels
		g.issues = append(g.issues, in)
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(in)
	case len(parts) >= 2 && parts[0] == "issues":
		n, _ := strconv.Atoi(parts[1])
		is := g.issues[n-1]
		switch {
		case len(parts) == 3 && parts[2] == "labels":
			for _, l := range in["labels"].([]any) {
				is["labels"] = append(is["labels"].([]map[string]any), map[string]any{"name": l})
			}
		case len(parts) == 2:
			for k, v := range in {
				is[k] = v
			}
		}
		_, _ = io.WriteString(w, "{}")
	default:
		http.NotFound(w, r)
	}
}

// githubEnv points fix --mode issues at g.
func githubEnv(t *testing.T, g *fakeGitHub) {
	t.Helper()
	srv := httptest.NewServer(g)
	t.Cleanup(srv.Close)
	t.Setenv("GITHUB_API_URL", srv.URL)
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GH_TOKEN", "")
	t.Setenv("GITHUB_SERVER_URL", "https://github.example")
	t.Setenv("GITHUB_SHA", "0123456789abcdef0123456789abcdef01234567")
}

func TestFixIssues(t *testing.T) {
	g := &fakeGitHub{}
	githubEnv(t, g)

	// A dry run lists what would happen and writes nothing.
	out, errOut, code := run(t, append(planArgs("fix", "--mode", "issues", "--dry-run", "--max-open", "3", "--queue", "1"), "--json")...)
	if code != 0 {
		t.Fatalf("dry run: %d %s", code, errOut)
	}
	var res fixIssues
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if !res.DryRun || res.Repo != "acme/infra" || len(res.Actions) != 4 || res.Actions[3].Kind != "queue" {
		t.Errorf("dry run: %+v", res)
	}
	if len(g.issues) != 0 || len(g.labels) != 0 {
		t.Fatalf("dry run wrote: %d issues, labels %v", len(g.issues), g.labels)
	}

	// The real run opens three issues, queues the first, and creates labels.
	out, errOut, code = run(t, planArgs("fix", "--mode", "issues", "--max-open", "3", "--queue", "1")...)
	if code != 0 {
		t.Fatalf("run: %d %s", code, errOut)
	}
	if strings.Count(out, "opened #") != 3 || !strings.Contains(out, "queued #1") {
		t.Errorf("output:\n%s", out)
	}
	if strings.Join(g.labels, ",") != "sarifix,agent-ready" || len(g.issues) != 3 {
		t.Fatalf("labels %v, %d issues", g.labels, len(g.issues))
	}
	body := g.issues[0]["body"].(string)
	if !strings.HasPrefix(body, "<!-- sarifix-batch: ") || !strings.Contains(body, "](https://github.example/acme/infra/blob/0123456789abcdef0123456789abcdef01234567/") {
		t.Errorf("body:\n%s", body)
	}

	// Nothing changed: nothing to do.
	out, _, code = run(t, planArgs("fix", "--mode", "issues", "--max-open", "3", "--queue", "1")...)
	if code != 0 || !strings.Contains(out, "acme/infra issues already match") {
		t.Errorf("second run: %d %s", code, out)
	}

	// API errors are runtime errors, and say what failed.
	g.fail = true
	_, errOut, code = run(t, planArgs("fix", "--mode", "issues")...)
	if code != ExitRuntime || !strings.Contains(errOut, "403 Resource not accessible by integration") {
		t.Errorf("api error: %d %s", code, errOut)
	}
	if _, errOut, code = run(t, append(planArgs("fix", "--mode", "issues", "--dry-run"), "--json")...); code != ExitRuntime || !strings.Contains(errOut, "list issues") {
		t.Errorf("api error with --json: %d %s", code, errOut)
	}
}

func TestFixIssuesConfigErrors(t *testing.T) {
	githubEnv(t, &fakeGitHub{})
	if _, errOut, code := run(t, planArgs("fix", "--mode", "issues", "--max-open", "1", "--queue", "2")...); code != ExitConfig || !strings.Contains(errOut, "--queue (2)") {
		t.Errorf("bad queue: %d %s", code, errOut)
	}
	if _, errOut, code := run(t, planArgs("fix", "--mode", "issues", "--github-repo", "nope")...); code != ExitConfig || !strings.Contains(errOut, `repository "nope"`) {
		t.Errorf("bad repo: %d %s", code, errOut)
	}
	t.Setenv("GITHUB_TOKEN", "")
	if _, errOut, code := run(t, planArgs("fix", "--mode", "issues")...); code != ExitConfig || !strings.Contains(errOut, "no GitHub token") {
		t.Errorf("no token: %d %s", code, errOut)
	}
}

func TestFixIssuesLinksFromGit(t *testing.T) {
	g := &fakeGitHub{}
	githubEnv(t, g)
	t.Setenv("GITHUB_SERVER_URL", "")
	t.Setenv("GITHUB_SHA", "")
	// Outside Actions, links use github.com and the checkout's HEAD (the
	// fixture repo sits inside this repository's checkout).
	if _, errOut, code := run(t, planArgs("fix", "--mode", "issues", "--max-open", "1")...); code != 0 {
		t.Fatalf("%d %s", code, errOut)
	}
	body := g.issues[0]["body"].(string)
	if !regexp.MustCompile(`\]\(https://github\.com/acme/infra/blob/[0-9a-f]{40}/`).MatchString(body) {
		t.Errorf("no link to HEAD:\n%s", body)
	}
}
