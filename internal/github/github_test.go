package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// call is one request the fake API received.
type call struct {
	Method, Path, Query string
	Body                map[string]any
}

// fakeAPI serves the issue endpoints from a handler and records every call.
func fakeAPI(t *testing.T, handle func(c call) (int, any)) (*Client, *[]call) {
	t.Helper()
	var calls []call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" || r.Header.Get("X-GitHub-Api-Version") == "" {
			t.Errorf("headers: %v", r.Header)
		}
		c := call{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery}
		if data, _ := io.ReadAll(r.Body); len(data) > 0 {
			if err := json.Unmarshal(data, &c.Body); err != nil {
				t.Errorf("body %q: %v", data, err)
			}
		}
		calls = append(calls, c)
		status, resp := handle(c)
		w.WriteHeader(status)
		if s, ok := resp.(string); ok {
			_, _ = io.WriteString(w, s)
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return &Client{API: srv.URL, Repo: "o/r", Token: "tok", HTTP: srv.Client()}, &calls
}

func TestListPagesAndSkipsPullRequests(t *testing.T) {
	t.Parallel()
	c, calls := fakeAPI(t, func(c call) (int, any) {
		page := 0
		_, _ = fmt.Sscanf(c.Query[strings.Index(c.Query, "page=")+5:], "%d", &page)
		if page == 1 {
			var items []map[string]any
			for i := 1; i <= 100; i++ {
				items = append(items, map[string]any{"number": i, "title": "t", "body": "b", "labels": []map[string]string{{"name": "sarifix"}}})
			}
			items[1]["pull_request"] = map[string]string{"url": "x"}
			return 200, items
		}
		return 200, []map[string]any{{"number": 101, "body": nil}}
	})
	got, err := c.List(context.Background(), "sarifix")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 100 || got[1].Number != 3 || got[99].Number != 101 || !slices.Equal(got[0].Labels, []string{"sarifix"}) {
		t.Errorf("issues: %d %+v %+v", len(got), got[1], got[len(got)-1])
	}
	if len(*calls) != 2 || !strings.Contains((*calls)[0].Query, "labels=sarifix") || !strings.Contains((*calls)[0].Query, "state=open") {
		t.Errorf("calls: %+v", *calls)
	}
}

func TestWrites(t *testing.T) {
	t.Parallel()
	c, calls := fakeAPI(t, func(c call) (int, any) {
		if c.Path == "/repos/o/r/labels" {
			return 422, map[string]string{"message": "Validation Failed"}
		}
		return 201, map[string]any{"number": 7}
	})
	ctx := context.Background()
	n, err := c.Create(ctx, "T", "B", []string{"sarifix"})
	if err != nil || n != 7 {
		t.Fatalf("create: %d %v", n, err)
	}
	if err := c.Update(ctx, 7, "T2", "B2"); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx, 7, "bye"); err != nil {
		t.Fatal(err)
	}
	if err := c.AddLabel(ctx, 7, "agent-ready"); err != nil {
		t.Fatal(err)
	}
	if err := c.EnsureLabel(ctx, "sarifix", "5319e7", "d"); err != nil {
		t.Fatalf("existing label: %v", err)
	}
	var got []string
	for _, c := range *calls {
		got = append(got, fmt.Sprintf("%s %s %v", c.Method, c.Path, c.Body))
	}
	want := []string{
		"POST /repos/o/r/issues map[body:B labels:[sarifix] title:T]",
		"PATCH /repos/o/r/issues/7 map[body:B2 title:T2]",
		"POST /repos/o/r/issues/7/comments map[body:bye]",
		"PATCH /repos/o/r/issues/7 map[state:closed state_reason:completed]",
		"POST /repos/o/r/issues/7/labels map[labels:[agent-ready]]",
		"POST /repos/o/r/labels map[color:5319e7 description:d name:sarifix]",
	}
	if !slices.Equal(got, want) {
		t.Errorf("calls:\n%s", strings.Join(got, "\n"))
	}
}

func TestErrors(t *testing.T) {
	t.Parallel()
	c, _ := fakeAPI(t, func(c call) (int, any) {
		if strings.HasSuffix(c.Path, "/comments") {
			return 403, map[string]string{"message": "Resource not accessible by integration"}
		}
		if c.Path == "/repos/o/r/labels" {
			return 500, "not json"
		}
		if c.Method == http.MethodGet {
			return 200, "{bad json"
		}
		return 404, ""
	})
	ctx := context.Background()
	err := c.Close(ctx, 1, "x")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Status != 403 || err.Error() != "GitHub POST /repos/o/r/issues/1/comments: 403 Resource not accessible by integration" {
		t.Errorf("close: %v", err)
	}
	if err := c.EnsureLabel(ctx, "x", "000000", ""); err == nil || !strings.Contains(err.Error(), "500 Internal Server Error") {
		t.Errorf("label: %v", err)
	}
	if _, err := c.List(ctx, "x"); err == nil {
		t.Error("bad JSON accepted")
	}
	if err := c.Update(ctx, 1, "", ""); err == nil || !strings.Contains(err.Error(), "404 Not Found") {
		t.Errorf("update: %v", err)
	}

	unreachable := &Client{API: "http://127.0.0.1:1", Repo: "o/r", Token: "t", HTTP: http.DefaultClient}
	if _, err := unreachable.Create(ctx, "", "", nil); err == nil {
		t.Error("unreachable API succeeded")
	}
	bad := &Client{API: "http://\x7f", Repo: "o/r", HTTP: http.DefaultClient}
	if err := bad.AddLabel(ctx, 1, "x"); err == nil {
		t.Error("bad URL accepted")
	}
	if err := c.do(ctx, http.MethodPost, "/x", map[string]any{"bad": func() {}}, nil); err == nil {
		t.Error("unmarshalable body accepted")
	}
}

func TestFromEnv(t *testing.T) {
	t.Setenv("GITHUB_REPOSITORY", "acme/infra")
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "gh")
	t.Setenv("GITHUB_API_URL", "https://ghe.example/api/v3/")
	c, err := FromEnv("")
	if err != nil || c.Repo != "acme/infra" || c.Token != "gh" || c.API != "https://ghe.example/api/v3" {
		t.Fatalf("%+v %v", c, err)
	}
	t.Setenv("GITHUB_TOKEN", "tok")
	t.Setenv("GITHUB_API_URL", "")
	if c, _ = FromEnv("o/r"); c.Repo != "o/r" || c.Token != "tok" || c.API != DefaultAPI {
		t.Errorf("%+v", c)
	}
	if _, err := FromEnv("not a repo"); err == nil || !strings.Contains(err.Error(), "--github-repo") {
		t.Errorf("bad repo: %v", err)
	}
	t.Setenv("GITHUB_TOKEN", "")
	t.Setenv("GH_TOKEN", "")
	if _, err := FromEnv("o/r"); err == nil || !strings.Contains(err.Error(), "GITHUB_TOKEN") {
		t.Errorf("no token: %v", err)
	}
}
