// Package github is a minimal GitHub REST client: the issue calls
// `sarifix fix --mode issues` needs, nothing more. It implements
// publish.Tracker.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rossedman/sarifix/pkg/publish"
)

// DefaultAPI is the API root used when GITHUB_API_URL is unset.
const DefaultAPI = "https://api.github.com"

// repoRE matches owner/name.
var repoRE = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$`)

// Client calls the GitHub REST API for one repository.
type Client struct {
	API   string
	Repo  string
	Token string
	HTTP  *http.Client
}

// FromEnv builds a client from the environment GitHub Actions sets:
// GITHUB_API_URL (default api.github.com), the repository (repo, else
// GITHUB_REPOSITORY) and a token (GITHUB_TOKEN, else GH_TOKEN).
func FromEnv(repo string) (*Client, error) {
	if repo == "" {
		repo = os.Getenv("GITHUB_REPOSITORY")
	}
	if !repoRE.MatchString(repo) {
		return nil, fmt.Errorf("repository %q is not owner/name; pass --github-repo or set GITHUB_REPOSITORY", repo)
	}
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		token = os.Getenv("GH_TOKEN")
	}
	if token == "" {
		return nil, errors.New("no GitHub token: set GITHUB_TOKEN (in Actions, ${{ github.token }} with issues: write) or GH_TOKEN")
	}
	api := os.Getenv("GITHUB_API_URL")
	if api == "" {
		api = DefaultAPI
	}
	return &Client{API: strings.TrimRight(api, "/"), Repo: repo, Token: token, HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

// issueJSON is the part of an issue the API returns that sarifix reads.
type issueJSON struct {
	Number      int    `json:"number"`
	Title       string `json:"title"`
	Body        string `json:"body"`
	PullRequest *struct {
		URL string `json:"url"`
	} `json:"pull_request"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// List returns the open issues with label, skipping pull requests (which
// the issues API also returns).
func (c *Client) List(ctx context.Context, label string) ([]publish.Issue, error) {
	var out []publish.Issue
	for page := 1; ; page++ {
		q := url.Values{"state": {"open"}, "labels": {label}, "per_page": {"100"}, "page": {strconv.Itoa(page)}}
		var batch []issueJSON
		if err := c.do(ctx, http.MethodGet, c.repoPath("issues")+"?"+q.Encode(), nil, &batch); err != nil {
			return nil, err
		}
		for _, is := range batch {
			if is.PullRequest != nil {
				continue
			}
			labels := make([]string, len(is.Labels))
			for i, l := range is.Labels {
				labels[i] = l.Name
			}
			out = append(out, publish.Issue{Number: is.Number, Title: is.Title, Body: is.Body, Labels: labels})
		}
		if len(batch) < 100 {
			return out, nil
		}
	}
}

// Create opens an issue.
func (c *Client) Create(ctx context.Context, title, body string, labels []string) (int, error) {
	var created issueJSON
	err := c.do(ctx, http.MethodPost, c.repoPath("issues"), map[string]any{"title": title, "body": body, "labels": labels}, &created)
	return created.Number, err
}

// Update replaces an issue's title and body.
func (c *Client) Update(ctx context.Context, number int, title, body string) error {
	return c.do(ctx, http.MethodPatch, c.repoPath("issues", strconv.Itoa(number)), map[string]any{"title": title, "body": body}, nil)
}

// Close comments on an issue, then closes it as completed.
func (c *Client) Close(ctx context.Context, number int, comment string) error {
	n := strconv.Itoa(number)
	if err := c.do(ctx, http.MethodPost, c.repoPath("issues", n, "comments"), map[string]any{"body": comment}, nil); err != nil {
		return err
	}
	return c.do(ctx, http.MethodPatch, c.repoPath("issues", n), map[string]any{"state": "closed", "state_reason": "completed"}, nil)
}

// AddLabel adds a label to an issue.
func (c *Client) AddLabel(ctx context.Context, number int, label string) error {
	return c.do(ctx, http.MethodPost, c.repoPath("issues", strconv.Itoa(number), "labels"), map[string]any{"labels": []string{label}}, nil)
}

// EnsureLabel creates a label, leaving an existing one as it is.
func (c *Client) EnsureLabel(ctx context.Context, name, color, description string) error {
	err := c.do(ctx, http.MethodPost, c.repoPath("labels"), map[string]any{"name": name, "color": color, "description": description}, nil)
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusUnprocessableEntity {
		return nil // already exists
	}
	return err
}

// APIError is a non-2xx response.
type APIError struct {
	Method, Path string
	Status       int
	Message      string
}

// Error describes the failed call and GitHub's message.
func (e *APIError) Error() string {
	return fmt.Sprintf("GitHub %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

// repoPath joins path segments under /repos/<owner>/<name>.
func (c *Client) repoPath(parts ...string) string {
	return "/repos/" + c.Repo + "/" + strings.Join(parts, "/")
}

// do sends a JSON request and decodes a JSON response into out (if not nil).
func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.API+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sarifix")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
		p, _, _ := strings.Cut(path, "?")
		return &APIError{Method: method, Path: p, Status: resp.StatusCode, Message: e.Message}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(data, out)
}
