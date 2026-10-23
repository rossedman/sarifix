package sarif

import (
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Normalizer turns SARIF artifact locations into repo-relative paths with
// forward slashes.
//
// Resolution order for a location:
//  1. Resolve uriBaseId through the run's originalUriBaseIds (recursively).
//  2. Absolute file paths under Root become relative to Root.
//  3. Absolute paths under a known CI workspace (CIRoots) become relative to
//     that workspace, since the scan ran in another checkout of the same repo.
//  4. A relative URI whose base resolved somewhere outside Root is kept as
//     relative, for the same reason.
//
// A path that escapes the repo (via "..") or stays absolute is rejected.
type Normalizer struct {
	// Root is the absolute repo root on this machine.
	Root string
	// CIRoots are absolute workspace roots used by CI systems. Entries may
	// contain glob metacharacters matched one path segment at a time.
	CIRoots []string
}

// DefaultCIRoots are the workspace layouts of common CI systems.
var DefaultCIRoots = []string{
	"/github/workspace",     // GitHub Actions container jobs
	"/home/runner/work/*/*", // GitHub-hosted runners
	"/builds/*/*",           // GitLab
	"/workspace",            // Cloud Build, Tekton
	"/src",                  // common docker -v mount point
}

// NewNormalizer returns a Normalizer for root, adding $GITHUB_WORKSPACE when
// set.
func NewNormalizer(root string) (*Normalizer, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	n := &Normalizer{Root: filepath.ToSlash(abs)}
	if ws := os.Getenv("GITHUB_WORKSPACE"); ws != "" {
		n.CIRoots = append(n.CIRoots, filepath.ToSlash(ws))
	}
	n.CIRoots = append(n.CIRoots, DefaultCIRoots...)
	return n, nil
}

// maxBaseDepth bounds uriBaseId chains, which may be cyclic in hostile input.
const maxBaseDepth = 8

// Path returns the repo-relative path for loc in run, or ok=false when the
// location has no usable URI or points outside the repo.
func (n *Normalizer) Path(run *Run, loc *ArtifactLocation) (string, bool) {
	if loc == nil || loc.URI == nil || *loc.URI == "" {
		return "", false
	}
	base := ""
	if loc.URIBaseID != nil {
		b, ok := n.resolveBase(run, *loc.URIBaseID, 0)
		if !ok {
			return "", false
		}
		base = b
	}
	return n.Resolve(base, *loc.URI)
}

// resolveBase follows a uriBaseId to an absolute or relative base path. An
// ID the run doesn't define resolves to "" (SARIF lets consumers supply
// bases out of band; sarifix assumes the repo root). A chain deeper than
// maxBaseDepth is treated as cyclic and fails.
func (n *Normalizer) resolveBase(run *Run, id string, depth int) (string, bool) {
	if depth > maxBaseDepth {
		return "", false
	}
	if run == nil {
		return "", true
	}
	al, ok := run.OriginalUriBaseIds[id]
	if !ok || al.URI == nil {
		return "", true
	}
	p, ok := uriPath(*al.URI)
	if !ok {
		return "", true
	}
	if al.URIBaseID != nil && !path.IsAbs(p) {
		parent, ok := n.resolveBase(run, *al.URIBaseID, depth+1)
		if !ok {
			return "", false
		}
		return joinBase(parent, p), true
	}
	return p, true
}

// Resolve resolves uri against base (either may be empty) and makes the
// result repo-relative.
func (n *Normalizer) Resolve(base, uri string) (string, bool) {
	p, ok := uriPath(uri)
	if !ok {
		return "", false
	}
	if !path.IsAbs(p) && path.IsAbs(base) {
		full := path.Join(base, p)
		if rel, ok := n.relative(full); ok {
			return rel, true
		}
		// The base is some other checkout's root: the relative part is what
		// identifies the file.
		return clean(p)
	}
	if !path.IsAbs(p) {
		return clean(joinBase(base, p))
	}
	return n.relative(p)
}

// relative strips Root or a CI root prefix from an absolute path.
func (n *Normalizer) relative(abs string) (string, bool) {
	abs = path.Clean(abs)
	if rel, ok := under(n.Root, abs); ok {
		return clean(rel)
	}
	for _, r := range n.CIRoots {
		if rel, ok := underGlob(r, abs); ok {
			return clean(rel)
		}
	}
	return "", false
}

// under reports abs relative to root when abs is inside root.
func under(root, abs string) (string, bool) {
	root = strings.TrimSuffix(path.Clean(root), "/")
	if root == "" || root == "/" {
		return "", false
	}
	if !strings.HasPrefix(abs, root+"/") {
		return "", false
	}
	return abs[len(root)+1:], true
}

// underGlob is under with a root whose segments may be glob patterns.
func underGlob(root, abs string) (string, bool) {
	rs := strings.Split(strings.Trim(path.Clean(root), "/"), "/")
	as := strings.Split(strings.Trim(abs, "/"), "/")
	if len(as) <= len(rs) {
		return "", false
	}
	for i, seg := range rs {
		if ok, err := path.Match(seg, as[i]); err != nil || !ok {
			return "", false
		}
	}
	return strings.Join(as[len(rs):], "/"), true
}

// joinBase joins a relative path onto an optional base.
func joinBase(base, p string) string {
	if base == "" {
		return p
	}
	return path.Join(base, p)
}

// clean rejects paths that escape the repo and normalizes the rest.
func clean(p string) (string, bool) {
	c := path.Clean(p)
	if c == "." || c == ".." || strings.HasPrefix(c, "../") || path.IsAbs(c) {
		return "", false
	}
	return c, true
}

// uriPath converts a SARIF URI (file:// URI, relative reference or plain
// path) to a slash path. Non-file schemes are rejected.
func uriPath(uri string) (string, bool) {
	uri = strings.ReplaceAll(uri, `\`, "/")
	if isWindowsAbs(uri) {
		return "/" + uri, true
	}
	u, err := url.Parse(uri)
	if err != nil {
		// Not a valid URI reference: treat it as a plain path.
		return uri, true
	}
	switch strings.ToLower(u.Scheme) {
	case "":
		p := u.Path
		if p == "" {
			return "", false
		}
		return p, true
	case "file":
		p := u.Path
		if isWindowsAbs(strings.TrimPrefix(p, "/")) {
			p = "/" + strings.TrimPrefix(p, "/")
		}
		if p == "" {
			return "", false
		}
		return p, true
	default:
		return "", false
	}
}

// isWindowsAbs reports a drive-letter path like C:/src.
func isWindowsAbs(p string) bool {
	return len(p) >= 3 && p[1] == ':' && p[2] == '/' &&
		(p[0] >= 'a' && p[0] <= 'z' || p[0] >= 'A' && p[0] <= 'Z')
}
