// Package gofiles walks Go packages and classifies their files, shared by
// the doccheck and generated tools.
package gofiles

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// File is one parsed Go source file.
type File struct {
	// Path is the slash path relative to the module root.
	Path string
	// AST is the parsed file, with comments.
	AST *ast.File
	// Fset positions AST nodes.
	Fset *token.FileSet
	// Generated reports a "// Code generated ... DO NOT EDIT." header.
	Generated bool
}

// Walk parses every non-test .go file under the given patterns. A pattern
// ending in "/..." walks recursively; others name one directory. testdata,
// vendor and hidden directories are skipped.
func Walk(patterns []string) ([]File, error) {
	fset := token.NewFileSet()
	var out []File
	seen := map[string]bool{}
	for _, p := range patterns {
		root, recursive := strings.CutSuffix(p, "/...")
		if root == "" || root == "." && p == "./..." {
			root = "."
		}
		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				name := d.Name()
				if path != root && (!recursive || name == "testdata" || name == "vendor" || strings.HasPrefix(name, ".") || name == "node_modules") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || seen[path] {
				return nil
			}
			seen[path] = true
			f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}
			out = append(out, File{Path: filepath.ToSlash(filepath.Clean(path)), AST: f, Fset: fset, Generated: ast.IsGenerated(f)})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// ModulePath reads the module path from go.mod in the current directory.
func ModulePath() (string, error) {
	data, err := os.ReadFile("go.mod")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module "); ok {
			return strings.TrimSpace(rest), nil
		}
	}
	return "", os.ErrNotExist
}
