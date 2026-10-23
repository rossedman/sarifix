// Command doccheck fails when a function, method or package lacks a doc
// comment. Generated files and tests are skipped; examples are checked.
//
// Usage: go run ./tools/doccheck ./...
package main

import (
	"fmt"
	"go/ast"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/rossedman/sarifix/tools/internal/gofiles"
)

// main runs the check over os.Args and exits non-zero on findings.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run checks the packages named by args and returns the exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		args = []string{"./..."}
	}
	files, err := gofiles.Walk(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "doccheck:", err)
		return 2
	}
	problems := check(files)
	for _, p := range problems {
		_, _ = fmt.Fprintln(stdout, p)
	}
	if len(problems) > 0 {
		_, _ = fmt.Fprintf(stderr, "doccheck: %d missing doc comments\n", len(problems))
		return 1
	}
	return 0
}

// check returns one line per missing doc comment, sorted.
func check(files []gofiles.File) []string {
	var problems []string
	pkgDoc := map[string]bool{}
	pkgFile := map[string]string{}
	for _, f := range files {
		if f.Generated {
			continue
		}
		dir := path.Dir(f.Path)
		if _, ok := pkgFile[dir]; !ok {
			pkgFile[dir] = f.Path
		}
		// Library packages say "Package x ..."; commands say "Command x ...".
		if doc := f.AST.Doc; doc != nil && (strings.HasPrefix(doc.Text(), "Package ") || f.AST.Name.Name == "main") {
			pkgDoc[dir] = true
		}
		for _, d := range f.AST.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok {
				continue
			}
			pos := f.Fset.Position(fn.Pos())
			name := funcName(fn)
			switch {
			case fn.Doc == nil:
				problems = append(problems, fmt.Sprintf("%s:%d: %s has no doc comment", f.Path, pos.Line, name))
			case !strings.HasPrefix(fn.Doc.Text(), fn.Name.Name+" "):
				problems = append(problems, fmt.Sprintf("%s:%d: doc comment for %s must start with %q", f.Path, pos.Line, name, fn.Name.Name))
			}
		}
	}
	for dir, file := range pkgFile {
		if !pkgDoc[dir] {
			problems = append(problems, fmt.Sprintf("%s: package %s has no package comment", file, dir))
		}
	}
	sort.Strings(problems)
	return problems
}

// funcName formats a function or method name for messages.
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if ix, ok := t.(*ast.IndexExpr); ok {
		t = ix.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}
