// Command generated prints the import-path-qualified names of generated Go
// files, one per line, for filtering them out of coverage profiles.
//
// Usage: go run ./tools/generated ./...
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/rossedman/sarifix/tools/internal/gofiles"
)

// main prints generated files for os.Args.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run writes one module-qualified path per generated file. With none, it
// prints a sentinel ("#" never appears in import paths), so grep -vFf still
// has a pattern and filters nothing.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		args = []string{"./..."}
	}
	mod, err := gofiles.ModulePath()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "generated: read go.mod:", err)
		return 2
	}
	files, err := gofiles.Walk(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "generated:", err)
		return 2
	}
	n := 0
	for _, f := range files {
		if f.Generated {
			_, _ = fmt.Fprintf(stdout, "%s/%s:\n", mod, f.Path)
			n++
		}
	}
	if n == 0 {
		_, _ = fmt.Fprintln(stdout, "#no-generated-files#")
	}
	return 0
}
