// Command sarifix turns any SARIF-emitting scanner into a verified
// auto-fixer.
package main

import (
	"context"
	"os"

	"github.com/rossedman/sarifix/internal/cli"
)

// main runs the CLI and exits with its documented exit code.
func main() {
	err := cli.Execute(context.Background(), os.Args[1:], os.Stdout, os.Stderr)
	os.Exit(cli.ExitCode(err))
}
