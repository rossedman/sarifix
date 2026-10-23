# Tools

Small programs that keep the repository's standards enforceable. CI and `make check` run them; none ship in the sarifix binary.

| Tool | Run with | What it does |
| --- | --- | --- |
| `check-cmds.sh` | `make check-cmds` | Fails if any file in `internal/cli/` (tests aside) defines anything other than exactly one `*cobra.Command`. One command per file, registered in that file's `init()`, keeps the CLI easy to find your way around. |
| `doccheck/` | `make doccheck` | Fails on any function or method without a doc comment, any doc comment that doesn't start with the identifier's name, and any package without a package comment. Generated files and tests are skipped; `examples/` is checked. |
| `generated/` | used by `make cover` | Prints the module-qualified paths of generated Go files (`// Code generated ... DO NOT EDIT.`), so the coverage gate can filter them out of the profile. With none, it prints a sentinel line that matches nothing. |
| `gendocs/` | `make docs` | Writes the generated reference pages: one page per command under `docs/reference/commands/` (via `cobra/doc`), and `docs/reference/config.md` built from the `doc`, `default` and `required` struct tags in `pkg/config`. `make docs-check` fails CI when they are stale. |
| `release-extras.sh` | goreleaser `before` hook | Generates the bash, zsh and fish completions and the gzipped man page into `completions/` and `manpages/`, which the release archives and the Homebrew cask ship. Both directories are gitignored. |
| `regen-fixtures.sh` | `tools/regen-fixtures.sh` | Regenerates the scanner fixtures in `testdata/sarif/` with real Trivy, Checkov and golangci-lint. See [`testdata/README.md`](../testdata/README.md). |
| `internal/gofiles/` | (library) | The package walker shared by `doccheck` and `generated`. |

The Go tools have their own tests and count toward the coverage gate like any other code.
