# 1. Repo layout and CLI wiring

- Status: accepted
- Date: 2026-10-22

## Context

The spec lays out `cmd/sarifix/` and `internal/cli/`. The go-bootstrap standard puts `main.go` at the root calling `cmd.Execute()`, with one cobra command per file in `cmd/` registered in that file's `init()`. The spec also lists `pkg/scanner` for template expansion and `pkg/policy` for globs.

## Decision

- Keep the spec's layout: `cmd/sarifix/main.go` calls `cli.Execute` and maps errors to the documented exit codes; commands live in `internal/cli/`.
- Apply the one-command-per-file rule to `internal/cli/` (`tools/check-cmds.sh` enforces it). Each file registers a constructor in `init()`; `NewRoot` builds a fresh tree from those constructors on every run, so tests never share flag state.
- `sarifix.yaml` is the product config and keeps the `--config` flag the spec gives it. Viper handles CLI settings only (flag > `SARIFIX_*` env > `settings.yaml` in `$XDG_CONFIG_HOME/sarifix`, `~/.config/sarifix` or `~/.sarifix`), and that file is chosen with `--settings`.
- Add two small packages the spec doesn't list: `pkg/placeholder` (argv templates, shared by config validation and the scanner runner without an import cycle) and `pkg/glob` (path and rule-key globs, used by config validation now and by `pkg/policy` in phase 1).
- Raise the coverage bar from the spec's 80% on `pkg/...` to the bootstrap standard's 90% on all hand-written code, which satisfies both.

## Consequences

`internal/cli/root.go` holds the root command and the shared plumbing (settings, logging, exit codes). Shared helpers for other commands go in that file or in a package outside `internal/cli/`.
