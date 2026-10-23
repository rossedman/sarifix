# Roadmap

sarifix is built in six phases. Each ends with a working, released binary and has to meet its done criteria before the next one starts.

!!! success "Where we are"
    Phases 0 and 1 are built: `config validate`, `scan`, `diff`, `plan`, `fix --mode report`, `fix --mode issues` and `version` run today. So does `check`, which reports what a change introduced and runs as a [Claude Code hook](tutorials/claude-code-hook.md) so Claude fixes its own findings. The autonomous fixing modes are planned and do not exist yet.

| Phase | Name | Status |
| --- | --- | --- |
| 0 | Foundation | Done |
| 1 | Report and plan | Done |
| 2 | Local fixing | Planned |
| 3 | PR mode and the GitHub Action | Planned |
| 4 | Review mode and agent hook | Planned |
| 5 | Campaigns, controller and metrics | Planned |

## Phase 0: Foundation

The repo scaffold, the SARIF, finding and config packages with full validation, and the commands `sarifix config validate`, `sarifix scan` and `sarifix diff`.

**Done when** fixtures from Trivy, Checkov, golangci-lint and one hand-written custom tool load, normalize and fingerprint correctly, and `diff` reports new, fixed and unchanged findings correctly when lines shift.

## Phase 1: Report and plan

Policy filtering, batching, `sarifix plan`, and `--mode report` with enriched SARIF output.

**Done when** `plan` on a fixture repo prints the expected batches and skip reasons, and the enriched SARIF validates against the schema.

## Phase 2: Local fixing

The agent (Claude Code, headless), a sandbox with git worktrees and Linux network isolation, the verify stages, `--mode local` and `sarifix doctor`.

**Done when**, on a fixture repo with seeded Dockerfile, Terraform and Go findings, `sarifix fix --mode local` fixes at least one allowed rule per scanner, verification passes, and a deliberately bad agent fake is caught by each verify stage.

## Phase 3: PR mode and the GitHub Action

The GitHub forge layer, PR publishing, a JSONL state store, `action.yml` and example workflows.

**Done when**, on a sandbox GitHub repo, a push to main produces scan, fix and one PR per rule batch, re-running produces no duplicate PRs, and workflow files are never modified.

## Phase 4: Review mode and agent hook

`--mode review` with baseline diff and suggested changes, and a documented Claude Code hook.

The hook part shipped early, in a simpler form: [`sarifix check --hook`](tutorials/claude-code-hook.md) runs as a Stop hook and reports findings to Claude instead of having sarifix fix them. See [ADR 6](adr/0006-feedback-hook.md).

**Done when** a PR that introduces two findings receives exactly two suggestions, pre-existing findings are ignored, and fork PRs get suggestions without write-token execution.

## Phase 5: Campaigns, controller and metrics

Campaigns in config, an org controller workflow using a GitHub App, a SQLite store, and `sarifix stats` with refresh.

**Done when** a campaign across at least three sandbox repos opens migration PRs, respects rate limits, and `stats` reports campaign progress and per-rule success and merge rates.

## Not in v1

- Auto-merging anything.
- Writing a scanner. sarifix consumes SARIF; other tools produce it.
- Forges other than GitHub, though the forge layer sits behind an interface.
- Findings with no file location, such as SBOM-only or account-level findings.

Design decisions that deviate from the plan are recorded as architecture decision records under Project.
