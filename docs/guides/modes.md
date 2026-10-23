# Modes

sarifix has four modes. They run the same pipeline and differ only in what triggers them, which findings they look at, and where the result goes.

!!! warning "Planned, not shipped"
    The four modes arrive in phases 1 to 4 of the [roadmap](../roadmap.md). Nothing on this page can be run yet. It describes the design so you can see where the project is heading. What does run today is `scan`, `diff` and `config validate`; see [Getting started](../getting-started.md).

| Mode | Trigger | Publishes | Typical use | Phase |
| --- | --- | --- | --- | --- |
| `report` | Anything | Enriched SARIF and a JSON summary. No edits. | Dry runs, triage, metrics | 1 |
| `local` | CLI or an agent hook | Edits in your working tree. No git operations. | Laptop use, Claude Code hooks | 2 |
| `pr` | A scan of the default branch | One PR per rule batch | Backlog burn-down, migrations, CVE response | 3 |
| `review` | A scan of a pull request | Suggested-change comments on that PR | PR assist | 4 |

## report

Writes no code. It runs ingest, fingerprint and filter, then writes the SARIF back out with a `properties.sarifix` block on each result recording its status and the reason it was or was not selected, plus a JSON summary. Use it to see what sarifix would do before you let it do anything, and to feed dashboards. `sarifix plan` shows the same batches without writing files.

## local

Runs the full fix and verify loop and leaves verified edits in your working tree, then prints a summary. It never commits or pushes. A Claude Code `PostToolUse` hook can call it with `--baseline` so an agent cleans up the findings it just introduced.

## pr

Runs on pushes to the default branch only, never on fork pull requests. Each verified batch becomes a branch, a commit with a conventional message and a pull request. The PR body lists each finding, the one-line rationale per finding, before and after counts from verification, the test results and a hidden marker used to avoid duplicates on re-runs. Reviewers come from `CODEOWNERS`. sarifix never auto-merges.

## review

Takes the baseline diff between the pull request and its merge base, so only findings the PR introduced are considered. Fixes for lines inside the PR diff come back as GitHub suggested changes the author can accept. A fix that spans lines outside the diff becomes a summary comment. On fork PRs it posts suggestions only and never runs with a write token against fork code.

## What every mode shares

- Findings come from SARIF through the [fingerprint](fingerprints.md) pipeline.
- Nothing is published until a rescan and your own `verify.commands` pass.
- `.github/workflows/**` is never edited. See [Security](../security.md).
