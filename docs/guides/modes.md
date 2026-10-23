# Modes

sarifix has four modes. They run the same pipeline and differ only in what triggers them, which findings they look at, and where the result goes.

!!! warning "Only report mode is shipped"
    `report` works today. `local`, `pr` and `review` arrive in phases 2 to 4 of the [roadmap](../roadmap.md); asking for one now exits with an error naming its phase. Their sections describe the design so you can see where the project is heading.

| Mode | Trigger | Publishes | Typical use | Phase |
| --- | --- | --- | --- | --- |
| `report` | Anything | Enriched SARIF and a JSON summary. No edits. | Dry runs, triage, metrics | 1 |
| `local` | CLI or an agent hook | Edits in your working tree. No git operations. | Laptop use, Claude Code hooks | 2 |
| `pr` | A scan of the default branch | One PR per rule batch | Backlog burn-down, migrations, CVE response | 3 |
| `review` | A scan of a pull request | Suggested-change comments on that PR | PR assist | 4 |

## report

Writes no code. It runs ingest, fingerprint, filter and group, then writes two files to `--out-dir` (default `sarifix-report/`):

- `sarifix.sarif`: every input run, unchanged except that each finding gets a `properties.sarifix` block with its status (`batched`, `deferred` or `skipped`), the skip reason, its batch and the branch a fix would use. It validates against the SARIF 2.1.0 schema, so code scanning and other SARIF viewers still read it.
- `summary.json`: counts by status and skip reason, and the batches in the order a run would attempt them.

```console
$ sarifix fix --mode report --sarif 'sarif/*.sarif'
...
✓ sarifix-report/sarifix.sarif
✓ sarifix-report/summary.json
```

A deferred finding from that run carries:

```json
"properties": {
  "sarifix": {
    "status": "deferred",
    "scanner": "checkov",
    "ruleKey": "checkov/CKV_AWS_24",
    "batch": "checkov/CKV_AWS_24",
    "branch": "sarifix/checkov/ckv_aws_24",
    "fingerprint": "fcadca11a498b6d6f0a7012e1e3081fc:1"
  }
}
```

Use it to see what sarifix would do before you let it do anything, and to feed dashboards. [`sarifix plan`](../reference/commands/sarifix_plan.md) shows the same batches without writing files.

### Skip reasons

Checks run in this order, and a finding gets the first reason that applies:

| Reason | Meaning |
| --- | --- |
| `unrouted` | No scanner's `match` covers the SARIF tool name. Kept in the report, never fixable. |
| `no_location` | No file location inside the repo. |
| `in_baseline` | Also in the `--baseline` scan, so not new. |
| `below_min_level` | Level is under `rules.min_level`. |
| `rule_denied` | Matches `rules.deny`. |
| `rule_not_allowed` | Not in `rules.allow` and not in a campaign. |
| `path_denied` | The file matches `paths.deny` (which always includes `.github/workflows/**`). |
| `not_selected` | Excluded by `--rule` or `--campaign`. |

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
