# Report on every pull request in GitHub Actions

Run the check from [Check only what a pull request introduced](pull-requests.md) on every pull request. The workflow scans the pull request and its merge base with the same config, posts what the change introduced to the job summary, and uploads the report.

## The workflow

Save as `.github/workflows/sarifix.yml`. It is also in the sarifix repository at [`examples/workflows/sarifix-pr.yml`](https://github.com/rossedman/sarifix/blob/main/examples/workflows/sarifix-pr.yml).

```yaml
--8<-- "examples/workflows/sarifix-pr.yml"
```

How it fits together:

- **Both sides use the pull request's `sarifix.yaml`.** The merge base is checked out as a worktree and scanned with `--config` pointing at the pull request's file. A pull request that changes the config is then judged by its own rules on both sides, rather than looking like it fixed or introduced everything a rule covers.
- **`fetch-depth: 0`** makes the merge base reachable. A shallow clone can't compute it.
- **Read-only.** `contents: read` is the only permission and no secrets are used, so it is safe to run on pull requests from forks.
- **Pinned tools.** Scanner versions are pinned, so a new rule in a scanner release shows up as a deliberate version bump, not as a wave of new findings on an unrelated pull request.

## What a run produces

The workflow's scan and report steps were run against the terragoat pull request from the [pull request tutorial](pull-requests.md), with the GitHub variables they read set by hand. The job summary they wrote:

```markdown
### sarifix
15 new, 2 fixed, 718 unchanged findings

Fixable now: 2 findings in 2 batches

| New finding | Location |
| --- | --- |
| `Checkov/CKV2_AWS_6` | `terraform/aws/reports.tf:1` |
| `Checkov/CKV2_AWS_62` | `terraform/aws/reports.tf:1` |
...
| `Trivy/AWS-0132` | `terraform/aws/reports.tf:1` |
```

The `sarifix-report` artifact holds `sarifix.sarif` (every finding with its status), `summary.json` (batches and skip counts) and `diff.json` (new, fixed and unchanged findings).

## Adapting it

- **Other scanners**: install them in the install step. The scan steps run whatever `sarifix.yaml` lists.
- **Fail the build on new findings**: add a step that exits non-zero when `jq '.counts.new' diff.json` is above zero. Start with a report-only workflow and turn this on once the numbers are trusted.
- **Scan the default branch on a schedule**: drop the merge-base step and run `sarifix fix --mode report` without `--baseline`. The report then covers the whole backlog.

!!! note
    The workflow uses `sarifix fix --mode report`, which came after the v0.1.0 release (v0.1.0 has only `scan` and `diff`). Until the next release, pin `SARIFIX_REF` to a commit SHA from `main` rather than `main` itself; after that, pin the release tag. Release binaries can be verified as described in [Security](../security.md#verifying-releases).
