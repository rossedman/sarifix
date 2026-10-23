# Workflows

## `sarifix-pr.yml`

A GitHub Actions workflow for pull requests. It scans the pull request and its merge base with the same `sarifix.yaml`, writes the new, fixed and unchanged counts and a table of new findings to the job summary, and uploads the report (`sarifix.sarif`, `summary.json`, `diff.json`) as an artifact.

It is read-only: `contents: read`, no secrets and no agent, so it is safe on pull requests from forks.

Copy it to `.github/workflows/sarifix.yml` in your repository and adjust:

- **Scanners:** it installs Trivy and Checkov. Add install steps for whatever your `sarifix.yaml` runs.
- **`SARIFIX_REF`:** the workflow needs `sarifix fix --mode report`, which came after the v0.1.0 release (v0.1.0 has only `scan` and `diff`). Until the next release, pin a commit SHA from `main`; after that, pin the release tag. `go install` from the repository only works while it is public.
- **Failing the build:** it only reports. To fail on new findings, add a step that exits non-zero when `jq '.counts.new' diff.json` is above zero.

The [GitHub Actions tutorial](https://rossedman.io/sarifix/tutorials/github-actions/) walks through it and shows a real job summary.

### How it was tested

The workflow passes `actionlint`. Its `run:` steps were executed against a real pull request on [terragoat](https://github.com/bridgecrewio/terragoat), with `RUNNER_TEMP`, `GITHUB_BASE_REF` and `GITHUB_STEP_SUMMARY` set by hand. The `uses:` steps (checkout, setup-go, setup-trivy, upload-artifact) are standard actions pinned to commit SHAs but haven't run together on GitHub yet.

## `sarifix-issues.yml`

A workflow that scans the default branch weekly, after every push to `main` and on demand. It uploads the SARIF to GitHub code scanning, then runs `sarifix fix --mode issues` to keep one open issue per batch. Issues are opened, refreshed and closed as the scans change. They're written in the agent-ready format of the [task-queue](https://github.com/rossedman/claude/tree/main/plugins/task-queue) plugin, so Claude can fix them in Actions one pull request at a time.

Copy it to `.github/workflows/`. `publish.issues` in `sarifix.yaml` sets how many issues may be open at once (`max_open`, default 10). The repository variable **`SARIFIX_QUEUE`** (default 0) sets how many to keep labeled `agent-ready`; above 0, it starts paid agent runs. Try `sarifix fix --mode issues --dry-run` locally first, with `GITHUB_TOKEN` and `GITHUB_REPOSITORY` set, to see what it would do.

The [tutorial](https://rossedman.io/sarifix/tutorials/claude-queue/) covers the agent side and how to turn it on gradually.

### How it was tested

The workflow passes `actionlint` and `zizmor`. Its `run:` steps were executed against a test repository with eight scanners, with `RUNNER_TEMP` and the Actions variables set by hand and an in-memory stand-in for the GitHub API. Three sync runs covered opening issues, an idempotent re-run, closing a fixed batch and refreshing a changed one. The `uses:` steps are pinned to commit SHAs but haven't run together on GitHub yet.
