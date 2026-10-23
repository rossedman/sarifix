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

The whole setup with the [sarifix GitHub Action](https://rossedman.io/sarifix/action/), in one job. On pushes to `main`, weekly and on demand, it installs sarifix and the scanners `sarifix.yaml` names, scans, uploads to code scanning and keeps one issue per batch (`sarifix fix --mode issues`) in the agent-ready format of the [task-queue](https://github.com/rossedman/claude/tree/main/plugins/task-queue) plugin. On pull requests it reports what the change introduced, in the job summary and as annotations.

Copy it to `.github/workflows/sarifix.yml`, and pin the action to the tag's commit SHA. `publish.issues.max_open` in `sarifix.yaml` caps how many issues are open at once (default 10). The repository variable **`SARIFIX_QUEUE`** (default 0) sets how many to keep labeled `agent-ready`; above 0, it starts paid agent runs. Add `dry-run: "true"` to the action's `with:` for a first run that changes nothing.

The [tutorial](https://rossedman.io/sarifix/tutorials/claude-queue/) covers the agent side and how to turn it on gradually.

### How it was tested

The workflow and the action pass `actionlint` and `zizmor`, and the action's scripts pass `shellcheck` and `shfmt`. CI runs the action from the checkout on every change (scan, issues in dry-run mode, check on pull requests). Locally, its install step installed all eight scanners from a clean `PATH`, checking each against its release's checksums. Its scan, issues and check scripts ran against a test repository, with the Actions variables set by hand and a stand-in for the GitHub API. `sarifix-pr.yml` above is the same pull request check, built by hand.
