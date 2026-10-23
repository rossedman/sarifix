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
