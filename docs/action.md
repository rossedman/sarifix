# GitHub Action

`rossedman/sarifix` is a GitHub Action that runs sarifix in a workflow. It installs a verified sarifix release and the scanners your `sarifix.yaml` names, then scans. What happens next depends on the event:

- **Pushes, schedules and manual runs:** it uploads the scan to code scanning and keeps one issue per batch (`sarifix fix --mode issues`), for Claude or a person to fix.
- **Pull requests:** it reports the findings the change introduced in the job summary and as annotations on the changed lines.

## Quick start

Add a `sarifix.yaml` to the repository (the [configuration guide](configuration.md) explains it), then save this as `.github/workflows/sarifix.yml`:

```yaml
--8<-- "examples/workflows/sarifix-issues.yml"
```

That's the whole setup. Only rules listed in `rules.allow` become issues, and nothing is handed to an agent until you set the repository variable `SARIFIX_QUEUE`. [Turn findings into issues Claude works through](tutorials/claude-queue.md) covers the agent side.

## Modes

| `mode` | What it does | Permissions |
| --- | --- | --- |
| `auto` (default) | `check` on pull requests, `issues` on every other event | as below |
| `issues` | Scan, upload to code scanning, then open, refresh, close and queue one issue per batch | `contents: read`, `security-events: write`, `actions: read` (private repos), `issues: write` |
| `scan` | Scan and upload to code scanning only | `contents: read`, `security-events: write`, `actions: read` (private repos) |
| `check` | Scan the merge base and the pull request with the pull request's `sarifix.yaml`, then write the new findings to the job summary and as warnings. Needs `fetch-depth: 0` | `contents: read` |
| `install` | Install sarifix and the scanners, for a later step to use, such as an agent fixing a sarifix issue | `contents: read` |

## Inputs

| Input | Default | Description |
| --- | --- | --- |
| `mode` | `auto` | One of the modes above |
| `config` | `sarifix.yaml` | Path to the config |
| `scanners` | `auto` | Scanners to install: `auto` (each scanner in the config that the action knows), `none`, or a comma-separated list. Scanners already on `PATH` are left alone |
| `upload-sarif` | `true` | Upload the scan to code scanning (issues and scan modes) |
| `sarif-category` | `sarifix` | The code scanning category |
| `queue` | (config) | Issues mode: how many issues to keep labeled `agent-ready`. Empty uses `publish.issues.queue`. Above 0, this starts paid agent runs |
| `dry-run` | `false` | Issues mode: show the changes in the job summary without making them |
| `fail-on-new` | `false` | Check mode: fail the step when the pull request introduces findings |
| `version` | the action's tag | The sarifix release to install, such as `v0.2.3`. Without a tag (a branch or SHA reference), the latest release |
| `install` | `true` | Set `false` to use a sarifix already on `PATH` |
| `token` | `github.token` | Token for the code scanning upload and the issues |

## Outputs

| Output | Description |
| --- | --- |
| `mode` | The mode that ran |
| `sarif-dir` | Directory of the per-scanner SARIF files (issues and scan modes) |
| `opened`, `closed`, `queued` | Issues changed (issues mode) |
| `new` | Findings the pull request introduced (check mode) |

## Scanners the action installs

With `scanners: auto`, each scanner in `sarifix.yaml` whose `name` is one of these is installed at a pinned version. Archives are checked against their release's published checksums, and Python scanners come from PyPI through pipx.

| Name | Version | From |
| --- | --- | --- |
| `trivy` | 0.76.1 | GitHub release, checksums |
| `golangci-lint` | 2.15.0 | GitHub release, checksums. Needs Go: add `actions/setup-go` first |
| `gitleaks` | 8.30.1 | GitHub release, checksums |
| `hadolint` | 2.14.0 | GitHub release, checksum |
| `tfmetrics` | 0.2.2 | GitHub release, checksums |
| `checkov` | 3.3.30 | PyPI |
| `ruff` | 0.17.1 | PyPI |
| `semgrep` | 1.182.1 | PyPI |

The versions move with action releases, on purpose: a new scanner release adds rules, and those arrive as new issues. To use another version, or a scanner the action doesn't know, install it in an earlier step. The action leaves anything already on `PATH` alone.

## Security

- The sarifix archive is checked against the release's `checksums.txt`. The action doesn't verify that file's cosign signature; [Supply chain](security.md#supply-chain) shows how to, and pinning the action to a commit SHA fixes which release it installs.
- Scan output goes to `$RUNNER_TEMP`, outside the checkout, so no scanner reads another's output and nothing is committed.
- Scanner messages in issues, annotations and job summaries are escaped, so they can't fake sarifix's markers, mention people, break tables or inject workflow commands.
- On pull requests from forks, the token is read-only. Check mode needs nothing more.
