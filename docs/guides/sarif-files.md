# Where SARIF files live

**Don't commit SARIF files.** They're build output, like test results: each one describes a single commit, scanned by particular scanner versions. They go stale with the next push, change completely when a scanner updates, and a secrets scanner's SARIF quotes the secrets it found. sarifix regenerates them on every run, and each place it runs keeps them somewhere else:

| Where sarifix runs | What writes SARIF | Where it goes | How long it lasts |
| --- | --- | --- | --- |
| Your machine | `sarifix scan` | `sarif/` in the repository, or `--out-dir`. Add `sarif/` and `sarifix-report/` to `.gitignore`. | Until the next scan |
| Claude Code hook (`sarifix check --hook`) | `sarifix check` | The working-tree scan goes to a temporary directory. The base scan is cached in `.git/sarifix/scans/<commit>-<config>/`, inside `.git`, so git never tracks it. | Working tree: one check. Base: until you delete it or run `--refresh` |
| Pull request workflow ([`sarifix-pr.yml`](../tutorials/github-actions.md)) | `sarifix scan` on the merge base and the pull request | `$RUNNER_TEMP`, then the `sarifix-report` artifact | The artifact retention period (90 days by default) |
| Default branch workflow ([`sarifix-issues.yml`](../tutorials/claude-queue.md)) | `sarifix scan` on `main` | `$RUNNER_TEMP`, then uploaded to **GitHub code scanning** and the `sarifix-report` artifact | Code scanning keeps the alert history. The issues the workflow opens are the work queue. |

## Why nothing needs a stored baseline

"What's new" always means new compared with another commit, and sarifix scans that commit again rather than reading an old file:

- `sarifix check` scans `--base` (default `HEAD`) in a temporary worktree, and caches the result by commit.
- The pull request workflow scans the merge base in the same job.
- The default branch workflow doesn't compare at all: every run reports the whole backlog, and the issue sync works out what changed.

Both sides of a comparison therefore use the same scanner versions and the same `sarifix.yaml`. A committed baseline from last month would mark every rule added since as "new".

`--baseline` takes any SARIF file. If you want to grandfather a frozen set of findings anyway, you can commit one for that. For everyday use, rely on `rules.deny`, `paths.deny` and the base scan instead.

## Uploading to code scanning

Upload the per-scanner files from `sarifix scan`, in their output directory:

```yaml
- uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1
  with:
    sarif_file: ${{ runner.temp }}/sarif
    category: sarifix
```

Each file keeps its scanner's tool name, so alerts are grouped by scanner in the Security tab. To track an alert across commits, code scanning uses the `primaryLocationLineHash` fingerprint. Some scanners write it themselves, and `upload-sarif` computes it for results that lack it.

Upload from the default branch, and optionally from pull requests. Code scanning compares a pull request's upload with the default branch's to annotate the diff. The job needs `security-events: write`, plus `actions: read` on private repositories, which also need GitHub Code Security.
