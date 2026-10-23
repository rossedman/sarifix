# 6. Feedback to Claude Code through a hook

- Status: accepted
- Date: 2026-10-23

## Context

The spec has sarifix drive an agent: it batches findings, runs Claude Code headless in a sandboxed worktree per batch, verifies the result, and publishes it (phases 2 to 4). That is the right shape for unattended runs, such as a nightly backlog burn-down. It is a lot of machinery for the most common case, though, which is a person working with Claude Code who wants Claude's own changes to pass the repository's scanners.

## Decision

Add `sarifix check`, which reports the findings the working tree introduced relative to a commit, and a `--hook` mode for Claude Code's Stop event.

- sarifix doesn't run the agent. Claude Code is already running, with the user's permissions and in the user's session. sarifix only tells it what to fix.
- **What counts as new:** a scan of the base commit (default `HEAD`) in a temporary git worktree, cached in the git directory per commit and scanner config, compared by fingerprint with a scan of the working tree. Pre-existing findings, including moved ones, are never reported.
- **Policy:** `rules.min_level`, `rules.deny` and `paths.deny` apply; `rules.allow` doesn't, unless `--allowed-only` is passed. `rules.allow` governs what sarifix may fix unattended, and a finding a change just introduced is worth fixing whatever the allow list says.
- **Hook protocol:** always exit 0, and answer in JSON. `hookSpecificOutput.additionalContext` sends findings to Claude, which keeps working, labelled "Stop hook feedback". `systemMessage` warns the user when findings remain after Claude's follow-up (`stop_hook_active`) or when the check couldn't run. Clean changes print nothing. An earlier version exited 2 with the findings on stderr. That worked, but Claude Code labels it "Stop hook error", which misdescribes normal feedback.
- **Scanner failures:** a scanner that fails on either side is excluded from the comparison and reported, rather than making all its findings look new or fixed.
- **Untrusted text:** messages and paths are sanitized and truncated, and the feedback labels them as tool output, not instructions. It also tells Claude not to suppress findings with ignore comments.
- **Stop, not PostToolUse:** whole-repo scanners take seconds per run, so checking once per turn is the practical granularity.

## Consequences

- The verify stages planned for phase 2 (rescan, targets gone, nothing new) already exist in this form for interactive use.
- The autonomous modes (`local`, `pr`, `review`) stay on the roadmap for unattended use, but they are no longer the only way to get value from fixing.
- Once a change is committed it stops being "new" relative to `HEAD`. Sessions that commit should use `--base` with the branch point.
- Tested end to end: in a real Claude Code session, Claude added an unhardened S3 bucket, the hook reported five Trivy findings, Claude added a public access block and KMS encryption, and the second check was clean.
