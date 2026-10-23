# 7. Issues mode: one GitHub issue per batch

- Status: accepted
- Date: 2026-10-23

## Context

The spec's unattended path is `pr` mode (phase 3): sarifix runs an agent on each batch in a sandboxed worktree, verifies the result and opens a pull request. Phase 3 also includes building the agent runner, sandbox and verification loop. Meanwhile there's already a good unattended agent: Claude Code in GitHub Actions, driven by an issue queue such as the task-queue plugin's `agent-queue.yml`, which implements an `agent-ready` issue and opens a pull request through the repository's normal CI and review.

The first version of that bridge was an example Python script that read report mode's `summary.json` and `sarifix.sarif` and synced issues through `gh`. It worked, but every repository had to copy it, and fixes to it reached nobody.

## Decision

Add `sarifix fix --mode issues`. It plans batches exactly as report mode does, then keeps one open issue per batch:

- **Matching:** a hidden `<!-- sarifix-batch: <id> -->` marker ties an issue to a batch, so titles can be edited. Only issues with both the marker and `publish.issues.label` are managed. The marker is the one the example script used, so its issues carry over.
- **Sync:** open issues for the most severe batches up to `publish.issues.max_open`, refresh an issue whose findings changed (ignoring commit SHAs, so a new scan alone changes nothing), and close, with a comment, an issue whose batch is gone.
- **Queueing:** label the most severe open issues `publish.issues.queue_label` until `publish.issues.queue` are queued or `agent-working`, never re-queueing `agent-failed`. The default is 0, because labeling starts paid agent runs.
- **Issue body:** the task-queue agent-ready format (context, findings with links, acceptance criteria, commands that prove the fix, out of scope). Scanner messages are collapsed to one line and capped. `<` is escaped so no message can open an HTML comment and fake the marker, and `@` mentions are defused so no message can notify anyone. The messages are labeled as data.
- **GitHub access:** a minimal REST client over `net/http` in `internal/github`, with no new dependency. The token, repository, API URL, server URL and commit come from the variables GitHub Actions sets. `pkg/publish` depends only on a `Tracker` interface, so the package doesn't import `internal/`.

## Consequences

- Backlogs can be burned down by Claude today, through PRs that run the repository's own CI and review, before `pr` mode's sandboxed agent exists.
- Verification is the agent's job, guided by the issue's **Done when** commands (a rescan of the batch's files and `sarifix check`). sarifix doesn't verify the fix itself, as `pr` mode will.
- `pr` mode stays on the roadmap for teams that want sarifix to run and verify the agent itself.
- The example script is removed: the mode supersedes it.
