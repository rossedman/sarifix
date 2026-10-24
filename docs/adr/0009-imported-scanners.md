# 9. Imported scanners: code scanning alerts as findings

- Status: accepted
- Date: 2026-10-24

## Context

Issues mode turns sarifix's own scan into issues. A repository's code scanning list can also hold alerts from tools sarifix doesn't run, mainly CodeQL, which GitHub runs itself (default setup or the CodeQL workflow) and which needs a build database that a `command` can't easily produce. On postmarkd, 4 of 39 open alerts were CodeQL's, and nothing turned them into issues.

## Decision

- **A scanner with no `command` is imported.** sarifix never runs it: `scan`, `check`, the Stop hook and the fixing modes skip it, and the action doesn't install it. It still routes findings by `match`, so rules, campaigns, `min_level`, path policy and `group_by` apply as usual.
- **`sarifix alerts export` reads its findings.** It lists the repository's open code scanning alerts on the default branch (`GET /repos/{owner}/{repo}/code-scanning/alerts`, paged) and writes the ones routed to an imported scanner as SARIF. The alert's number and URL are kept in each result's properties. Plan and issues mode read that file like any other SARIF.
- **Only imported scanners' alerts.** Alerts from the scanners sarifix runs are left out: its own scan already reports them, and reading them back would count every finding twice.
- **An empty run per imported scanner.** Issues mode closes an issue only when its scanner's SARIF was read. Writing a run with no results for a scanner with no open alerts lets its last issues close. When the export fails, there is no run, so nothing closes.
- **Issues prove the fix differently.** The agent can't rerun CodeQL, so an imported batch's issue says code scanning on the pull request must stop reporting the alerts, keeps `sarifix check` for everything else, and adds "no dismissing alerts" to what's out of scope.
- **The action runs the export in issues mode.** It writes the file outside the uploaded SARIF directory, so the alerts are never uploaded back under the `sarifix` category. A failed read (403 without Advanced Security, or a missing permission) is a warning.

## Consequences

- Adding `- name: codeql` with `match: [CodeQL]` is the whole setup in the action. The token already has `security-events: write` for the upload, which includes read.
- Fixed CodeQL alerts close in code scanning when GitHub's next analysis runs, and their issues close on the next sarifix run after that, so the two can be a run apart.
- `pr` mode (phase 3) can't verify an imported batch with a rescan; it will need another check before it handles them.
