# 5. Policy and batching details

- Status: accepted
- Date: 2026-10-23

## Context

Phase 1 adds filtering, grouping, `sarifix plan` and `--mode report`. The spec fixes the overall shape (batch key = `scanner/ruleId` or campaign ID, order by severity then count, cap at `batches_per_run`) but leaves several details open.

## Decision

- **Package layout.** `pkg/policy` filters and `pkg/group` batches, as the spec lays out. A small `pkg/plan` runs both and records a status per finding, so `plan` and `fix` share one code path. The report writer lives in `pkg/publish`, next to the mode handlers still to come.
- **Every skip has a reason.** Checks run in a fixed order (`unrouted`, `no_location`, `in_baseline`, `below_min_level`, `rule_denied`, `rule_not_allowed`, `path_denied`, `not_selected`), and a finding gets the first reason that applies. Unrouted findings stay in the report, as the spec asks, but are never fixable.
- **Campaign rules count as allowed.** A finding matching a campaign's rules needs no separate `rules.allow` entry; the spec's example config relies on this. `rules.deny`, `min_level` and `paths.deny` still apply.
- **The baseline is a multiset.** One old finding hides one new copy, not every identical finding, matching `sarifix diff`.
- **Splitting keeps files whole.** A group is sorted by path and line, then cut so no part exceeds `files_per_batch` or `findings_per_batch`. A file moves between parts as a unit unless it alone has more than `findings_per_batch` findings. Parts are numbered `#2`, `#3`, and their branches get `-2`, `-3`.
- **Ordering is per group.** Groups are ranked by their most severe finding, then by total findings, then by key; a group's parts stay together and in order. Ranking each part on its own size would put `#3` before `#2`.
- **Branch names are deterministic.** `<prefix>/<scanner>/<rule-slug>` for rules and `<prefix>/campaign/<id>` for campaigns (a campaign spans several rules). The slug is the lower-cased ID with unsafe runs replaced by `-`. When that changes more than case, truncates, comes out empty or ends in `.lock`, a 6-hex hash of the original ID is appended, so `go/sql-injection` and `go-sql-injection` don't share a branch. IDs that differ only in case do share one.
- **CLI shape.** `fix` exists now with only `--mode report`. The other modes exit 1 with the phase that brings them, so scripts written today keep working when they land. `plan` takes the same selection flags as `fix` (`--rule`, `--campaign`, `--baseline`), since it previews a fix run.
- **Report files.** `--out-dir` (default `sarifix-report/`) receives `sarifix.sarif` (every input run, patched with `properties.sarifix` on each finding) and `summary.json`. Results that aren't findings (`kind` other than `fail`) are left untouched.
