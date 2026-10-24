# 8. Grouping findings by file

- Status: accepted
- Date: 2026-10-23

## Context

The spec makes a batch one rule (`<scanner>/<ruleId>`) or one campaign. That suits rules spread across many files, such as a TLS setting missing in seven Go files. It doesn't suit scanners that report many rules against one file. Trivy's Kubernetes checks each flag one setting in the same manifest, so one manifest made eight issues of one finding each, all fixed by one edit to one file. In issues mode, that's eight agent runs and eight pull requests touching the same lines.

Campaigns can already group rules, but each campaign is written by hand and is meant for migrations that span repositories.

## Decision

Add `limits.group_by`:

- **`rule`** (default): one batch per rule, as before, so existing issues and branches keep their IDs.
- **`file`**: one batch per scanner and file, with every rule that scanner reports there.
- **`auto`**: one batch per rule, except that rules a scanner reports in only one file share that file's batch, when at least two of them do. A rule spread across files keeps its own batch, and a lone single-file rule keeps its rule ID.

Campaigns still come first under every setting. A file batch's key is `<scanner>:<path>`, and its branch is `<prefix>/file/<scanner>/<path-slug>`. Batches gain `file` and `rules` in JSON (fields are only added). Batches stay within one scanner, so a fix is still checked by one scanner's rescan.

An issue for a file batch lists its rules, and its **Done when** command passes one `--rule` per rule. Campaign issues now select with `--campaign`. Before, they passed the campaign ID to `--rule`, which matched nothing.

## Consequences

- Turning on `file` or `auto` changes batch IDs. Issues mode closes the old per-rule issues and opens the merged ones.
- Under `auto`, a batch's shape can change as findings move: when a rule spreads to a second file, it leaves the file batch and gets its own.
