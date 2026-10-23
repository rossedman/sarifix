# 3. Fingerprint details

- Status: accepted
- Date: 2026-10-22

## Context

The spec says: use `partialFingerprints` when present (prefer `primaryLocationLineHash`), otherwise hash tool, rule, path and the whitespace-collapsed snippet, and never use line numbers. Several cases need more precision.

## Decision

1. Precedence: `primaryLocationLineHash` (with GitHub's `:N` occurrence suffix removed), then the tool's other partial fingerprints (sorted `key=value` pairs), then `partialFingerprints["sarifix/v1"]`, then the hash of the anchor (item 6), then a hash of the message. Every hash includes tool and rule ID. (Amended 2026-10-23: `sarifix/v1` used to rank below lines read from the repo. Testing `plan --baseline` against a scan of an older release showed that re-reading lines in a newer checkout hashes the wrong text.)
2. The snippet is `region.snippet.text` when the tool provides one, else the region's lines read from the repo (capped at 200 lines). A snippet that is only whitespace counts as no snippet; the fuzzer found that the two were hashed differently.
3. Identical findings in one run (same tool, rule, path and snippet) are numbered in order of appearance (`<hash>:1`, `<hash>:2`), so they stay distinct and a diff still pairs them correctly.
4. `sarifix scan` records the snippet hash under `partialFingerprints["sarifix/v1"]`. A later diff that can't read the files (for example, against a scan of another commit) gets the same fingerprint.
5. Findings with no snippet and no fingerprints fall back to the message, which is still independent of line numbers.

6. **Anchors** (amended 2026-10-23). The computed hash covers the finding's anchor, not every flagged line. For a one-line region the anchor is that line. For a block it is the shortest run of lines, from the block's first non-blank line, that occurs nowhere else in the file. Testing against real repositories showed why: Checkov and Trivy flag whole Terraform resources and Kubernetes objects, so hashing the whole block made one attribute edit flip every other finding on that resource. On terragoat, one such edit plus a new bucket diffed as 25 new and 12 fixed with whole-block hashes, and as 15 new and 2 fixed (the true answer) with anchors. A first-line-only anchor was rejected: in a multi-document Kubernetes file every Deployment starts `apiVersion: apps/v1`, which gave 183 collisions on microservices-demo.

    The file is used only when it holds the lines the tool scanned. If the SARIF has a snippet that disagrees with the file, the anchor is the snippet's first non-blank line.

## Consequences

- Edits inside a block below its anchor keep every finding's identity. Edits to the anchor lines (renaming a resource, inserting a line between `metadata:` and `name:`) report the block's findings as fixed and new.
- Whole-file findings, such as Checkov's `CKV_DOCKER_2`, are now stable unless their file's first line changes. The shifted-lines fixture asserts all 28 findings match; `testdata/repos/edited` asserts that editing inside two resources only fixes the finding the edit addressed.
- Precedence item 1 changes accordingly: the anchor hash takes the place of "the hash of a snippet the tool wrote" and "the hash of lines read from the repo".
