# 3. Fingerprint details

- Status: accepted
- Date: 2026-10-22

## Context

The spec says: use `partialFingerprints` when present (prefer `primaryLocationLineHash`), otherwise hash tool, rule, path and the whitespace-collapsed snippet, and never use line numbers. Several cases need more precision.

## Decision

1. Precedence: `primaryLocationLineHash` (with GitHub's `:N` occurrence suffix removed), then the tool's other partial fingerprints (sorted `key=value` pairs), then the hash of a snippet the tool wrote, then `partialFingerprints["sarifix/v1"]`, then the hash of lines read from the repo, then a hash of the message. Every hash includes tool and rule ID. (Amended 2026-10-23: `sarifix/v1` used to rank below lines read from the repo. Testing `plan --baseline` against a scan of an older release showed that re-reading lines in a newer checkout hashes the wrong text.)
2. The snippet is `region.snippet.text` when the tool provides one, else the region's lines read from the repo (capped at 200 lines). A snippet that is only whitespace counts as no snippet; the fuzzer found that the two were hashed differently.
3. Identical findings in one run (same tool, rule, path and snippet) are numbered in order of appearance (`<hash>:1`, `<hash>:2`), so they stay distinct and a diff still pairs them correctly.
4. `sarifix scan` records the snippet hash under `partialFingerprints["sarifix/v1"]`. A later diff that can't read the files (for example, against a scan of another commit) gets the same fingerprint.
5. Findings with no snippet and no fingerprints fall back to the message, which is still independent of line numbers.

## Consequences

A finding whose region covers the whole file, such as Checkov's `CKV_DOCKER_2`, changes fingerprint whenever any line of that file changes. The shifted-lines fixture test asserts this explicitly rather than hiding it.
