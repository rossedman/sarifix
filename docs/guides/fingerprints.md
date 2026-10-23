# Fingerprints

A fingerprint is how sarifix recognizes the same finding across two scans, even after the code around it has moved. This page explains how one is chosen, what it ignores, and where it can fail.

## Why line numbers cannot be the key

A scan reports `main.tf:5`. Someone adds a license header, and the next scan reports `main.tf:7`. If the line number were part of the identity, every finding below the header would look fixed and new at once, and a baseline diff would be useless.

So sarifix never uses line numbers. Compare the repository's two fixtures, which hold the same findings with two lines added near the top of each file:

```console
$ sarifix diff --base '../../sarif/basic/*.sarif' --head '../../sarif/shifted/*.sarif' \
    --repo ../shifted --base-root . --unchanged
2 new  2 fixed  26 unchanged
...
Unchanged
  = Checkov/CKV_AWS_24 main.tf:7 Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
```

That finding was at `main.tf:5` in the base scan. It is reported at line 7 in the head scan and is still unchanged.

## How a fingerprint is chosen

For each result, sarifix takes the first of these that exists:

1. **`primaryLocationLineHash`**, when the tool provides it. This is the hash GitHub code scanning uses, so it is already designed to survive edits. A trailing `:N` occurrence suffix is stripped and sarifix numbers occurrences itself.
2. **Any other `partialFingerprints`** the tool wrote, in key order. Entries written by sarifix itself are not mixed in.
3. **A computed hash**: `sha256(tool, ruleId, path, snippet)`, where the snippet is the flagged lines with every run of whitespace collapsed to a single space. Reformatting or re-indenting the flagged code does not change it.

The snippet comes from the SARIF region when the tool included one. Otherwise sarifix reads the lines from the files: under `--repo` for the head scan and `--base-root` for the base scan. When neither is available it falls back to the `sarifix/v1` fingerprint that `sarifix scan` recorded.

Identical findings in the same run (same tool, rule, path and snippet) are numbered in order of appearance, so each still has a distinct fingerprint. Diffs compare fingerprints as a multiset: two identical findings in the head and one in the base give one unchanged and one new.

## What `sarifix scan` records

`sarifix scan` writes the SARIF each tool produced and adds `partialFingerprints["sarifix/v1"]` to every result that has a snippet:

```json
"partialFingerprints": {
  "sarifix/v1": "fcadca11a498b6d6f0a7012e1e3081fc"
}
```

That makes a scan self-contained. A later `sarifix diff` against it does not need a checkout of the commit it came from.

## The whole-file limitation

A finding whose region is the entire file has the entire file as its snippet. Change any line of that file and the snippet hash changes, so the finding looks fixed and new.

The fixtures show this. Checkov reports `CKV_DOCKER_2` (no `HEALTHCHECK`) and `CKV_DOCKER_3` (no user) against the whole Dockerfile, and the two inserted lines change it:

```console
2 new  2 fixed  26 unchanged

New
  + Checkov/CKV_DOCKER_2 Dockerfile:1 Ensure that HEALTHCHECK instructions have been added to container images
  ...
Fixed
  - Checkov/CKV_DOCKER_2 Dockerfile:1 Ensure that HEALTHCHECK instructions have been added to container images
  ...
```

What this means in practice:

- It applies to findings about something that is *missing* from a file, where the tool has no line to point at.
- The cost is bounded: a finding is treated as new once after its file changes, and then keeps its new identity.
- If the tool provides `primaryLocationLineHash` or other partial fingerprints, those are used instead and the limitation does not apply.

## Reading the output

`sarifix diff` prints a count line, then **New**, **Fixed** and (with `--unchanged`) **Unchanged** sections. Each entry is `tool/rule path:line message`. Use `--json` for the fingerprints and source file of every finding.
