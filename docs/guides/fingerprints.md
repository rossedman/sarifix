# Fingerprints

A fingerprint is how sarifix recognizes the same finding across two scans, even after the code around it has moved. This page explains how one is chosen, what it ignores, and where it can fail.

## Why line numbers cannot be the key

A scan reports `main.tf:5`. Someone adds a license header, and the next scan reports `main.tf:7`. If the line number were part of the identity, every finding below the header would look fixed and new at once, and a baseline diff would be useless.

So sarifix never uses line numbers. Compare the repository's two fixtures, which hold the same findings with two lines added near the top of each file:

```console
$ sarifix diff --base '../../sarif/basic/*.sarif' --head '../../sarif/shifted/*.sarif' \
    --repo ../shifted --base-root . --unchanged
0 new  0 fixed  28 unchanged
...
Unchanged
  = Checkov/CKV_AWS_24 main.tf:7 Ensure no security groups allow ingress from 0.0.0.0:0 to port 22
```

That finding was at `main.tf:5` in the base scan. It is reported at line 7 in the head scan and is still unchanged.

## How a fingerprint is chosen

For each result, sarifix takes the first of these that exists:

1. **`primaryLocationLineHash`**, when the tool provides it. This is the hash GitHub code scanning uses, so it is already designed to survive edits. A trailing `:N` occurrence suffix is stripped and sarifix numbers occurrences itself.
2. **Any other `partialFingerprints`** the tool wrote, in key order. Entries written by sarifix itself are not mixed in.
3. **The `sarifix/v1` fingerprint** that `sarifix scan` recorded. It was computed with the scanned checkout at hand, so it beats anything worked out later from files that may have changed since.
4. **A computed hash**: `sha256(tool, ruleId, path, anchor)`, with every run of whitespace in the anchor collapsed to one space, so reformatting or re-indenting doesn't change it. The anchor is explained [below](#anchors-findings-about-a-whole-block).
5. **The message**, when there is no location to anchor to.

sarifix reads the anchor's lines from the files: under `--repo` for the head scan, and under `--base-root` (`diff`) or `--baseline-root` (`plan`, `fix`) for the base scan. If the tool put a snippet in the SARIF and the file's lines don't match it, the file belongs to a different checkout, and only the snippet is used.

Identical findings in the same run (same tool, rule, path and anchor) are numbered in order of appearance, so each still has a distinct fingerprint. Diffs compare fingerprints as a multiset: two identical findings in the head and one in the base give one unchanged and one new.

## What `sarifix scan` records

`sarifix scan` writes the SARIF each tool produced and adds `partialFingerprints["sarifix/v1"]` to every result that has a snippet:

```json
"partialFingerprints": {
  "sarifix/v1": "fcadca11a498b6d6f0a7012e1e3081fc"
}
```

That makes a scan self-contained. A later `sarifix diff` against it does not need a checkout of the commit it came from.

## Anchors: findings about a whole block

Infrastructure scanners usually flag a whole block. Checkov's "RDS cluster has no deletion protection" points at lines 1 to 15 of `rds.tf`, the entire `aws_rds_cluster` resource. Hashing all 15 lines would tie the finding's identity to every attribute in the resource. Fix one rule on that resource and every *other* finding on it would look fixed and new at the same time.

So the identity of a finding is its **anchor**:

- For a one-line region, the anchor is that line.
- For a block, sarifix starts at the block's first non-blank line and takes the fewest lines that appear nowhere else in the file. For Terraform that is the resource header, `resource "aws_rds_cluster" "app1-rds-cluster" {`. For a Kubernetes manifest with several Deployments in one file, it runs from `apiVersion: apps/v1` down to the `name:` line that tells them apart.

Edits inside the block, below the anchor, leave the identity alone. On the [terragoat](https://github.com/bridgecrewio/terragoat) repository, a change that set `deletion_protection = true` on one RDS cluster and added a new S3 bucket diffed as:

```console
$ sarifix diff --base 'base/*.sarif' --head 'pr/*.sarif'
15 new  2 fixed  718 unchanged

Fixed
  - Checkov/CKV_AWS_139 terraform/aws/rds.tf:1 Ensure that RDS clusters have deletion protection enabled
  - Trivy/AWS-0343 terraform/aws/rds.tf:1 Artifact: terraform/aws/rds.tf Type: terraform Vulnerability AWS-0343 Severity: MEDIUM Message: Cluster does not have De…
```

The two fixed findings are the deletion-protection checks from both scanners, and all 15 new ones are in the new bucket's file. Hashing whole blocks instead reported 25 new and 12 fixed for the same change: the cluster's other nine Checkov findings each counted twice.

### What still changes identity

- **Edits to the anchor lines themselves**, such as renaming a resource, or inserting a line between `metadata:` and `name:` in a Kubernetes object. sarifix sees a finding on a different block, so it reports one fixed and one new.
- **Changes to a flagged single line**. On [cobra](https://github.com/spf13/cobra), fixing the typo in `fmt.Fprintf(w, "\n\nAdditional help topcis:")` reported the unchecked-error finding on that line as fixed and new. The line's text changed, so it is a different line.
- **SARIF read without its files**. If a tool includes a snippet but sarifix can't read the matching file and no `sarifix/v1` was recorded, the anchor falls back to the snippet's first non-blank line. That is less precise when blocks share a first line. Scans made with `sarifix scan` always record `sarifix/v1`, so this only affects SARIF from elsewhere.

If the tool provides `primaryLocationLineHash` or other partial fingerprints, those are used instead and none of this applies.
