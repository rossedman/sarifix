# Check only what a pull request introduced

Compare a pull request's scan with its base branch, so reviewers and fixers see the findings the change introduced and nothing else.

This continues from [Triage an infrastructure backlog](iac-backlog.md), with the tuned `sarifix.yaml` committed to terragoat's `master` branch.

## 1. Make a change

The pull request fixes one finding and introduces new ones. It turns on deletion protection for one RDS cluster and adds an S3 bucket with no hardening:

```sh
git worktree add -b add-reports-bucket ../terragoat-pr
cd ../terragoat-pr
# rds.tf: add `deletion_protection = true` to aws_rds_cluster.app1-rds-cluster
# reports.tf: a new aws_s3_bucket "reports" with only a bucket name
git commit -am "Protect app1 cluster; add reports bucket"
```

A worktree keeps both commits checked out side by side, which is what the base scan below needs.

## 2. Scan both sides

Scan `master` into a directory outside both checkouts:

```sh
cd ../terragoat
sarifix scan --out-dir ../base-sarif --log-level warn
```

Then the branch, and diff the two:

```console
$ git diff --stat master
 terraform/aws/rds.tf     | 1 +
 terraform/aws/reports.tf | 3 +++
 2 files changed, 4 insertions(+)
$ sarifix scan --log-level warn
✓ trivy 260 findings → sarif/trivy.sarif
✓ checkov 473 findings → sarif/checkov.sarif
$ sarifix diff --base '../base-sarif/*.sarif' --head 'sarif/*.sarif'
15 new  2 fixed  718 unchanged

New
  + Checkov/CKV2_AWS_6 terraform/aws/reports.tf:1 Ensure that S3 bucket has a Public Access block
  + Checkov/CKV2_AWS_62 terraform/aws/reports.tf:1 Ensure S3 buckets should have event notifications enabled
  + Checkov/CKV_AWS_18 terraform/aws/reports.tf:1 Ensure the S3 bucket has access logging enabled
  + Checkov/CKV2_AWS_61 terraform/aws/reports.tf:1 Ensure that an S3 bucket has a lifecycle configuration
  + Checkov/CKV_AWS_144 terraform/aws/reports.tf:1 Ensure that S3 bucket has cross-region replication enabled
  + Checkov/CKV_AWS_21 terraform/aws/reports.tf:1 Ensure all data stored in the S3 bucket have versioning enabled
  + Checkov/CKV_AWS_145 terraform/aws/reports.tf:1 Ensure that S3 buckets are encrypted with KMS by default
  + Trivy/AWS-0086 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0086 Severity: HIGH Message: No public access block…
  + Trivy/AWS-0087 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0087 Severity: HIGH Message: No public access block…
  + Trivy/AWS-0089 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0089 Severity: LOW Message: Bucket has logging disa…
  + Trivy/AWS-0090 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0090 Severity: MEDIUM Message: Bucket does not have…
  + Trivy/AWS-0091 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0091 Severity: HIGH Message: No public access block…
  + Trivy/AWS-0093 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0093 Severity: HIGH Message: No public access block…
  + Trivy/AWS-0094 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0094 Severity: LOW Message: Bucket does not have a …
  + Trivy/AWS-0132 terraform/aws/reports.tf:1 Artifact: terraform/aws/reports.tf Type: terraform Vulnerability AWS-0132 Severity: HIGH Message: Bucket does not encryp…

Fixed
  - Checkov/CKV_AWS_139 terraform/aws/rds.tf:1 Ensure that RDS clusters have deletion protection enabled
  - Trivy/AWS-0343 terraform/aws/rds.tf:1 Artifact: terraform/aws/rds.tf Type: terraform Vulnerability AWS-0343 Severity: MEDIUM Message: Cluster does not have De…
```

The `deletion_protection` change fixed one problem that both scanners report. Checkov calls it `CKV_AWS_139` and Trivy calls it `AWS-0343`. Every new finding is in the new file.

The RDS cluster has other findings too: missing encryption, IAM authentication, audit logging. They are unchanged, even though a line was added inside that resource. sarifix identifies a finding about a whole resource by the resource's header line, not by every line inside it. Without that, adding one attribute would make all of the cluster's other findings look fixed and new again. [Fingerprints](../guides/fingerprints.md#anchors-findings-about-a-whole-block) explains how this works and what still changes a finding's identity.

## 3. Plan only the new findings

`--baseline` skips anything already present in another scan:

```console
$ sarifix plan --sarif 'sarif/*.sarif' --baseline '../base-sarif/*.sarif'
733 findings  2 batched in 2 batches  0 deferred  731 skipped

Batches
  1. checkov/CKV_AWS_145 error   1 finding in 1 file → sarifix/checkov/ckv_aws_145
     terraform/aws/reports.tf
  2. checkov/CKV_AWS_21  error   1 finding in 1 file → sarifix/checkov/ckv_aws_21
     terraform/aws/reports.tf

Skipped
  in_baseline      718
  below_min_level  2
  rule_denied      2
  rule_not_allowed 9
```

Without it, the same plan queues the repository's whole backlog:

```console
$ sarifix plan --sarif 'sarif/*.sarif'
733 findings  14 batched in 3 batches  153 deferred  566 skipped
```

Of the 15 new findings, two are fixable under this config. Two hit the rules you denied, two are Trivy LOW findings below `min_level`, and nine aren't allowed: six from Trivy, which isn't in `rules.allow`, and three Checkov `CKV2_AWS_*` rules. `checkov/CKV_AWS_*` doesn't match `CKV2_AWS_*`, so add that glob too if you want Checkov's second-generation AWS rules.

## When the base scan didn't come from `sarifix scan`

`sarifix scan` records a fingerprint in every result, computed from the files it scanned. That is why the base scan above needed no checkout. Its files could have been deleted. For SARIF from elsewhere (a CI artifact from another tool, say), sarifix reads the flagged lines to fingerprint them, so it needs the checkout the scan came from:

```sh
sarifix diff --base base.sarif --base-root ../terragoat --head head.sarif
sarifix plan --sarif head.sarif --baseline base.sarif --baseline-root ../terragoat
```

Use the same `sarifix.yaml` and the same scanner versions for both scans. A rule that exists on one side only shows up as all new or all fixed.

## What you learned

- `diff` compares two scans by fingerprint, so edits around and inside a flagged resource don't produce noise.
- `plan --baseline` (and `fix --baseline`) narrow a run to what a change introduced.
- Scans made with `sarifix scan` are self-contained, and other SARIF needs `--base-root` or `--baseline-root`.

Next: run this check automatically in [GitHub Actions](github-actions.md), or [compare against an older release](release-history.md).
