# Triage an infrastructure backlog

Point Trivy and Checkov at a Terraform repository with hundreds of findings, then use `sarifix plan` to turn the pile into a short, ordered work queue.

You'll use [terragoat](https://github.com/bridgecrewio/terragoat), a deliberately insecure Terraform project for AWS, Azure, GCP, Alibaba Cloud and Oracle Cloud. It is a stand-in for a real infrastructure repository with years of findings nobody has had time for.

## 1. Describe the scanners

```sh
git clone https://github.com/bridgecrewio/terragoat
cd terragoat
```

Create `sarifix.yaml` at the repository root:

```yaml
version: 1

scanners:
  - name: trivy
    match: ["Trivy"]
    command: ["trivy", "config", "--format", "sarif", "-o", "{out}", "{dir}"]
  - name: checkov
    match: ["Checkov"]
    command: ["checkov", "-d", "{dir}", "--framework", "terraform", "-o", "sarif", "--output-file-path", "{outdir}"]
    output: "{outdir}/results_sarif.sarif"

rules:
  allow: ["checkov/CKV_AWS_*"]
```

Each scanner is an argv list run without a shell. `match` names the `tool.driver.name` each tool writes into its SARIF, so sarifix knows which scanner a finding belongs to. Checkov picks its own file name inside the output directory, so its entry says where to find it with `output`.

`rules.allow` decides what may be fixed. Start narrow: here, only Checkov's AWS rules. Everything else is still scanned and reported, just never queued.

## 2. Scan

```console
$ sarifix config validate -q
✓ sarifix.yaml
$ sarifix scan
INFO  sarifix: scanned scanner=trivy findings=253
INFO  sarifix: scanned scanner=checkov findings=467
✓ trivy 253 findings → sarif/trivy.sarif
✓ checkov 467 findings → sarif/checkov.sarif
```

720 findings in about eight seconds. `sarif/` now holds one file per scanner, each with a fingerprint added to every result (see [Fingerprints](../guides/fingerprints.md)).

## 3. Read the plan

```console
$ sarifix plan --sarif 'sarif/*.sarif'
720 findings  45 batched in 5 batches  132 deferred  543 skipped

Batches
  1. checkov/CKV_AWS_139 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_139
     terraform/aws/rds.tf
  2. checkov/CKV_AWS_162 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_162
     terraform/aws/rds.tf
  3. checkov/CKV_AWS_313 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_313
     terraform/aws/rds.tf
  4. checkov/CKV_AWS_324 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_324
     terraform/aws/rds.tf
  5. checkov/CKV_AWS_325 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_325
     terraform/aws/rds.tf
  ...
Deferred (over limits.batches_per_run)
   1. checkov/CKV_AWS_326 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_326
      terraform/aws/rds.tf
   2. checkov/CKV_AWS_327 error   9 findings in 1 file  → sarifix/checkov/ckv_aws_327
      terraform/aws/rds.tf
  ...

Skipped
  below_min_level  58
  rule_not_allowed 485
```

Reading from the top:

- **Batches** are what one run would attempt: one rule each, at most five per run (`limits.batches_per_run` defaults to 5). Each has a deterministic branch name, so a later run won't open a second PR for the same work.
- **Deferred** batches are fixable but over the per-run cap. The next run picks them up.
- **Skipped** counts findings that will never be queued, by reason. `rule_not_allowed` is everything outside `checkov/CKV_AWS_*`. `below_min_level` is Trivy's LOW findings, which arrive as SARIF `note` and fall under the default `min_level: warning`.

Every batch above is nine findings in `rds.tf`. Terragoat defines nine RDS clusters with the same gaps, so each Checkov rule fires nine times in one file.

## 4. Look closer before deciding

`--rule` narrows the plan to some rules, and `--details` lists each finding:

```console
$ sarifix plan --sarif 'sarif/*.sarif' --rule checkov/CKV_AWS_144 --rule '*/AWS-0079' --details
720 findings  6 batched in 1 batch  0 deferred  714 skipped

Batches
  1. checkov/CKV_AWS_144 error   6 findings in 2 files → sarifix/checkov/ckv_aws_144
     checkov/CKV_AWS_144 terraform/aws/ec2.tf:271
     checkov/CKV_AWS_144 terraform/aws/s3.tf:1
     checkov/CKV_AWS_144 terraform/aws/s3.tf:42
     checkov/CKV_AWS_144 terraform/aws/s3.tf:65
     checkov/CKV_AWS_144 terraform/aws/s3.tf:89
     checkov/CKV_AWS_144 terraform/aws/s3.tf:113

Skipped
  below_min_level  58
  rule_not_allowed 485
     trivy/AWS-0079 terraform/aws/rds.tf:1
     trivy/AWS-0079 terraform/aws/rds.tf:17
     trivy/AWS-0079 terraform/aws/rds.tf:33
     trivy/AWS-0079 terraform/aws/rds.tf:49
     trivy/AWS-0079 terraform/aws/rds.tf:65
     trivy/AWS-0079 terraform/aws/rds.tf:81
     trivy/AWS-0079 terraform/aws/rds.tf:97
     trivy/AWS-0079 terraform/aws/rds.tf:113
     trivy/AWS-0079 terraform/aws/rds.tf:130
  not_selected     171
```

Two things stand out:

- `CKV_AWS_144` wants cross-region replication on every bucket. That is a cost and architecture decision, not a mechanical fix. The same goes for `CKV_AWS_18` (access logging needs a log bucket first).
- Trivy flags the same problem as `AWS-0079`, but Trivy isn't in `rules.allow`, so those findings are skipped. Both scanners overlap heavily on AWS, and allowing one of them per rule family avoids fixing the same thing twice.

## 5. Tune

Deny the two decision-shaped rules, and make batches smaller so each PR is quick to review:

```yaml
rules:
  allow: ["checkov/CKV_AWS_*"]
  deny:
    - checkov/CKV_AWS_144 # cross-region replication: a cost decision, not a fix
    - checkov/CKV_AWS_18  # access logging needs a log bucket to exist first

limits:
  batches_per_run: 3
  findings_per_batch: 5
```

`sarifix config validate --strict` catches typos such as an `allow` glob naming a scanner that doesn't exist. Plan again:

```console
$ sarifix plan --sarif 'sarif/*.sarif'
720 findings  14 batched in 3 batches  152 deferred  554 skipped

Batches
  1. checkov/CKV_AWS_139   error   5 findings in 1 file  → sarifix/checkov/ckv_aws_139
     terraform/aws/rds.tf
  2. checkov/CKV_AWS_139#2 error   4 findings in 1 file  → sarifix/checkov/ckv_aws_139-2
     terraform/aws/rds.tf
  3. checkov/CKV_AWS_162   error   5 findings in 1 file  → sarifix/checkov/ckv_aws_162
     terraform/aws/rds.tf
  ...
Deferred (over limits.batches_per_run)
   1. checkov/CKV_AWS_162#2 error   4 findings in 1 file  → sarifix/checkov/ckv_aws_162-2
      terraform/aws/rds.tf
  ...

Skipped
  below_min_level  58
  rule_denied      11
  rule_not_allowed 485
```

`CKV_AWS_139` now splits into two batches (`#2` gets its own branch, `ckv_aws_139-2`) because nine findings exceed `findings_per_batch: 5`. Batches of one rule stay together and in order, and a file is only split across batches when it alone has more findings than the limit. The 11 `rule_denied` findings are the two rules you just turned off.

## 6. Write a report

`sarifix fix --mode report` writes the same plan to files, for dashboards or to attach to a ticket:

```console
$ sarifix fix --mode report --sarif 'sarif/*.sarif' --log-level warn | tail -2
✓ sarifix-report/sarifix.sarif
✓ sarifix-report/summary.json
$ jq '{findings, batched, deferred, skipped}' sarifix-report/summary.json
{
  "findings": 720,
  "batched": 14,
  "deferred": 152,
  "skipped": {
    "below_min_level": 58,
    "rule_denied": 11,
    "rule_not_allowed": 485
  }
}
$ jq -r '.batches[] | "\(.id)  \(.findings)  \(.branch)"' sarifix-report/summary.json
checkov/CKV_AWS_139  5  sarifix/checkov/ckv_aws_139
checkov/CKV_AWS_139#2  4  sarifix/checkov/ckv_aws_139-2
checkov/CKV_AWS_162  5  sarifix/checkov/ckv_aws_162
```

`sarifix-report/sarifix.sarif` is the scanners' SARIF, unchanged except that every finding carries a `properties.sarifix` block with its status, skip reason, batch and branch. It still validates against the SARIF 2.1.0 schema, so code-scanning tools read it as usual. The [Modes](../guides/modes.md#report) page shows a full example.

## What you learned

- One `scanners` entry per tool; `match` routes findings by SARIF tool name.
- `plan` is the cheap way to see what a run would do. `--rule` and `--details` answer "why is this here, or not?".
- `rules.deny`, `findings_per_batch` and `batches_per_run` shape the queue into reviewable pieces.

Next: [check only what a pull request introduced](pull-requests.md).
