# Roll out a policy across repositories

A platform team keeps one default config that every repository layers its own `sarifix.yaml` over. The default owns the scanners and guardrails, and each repository opts in to the rules it is ready for.

You'll use Google's [microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo): eleven services with Kubernetes manifests, Kustomize overlays, a Helm chart, Terraform and Dockerfiles.

## 1. The platform default

Kept in a central repository and checked out next to each service repository, here as `../platform/sarifix-org.yaml`:

```yaml
# Platform team default, layered under every repo's own sarifix.yaml.
version: 1

scanners:
  - name: trivy
    match: ["Trivy"]
    command: ["trivy", "config", "--format", "sarif", "-o", "{out}", "{dir}"]
  - name: checkov
    match: ["Checkov"]
    command: ["checkov", "-d", "{dir}", "--framework", "kubernetes,dockerfile,terraform",
              "-o", "sarif", "--output-file-path", "{outdir}"]
    output: "{outdir}/results_sarif.sarif"

rules:
  deny: ["*/*SECRET*"]
  min_level: error

paths:
  deny: ["vendor/**", "**/genproto/**"]

limits:
  batches_per_run: 3
```

## 2. The repository's opt-in

`sarifix.yaml` in the service repository only adds what is specific to it:

```yaml
version: 1

rules:
  allow:
    - checkov/CKV_K8S_*
    - trivy/KSV-*
```

How layers combine:

- Scalars and lists in the repository file replace the default's. Here `rules.allow` comes from the repository, and `rules.deny`, `min_level` and `limits` from the default.
- Scanners and campaigns merge by `name` and `id`. A repository can override one scanner, or add its own, without copying the rest.
- `.github/workflows/**` is always in `paths.deny`, whatever either file says.

## 3. Validate, scan, plan

```console
$ sarifix config validate --org-config ../platform/sarifix-org.yaml -q
✓ ../platform/sarifix-org.yaml
✓ sarifix.yaml
$ sarifix scan --org-config ../platform/sarifix-org.yaml --log-level warn
✓ trivy 369 findings → sarif/trivy.sarif
✓ checkov 374 findings → sarif/checkov.sarif
$ sarifix plan --org-config ../platform/sarifix-org.yaml --sarif 'sarif/*.sarif'
743 findings  70 batched in 3 batches  263 deferred  410 skipped

Batches
  1. checkov/CKV_K8S_21   error   23 findings in 7 files  → sarifix/checkov/ckv_k8s_21
     kubernetes-manifests/adservice.yaml, kubernetes-manifests/cartservice.yaml, kubernetes-manifests/checkoutservice.yaml, kubernetes-manifests/currencyservice.yaml, kubernetes-manifests/emailservice.yaml…
  2. checkov/CKV_K8S_21#2 error   23 findings in 7 files  → sarifix/checkov/ckv_k8s_21-2
     kubernetes-manifests/paymentservice.yaml, kubernetes-manifests/productcatalogservice.yaml, kubernetes-manifests/recommendationservice.yaml, kubernetes-manifests/shippingservice.yaml, kustomize/base/ad…
  3. checkov/CKV_K8S_21#3 error   24 findings in 8 files  → sarifix/checkov/ckv_k8s_21-3
     kustomize/base/currencyservice.yaml, kustomize/base/emailservice.yaml, kustomize/base/frontend.yaml, kustomize/base/loadgenerator.yaml, kustomize/base/paymentservice.yaml, kustomize/base/productcatalo…
  ...
Deferred (over limits.batches_per_run)
   1. checkov/CKV_K8S_21#4 error   7 findings in 3 files   → sarifix/checkov/ckv_k8s_21-4
      kustomize/components/google-cloud-operations/otel-collector.yaml, kustomize/components/shopping-assistant/shoppingassistantservice.yaml, kustomize/components/without-loadgenerator/delete-loadgenerator…
   2. checkov/CKV_K8S_21#5 error   25 findings in 1 file   → sarifix/checkov/ckv_k8s_21-5
      release/kubernetes-manifests.yaml
  ...

Skipped
  below_min_level  353
  rule_not_allowed 57
```

`config validate` lists both files it loaded. Errors name the file and line they came from, so a typo in the default is reported against `sarifix-org.yaml`.

`below_min_level` is large because the default only queues `error`-level findings.

## 4. Find what shouldn't be in the queue

The deferred list shows `release/kubernetes-manifests.yaml`, a single file with 35 findings for one rule alone. The report says where all the queued findings sit:

```console
$ jq '[.runs[].results[] | select(.properties.sarifix.status != "skipped") | .locations[0].physicalLocation.artifactLocation.uri | split("/")[0]] | group_by(.) | map({(.[0]): length}) | add' sarifix-report/sarifix.sarif
{
  "kubernetes-manifests": 101,
  "kustomize": 131,
  "release": 101
}
```

`release/` is generated from `kubernetes-manifests/` by the project's release scripts, and fixing it by hand would be overwritten at the next release. Exclude it in the repository config:

```yaml
paths:
  # Lists replace the org's list, so repeat its entries. release/ is
  # generated from kubernetes-manifests/ by the release scripts.
  deny: ["vendor/**", "**/genproto/**", "release/**"]
```

Because lists replace rather than merge, the repository repeats the default's two entries. Check the resolved value rather than guessing:

```console
$ sarifix config validate --org-config ../platform/sarifix-org.yaml --json | jq -c .paths.deny
[".github/workflows/**","vendor/**","**/genproto/**","release/**"]
$ sarifix plan --org-config ../platform/sarifix-org.yaml --sarif 'sarif/*.sarif' | head -1
743 findings  70 batched in 3 batches  162 deferred  511 skipped
$ sarifix plan --org-config ../platform/sarifix-org.yaml --sarif 'sarif/*.sarif' | sed -n '/^Skipped/,$p'
Skipped
  below_min_level  353
  rule_not_allowed 57
  path_denied      101
```

101 findings in generated files are now `path_denied` instead of queued.

## 5. A change to one Deployment

Diffs stay exact in multi-document Kubernetes files. Adding a namespace to the `adservice` Deployment:

```console
$ git diff
diff --git a/kubernetes-manifests/adservice.yaml b/kubernetes-manifests/adservice.yaml
index 25ff1b7f..bdaa043c 100644
--- a/kubernetes-manifests/adservice.yaml
+++ b/kubernetes-manifests/adservice.yaml
@@ -16,6 +16,7 @@ apiVersion: apps/v1
 kind: Deployment
 metadata:
   name: adservice
+  namespace: shop
   labels:
     app: adservice
 spec:
$ sarifix scan --org-config ../platform/sarifix-org.yaml --log-level warn
✓ trivy 368 findings → sarif/trivy.sarif
✓ checkov 373 findings → sarif/checkov.sarif
$ sarifix diff --base '../ms-base/*.sarif' --head 'sarif/*.sarif'
0 new  2 fixed  741 unchanged

Fixed
  - Checkov/CKV_K8S_21 kubernetes-manifests/adservice.yaml:15 The default namespace should not be used
  - Trivy/KSV-0110 kubernetes-manifests/adservice.yaml:17 Artifact: kubernetes-manifests/adservice.yaml Type: kubernetes Vulnerability KSV-0110 Severity: LOW Message: deployment …
```

The change fixes exactly the two namespace findings. Every other finding on the same Deployment is unchanged. In a file with several objects that all start with `apiVersion: apps/v1`, sarifix identifies each object by its opening lines down to its `name:`. Edits further into the object don't change that identity.

## What you learned

- `--org-config` layers a shared default under each repository's file. Scanners and campaigns merge, while scalars and lists replace.
- `config validate --json` shows the resolved config, which is the fastest way to check a layering question.
- Report mode plus `jq` finds what is filling the queue, such as generated files that belong in `paths.deny`.

Next: [report on every pull request in GitHub Actions](github-actions.md).
