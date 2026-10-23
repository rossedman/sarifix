# Bring your own scanner and run a migration

Any program that writes SARIF 2.1.0 works with sarifix. This tutorial adds two: [Hadolint](https://github.com/hadolint/hadolint), a Dockerfile linter, and a short Python script that flags end-of-life base images. The script's findings are then grouped into a migration campaign.

You'll use [awesome-compose](https://github.com/docker/awesome-compose), Docker's collection of sample applications, with 35 Dockerfiles across dozens of stacks.

## 1. Write the in-house scanner

The script is in the sarifix repository at [`examples/eol-images/eol_images.py`](https://github.com/rossedman/sarifix/blob/main/examples/eol-images/eol_images.py). Copy it into `tools/eol_images.py`. It walks every `Dockerfile`, matches each `FROM` line against a small table of end-of-life image tags, and writes one SARIF result per hit:

```console
$ jq '.runs[0].results[0]' sarif/eol-images.sarif
{
  "level": "warning",
  "locations": [
    {
      "physicalLocation": {
        "artifactLocation": {
          "uri": "angular/angular/Dockerfile"
        },
        "region": {
          "startLine": 3
        }
      }
    }
  ],
  "message": {
    "text": "node:17.0.1-bullseye-slim is end of life. Node.js 18 and older are end of life; use node:22 or newer."
  },
  "partialFingerprints": {
    "sarifix/v1": "1784b654b3d675236f3d9e6c6e0346fc"
  },
  "ruleId": "EOL_BASE_IMAGE"
}
```

That is a complete result: a rule ID, a level, a message, and a file and line. The `sarifix/v1` fingerprint wasn't written by the script; `sarifix scan` added it. Everything else a scanner might add, such as rule help text or columns, is optional.

## 2. Configure both scanners and a campaign

```yaml
version: 1

scanners:
  - name: hadolint
    # hadolint lints the files it's given and prints SARIF to stdout, so a
    # small sh -c finds the Dockerfiles; sarifix passes {out} as $0.
    command:
      - sh
      - -c
      - find . -name Dockerfile -not -path './.git/*' -print0 | xargs -0 hadolint --no-fail -f sarif > "$0"
      - "{out}"
  - name: eol-images
    command: ["python3", "tools/eol_images.py", "{dir}", "{out}"]

rules:
  allow: ["hadolint/DL3*"]
  min_level: warning

campaigns:
  - id: eol-base-images
    scanner: eol-images
    rules: ["eol-images/EOL_BASE_IMAGE"]
    pr_title: "chore: move off end-of-life base images"
    labels: [migration]
```

sarifix never runs commands through a shell. Hadolint takes file names and writes SARIF to stdout, so this entry calls `sh -c` explicitly to find the Dockerfiles and redirect output. Passing `{out}` as a separate argument, `$0` inside the script, avoids quoting the path.

The `eol-images` rule isn't in `rules.allow`, and it doesn't need to be. Being in a campaign is what makes a rule fixable. `rules.deny`, `min_level` and `paths.deny` still apply to it.

## 3. Scan

```console
$ sarifix config validate -q --strict
✓ sarifix.yaml
$ sarifix scan --log-level warn
✓ hadolint 56 findings → sarif/hadolint.sarif
✓ eol-images 17 findings → sarif/eol-images.sarif
```

## 4. Plan the campaign

`--campaign` limits a run to one campaign:

```console
$ sarifix plan --sarif 'sarif/*.sarif' --campaign eol-base-images --details
73 findings  17 batched in 2 batches  0 deferred  56 skipped

Batches
  1. eol-base-images   warning 10 findings in 10 files → sarifix/campaign/eol-base-images
     eol-images/EOL_BASE_IMAGE angular/angular/Dockerfile:3
     eol-images/EOL_BASE_IMAGE aspnet-mssql/app/aspnetapp/Dockerfile:5
     eol-images/EOL_BASE_IMAGE django/app/Dockerfile:3
     eol-images/EOL_BASE_IMAGE nginx-aspnet-mysql/backend/Dockerfile:3
     eol-images/EOL_BASE_IMAGE nginx-aspnet-mysql/proxy/Dockerfile:1
     eol-images/EOL_BASE_IMAGE nginx-flask-mysql/proxy/Dockerfile:1
     eol-images/EOL_BASE_IMAGE nginx-nodejs-redis/nginx/Dockerfile:1
     eol-images/EOL_BASE_IMAGE nginx-nodejs-redis/web/Dockerfile:1
     eol-images/EOL_BASE_IMAGE nginx-wsgi-flask/flask/Dockerfile:1
     eol-images/EOL_BASE_IMAGE nginx-wsgi-flask/nginx/Dockerfile:1
  2. eol-base-images#2 warning 7 findings in 7 files   → sarifix/campaign/eol-base-images-2
     eol-images/EOL_BASE_IMAGE react-express-mongodb/backend/Dockerfile:3
     eol-images/EOL_BASE_IMAGE react-express-mongodb/frontend/Dockerfile:4
     eol-images/EOL_BASE_IMAGE react-express-mysql/frontend/Dockerfile:37
     eol-images/EOL_BASE_IMAGE react-java-mysql/frontend/Dockerfile:38
     eol-images/EOL_BASE_IMAGE react-rust-postgres/backend/Dockerfile:2
     eol-images/EOL_BASE_IMAGE react-rust-postgres/frontend/Dockerfile:36
     eol-images/EOL_BASE_IMAGE vuejs/vuejs/Dockerfile:2

Skipped
  below_min_level  13
  rule_not_allowed 23
  not_selected     20
```

All 17 end-of-life images form one campaign, split into two batches because `files_per_batch` defaults to 10. Campaign batches get a `campaign/` branch, so the whole migration can be tracked by name across repositories.

Without `--campaign`, the campaign and Hadolint's rules share the run. Batches are ranked by severity and then size, so the 17-finding campaign comes first:

```console
$ sarifix plan --sarif 'sarif/*.sarif'
73 findings  34 batched in 5 batches  3 deferred  36 skipped

Batches
  1. eol-base-images   warning 10 findings in 10 files → sarifix/campaign/eol-base-images
     angular/angular/Dockerfile, aspnet-mssql/app/aspnetapp/Dockerfile, django/app/Dockerfile, nginx-aspnet-mysql/backend/Dockerfile, nginx-aspnet-mysql/proxy/Dockerfile, nginx-flask-mysql/proxy/Dockerfile…
  2. eol-base-images#2 warning 7 findings in 7 files   → sarifix/campaign/eol-base-images-2
     react-express-mongodb/backend/Dockerfile, react-express-mongodb/frontend/Dockerfile, react-express-mysql/frontend/Dockerfile, react-java-mysql/frontend/Dockerfile, react-rust-postgres/backend/Dockerfi…
  3. hadolint/DL3018   warning 7 findings in 7 files   → sarifix/hadolint/dl3018
     nginx-flask-mongo/flask/Dockerfile, nginx-flask-mysql/backend/Dockerfile, nginx-golang-mysql/backend/Dockerfile, nginx-golang-postgres/backend/Dockerfile, nginx-golang/backend/Dockerfile, nginx-wsgi-f…
  4. hadolint/DL3022   warning 5 findings in 5 files   → sarifix/hadolint/dl3022
     nginx-flask-mongo/flask/Dockerfile, nginx-flask-mysql/backend/Dockerfile, nginx-golang-mysql/backend/Dockerfile, nginx-golang-postgres/backend/Dockerfile, nginx-golang/backend/Dockerfile
  5. hadolint/DL3067   warning 5 findings in 5 files   → sarifix/hadolint/dl3067
     nginx-flask-mongo/flask/Dockerfile, nginx-flask-mysql/backend/Dockerfile, nginx-golang-mysql/backend/Dockerfile, nginx-golang-postgres/backend/Dockerfile, nginx-golang/backend/Dockerfile
  ...
Deferred (over limits.batches_per_run)
  1. hadolint/DL3042   warning 2 findings in 1 file    → sarifix/hadolint/dl3042
     nginx-wsgi-flask/flask/Dockerfile
  ...

Skipped
  below_min_level  13
  rule_not_allowed 23
```

## What you learned

- A scanner is anything that writes SARIF: a binary, a shell pipeline, a short script.
- sarifix doesn't use a shell, but your command can call `sh -c` when a tool needs one.
- A campaign groups a migration's rules under one ID, its own branches, and its own PR title and labels.

Next: [roll out a policy across repositories](org-policy.md).
