# Examples

Files to copy from when setting up sarifix. Each one is exercised by the test suite or was run for the [tutorials](https://rossedman.io/sarifix/tutorials/), so they stay accurate.

| Path | What it is |
| --- | --- |
| [`sarifix.yaml`](sarifix.yaml) | A complete config that shows every key: four scanners, rule and path policy, a campaign, limits, verify, agent and publish settings. Start here and delete what you don't need. |
| [`eol-images/`](eol-images/) | A small in-house scanner in Python that flags end-of-life Docker base images. It shows that any program writing SARIF plugs into sarifix. |
| [`workflows/`](workflows/) | GitHub Actions workflows: one reports what each pull request introduced; the other scans the default branch, uploads to code scanning and keeps one agent-ready issue per batch. |

## `sarifix.yaml`

Every key is shown, so most of the file restates defaults. A minimal config needs only `version`, at least one scanner and a `rules.allow` list:

```yaml
version: 1
scanners:
  - name: trivy
    match: ["Trivy"]
    command: ["trivy", "config", "--format", "sarif", "-o", "{out}", "{dir}"]
rules:
  allow: ["trivy/DS-0002"]
```

The `image-migrate` scanner points at `./tools/image-migrate.sh`, which stands in for your own in-house tool. The integration test runs this file against the fixture repo after replacing that path with [`testdata/tools/image-migrate.sh`](../testdata/tools/image-migrate.sh). `TestLoadExample` in `pkg/config` and `TestConfigValidate` in `internal/cli` validate it with `--strict`, so a change to the config schema that breaks it fails CI.

Check your own copy with:

```sh
sarifix config validate --strict
```

The [configuration guide](https://rossedman.io/sarifix/configuration/) explains each section, and the [config reference](https://rossedman.io/sarifix/reference/config/) lists every key with its default.
