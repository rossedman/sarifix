<p align="center"><img src="docs/assets/banner.png" alt="sarifix: turn any SARIF scanner into a verified fixer" width="100%"></p>

<p align="center">
  <a href="https://github.com/rossedman/sarifix/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/rossedman/sarifix/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/rossedman/sarifix/actions/workflows/ci.yml"><img alt="Coverage ≥ 90%" src="https://img.shields.io/badge/coverage-%E2%89%A590%25-3DF5B5"></a>
  <a href="https://goreportcard.com/report/github.com/rossedman/sarifix"><img alt="Go Report Card" src="https://goreportcard.com/badge/github.com/rossedman/sarifix"></a>
  <a href="https://github.com/rossedman/sarifix/releases"><img alt="Release" src="https://img.shields.io/github/v/release/rossedman/sarifix?include_prereleases"></a>
  <a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <a href="https://rossedman.io/sarifix/"><img alt="Docs" src="https://img.shields.io/badge/docs-rossedman.io%2Fsarifix-3DF5B5"></a>
</p>

sarifix turns any SARIF-emitting scanner into an automated fixer. It reads SARIF findings, has an AI agent fix them in small single-rule batches, proves each fix by re-running the scanner and your tests, and publishes the result as a PR, review suggestions or local edits. Trivy, Checkov, golangci-lint and your in-house tools plug in through config, with no code changes.

> **Status: Phase 1 (report and plan).** Loading, validating, normalizing and fingerprinting SARIF works today, as do `config validate`, `scan`, `diff`, `plan` and `fix --mode report`. Fixing code (the local, pr and review modes), `doctor` and `stats` land in phases 2 to 5. See the [roadmap](https://rossedman.io/sarifix/roadmap/).

## Install

```sh
go install github.com/rossedman/sarifix/cmd/sarifix@latest
```

Or download a binary from [releases](https://github.com/rossedman/sarifix/releases) and verify it (see [Verifying releases](SECURITY.md#verifying-releases)). Container image: `ghcr.io/rossedman/sarifix`.

## Quick start

Describe your scanners in `sarifix.yaml` at the repo root. Each one is an argv list with placeholders, run without a shell:

```yaml
version: 1
scanners:
  - name: trivy
    match: ["Trivy"]
    command: ["trivy", "config", "--format", "sarif", "-o", "{out}", "{dir}"]
  - name: golangci-lint
    command: ["golangci-lint", "run", "--output.sarif.path={out}", "./..."]
rules:
  allow: [trivy/DS-0002, golangci-lint/errcheck]
```

Check it, scan, change some code, scan again, and compare the two scans by fingerprint. Line numbers never count, so here the errcheck finding that moved from line 8 to line 11 is unchanged:

```console
$ sarifix config validate -q
✓ sarifix.yaml
$ sarifix scan --out-dir base --log-level warn
✓ trivy 3 findings → base/trivy.sarif
✓ golangci-lint 1 finding → base/golangci-lint.sarif
$ sarifix scan --log-level warn
✓ trivy 3 findings → sarif/trivy.sarif
✓ golangci-lint 1 finding → sarif/golangci-lint.sarif
$ sarifix diff --base 'base/*.sarif' --head 'sarif/*.sarif' --unchanged
0 new  0 fixed  4 unchanged

Unchanged
  = golangci-lint/errcheck main.go:11 Error return value of `f.Close` is not checked
  = Trivy/DS-0002 Dockerfile:1 Artifact: Dockerfile Type: dockerfile Vulnerability DS-0002 Severity: HIGH Message: Specify at least 1 USER command in D…
  = Trivy/DS-0025 Dockerfile:2 Artifact: Dockerfile Type: dockerfile Vulnerability DS-0025 Severity: HIGH Message: '--no-cache' is missed: apk add curl…
  = Trivy/DS-0026 Dockerfile:1 Artifact: Dockerfile Type: dockerfile Vulnerability DS-0026 Severity: LOW Message: Add HEALTHCHECK instruction in your D…
```

Every command takes `--json` for machine output. Exit codes: `0` success, `1` runtime error, `2` config error, `3` some batches failed verification.

[`examples/sarifix.yaml`](examples/sarifix.yaml) shows every key. The [configuration guide](https://rossedman.io/sarifix/configuration/) and the generated [reference](https://rossedman.io/sarifix/reference/config/) cover them in detail.

## Settings precedence

sarifix's own CLI settings resolve as **flag > `SARIFIX_*` environment variable > settings file** (`$XDG_CONFIG_HOME/sarifix/settings.yaml`, `~/.config/sarifix/settings.yaml` or `~/.sarifix/settings.yaml`, or the file named by `--settings`). For example, `SARIFIX_LOG_LEVEL=debug` or `log-level: debug`. `sarifix.yaml` is separate: it is the repo's fixing policy, chosen with `--config` and optionally layered over an org default with `--org-config`.

## Documentation

The full docs live at **<https://rossedman.io/sarifix/>**: [getting started](https://rossedman.io/sarifix/getting-started/), [how fingerprints work](https://rossedman.io/sarifix/guides/fingerprints/), the [security model](https://rossedman.io/sarifix/security/) and the [command reference](https://rossedman.io/sarifix/reference/commands/sarifix/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). `make check` runs everything CI runs. Security reports go through [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
