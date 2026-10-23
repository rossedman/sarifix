# Configuration

How `sarifix.yaml` is put together: scanners, the placeholders in their commands, the globs in `rules` and `paths`, and how an org default file layers under a repo file. This page is the guide; the [config reference](reference/config.md) lists every field, type and default.

## The shape of the file

One YAML file per repo. `version: 1` is required, and every other key has a default except `scanners`.

```yaml title="sarifix.yaml"
version: 1

scanners:      # how to run each SARIF-producing tool
  - name: trivy
    match: ["Trivy"]
    command: ["trivy", "config", "--format", "sarif", "-o", "{out}", "{dir}"]

rules:         # which findings are eligible to be fixed (planned phases)
  allow: ["trivy/DS-0002"]
  min_level: warning

paths:         # files that are never edited
  deny: ["vendor/**", "**/*_generated.go"]
```

Run `sarifix config validate` to load the file, apply defaults and print the resolved result. Errors name the file, the key path and the line, for example `scanners[2].command: must not be empty`. There are 28 checks, covering unknown placeholders, duplicate scanner names, overlapping `match` values, empty commands, campaigns that reference an unknown scanner, bad globs and out-of-range limits. Add `--strict` to also reject an `allow` glob that matches no configured scanner.

!!! note "Which sections do something today"
    `scanners` drives `sarifix scan`. `rules`, `paths`, `limits`, `verify`, `agent`, `publish` and `campaigns` are validated now and used by the fixing phases on the [roadmap](roadmap.md).

## Scanners

A scanner is any command that writes SARIF. sarifix needs to know three things: what to call it, which SARIF tool names it produces, and how to run it.

| Field | Purpose |
| --- | --- |
| `name` | Unique ID. Used in rule keys such as `trivy/DS-0002` and in branch names. |
| `match` | The `tool.driver.name` values routed to this scanner. Defaults to `[name]`, compared case-insensitively. |
| `command` | The argv to run. There is no shell. Placeholders are expanded in each element. |
| `output` | Where the SARIF lands, for tools that choose their own file name. Default `{out}`. |
| `workdir` | Working directory. Default `{repo}`. |
| `env` | Extra environment variables. |
| `scope` | Rescan scope during verification: `changed`, `dir` or `repo`. |
| `timeout` | Per invocation. Default 5 minutes. |
| `offline` | Run verification rescans without network. |

A tool that is not a known scanner needs no code. The repo's custom-tool fixture is a 25-line shell script that prints SARIF, wired in with this entry:

```yaml
- name: image-migrate
  command: ["./tools/image-migrate.sh", "{dir}", "{out}"]
  env: { CT_MODE: "ci" }
  scope: changed
```

### Placeholders

Placeholders are expanded in `command`, `output`, `workdir` and `env` values. Any other brace is literal text, so JSON arguments pass through unchanged. An unknown placeholder is a config error.

| Placeholder | Expands to |
| --- | --- |
| `{out}` | The SARIF file sarifix expects the tool to write. |
| `{outdir}` | The directory for that file, for tools that take a directory. |
| `{dir}` | The directory to scan. |
| `{paths}` | The files to scan. A whole argv element equal to `{paths}` becomes one element per path; inside a larger element the paths are joined with spaces. |
| `{repo}` | The repository root. |

Checkov takes an output directory and picks its own file name, so it sets `output` as well:

```yaml
- name: checkov
  match: ["Checkov"]
  command: ["checkov", "-d", "{dir}", "-o", "sarif", "--output-file-path", "{outdir}"]
  output: "{outdir}/results_sarif.sarif"
```

## Rules and paths

`rules.allow` and `rules.deny` are globs over the key `<scanner>/<ruleId>`, such as `checkov/CKV_AWS_20`. `paths.deny` is a list of globs over repo-relative paths. The two kinds of glob behave differently, on purpose.

| | Rule keys (`rules.*`) | Paths (`paths.deny`) |
| --- | --- | --- |
| `*` | Matches any run of characters, **including `/`**, because rule IDs can contain slashes. | Stays inside one path segment. |
| `?` | One character. | One character within a segment. |
| `**` | Not special. | A whole path segment matching zero or more segments. `**/*_generated.go` is valid; `a**b` is an error. |
| Example | `checkov/CKV_AWS_*` | `vendor/**` |

```yaml
rules:
  allow:
    - trivy/DS-0002
    - checkov/CKV_AWS_*
    - image-migrate/*
  deny: ["*/secrets-*"]
paths:
  deny: [".github/workflows/**", "vendor/**", "**/*_generated.go"]
```

!!! warning "Workflows are always denied"
    `.github/workflows/**` is denied however you configure `paths.deny`, including when you replace the list. Fixing tools that edit CI are a way to escalate privileges, so this is not optional. The planned diff guard enforces it on the actual diff, not only in the prompt. See [Security](security.md).

## Layering with an org config

Pass `--org-config` to put an org-wide default file under the repo's file:

```bash
sarifix config validate --org-config org/sarifix.yaml --config sarifix.yaml
```

The repo file is applied on top of the org file:

- **Scalars and lists replace.** If the repo sets `rules.allow`, the org's `rules.allow` is gone, not appended to.
- **`scanners` merge by `name`** and **`campaigns` merge by `id`.** A repo entry with the same name as an org entry replaces it whole; other org entries are kept.

For example, with an org file that defines `trivy` and `checkov`, and a repo file that redefines `trivy` and adds `golangci-lint`, the resolved config has three scanners: the repo's `trivy`, the org's `checkov` and the repo's `golangci-lint`. The resolved output of `config validate` shows which result you get, and error messages point at the file where the offending entry was defined.

## Reference

Every field, its type and its default are in the [config reference](reference/config.md), generated from the same schema the validator uses. The command flags are in the [command reference](reference/commands/sarifix.md).
