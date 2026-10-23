# Test fixtures

Shared fixtures for the Go tests. Package-specific fixtures live next to their package instead (`pkg/scanner/testdata/`, `tools/doccheck/testdata/`, and fuzz corpora under `*/testdata/fuzz/`).

## Layout

| Path | Contents | Used by |
| --- | --- | --- |
| `repos/basic/` | A tiny project with seeded findings: a `Dockerfile`, a `main.tf` (an S3 bucket and an open security group) and a `main.go` with an unchecked error | everything that needs real findings |
| `repos/shifted/` | `basic` with lines inserted near the top of each file, so most findings move down | line-shift tests: all 28 findings must still match |
| `repos/edited/` | `basic` with edits inside two Terraform resources: a `description` on the security group rule, and an unrelated attribute on the bucket | anchor tests: only Trivy's `AWS-0124` (the description check) may change |
| `sarif/{basic,shifted,edited}/` | Real output of Trivy, Checkov, golangci-lint and the custom tool for each repo | see below |
| `sarif/broken/` | Hand-written SARIF that is invalid or awkward on purpose | loader and extractor edge cases |
| `tools/image-migrate.sh` | A hand-written SARIF producer (a POSIX shell script) that flags deprecated `alpine` base images | the custom-tool fixture, `examples/sarifix.yaml`, integration tests |
| `plan/` | `sarifix.yaml` that produces every config-driven skip reason, plus golden output | `internal/cli` golden tests |

Finding counts per scanner:

| Repo | Trivy | Checkov | golangci-lint | image-migrate |
| --- | --- | --- | --- | --- |
| `basic` | 14 | 12 | 1 | 1 |
| `shifted` | 14 | 12 | 1 | 1 |
| `edited` | 13 | 12 | 1 | 1 |

### `sarif/broken/`

| File | What it tests |
| --- | --- |
| `not-json.sarif` | A file that isn't JSON is skipped with a warning |
| `old-version.sarif` | SARIF 2.0.0 is rejected with a warning |
| `partial.sarif` | One valid run among three invalid ones: the valid run loads, each invalid run is skipped with its own warning |
| `edge.sarif` | Rule lookup by index and by reference, default levels, markdown-only messages, `kind: pass`, `uriBaseId` chains (including a cycle), escaping paths, non-file URIs, duplicate findings |

## Regenerating the scanner fixtures

```sh
tools/regen-fixtures.sh
```

The script runs each scanner over each repo and rewrites `sarif/{basic,shifted,edited}/`. Tests assert exact counts, so use the versions the fixtures were made with, or expect to update tests:

| Tool | Version |
| --- | --- |
| Trivy | 0.76.1 |
| Checkov | 3.3.30 |
| golangci-lint | 2.15.0 |

What the script takes care of:

- **Absolute paths:** scanners write the checkout's absolute path into `originalUriBaseIds`. The script replaces it with `file:///github/workspace/`, so fixtures don't depend on where they were made. It also exercises sarifix's CI-workspace path handling.
- **golangci-lint config:** golangci-lint looks for a config in parent directories, and this repo's own `.golangci.yml` excludes `testdata`. The script passes `--no-config`. Without it, golangci-lint reports nothing.
- **Exit codes:** Checkov and golangci-lint exit non-zero when they find something, which the script ignores.

With the versions above, regenerating changes nothing except the order of Checkov's results, which can vary between runs. No test depends on that order.

## Changing a fixture repo

Edit the files under `repos/`, run `tools/regen-fixtures.sh`, then run `go test ./...` and update any counts the change affects (`pkg/baseline`, `pkg/finding`, `pkg/sarif` and `internal/cli` tests, and the golden files below).

## Golden files

`plan/plan.txt`, `plan/plan-details.txt`, `plan/plan.json` and `plan/summary.json` are the exact output of `sarifix plan` and `sarifix fix --mode report` against `plan/sarifix.yaml`. After a deliberate output change:

```sh
go test ./internal/cli -run 'Golden|FixReport' -update
git diff testdata/plan   # review before committing
```
