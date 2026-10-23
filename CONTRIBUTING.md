# Contributing to sarifix

<!-- --8<-- [start:body] -->
Thanks for helping. sarifix is built phase by phase from its [spec](https://rossedman.io/sarifix/roadmap/); check the roadmap before starting large work, and open an issue first for anything that changes the CLI or `sarifix.yaml`.

## Set up

You need Go (the version in `go.mod`; `GOTOOLCHAIN=auto` fetches it), [golangci-lint](https://golangci-lint.run/) v2, and [uv](https://docs.astral.sh/uv/) for the docs site.

```sh
git clone https://github.com/rossedman/sarifix
cd sarifix
make build          # bin/sarifix
make test           # race detector + coverage profile
```

The integration tests run real scanners. Install `trivy`, `checkov` and `golangci-lint`, then:

```sh
go test -tags integration ./test/integration/
```

## Find your way around

[Architecture](https://rossedman.io/sarifix/architecture/) explains how the packages fit together and what each command does. The top-level folders:

| Folder | What's there |
| --- | --- |
| [`cmd/sarifix`](https://github.com/rossedman/sarifix/tree/main/cmd/sarifix) | `main` |
| [`internal/`](https://github.com/rossedman/sarifix/tree/main/internal) | The CLI (`internal/cli`, one command per file), terminal styles and build info |
| [`pkg/`](https://github.com/rossedman/sarifix/tree/main/pkg) | The pipeline, one package per step: SARIF loading, findings, policy, batching, report output |
| [`tools/`](https://github.com/rossedman/sarifix/tree/main/tools) | Repo checks and generators run by `make` and CI ([README](https://github.com/rossedman/sarifix/blob/main/tools/README.md)) |
| [`testdata/`](https://github.com/rossedman/sarifix/tree/main/testdata) | Fixture repos and real scanner output ([README](https://github.com/rossedman/sarifix/blob/main/testdata/README.md)) |
| [`test/integration/`](https://github.com/rossedman/sarifix/tree/main/test/integration) | Tests against real scanner binaries ([README](https://github.com/rossedman/sarifix/blob/main/test/integration/README.md)) |
| [`examples/`](https://github.com/rossedman/sarifix/tree/main/examples) | Config, an in-house scanner and a CI workflow to copy from ([README](https://github.com/rossedman/sarifix/blob/main/examples/README.md)) |
| [`docs/`](https://github.com/rossedman/sarifix/tree/main/docs), [`overrides/`](https://github.com/rossedman/sarifix/tree/main/overrides) | The docs site; see [Working on the docs](#working-on-the-docs) |

## The one command

```sh
make check
```

It runs everything CI runs: build, lint, tests with the coverage gate, the one-command-per-file check, doc-comment check, govulncheck, benchmark and fuzz smoke runs, the generated-docs drift check, the strict docs build and `goreleaser check`. `make fmt` fixes formatting.

## Quality bars

- **Coverage:** at least 90% of hand-written code (generated files and `examples/` are excluded). Don't test trivial getters just for the number.
- **Tests:** table-driven, `t.Parallel()` where safe. Commands are tested through `cli.Execute` with captured output. No network in unit tests; every external boundary has a fake.
- **Doc comments:** every function and method, exported or not, has a comment starting with its name, and every package has a package comment (`go run ./tools/doccheck ./...`).
- **One cobra command per file** in `internal/cli/`, registered in that file's `init()`. The file is named after the command (`config_validate.go` for `config validate`).
- **Benchmarks and fuzzing:** every critical path below has a benchmark using `b.Loop()` and `b.ReportAllocs()`. Every one that takes external input has a fuzz target that asserts properties, not just "didn't crash". Commit failing inputs the fuzzer finds under `testdata/fuzz/`.
- **Untrusted input:** SARIF messages, rule help and repo contents are untrusted. Never log full SARIF messages at info level, and pass anything printed to a terminal through `ui.Sanitize`.
- **Dependencies:** ask in an issue before adding a module beyond those already in `go.mod`.
- **Design decisions** that deviate from the spec go in `docs/adr/`.

## Critical paths

These need a benchmark, and a fuzz target where they take external input.

| Function | Why | Benchmark | Fuzz |
| --- | --- | --- | --- |
| `sarif.Parse`, `sarif.LoadGlobs` | Parses untrusted SARIF; the ingest hot path | `BenchmarkParse50MB`, `BenchmarkParse50MBNoValidate` | `FuzzParse` |
| `sarif.Normalizer.Resolve`, `.Path` | Turns untrusted URIs into repo paths; must never escape the repo | `BenchmarkResolve` | `FuzzNormalize` |
| `finding.Extractor.Extract`, `SnippetHash` | Runs once per result; defines finding identity | `BenchmarkExtract50MB`, `BenchmarkSnippetHash` | `FuzzFingerprint` |
| `baseline.Compare` | Diffs whole finding sets | `BenchmarkCompare` | n/a (no external input) |
| `config.Parse`, `Loaded.Validate` | Config resolution from repo-owned YAML | `BenchmarkLoadAndValidate` | `FuzzParse` (pkg/config) |
| `placeholder.ExpandArgs`, `Expand` | Builds scanner argv from config | `BenchmarkExpandArgs` | `FuzzExpand` |
| `glob.MatchPath`, `glob.MatchKey` | Policy checks for every finding and changed file | `BenchmarkMatchPath`, `BenchmarkMatchKey` | `FuzzMatchPath` |
| `ui.Sanitize` | Makes untrusted text safe for terminals | `BenchmarkSanitize` | `FuzzSanitize` |
| `policy.Policy.Apply` | Judges every finding against the rules | `BenchmarkApply` | n/a (inputs are already-parsed findings) |
| `group.Batches`, `group.Slug` | Batches every fixable finding; slugs become branch names | `BenchmarkBatches` | `FuzzSlug` |
| `publish.IssueBody`, `quote` | Puts untrusted scanner messages into issues an agent reads; must not fake the batch marker or mention anyone | `BenchmarkIssueBody` | `FuzzQuote` |
| `plan.Build` | Runs policy and grouping for a whole scan | `BenchmarkBuild` | n/a (no external input) |

Compare benchmark runs with [benchstat](https://pkg.go.dev/golang.org/x/perf/cmd/benchstat): `make bench` saves results under `bench/`.

## Working on the docs

The site is MkDocs Material, built with [uv](https://docs.astral.sh/uv/), with dependencies pinned in `requirements-docs.txt`.

```sh
make docs-serve   # live preview at http://127.0.0.1:8000
make docs-build   # what CI runs: strict, so broken links and anchors fail
```

- **Generated pages:** `docs/reference/` is written by `make docs` (`tools/gendocs`) from the CLI and the config structs. Don't edit it by hand: change the command's help text or the struct's `doc` tag, then run `make docs`. CI fails when the committed pages are stale.
- **Graphics:** the banner, social card and pipeline diagram are HTML in `docs/assets/src/`, rendered to PNG by `docs/assets/render.sh` with headless Chrome or Chromium (`CHROME=/path/to/chrome docs/assets/render.sh banner`). Commit the HTML and the PNG together.
- **The landing page** is `overrides/home.html`. Its numbers (for example "28 load-time checks") are counted from the code, so update them when the code changes.
- **Output in docs is real.** Every console block comes from running the command. When a command's output changes, rerun it and paste the new output rather than editing the old block by hand.
- **New pages** go in `nav:` in `mkdocs.yml`; the strict build fails on a page missing from it.

## CI

`.github/workflows/ci.yml` runs on every push to `main` and every pull request:

| Job | What it checks |
| --- | --- |
| `lint` | golangci-lint, one command per file, doc comments, generated docs are current |
| `test` | `go test -race`, the 90% coverage gate, a one-iteration benchmark run |
| `govulncheck` | Known vulnerabilities in reachable code |
| `fuzz <pkg> <target>` | Each fuzz target for 30 seconds; failing inputs are uploaded as an artifact |
| `integration (real scanners)` | `test/integration` with pinned Trivy, Checkov and golangci-lint |
| `goreleaser snapshot` | `goreleaser check` and a full snapshot release, including the container image |

`docs.yml` builds the site on changes to it and deploys from `main`; `release.yml` publishes signed releases on `v*` tags.

## Commits and pull requests

Commit messages and PR titles follow [Conventional Commits](https://www.conventionalcommits.org/):

```text
feat(scan): add --scanner to run a subset
fix(sarif): reject cyclic uriBaseId chains
docs: explain fingerprint precedence
```

PRs are squash-merged once CI is green and a code owner has approved. Keep each PR to one phase or one change, with its tests and docs.

## Questions

Open an [issue](https://github.com/rossedman/sarifix/issues). For anything security related, use the private process in [SECURITY.md](https://github.com/rossedman/sarifix/blob/main/SECURITY.md).
<!-- --8<-- [end:body] -->
