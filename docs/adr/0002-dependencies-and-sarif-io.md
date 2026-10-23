# 2. Dependencies and SARIF I/O

- Status: accepted
- Date: 2026-10-22

## Context

The spec asks for approval before adding dependencies beyond cobra, viper, a SARIF library (evaluate `github.com/owenrumney/go-sarif`), go-github and a SQLite driver. The go-bootstrap standard requires Charmbracelet libraries for terminal output.

## Decision

- **go-sarif v3** provides the SARIF 2.1.0 object model used for reading. Evaluating it showed that its structs are not safe to write back: fields without `omitempty` serialize as `null`, `""`, `0` or `false`. A round trip writes `"language": ""` (schema-invalid), `"rank": 0` and, worst, `"enabled": false` on rule configurations, which disables rules. So sarifix keeps each run's original JSON and writes that, applying its own changes (for now, `partialFingerprints["sarifix/v1"]`) as patches.
- **gojsonschema**, already a dependency of go-sarif, is used directly to validate each run against the official OASIS SARIF 2.1.0 schema (errata01), vendored at `pkg/sarif/sarif-schema-2.1.0.json`. Validating run by run lets one bad run be skipped with a warning while the rest load. go-sarif's own `Validate` validates the re-marshaled struct (so it judges the lossy form) and recompiles the schema on every call.
- **Charmbracelet** (`fang`, `lipgloss`, `log`) for help, styled output and the `slog` handler, as the bootstrap standard requires. `fang`'s default error handler title-cases and re-wraps messages, which mangles file paths, so sarifix installs its own.
- **go.yaml.in/yaml/v3** (already required by viper) decodes `sarifix.yaml` with known-field checking and node positions, so errors name the file, key path and line.
- **cobra/doc** generates the command reference.

## Consequences

Schema validation dominates ingest cost: on a 50 MB file, parsing takes about 8 s with validation and about 1.1 s without (see `BenchmarkParse50MB*`). `sarif.Options.SkipValidation` exists for callers that have already validated their input; a faster validator can replace gojsonschema behind `validateRun` if needed.
