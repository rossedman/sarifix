# Compare against an older release

Scan two commits of a Go library with golangci-lint and diff them: what got fixed since the last release, and what is new. Comparing commits months apart has pitfalls that a same-day pull request doesn't, and this tutorial runs into each of them.

You'll use [cobra](https://github.com/spf13/cobra), comparing its `v1.9.1` tag with the current default branch.

## 1. Check out both commits

```sh
git clone https://github.com/spf13/cobra
cd cobra
git worktree add ../cobra-v1.9.1 v1.9.1
```

## 2. The naive scan fails on the old commit

A plain golangci-lint scanner works on today's cobra. On `v1.9.1` it fails:

```console
$ sarifix scan --config ../cobra-naive.yaml --log-level warn
ERROR sarifix: scanner failed scanner=golangci-lint
  err=
  │ golangci-lint: exit status 3: Error: can't load config: unsupported version of the configuration: "" See https://golangci-lint.run/docs/product/migration-guide for migration instructions
  │ The command is terminated due to an error: can't load config: unsupported version of the configuration: "" See https://golangci-lint.run/docs/product/migration-guide for migration instructions
✗ golangci-lint golangci-lint: exit status 3: Error: can't load config: unsupported version of the configuration: "" See https://golangci-lint.run/docs/product/migration-guide for migration instructions The command is terminated due to an error: can't load config: unsupported version of the configuration: "" See ht…
Error: 1 of 1 scanners failed
```

golangci-lint reads each commit's own `.golangci.yml`, and `v1.9.1`'s is written for an older golangci-lint major version. Even when an old config does load, it enables different linters than today's, so the diff would report linters, not code.

The tool also caps its own output by default (`--max-issues-per-linter` and `--max-same-issues`). That silently drops findings, and the dropped ones then look fixed.

## 3. Pin the scanner

Keep the config outside both checkouts, as `../cobra-sarifix.yaml`:

```yaml
version: 1

scanners:
  - name: golangci-lint
    command:
      - golangci-lint
      - run
      - --no-config                 # ignore each commit's own .golangci.yml
      - --default=standard
      - --enable=gosec,revive,misspell
      - --max-issues-per-linter=0   # golangci-lint caps output by default
      - --max-same-issues=0
      - --output.sarif.path={out}
      - --output.text.path=stderr
      - ./...
    timeout: 10m

rules:
  allow:
    - golangci-lint/errcheck
    - golangci-lint/staticcheck
    - golangci-lint/misspell
  min_level: note
```

`--no-config` plus an explicit linter list makes both scans use the same linters. `--no-config` also stops golangci-lint from finding a `.golangci.yml` in a parent directory, which can happen when a checkout sits inside another repository and silently changes what gets scanned. golangci-lint reports most findings as `error`, but some linters use lower levels, so `min_level: note` keeps them all.

## 4. Scan and diff

```console
$ cd ../cobra-v1.9.1
$ sarifix scan --config ../cobra-sarifix.yaml --out-dir ../sarif-v1.9.1 --log-level warn
✓ golangci-lint 191 findings → ../sarif-v1.9.1/golangci-lint.sarif
```

```console
$ cd ../cobra
$ sarifix scan --config ../cobra-sarifix.yaml --out-dir ../sarif-main --log-level warn
✓ golangci-lint 176 findings → ../sarif-main/golangci-lint.sarif
$ sarifix diff --base '../sarif-v1.9.1/*.sarif' --head '../sarif-main/*.sarif'
5 new  20 fixed  171 unchanged

New
  + golangci-lint/errcheck command.go:2028 Error return value of `fmt.Fprintf` is not checked
  + golangci-lint/revive command_test.go:2930 context-keys-type: should not use basic type string as key in context.WithValue
  + golangci-lint/revive command_test.go:2933 unused-parameter: parameter 'args' seems to be unused, consider removing or renaming it as _
  + golangci-lint/revive completions.go:123 exported: exported method CompletionOptions.SetDefaultShellCompDirective should have comment or be unexported
  + golangci-lint/revive completions_test.go:4099 unused-parameter: parameter 'cmd' seems to be unused, consider removing or renaming it as _

Fixed
  - golangci-lint/errcheck command.go:2023 Error return value of `fmt.Fprintf` is not checked
  - golangci-lint/gosec completions.go:943 G302: Expect file permissions to be 0600 or less
  - golangci-lint/staticcheck completions.go:378 QF1001: could apply De Morgan's law
  - golangci-lint/staticcheck completions.go:776 QF1001: could apply De Morgan's law
  - golangci-lint/staticcheck completions_test.go:2902 QF1011: could omit type CompletionFunc from declaration; it will be inferred from the right-hand side
  - golangci-lint/staticcheck completions_test.go:2916 QF1011: could omit type CompletionFunc from declaration; it will be inferred from the right-hand side
  - golangci-lint/staticcheck completions_test.go:2930 QF1011: could omit type func(cmd *Command, args []string, toComplete string) ([]string, ShellCompDirective) from declara…
  - golangci-lint/staticcheck completions_test.go:2931 QF1011: could omit type func(cmd *Command, args []string, toComplete string) ([]Completion, ShellCompDirective) from dec…
  - golangci-lint/staticcheck completions_test.go:2970 QF1011: could omit type CompletionFunc from declaration; it will be inferred from the right-hand side
...
```

171 findings are unchanged, even though most of them moved: `command.go` alone grew by five lines above them. Of the 20 fixed, most are staticcheck suggestions cleaned up since the release.

Look at the errcheck pair: "fixed" at `command.go:2023` and "new" at `command.go:2028`. They are not the same finding, because the flagged line changed:

```diff
-		fmt.Fprintf(w, "\n\nAdditional help topcis:")
+		fmt.Fprintf(w, "\n\nAdditional help topics:")
```

A typo fix touched a line that already had an unchecked error. To sarifix that is a different line of code, so the old finding is gone and a new one exists. Line moves never change a finding's identity, but changes to the flagged line itself do.

## 5. Queue only what is new since the release

```console
$ sarifix plan --config ../cobra-sarifix.yaml --sarif '../sarif-main/*.sarif' --baseline '../sarif-v1.9.1/*.sarif'
176 findings  1 batched in 1 batch  0 deferred  175 skipped

Batches
  1. golangci-lint/errcheck error   1 finding in 1 file → sarifix/golangci-lint/errcheck
     command.go

Skipped
  in_baseline      171
  rule_not_allowed 4
```

Of the five new findings, one is errcheck, which is allowed. The four `revive` findings aren't on the allow list.

## What you learned

- Pin the scanner's configuration and limits so two scans differ only in the code.
- Line moves never change a finding's identity; edits to the flagged line do.
- `--baseline` against a release scan gives "what regressed since v1.9.1".

Next: [bring your own scanner](custom-scanner.md).
