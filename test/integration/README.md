# Integration tests

End-to-end tests that run sarifix against real scanner binaries, behind the `integration` build tag so `go test ./...` stays fast and needs no extra tools.

```sh
go test -tags integration ./test/integration/
```

They need `trivy`, `checkov` and `golangci-lint` on `PATH`; the test fails, rather than skips, when one is missing. CI installs the versions listed in [`testdata/README.md`](../../testdata/README.md) in the `integration (real scanners)` job.

## What `TestRealScanners` checks

1. Copies `testdata/repos/basic` and `testdata/repos/shifted` to temporary directories.
2. Runs `sarifix scan` on each with [`examples/sarifix.yaml`](../../examples/sarifix.yaml), so the example config is proven against all four scanners. Every scanner must report at least one finding.
3. Runs `sarifix diff` between the two scans with `--repo` pointing at an empty directory. With no files to read, matching relies only on the fingerprints `sarifix scan` recorded, and every finding must match even though every line moved.

Unlike the unit tests, which read the committed fixtures in `testdata/sarif/`, this test exercises today's scanner versions. A scanner release that changes its SARIF in a way sarifix can't handle fails here first.

## What `TestCheckWithRealScanners` checks

Commits a copy of `testdata/repos/basic` as a git repository, adds an unhardened S3 bucket in a new file, and runs `sarifix check`. It must exit 3 and report findings from both Trivy and Checkov, all in the new file, and none of the fixture's existing findings.
