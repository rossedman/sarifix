# Getting started

Install sarifix, write a first config, scan a repo, and compare two scans. Everything on this page runs today.

!!! note "What exists today"
    sarifix is at phase 0. The commands `scan`, `diff`, `config validate` and `version` work. The commands that fix findings (`fix`, `plan`, `doctor`, `stats`) and the four modes are planned; see the [roadmap](roadmap.md).

## Install

=== "go install"

    Needs Go 1.27 or newer.

    ```bash
    go install github.com/rossedman/sarifix/cmd/sarifix@latest
    sarifix version
    ```

=== "Release binary"

    Download the archive for your platform and `checksums.txt` from the [releases page](https://github.com/rossedman/sarifix/releases), then verify before you run anything. Releases are built by `.github/workflows/release.yml` and the checksums file is signed with cosign through GitHub's OIDC identity, so there is no key to manage.

    ```bash
    cosign verify-blob checksums.txt \
      --bundle checksums.txt.sigstore.json \
      --certificate-identity-regexp '^https://github.com/rossedman/sarifix/\.github/workflows/release\.yml@refs/tags/v' \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com
    sha256sum --ignore-missing -c checksums.txt
    ```

    The first command proves the checksums file came from the release workflow. The second proves your download matches it. Then unpack the archive and put `sarifix` on your `PATH`.

## Write a first config

sarifix reads `sarifix.yaml` from the current directory. The smallest useful file declares one scanner: a name, the SARIF `tool.driver.name` it produces, and the command that runs it.

```yaml title="sarifix.yaml"
version: 1
scanners:
  - name: trivy
    match: ["Trivy"]
    command: ["trivy", "config", "--format", "sarif", "-o", "{out}", "{dir}"]
```

`{out}` is where sarifix wants the SARIF file and `{dir}` is the directory to scan. The [configuration guide](configuration.md) explains every placeholder, and the [config reference](reference/config.md) lists every field.

Validate it:

```bash
sarifix config validate
```

On success this prints each file it loaded with a check mark, followed by the resolved config with every default filled in. Mistakes are reported with the file, the key path and the line, and the exit code is 2.

The repository ships a complete example, [`examples/sarifix.yaml`](https://github.com/rossedman/sarifix/blob/main/examples/sarifix.yaml), that wires up Trivy, Checkov, golangci-lint and a custom script.

## Scan

`sarifix scan` runs every configured scanner over the repo and writes one SARIF file per scanner. Each result gets a `sarifix/v1` fingerprint so later diffs match findings without needing the source files.

```console
$ sarifix scan --log-level warn
✓ trivy 14 findings → sarif/trivy.sarif
✓ checkov 12 findings → sarif/checkov.sarif
✓ golangci-lint 1 finding → sarif/golangci-lint.sarif
✓ image-migrate 1 finding → sarif/image-migrate.sarif
```

This is the output on the repo's own fixture (`testdata/repos/basic`) with the example config. Your paths will differ. Useful flags:

| Flag | Effect |
| --- | --- |
| `--scanner trivy` | Run only the named scanner. Repeatable. |
| `--out-dir sarif/` | Where the `<scanner>.sarif` files go, relative to `--repo`. Default `sarif`. |
| `--dry-run` | Print the commands that would run and run nothing. |

A scanner that exits non-zero but still writes SARIF counts as a success, because most tools exit non-zero when they find something.

## Compare two scans

`sarifix diff` compares a base and a head SARIF set by fingerprint and prints what is new, fixed and unchanged.

The repository fixtures contain the same findings twice, with two lines inserted near the top of each file in the second copy. From `testdata/repos/basic`:

```console
$ sarifix diff --base '../../sarif/basic/*.sarif' --head '../../sarif/shifted/*.sarif' \
    --repo ../shifted --base-root .
2 new  2 fixed  26 unchanged

New
  + Checkov/CKV_DOCKER_2 Dockerfile:1 Ensure that HEALTHCHECK instructions have been added to container images
  + Checkov/CKV_DOCKER_3 Dockerfile:1 Ensure that a user for the container has been created

Fixed
  - Checkov/CKV_DOCKER_2 Dockerfile:1 Ensure that HEALTHCHECK instructions have been added to container images
  - Checkov/CKV_DOCKER_3 Dockerfile:1 Ensure that a user for the container has been created
```

Twenty-six findings moved but are still recognized as the same finding. The two reported as new and fixed are whole-file findings, which change identity whenever the file changes. [Fingerprints](guides/fingerprints.md) explains why, and what that limitation means for you.

`--repo` is the checkout of the head commit and `--base-root` the checkout of the base commit. sarifix reads source lines from them when the SARIF has no snippet. Add `--unchanged` to list the unchanged findings too, or `--json` for machine output.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success, including nothing to do |
| 1 | Runtime error |
| 2 | Config error |
| 3 | Some batches failed verification (used by the planned fixing commands) |

## Next steps

- Learn the full [configuration](configuration.md) model.
- Read how [fingerprints](guides/fingerprints.md) keep findings stable.
- See what is coming on the [roadmap](roadmap.md).
