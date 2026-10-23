# Security policy

<!-- --8<-- [start:body] -->
## Supported versions

sarifix is pre-1.0. Security fixes land on `main` and ship in the next release; only the latest release is supported.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| Older releases | No |

## Reporting a vulnerability

Please do not open a public issue. Report privately through GitHub's private vulnerability reporting at <https://github.com/rossedman/sarifix/security/advisories/new>.

Include the sarifix version (`sarifix version`), the scanner and SARIF input involved (trimmed to the smallest example), and what an attacker gains. SARIF that tries to steer the fixing agent, path tricks that escape the repo, and ways around the denied-path rules are all in scope.

## What to expect

- An acknowledgement within 3 business days.
- A fix, or a plan with a timeline, within 30 days.
- Credit in the published advisory, unless you prefer to stay anonymous.

## Verifying releases

Every release is built by `.github/workflows/release.yml` and signed keylessly with [cosign](https://docs.sigstore.dev/) through GitHub's OIDC identity, so there are no signing keys to leak. The signed `checksums.txt` covers every archive and SBOM.

```sh
cosign verify-blob checksums.txt \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/rossedman/sarifix/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
gh attestation verify sarifix_<version>_linux_amd64.tar.gz --repo rossedman/sarifix
```

Container images are signed by digest:

```sh
cosign verify ghcr.io/rossedman/sarifix:<version> \
  --certificate-identity-regexp '^https://github.com/rossedman/sarifix/.github/workflows/release.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

A signature from any other repository or workflow fails these checks.
<!-- --8<-- [end:body] -->
