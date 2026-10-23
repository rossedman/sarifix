# Tutorials

Walk-throughs on real open-source repositories, each built around one job sarifix does. Every command was run for these pages, and every block of output is what it printed. Long output is trimmed where you see `...`.

- **[Triage an infrastructure backlog](iac-backlog.md)** on [terragoat](https://github.com/bridgecrewio/terragoat) (Terraform). Point two scanners at a repository, read a plan, and tune rules and limits until the work queue makes sense.
- **[Check only what a pull request introduced](pull-requests.md)** on terragoat. Diff two scans, and use `--baseline` to keep pre-existing findings out of the way.
- **[Compare against an older release](release-history.md)** on [cobra](https://github.com/spf13/cobra) (Go). Scan two commits like for like with golangci-lint, and avoid the settings that silently skew the comparison.
- **[Bring your own scanner and run a migration](custom-scanner.md)** on [awesome-compose](https://github.com/docker/awesome-compose) (Dockerfiles). Plug in Hadolint and a short Python script, and group a migration into a campaign.
- **[Roll out a policy across repositories](org-policy.md)** on [microservices-demo](https://github.com/GoogleCloudPlatform/microservices-demo) (Kubernetes). Layer a platform default config under each repository's own, and keep generated files out of the queue.
- **[Give Claude Code feedback on its changes](claude-code-hook.md)**, for any repository. Run `sarifix check --hook` as a Claude Code Stop hook, so Claude fixes the findings its changes introduced before it finishes.
- **[Report on every pull request in GitHub Actions](github-actions.md)**, for any repository. Run the pull-request check in CI and publish a job summary.
- **[Turn findings into issues Claude works through](claude-queue.md)**, for any GitHub repository. Scan the default branch, upload to code scanning, keep one agent-ready issue per batch, and let Claude fix them one pull request at a time.

## Before you start

Install sarifix (see [Getting started](../getting-started.md)) and the scanners each tutorial uses. These pages were written with:

| Tool | Version | Used in |
| --- | --- | --- |
| [Trivy](https://trivy.dev/) | 0.76.1 | infrastructure, pull requests, org policy |
| [Checkov](https://www.checkov.io/) | 3.3.30 | infrastructure, pull requests, org policy |
| [golangci-lint](https://golangci-lint.run/) | 2.15.0 | release history |
| [Hadolint](https://github.com/hadolint/hadolint) | 2.15.1 | custom scanner |
| Python | 3.13 | custom scanner |
| [jq](https://jqlang.org/) | any | reading reports |

Other versions work. Their rules and counts will differ from the output shown here.

!!! note "What these tutorials cover"
    sarifix fixes nothing yet: the agent and the `local`, `pr` and `review` modes arrive in later [phases](../roadmap.md). These tutorials cover everything that runs today, namely scanning, fingerprints and diffs, the policy, batching, and report mode. Those decide what a fix run will do once fixing lands.

Each tutorial writes scan output into the repository (`sarif/`, `sarifix-report/`). In a repository of your own, add both to `.gitignore`: SARIF files are regenerated on every run and never committed. See [Where SARIF files live](../guides/sarif-files.md).
