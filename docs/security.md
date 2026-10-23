# Security

How sarifix treats untrusted input, what it will never touch, and how to report a vulnerability. The first half is the security policy; the second is the model behind the design.

--8<-- "SECURITY.md:body"

## Security model

sarifix reads SARIF written by other tools and, once the fixing phases land, hands findings to an AI agent that edits your code. Both are attack surface, so the design assumes that everything it reads (SARIF messages, rule help text, repository files) can be hostile.

!!! note "What is enforced today"
    sarifix does not yet run an agent or change files (that starts in phase 2). Today the model means: SARIF is validated against the 2.1.0 schema and invalid runs are skipped with a warning, scanner commands run as argv without a shell, and unknown placeholders are rejected at load. The agent controls in the table below are the design for phases 2 to 5.

### The agent's boundaries

The agent sees findings as quoted data. It can read and edit files in its own git worktree and run the batch's scanner and your `verify.commands`. It has no network access, no secrets and no push rights. The prompt is built by code with fixed sections: findings go in a delimited block labelled untrusted, with messages and help text truncated to 2,000 characters and stripped of control characters.

### Threats and controls

| Threat | Control |
| --- | --- |
| Prompt injection through a SARIF message or help text, from a malicious tool or pull request | Findings are delimited, labelled untrusted and truncated; the agent's tools are restricted; verification never relies on the agent's own claims. |
| Injection through repository file contents | The same tool limits apply, and the diff guard rejects edits outside the batch's files and to denied paths. |
| Exfiltration | The sandbox has no network. No secrets are in the agent's environment; the API key is used only by the provider process. |
| Workflow tampering | `.github/workflows/**` is denied by default and enforced in the diff guard on the actual diff, not only in the prompt. |
| Fork pull requests | `pr` mode runs only on default-branch pushes. `review` mode on forks posts suggestions only and never runs with write tokens against fork code. |
| Runaway cost | A per-batch timeout, a per-run batch cap and recorded token usage. |
| Suppression instead of a fix | The diff guard flags added `nolint`, `#checkov:skip`, `.trivyignore` entries and similar, unless the rule allows them. |

### Verification is independent

A batch is published only when every stage passes, in order: the diff guard (no denied paths, diff under `limits.max_diff_lines`, no files outside the batch), a rescan with the batch's scanner, every target fingerprint gone, no new findings from that scanner, and each `verify.commands` entry exiting 0. Because the checks re-run the scanner and your tests, an agent that lies about its work still cannot get a change through.

### Supply chain

Release checksums are signed with cosign, and the signature bundle is published beside them. See [Getting started](getting-started.md#install) for the verification commands.
