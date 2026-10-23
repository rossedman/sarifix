# 4. Config semantics the spec leaves open

- Status: accepted
- Date: 2026-10-22

## Decision

- **Workflows are always denied.** `.github/workflows/**` is added to `paths.deny` even if the file sets its own list, so a repo config can't open workflow files to the agent. The spec calls this "denied by default". Making it unconditional is the safer reading.
- **Layering.** With `--org-config`, scalars and lists in the repo file replace the org values. Scanners merge by `name` and campaigns by `id`, with the repo entry winning. Duplicates inside one file are kept so validation reports them, and errors point at the file and line that defined the entry.
- **Matching** of `tool.driver.name` against `scanners[].match` is case-insensitive, so overlap detection is too.
- **Placeholders** are `{name}` tokens. Any other brace is literal, so JSON in an argument passes through unchanged.
- **Globs.** In rule keys, `*` matches `/` too, because rule IDs such as CodeQL's `go/sql-injection` contain slashes. In paths, `*` stays within one segment and `**` must be a whole segment.
- **`--strict`** rejects a `rules.allow` glob whose scanner part matches no configured scanner. Rule IDs can't be known before a scan, so only the scanner part is checked.
- **Scanner exit codes.** A non-zero exit counts as success when the tool wrote SARIF, since most scanners exit non-zero when they find something. Each scanner runs in its own process group, so a timeout also kills its children.
