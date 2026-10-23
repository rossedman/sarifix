# eol-images

A short Python scanner that flags Dockerfile `FROM` lines using end-of-life base images (Node.js 18 and older, including `node:lts-buster`, Python 3.9 and older, nginx 1.24 and older, .NET 7 and older, and Rust images on Debian buster), and writes one SARIF result per hit. It is the in-house scanner in the [custom scanner tutorial](https://rossedman.io/sarifix/tutorials/custom-scanner/).

It exists to show how little a scanner needs: walk the files, decide what is wrong, and write SARIF 2.1.0 with a rule ID, a level, a message and a file and line. sarifix adds fingerprints, routing, policy and batching.

## Run it

```sh
python3 eol_images.py <dir> <out.sarif>
```

It needs Python 3.9 or newer and nothing outside the standard library.

## Use it with sarifix

Copy `eol_images.py` into your repository (the tutorial uses `tools/`) and add a scanner and, optionally, a campaign:

```yaml
scanners:
  - name: eol-images
    command: ["python3", "tools/eol_images.py", "{dir}", "{out}"]

campaigns:
  - id: eol-base-images
    scanner: eol-images
    rules: ["eol-images/EOL_BASE_IMAGE"]
    pr_title: "chore: move off end-of-life base images"
```

`match` isn't needed: the script writes `eol-images` as its `tool.driver.name`, which matches the scanner name by default.

## Change what it flags

The `EOL` table at the top maps an image name to a tag regex and the advice shown in the message. Add an entry per image you track. The dates in the advice reflect upstream support as of October 2026; check them against [endoflife.date](https://endoflife.date/) before relying on them.

## Limits

It reads `FROM` lines with a regex, so it doesn't resolve build arguments (`FROM node:${VERSION}`) or follow multi-stage aliases. Unknown images and tags are never flagged.

The code passes `ruff check` and `ruff format`.
