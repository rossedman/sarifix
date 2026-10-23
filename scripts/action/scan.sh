#!/usr/bin/env bash
# Scan the checkout for the GitHub Action (action.yml) and write one SARIF
# file per scanner to $RUNNER_TEMP/sarifix/sarif, outside the checkout so no
# scanner reads the others' output.
set -euo pipefail

dir="${RUNNER_TEMP:-/tmp}/sarifix/sarif"
mkdir -p "$dir"
sarifix scan --config "${CONFIG:-sarifix.yaml}" --out-dir "$dir" --log-level warn
echo "sarif-dir=$dir" >>"$GITHUB_OUTPUT"
