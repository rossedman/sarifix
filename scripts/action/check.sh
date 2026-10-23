#!/usr/bin/env bash
# Report what a pull request introduced, for the GitHub Action (action.yml):
# sarifix check scans the merge base and the pull request with the pull
# request's sarifix.yaml and lists the new findings. Writes them to the job
# summary, and fails the step when FAIL_ON_NEW is true and there are any.
set -euo pipefail

if ! base=$(git merge-base "origin/${GITHUB_BASE_REF:?not a pull request}" HEAD 2>/dev/null); then
  echo "::error title=sarifix::can't find the merge base with origin/$GITHUB_BASE_REF; check out with fetch-depth: 0"
  exit 1
fi

out="${RUNNER_TEMP:-/tmp}/sarifix/check.json"
mkdir -p "$(dirname "$out")"
code=0
sarifix check --config "${CONFIG:-sarifix.yaml}" --base "$base" --json --log-level warn >"$out" || code=$?
if [[ $code != 0 && $code != 3 ]]; then
  exit "$code"
fi

new=$(jq '.new | length' "$out")
{
  echo "check-json=$out"
  echo "new=$new"
  echo "fixed=$(jq '.fixed' "$out")"
} >>"$GITHUB_OUTPUT"

{
  echo "### sarifix"
  jq -r '"\(.new | length) new, \(.fixed) fixed findings since \(.base[0:12])"' "$out"
  jq -r 'if (.skippedScanners // []) | length > 0 then "\nNot checked, the scanner failed: \(.skippedScanners | join(", "))" else empty end' "$out"
  if [[ $new != 0 ]]; then
    echo
    echo "| New finding | Level | Location |"
    echo "| --- | --- | --- |"
    jq -r 'def cell: gsub("[|`\r\n]"; " ");
      .new[] | "| `\(.ruleKey | cell)` | \(.level | cell) | `\(.path | cell):\(.line)` |"' "$out"
  fi
} >>"$GITHUB_STEP_SUMMARY"

if [[ $new != 0 ]]; then
  # Workflow command escaping: %, CR and LF in the message; also : and ,
  # in properties. Scanner text can't break out of its annotation.
  jq -r 'def msg: gsub("%"; "%25") | gsub("\r"; "%0D") | gsub("\n"; "%0A");
    def prop: msg | gsub(":"; "%3A") | gsub(","; "%2C");
    .new[] | "::warning file=\(.path | prop),line=\(.line),title=\(.ruleKey | prop)::\(.message | msg)"' "$out"
  if [[ ${FAIL_ON_NEW:-false} == true ]]; then
    echo "::error title=sarifix::this pull request introduces $new new findings"
    exit 3
  fi
fi
