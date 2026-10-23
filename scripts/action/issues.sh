#!/usr/bin/env bash
# Keep one GitHub issue per batch (sarifix fix --mode issues) for the GitHub
# Action (action.yml), and record the actions as outputs and in the job
# summary. QUEUE, when set, overrides publish.issues.queue.
set -euo pipefail

args=(fix --mode issues --config "${CONFIG:-sarifix.yaml}" --sarif "$SARIF_DIR/*.sarif" --json --log-level warn)
[[ -n ${QUEUE:-} ]] && args+=(--queue "$QUEUE")
[[ ${DRY_RUN:-false} == true ]] && args+=(--dry-run)
out="${RUNNER_TEMP:-/tmp}/sarifix/issues.json"
sarifix "${args[@]}" >"$out"

{
  echo "issues-json=$out"
  echo "opened=$(jq '[.actions[] | select(.kind == "create")] | length' "$out")"
  echo "closed=$(jq '[.actions[] | select(.kind == "close")] | length' "$out")"
  echo "queued=$(jq '[.actions[] | select(.kind == "queue")] | length' "$out")"
} >>"$GITHUB_OUTPUT"

{
  echo "### sarifix issues$([[ ${DRY_RUN:-false} == true ]] && echo " (dry run: nothing was changed)")"
  if [[ $(jq '.actions | length' "$out") == 0 ]]; then
    echo "Issues already match the scan."
  else
    echo "| Change | Issue | Batch |"
    echo "| --- | --- | --- |"
    jq -r 'def cell: gsub("[|`\r\n]"; " ");
      .actions[] | "| \(.kind) | #\(.number // "") | `\(.batch | cell)` |"' "$out"
  fi
} >>"$GITHUB_STEP_SUMMARY"
