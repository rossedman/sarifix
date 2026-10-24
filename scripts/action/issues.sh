#!/usr/bin/env bash
# Keep one GitHub issue per batch (sarifix fix --mode issues) for the GitHub
# Action (action.yml), and record the actions as outputs and in the job
# summary. Open code scanning alerts for imported scanners are read too.
# QUEUE, when set, overrides publish.issues.queue. DISPATCH, when
# set, names a workflow to start for each issue this run queued, with the
# issue number as its issue input: labels added with the job's token start no
# workflows, so without it the agent queue only sees them on its own schedule.
set -euo pipefail

args=(fix --mode issues --config "${CONFIG:-sarifix.yaml}" --sarif "$SARIF_DIR/*.sarif" --json --log-level warn)
[[ -n ${QUEUE:-} ]] && args+=(--queue "$QUEUE")
[[ ${DRY_RUN:-false} == true ]] && args+=(--dry-run)
# Imported scanners (no command, such as CodeQL) get their open alerts from
# code scanning. It's written outside SARIF_DIR so the upload step never
# sends the alerts back. Without imported scanners this writes nothing.
alerts="${RUNNER_TEMP:-/tmp}/sarifix/code-scanning.sarif"
rm -f "$alerts"
if sarifix alerts export --config "${CONFIG:-sarifix.yaml}" --out "$alerts" --log-level warn; then
  [[ -f $alerts ]] && args+=(--sarif "$alerts")
else
  echo "::warning title=sarifix::couldn't read code scanning alerts, so imported scanners' issues are left as they are"
fi
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

dispatched=0
mapfile -t queued < <(jq -r '.actions[] | select(.kind == "queue") | .number' "$out")
if [[ -n ${DISPATCH:-} && ${DRY_RUN:-false} != true && ${#queued[@]} -gt 0 ]]; then
  api=${GITHUB_API_URL:-https://api.github.com}
  ref=${DEFAULT_BRANCH:-${GITHUB_REF_NAME:-main}}
  # dispatch BODY: start $DISPATCH, leaving the HTTP status in $code.
  dispatch() {
    code=$(curl -sS -o "$out.dispatch" -w '%{http_code}' -X POST \
      -H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$api/repos/$GITHUB_REPOSITORY/actions/workflows/$DISPATCH/dispatches" -d "$1") || code=000
  }
  for n in "${queued[@]}"; do
    dispatch "$(jq -cn --arg ref "$ref" --arg n "$n" '{ref: $ref, inputs: {issue: $n}}')"
    if [[ $code == 422 ]]; then
      # The workflow takes no issue input: start it once, and it picks the
      # oldest agent-ready issue. More bare runs would share one concurrency
      # group, where GitHub keeps only one pending run.
      dispatch "$(jq -cn --arg ref "$ref" '{ref: $ref}')"
      [[ $code == 204 ]] && dispatched=$((dispatched + 1))
      break
    fi
    [[ $code == 204 ]] || break
    dispatched=$((dispatched + 1))
  done
  if [[ $code != 204 ]]; then
    msg=$(jq -r '.message // empty' "$out.dispatch" 2>/dev/null || true)
    hint=""
    [[ $code == 403 ]] && hint=": add actions: write to the job's permissions"
    [[ $code == 404 ]] && hint=": is .github/workflows/$DISPATCH on $ref?"
    echo "::warning title=sarifix::couldn't start $DISPATCH (HTTP $code${msg:+, $msg})$hint"
  fi
  echo "Started $dispatched run(s) of $DISPATCH" >>"$GITHUB_STEP_SUMMARY"
fi
echo "dispatched=$dispatched" >>"$GITHUB_OUTPUT"
