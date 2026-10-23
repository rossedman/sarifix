#!/usr/bin/env sh
# flag-lines: a scriptable SARIF producer for check tests.
# Usage: flag-lines.sh <dir> <out.sarif>
#   Lines containing INSECURE in *.txt files are error findings, lines
#   containing NOTE are note findings. If <dir>/FAIL exists the scanner
#   fails without writing SARIF. With FLAG_LOG set, each run appends <dir>
#   to that file, so tests can count scans.
set -eu
dir=$1
out=$2
if [ -n "${FLAG_LOG:-}" ]; then echo "$dir" >>"$FLAG_LOG"; fi
if [ -e "$dir/FAIL" ]; then
  echo "flag-lines: FAIL marker present" >&2
  exit 3
fi
results=""
sep=""
for f in $(cd "$dir" && find . -name '*.txt' -not -path './.git/*' | sort); do
  rel=${f#./}
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in
    *INSECURE*) rule=INSECURE_LINE level=error ;;
    *NOTE*) rule=NOTE_LINE level=note ;;
    *) continue ;;
    esac
    results="$results$sep{\"ruleId\":\"$rule\",\"level\":\"$level\",\"message\":{\"text\":\"Line $n is flagged.\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"$rel\"},\"region\":{\"startLine\":$n}}}]}"
    sep=","
  done <"$dir/$rel"
done
printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"flag-lines","rules":[{"id":"INSECURE_LINE","help":{"text":"Remove the INSECURE marker."}},{"id":"NOTE_LINE"}]}},"results":[%s]}]}\n' "$results" >"$out"
