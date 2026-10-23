#!/usr/bin/env sh
# fake.sh MODE OUT: a stand-in scanner for tests.
#   ok      write a one-result SARIF to OUT and exit 0
#   findings write SARIF and exit 1, like most scanners with findings
#   fail    write nothing, print to stderr and exit 2
#   silent  write nothing and exit 0
#   garbage write a non-SARIF file
#   empty   write SARIF whose only run is invalid
#   sleep   sleep past any short timeout
#   env     write SARIF whose message is $FAKE_MSG, and record pwd and args
set -eu
mode=$1
out=${2:-}
sarif() {
  printf '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Fake"}},"results":[{"ruleId":"F1","message":{"text":"%s"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.txt"},"region":{"startLine":1}}}]}]}]}' "$1" >"$out"
}
case $mode in
ok) sarif ok ;;
findings) sarif found; exit 1 ;;
fail) echo "boom: bad flag" >&2; exit 2 ;;
silent) ;;
garbage) echo nope >"$out" ;;
empty) echo '{"version":"2.1.0","runs":[{"tool":{"driver":{}}}]}' >"$out" ;;
sleep) sleep 5 ;;
env) sarif "$FAKE_MSG"; shift 2; echo "$(pwd) $*" >"$(dirname "$out")/argv.txt" ;;
esac
