#!/usr/bin/env sh
# Fail if any internal/cli/*.go (non-test) file defines other than one cobra
# command. root.go also holds the shared app plumbing; it still defines one.
set -eu
fail=0
for f in internal/cli/*.go; do
  case "$f" in *_test.go) continue ;; esac
  n=$(grep -c '&cobra.Command{' "$f" || true)
  if [ "$n" -ne 1 ]; then
    echo "$f defines $n commands"
    fail=1
  fi
done
exit $fail
