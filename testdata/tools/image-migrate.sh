#!/usr/bin/env sh
# image-migrate: a hand-written SARIF producer used as the custom-tool fixture.
# It flags Dockerfile FROM lines that use a deprecated alpine base image.
# Usage: image-migrate.sh <dir> <out.sarif>
set -eu
dir=$1
out=$2
results=""
sep=""
for f in $(cd "$dir" && find . -name Dockerfile -not -path './.git/*' | sort); do
  rel=${f#./}
  n=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    case "$line" in
    "FROM alpine:3.1"[0-8]*)
      results="$results$sep{\"ruleId\":\"DEPRECATED_BASE\",\"level\":\"warning\",\"message\":{\"text\":\"Base image is deprecated; use the platform base image v4.\"},\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"$rel\",\"uriBaseId\":\"SRCROOT\"},\"region\":{\"startLine\":$n}}}]}"
      sep=","
      ;;
    esac
  done <"$dir/$rel"
done
cat >"$out" <<SARIF
{"\$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"image-migrate","rules":[{"id":"DEPRECATED_BASE","shortDescription":{"text":"Deprecated base image"},"help":{"text":"Replace the FROM line with registry.example.com/platform/base:4."}}]}},"originalUriBaseIds":{"SRCROOT":{"uri":"file://$(cd "$dir" && pwd)/"}},"results":[$results]}]}
SARIF
