#!/usr/bin/env bash
# Regenerate the scanner fixtures in testdata/sarif/ from the fixture repos
# in testdata/repos/, using the real scanners. Run from the repo root:
#
#   tools/regen-fixtures.sh
#
# Needs trivy, checkov and golangci-lint on PATH. Tests assert exact
# finding counts, so use the versions in testdata/README.md or expect to
# update the tests.
set -euo pipefail

root=$(pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

for repo in basic shifted edited; do
  src="testdata/repos/$repo"
  out="$root/testdata/sarif/$repo"
  mkdir -p "$out"
  (
    cd "$src"
    trivy config --quiet --format sarif -o "$out/trivy.sarif" .
    # Checkov exits non-zero when it finds something.
    checkov -d . -o sarif --output-file-path "$tmp/$repo" --quiet >/dev/null || true
    cp "$tmp/$repo/results_sarif.sarif" "$out/checkov.sarif"
    # --no-config: don't pick up this repo's own .golangci.yml, which
    # excludes testdata. golangci-lint exits non-zero on findings.
    golangci-lint run --no-config --output.sarif.path="$out/golangci-lint.sarif" ./... >/dev/null || true
    "$root/testdata/tools/image-migrate.sh" . "$out/image-migrate.sarif"
    rm -f out.txt
  )
  # Scanners write this machine's absolute checkout path; replace it with a
  # CI-style workspace so fixtures don't depend on where they were made.
  sed -i.bak "s|file://$root/testdata/repos/$repo/|file:///github/workspace/|g" "$out"/*.sarif
  rm -f "$out"/*.bak
done
echo "regenerated testdata/sarif/{basic,shifted,edited}"
