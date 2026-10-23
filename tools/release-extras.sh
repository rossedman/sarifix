#!/bin/sh
# Generate the shell completions and man page that release archives and the
# Homebrew cask ship. Run by goreleaser before it builds (see .goreleaser.yaml).
set -eu
rm -rf completions manpages
mkdir -p completions manpages
for sh in bash zsh fish; do
  go run ./cmd/sarifix completion "$sh" >"completions/sarifix.$sh"
done
go run ./cmd/sarifix man | gzip -c -9 >manpages/sarifix.1.gz
