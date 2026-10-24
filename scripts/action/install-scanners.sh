#!/usr/bin/env bash
# Install the scanners sarifix.yaml names, for the GitHub Action (action.yml).
# SCANNERS is "auto" (every scanner in the config the action knows), "none",
# or a comma-separated list. A scanner already on PATH is left alone. Each
# download is checked against its release's published checksums; Python
# scanners come from PyPI through pipx. Versions are pinned here and bumped
# on purpose, because a new scanner release adds rules.
set -euo pipefail

TRIVY_VERSION=${TRIVY_VERSION:-0.76.1}
GOLANGCI_LINT_VERSION=${GOLANGCI_LINT_VERSION:-2.15.0}
GITLEAKS_VERSION=${GITLEAKS_VERSION:-8.30.1}
HADOLINT_VERSION=${HADOLINT_VERSION:-2.14.0}
TFMETRICS_VERSION=${TFMETRICS_VERSION:-0.2.2}
CHECKOV_VERSION=${CHECKOV_VERSION:-3.3.30}
RUFF_VERSION=${RUFF_VERSION:-0.17.1}
SEMGREP_VERSION=${SEMGREP_VERSION:-1.182.1}

scanners=${SCANNERS:-auto}
config=${CONFIG:-sarifix.yaml}
[[ $scanners == none ]] && exit 0

names=()
if [[ $scanners == auto ]]; then
  mapfile -t names < <(sarifix config validate --config "$config" --json | jq -r '.scanners[] | select((.command // []) | length > 0) | .name')
else
  IFS=, read -ra names <<<"$scanners"
fi

case "${RUNNER_OS:-$(uname -s)}" in
Linux) os=linux ;;
macOS | Darwin) os=darwin ;;
*)
  echo "::error title=sarifix::scanners install on Linux and macOS runners only"
  exit 1
  ;;
esac
case "${RUNNER_ARCH:-$(uname -m)}" in
X64 | x86_64) arm=false ;;
ARM64 | arm64 | aarch64) arm=true ;;
*)
  echo "::error title=sarifix::no scanner builds for ${RUNNER_ARCH:-$(uname -m)}"
  exit 1
  ;;
esac

bin="${RUNNER_TEMP:-/tmp}/sarifix-scanners"
work="$bin/downloads"
mkdir -p "$work"
# pipx installs into ~/.local/bin, which isn't always on PATH.
{
  echo "$bin"
  echo "$HOME/.local/bin"
} >>"$GITHUB_PATH"
export PATH="$bin:$HOME/.local/bin:$PATH"

# fetch <base-url> <asset> <checksums-file>: download asset and its checksums
# into $work, and verify the asset.
fetch() {
  local base=$1 asset=$2 sums=$3
  curl -fsSL --retry 3 -o "$work/$asset" "$base/$asset"
  curl -fsSL --retry 3 -o "$work/$sums" "$base/$sums"
  (
    cd "$work"
    grep -E "[ *]$asset\$" "$sums" >want.txt || {
      echo "::error title=sarifix::$asset is not listed in $sums"
      exit 1
    }
    if command -v sha256sum >/dev/null; then sha256sum -c want.txt; else shasum -a 256 -c want.txt; fi
  )
}

# pyinstall <package==version>: install a Python scanner with pipx (on
# GitHub's runners), else uv.
pyinstall() {
  if command -v pipx >/dev/null; then
    pipx install --quiet "$1"
  elif command -v uv >/dev/null; then
    uv tool install --quiet "$1"
  else
    echo "::error title=sarifix::installing $1 needs pipx or uv"
    exit 1
  fi
}

# pick <linux-x64> <linux-arm64> <darwin-x64> <darwin-arm64>: the word for
# this runner.
pick() {
  case "$os-$arm" in
  linux-false) echo "$1" ;;
  linux-true) echo "$2" ;;
  darwin-false) echo "$3" ;;
  darwin-true) echo "$4" ;;
  esac
}

for raw in "${names[@]}"; do
  name=$(echo "$raw" | tr -d '[:space:]')
  [[ -z $name ]] && continue
  if command -v "$name" >/dev/null; then
    echo "$name is already installed: $(command -v "$name")"
    continue
  fi
  case $name in
  trivy)
    a="trivy_${TRIVY_VERSION}_$(pick Linux-64bit Linux-ARM64 macOS-64bit macOS-ARM64).tar.gz"
    fetch "https://github.com/aquasecurity/trivy/releases/download/v$TRIVY_VERSION" "$a" "trivy_${TRIVY_VERSION}_checksums.txt"
    tar -xzf "$work/$a" -C "$bin" trivy
    ;;
  golangci-lint)
    command -v go >/dev/null || echo "::warning title=sarifix::golangci-lint needs Go: add actions/setup-go before this step"
    d="golangci-lint-${GOLANGCI_LINT_VERSION}-$(pick linux-amd64 linux-arm64 darwin-amd64 darwin-arm64)"
    fetch "https://github.com/golangci/golangci-lint/releases/download/v$GOLANGCI_LINT_VERSION" "$d.tar.gz" "golangci-lint-${GOLANGCI_LINT_VERSION}-checksums.txt"
    tar -xzf "$work/$d.tar.gz" -C "$work" "$d/golangci-lint"
    mv "$work/$d/golangci-lint" "$bin/"
    ;;
  gitleaks)
    a="gitleaks_${GITLEAKS_VERSION}_$(pick linux_x64 linux_arm64 darwin_x64 darwin_arm64).tar.gz"
    fetch "https://github.com/gitleaks/gitleaks/releases/download/v$GITLEAKS_VERSION" "$a" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"
    tar -xzf "$work/$a" -C "$bin" gitleaks
    ;;
  hadolint)
    a="hadolint-$(pick linux-x86_64 linux-arm64 macos-x86_64 macos-arm64)"
    fetch "https://github.com/hadolint/hadolint/releases/download/v$HADOLINT_VERSION" "$a" "$a.sha256"
    install -m 0755 "$work/$a" "$bin/hadolint"
    ;;
  tfmetrics)
    a="tfmetrics_${TFMETRICS_VERSION}_$(pick linux_amd64 linux_arm64 darwin_amd64 darwin_arm64).tar.gz"
    fetch "https://github.com/rossedman/tfmetrics/releases/download/v$TFMETRICS_VERSION" "$a" checksums.txt
    tar -xzf "$work/$a" -C "$bin" tfmetrics
    ;;
  checkov) pyinstall "checkov==$CHECKOV_VERSION" ;;
  ruff) pyinstall "ruff==$RUFF_VERSION" ;;
  semgrep) pyinstall "semgrep==$SEMGREP_VERSION" ;;
  *)
    echo "::notice title=sarifix::the action doesn't install the scanner \"$name\"; install it in a step before this one"
    continue
    ;;
  esac
  echo "installed $name"
done
