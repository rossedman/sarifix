#!/usr/bin/env bash
# Install a sarifix release for the GitHub Action (action.yml): the version
# asked for, else the action's own tag, else the latest release. Downloads
# from the public release page (no token needed) and verifies the archive
# against the release's checksums.txt.
set -euo pipefail

repo=rossedman/sarifix
tag=${SARIFIX_VERSION:-}
if [[ -z $tag && ${ACTION_REF:-} =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  tag=$ACTION_REF
fi
if [[ -z $tag || $tag == latest ]]; then
  # /releases/latest redirects to /releases/tag/<tag>.
  url=$(curl -fsSLI --retry 3 -o /dev/null -w '%{url_effective}' "https://github.com/$repo/releases/latest")
  tag=${url##*/}
fi
[[ $tag == v* ]] || tag=v$tag

case "${RUNNER_OS:-$(uname -s)}" in
Linux) os=linux ;;
macOS | Darwin) os=darwin ;;
*)
  echo "::error title=sarifix::the action runs on Linux and macOS runners, not ${RUNNER_OS:-$(uname -s)}"
  exit 1
  ;;
esac
case "${RUNNER_ARCH:-$(uname -m)}" in
X64 | x86_64) arch=amd64 ;;
ARM64 | arm64 | aarch64) arch=arm64 ;;
*)
  echo "::error title=sarifix::no sarifix build for ${RUNNER_ARCH:-$(uname -m)}"
  exit 1
  ;;
esac

archive="sarifix_${tag#v}_${os}_${arch}.tar.gz"
dir="${RUNNER_TEMP:-/tmp}/sarifix-$tag"
mkdir -p "$dir"
for f in "$archive" checksums.txt; do
  curl -fsSL --retry 3 -o "$dir/$f" "https://github.com/$repo/releases/download/$tag/$f"
done
(
  cd "$dir"
  grep " $archive\$" checksums.txt >want.txt
  if command -v sha256sum >/dev/null; then sha256sum -c want.txt; else shasum -a 256 -c want.txt; fi
  tar -xzf "$archive" sarifix
)
echo "$dir" >>"$GITHUB_PATH"
"$dir/sarifix" version
