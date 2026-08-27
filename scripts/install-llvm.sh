#!/usr/bin/env bash
# Add apt.llvm.org and install the named LLVM packages.
#
# usage: scripts/install-llvm.sh <major> <package>...
#   builder stage: install-llvm.sh 22 llvm-22-dev          (headers + llvm-config)
#   runtime stage: install-llvm.sh 22 clang-22 libllvm22   (emit IR + the linked lib)
#
# Not apt.llvm.org's own llvm.sh: that installs the whole toolchain — lldb, lld,
# clangd — which cost 1.5 GB in the runtime image against the 540 MB the C/C++
# frontend actually needs.
#
# One script rather than the same dozen lines in two Dockerfile stages and CI,
# for the reason scripts/smoke-image.sh exists: a recipe stated twice drifts, and
# the builder's LLVM disagreeing with the runtime's clang is a bitcode-version
# bug that only shows up at scan time.
#
# It does NOT purge wget/gnupg afterwards. Doing so is right in a Docker layer
# and wrong on a CI runner, where later steps may need them; the Dockerfile
# purges in the same RUN, which is what keeps them out of the image anyway.
set -euo pipefail

major="${1:?usage: install-llvm.sh <major> <package>...}"
shift
[ "$#" -gt 0 ] || { echo "install-llvm.sh: no packages given" >&2; exit 2; }

. /etc/os-release   # VERSION_CODENAME: the apt.llvm.org suite is per Debian release

# Root in a Docker build, an unprivileged runner in CI.
sudo=""
[ "$(id -u)" -eq 0 ] || sudo=sudo

$sudo apt-get update
$sudo apt-get install -y --no-install-recommends wget gnupg ca-certificates
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
  | $sudo gpg --dearmor -o /usr/share/keyrings/llvm.gpg
echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-${major} main" \
  | $sudo tee /etc/apt/sources.list.d/llvm.list > /dev/null

$sudo apt-get update
$sudo apt-get install -y --no-install-recommends "$@"

$sudo rm -rf /var/lib/apt/lists/*
