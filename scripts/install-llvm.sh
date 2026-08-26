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
# One script rather than the same dozen lines in two Dockerfile stages, for the
# reason scripts/smoke-image.sh exists: a recipe stated twice drifts, and the
# builder's LLVM and the runtime's clang disagreeing is a bitcode-version bug
# that only shows up at scan time.
set -euo pipefail

major="${1:?usage: install-llvm.sh <major> <package>...}"
shift
[ "$#" -gt 0 ] || { echo "install-llvm.sh: no packages given" >&2; exit 2; }

. /etc/os-release   # VERSION_CODENAME: the apt.llvm.org suite is per Debian release

apt-get update
apt-get install -y --no-install-recommends wget gnupg ca-certificates
wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key \
  | gpg --dearmor -o /usr/share/keyrings/llvm.gpg
echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/${VERSION_CODENAME}/ llvm-toolchain-${VERSION_CODENAME}-${major} main" \
  > /etc/apt/sources.list.d/llvm.list

apt-get update
apt-get install -y --no-install-recommends "$@"

# wget/gnupg were only needed to reach the repo. Purged in the same layer, or
# they would still be in the image regardless.
apt-get purge -y wget gnupg
apt-get autoremove -y
rm -rf /var/lib/apt/lists/*
