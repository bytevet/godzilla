#!/usr/bin/env bash
# Smoke-test a built Godzilla image: every command in ./cmd/ ships in it and
# starts.
#
# The Dockerfile builds `./cmd/...` so that adding a command needs no edit
# there; this enumerates the same way, so it needs none either. A hard-coded
# list would put the edit back one file over and let a third command ship
# untested.
#
# usage: scripts/smoke-image.sh <image>
set -euo pipefail

img="${1:?usage: scripts/smoke-image.sh <image>}"
cd "$(dirname "$0")/.."

# Filled with a read loop rather than mapfile: macOS still ships bash 3.2, and a
# script that only runs in CI is not much of a local check.
cmds=()
while IFS= read -r line; do cmds+=("$line"); done < <(
  go list -f '{{.Dir}}' ./cmd/... | xargs -n1 basename | sort
)
if [ "${#cmds[@]}" -eq 0 ]; then
  echo "smoke: found no commands under ./cmd — nothing to check" >&2
  exit 1
fi
echo "smoke: $img — expecting ${cmds[*]}"

for bin in "${cmds[@]}"; do
  # Presence first, and as its own assertion: `docker run --entrypoint missing`
  # reports the name in its OWN error text, so grepping the run output for the
  # binary's name would pass for a binary that is not there.
  if ! docker run --rm --entrypoint sh "$img" -c "test -x /usr/local/bin/$bin"; then
    echo "smoke: FAIL $bin is not in the image" >&2
    exit 1
  fi
  # Then that it starts. Exit codes differ by design — `godzilla -h` is a usage
  # error (2) while a flag-parsing command exits 0 — so this asserts "ran and
  # chose an exit code", not a specific one. A binary that cannot start (missing
  # shared library, wrong arch) fails well outside that range.
  set +e
  out=$(docker run --rm --entrypoint "$bin" "$img" -h 2>&1)
  rc=$?
  set -e
  if [ "$rc" -gt 2 ]; then
    echo "smoke: FAIL $bin exited $rc" >&2
    printf '%s\n' "$out" >&2
    exit 1
  fi
  printf 'smoke: ok   %-22s %s\n' "$bin" "$(printf '%s' "$out" | head -1)"
done

echo "smoke: all ${#cmds[@]} command(s) present and runnable"
