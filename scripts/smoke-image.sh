#!/usr/bin/env bash
# Smoke-test a built Godzilla image: every command in ./cmd/ ships in it and
# starts.
#
# The Dockerfile builds `./cmd/...` so that adding a command needs no edit
# there; this enumerates the same way, so it needs none either. A hard-coded
# list would put the edit back one file over and let a third command ship
# untested.
#
# usage: scripts/smoke-image.sh <image> [variant]
#
# With a variant it also asserts the LANGUAGES that variant is supposed to scan.
# That is not the same check as "the binary runs": `full` shipping a binary built
# WITHOUT the `llvm` build tag still starts, still prints the same version, and
# fails only by reporting cpp=FAILED in a scan nobody looks at. The C/C++
# frontend is compiled in, not installed, so nothing about the image's file list
# reveals its absence.
#
# The table below is the single source of truth for what each image scans; the
# README table and the Dockerfile header quote it.
set -euo pipefail

img="${1:?usage: scripts/smoke-image.sh <image> [variant]}"
variant="${2:-}"
cd "$(dirname "$0")/.."

case "$variant" in
  slim) want_langs="go python javascript ruby" ;;
  full) want_langs="go python javascript ruby java rust cpp" ;;
  "")   want_langs="" ;;
  *)    echo "smoke: unknown variant '$variant' (want slim|full)" >&2; exit 2 ;;
esac

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

[ -n "$want_langs" ] || exit 0

# One tiny file per language, so every frontend the variant claims is exercised.
# Built here rather than reusing test/ because .dockerignore keeps that out of
# the image and the fixture has to stay small enough to scan in seconds.
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cat > "$fixture/go.mod" <<'GOMOD'
module smoke

go 1.21
GOMOD
printf 'package main\n\nfunc main() { println("hi") }\n'        > "$fixture/main.go"
printf 'print("hi")\n'                                          > "$fixture/app.py"
printf 'console.log("hi");\n'                                   > "$fixture/app.js"
printf 'puts "hi"\n'                                            > "$fixture/app.rb"
printf 'public class App { public static void main(String[] a) {} }\n' > "$fixture/App.java"
printf 'pub fn hi() -> i32 { 1 }\n'                             > "$fixture/lib.rs"
printf '#include <cstdio>\nint main() { std::printf("hi"); }\n' > "$fixture/main.cpp"

# mktemp -d is 0700 and owned by the invoking user; the image runs as uid 1000,
# which is a DIFFERENT user on a CI runner. Without this the container cannot
# read the mount and the scan reports nothing. Docker Desktop on macOS hides it
# by mapping ownership permissively, so it fails only on Linux.
chmod -R a+rX "$fixture"

echo "smoke: $img — expecting to scan: $want_langs"
set +e
scan=$(docker run --rm -v "$fixture:/src:ro" "$img" scan /src 2>&1)
set -e
cov=$(printf '%s\n' "$scan" | grep '^coverage:' || true)
if [ -z "$cov" ]; then
  # The scan output IS the diagnosis here — a mount it cannot read, a missing
  # shared library, a toolchain that will not start — so print it rather than
  # leaving the next reader to reproduce it.
  echo "smoke: FAIL the scan printed no coverage line. Its output was:" >&2
  printf '%s\n' "$scan" >&2
  exit 1
fi
echo "smoke: $cov"

rc=0
for lang in $want_langs; do
  # `ok` or PARTIAL both mean the frontend RAN. FAILED or absent means it did
  # not — the frontend is missing from this image, or its toolchain is.
  case "$cov" in
    *"$lang=ok"*|*"$lang=PARTIAL"*) ;;
    *) echo "smoke: FAIL $variant should scan $lang, but coverage says otherwise" >&2; rc=1 ;;
  esac
done
[ "$rc" -eq 0 ] || exit 1
echo "smoke: all $(echo "$want_langs" | wc -w | tr -d ' ') language(s) scanned by $variant"
