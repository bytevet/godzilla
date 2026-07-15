#!/usr/bin/env bash
#
# pr-quality-gate.sh — per-PR quality gate for Godzilla.
#
# Compares two git revisions (base..head) and reports four things a reviewer
# needs to sign off on a change to a SAST engine:
#
#   1. LOC modified, excluding tests   — how big the change to product source is.
#   2. Corpus TP/FP/FN vs. base        — did precision or recall move?
#   3. Rules added / modified          — how much detection surface changed?
#   4. Performance change              — did scans get slower? (the primary gate)
#
# All four are computed from tooling that already exists: `git diff`, the corpus
# scorer (TestCorpusSignalToNoise), the rulepack YAML, and the Go benchmarks.
# Nothing about the engine or gIR is touched.
#
# Both revisions are measured back-to-back on the SAME machine (via `git
# worktree`), because the corpus sample count and benchmark timings are
# environment-dependent — only same-environment numbers are comparable.
#
# Usage:
#   scripts/pr-quality-gate.sh <base-ref> [head-ref]
#
# Common flags (see --help):
#   --format md|json          output format (default: md)
#   --output FILE             write report to FILE instead of stdout
#   --no-gate                 report only; always exit 0
#   --perf-threshold PCT      benchmark time (sec/op) regression bound (default: 10)
#   --mem-threshold PCT       benchmark memory (B/op, allocs/op) bound (default: 10)
#   --runs N                  wall-clock runs per revision (informational, default: 20)
#   --bench-count N           `go test -bench -count`          (default: 10)
#   --no-bench | --no-wall | --no-corpus   skip that measurement (faster runs)
#
# Exit codes: 0 = gate passed (or --no-gate), 1 = a hard gate tripped,
#             2 = bad usage, 3 = operational error (missing tool, bad ref, ...).

set -euo pipefail

# --------------------------------------------------------------------------- #
# Configuration — the single extension point if the repo layout changes.
# --------------------------------------------------------------------------- #

# Product-source directories counted toward "LOC modified". `test/` is excluded
# by simply not appearing here.
LOC_INCLUDES=(cmd converters internal pkg proto rulepacks)
# Path globs excluded from the LOC count even inside the dirs above: tests,
# fixtures, and generated protobuf bindings.
LOC_EXCLUDES=(':(exclude)**/*_test.go' ':(exclude)**/testdata/**' ':(exclude)pkg/ir/v1/*.pb.go')

# Packages whose benchmarks form the Go hot-path signal (the taint engine is
# language-neutral, so these catch a shared-engine regression that would hit
# every language).
BENCH_PKGS=(./internal/scan/ ./internal/analysis/ ./internal/rules/)
# Key benchmarks the perf gate blocks on (names as `go test` prints them,
# minus the trailing GOMAXPROCS suffix and any sub-benchmark params).
KEY_BENCHMARKS=(Engine_RuleScaling MatchGlob Scan_GoWithDeps)

# Languages measured by the full-pipeline wall clock, paired with the tool that
# must be on PATH (empty = always available: in-binary frontend). c/cpp are
# omitted — their LLVM frontend is an opt-in cgo build, not in the default binary.
# Each language's perf sample is test/<lang>/command_injection (exists for all).
PERF_LANGS=(go python js rust java ruby)
declare -A PERF_TOOL=([go]="" [python]=python3 [js]="" [rust]=rustc [java]=java [ruby]=ruby)

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #

FORMAT=md
OUTPUT=""
DO_GATE=1
PERF_THRESHOLD=10   # sec/op regression bound (gated)
MEM_THRESHOLD=10    # B/op & allocs/op regression bound (gated)
RUNS=20             # wall-clock runs (informational only)
BENCH_COUNT=10
DO_BENCH=1
DO_WALL=1
DO_CORPUS=1

die()  { echo "pr-quality-gate: $*" >&2; exit 3; }
usage_err() { echo "pr-quality-gate: $*" >&2; echo "try: $0 --help" >&2; exit 2; }

print_help() {
  sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)        print_help ;;
    --format)         FORMAT="${2:?}"; shift 2 ;;
    --output)         OUTPUT="${2:?}"; shift 2 ;;
    --no-gate)        DO_GATE=0; shift ;;
    --perf-threshold) PERF_THRESHOLD="${2:?}"; shift 2 ;;
    --mem-threshold)  MEM_THRESHOLD="${2:?}"; shift 2 ;;
    --runs)           RUNS="${2:?}"; shift 2 ;;
    --bench-count)    BENCH_COUNT="${2:?}"; shift 2 ;;
    --no-bench)       DO_BENCH=0; shift ;;
    --no-wall)        DO_WALL=0; shift ;;
    --no-corpus)      DO_CORPUS=0; shift ;;
    --)               shift; while [[ $# -gt 0 ]]; do POSITIONAL+=("$1"); shift; done ;;
    -*)               usage_err "unknown flag: $1" ;;
    *)                POSITIONAL+=("$1"); shift ;;
  esac
done

[[ "$FORMAT" == md || "$FORMAT" == json ]] || usage_err "--format must be md or json"
[[ ${#POSITIONAL[@]} -ge 1 ]] || usage_err "missing <base-ref>"
BASE_REF="${POSITIONAL[0]}"
HEAD_REF="${POSITIONAL[1]:-HEAD}"

# --------------------------------------------------------------------------- #
# Environment / preflight
# --------------------------------------------------------------------------- #

command -v git >/dev/null || die "git not found"
command -v go  >/dev/null || die "go not found"
REPO_ROOT="$(git rev-parse --show-toplevel)" || die "not a git repository"
cd "$REPO_ROOT"

BASE_SHA="$(git rev-parse --verify "${BASE_REF}^{commit}" 2>/dev/null)" || die "bad base ref: $BASE_REF"
HEAD_SHA="$(git rev-parse --verify "${HEAD_REF}^{commit}" 2>/dev/null)" || die "bad head ref: $HEAD_REF"
BASE_SHORT="$(git rev-parse --short "$BASE_SHA")"
HEAD_SHORT="$(git rev-parse --short "$HEAD_SHA")"

# A private scratch dir for worktrees, benchmark files, and report fragments.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/godzilla-qgate.XXXXXX")"
BASE_WT="$WORK/base"
HEAD_WT="$WORK/head"
BASE_ADDED=0
HEAD_ADDED=0
# shellcheck disable=SC2317  # invoked indirectly via the EXIT trap
cleanup() {
  if [[ $BASE_ADDED -eq 1 ]]; then git worktree remove --force "$BASE_WT" 2>/dev/null || true; fi
  if [[ $HEAD_ADDED -eq 1 ]]; then git worktree remove --force "$HEAD_WT" 2>/dev/null || true; fi
  git worktree prune 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

log() { echo "[qgate] $*" >&2; }

BENCHSTAT="$(command -v benchstat || echo "$(go env GOPATH)/bin/benchstat")"
HAVE_BENCHSTAT=0
[[ -x "$BENCHSTAT" ]] && HAVE_BENCHSTAT=1
HAVE_HYPERFINE=0
command -v hyperfine >/dev/null 2>&1 && HAVE_HYPERFINE=1

# Collected gate failures (human-readable reasons). Non-empty => hard fail.
GATE_FAILURES=()

# --------------------------------------------------------------------------- #
# Metric 1 — LOC modified (excluding tests)
# --------------------------------------------------------------------------- #

# numstat over product source only; drop binary rows ("-" counts). Emits
# "added removed path" lines.
loc_numstat() {
  git diff --numstat "$BASE_SHA" "$HEAD_SHA" -- "${LOC_INCLUDES[@]}" "${LOC_EXCLUDES[@]}" \
    | awk '$1 != "-" && $2 != "-"'
}

LOC_ADDED=0; LOC_REMOVED=0; LOC_FILES=0
declare -A LOC_DIR_ADDED LOC_DIR_REMOVED
compute_loc() {
  local a r path top
  while read -r a r path; do
    [[ -z "${path:-}" ]] && continue
    LOC_ADDED=$((LOC_ADDED + a))
    LOC_REMOVED=$((LOC_REMOVED + r))
    LOC_FILES=$((LOC_FILES + 1))
    top="${path%%/*}"
    LOC_DIR_ADDED[$top]=$(( ${LOC_DIR_ADDED[$top]:-0} + a ))
    LOC_DIR_REMOVED[$top]=$(( ${LOC_DIR_REMOVED[$top]:-0} + r ))
  done < <(loc_numstat)
  return 0
}

# --------------------------------------------------------------------------- #
# Metric 3 — rules added / modified
# --------------------------------------------------------------------------- #

# All rule IDs present in rulepacks/*.yaml at a given ref, sorted & unique.
rule_ids_at() {
  git grep -hE '^[[:space:]]*-[[:space:]]*id:[[:space:]]*' "$1" -- 'rulepacks/*.yaml' 2>/dev/null \
    | sed -E 's/.*id:[[:space:]]*//; s/[[:space:]]*$//; s/^["'"'"']//; s/["'"'"']$//' \
    | sort -u
}

RULES_ADDED=""; RULES_REMOVED=""; RULES_MODIFIED=""; PROPAGATORS_CHANGED=0
compute_rules() {
  local base_ids head_ids changed_files changed_ids
  base_ids="$(rule_ids_at "$BASE_SHA")"
  head_ids="$(rule_ids_at "$HEAD_SHA")"
  RULES_ADDED="$(comm -13 <(echo "$base_ids") <(echo "$head_ids") | grep -v '^$' || true)"
  RULES_REMOVED="$(comm -23 <(echo "$base_ids") <(echo "$head_ids") | grep -v '^$' || true)"
  # Modified = an ID present in BOTH refs that lives in a changed rulepack file.
  # (File granularity: for a multi-rule file, a change lists every ID in it.)
  changed_files="$(git diff --name-only "$BASE_SHA" "$HEAD_SHA" -- 'rulepacks/*.yaml' || true)"
  if [[ -n "$changed_files" ]]; then
    changed_ids="$(echo "$changed_files" | while read -r f; do
        [[ -z "$f" ]] && continue
        git show "$HEAD_SHA:$f" 2>/dev/null | sed -nE 's/^[[:space:]]*-[[:space:]]*id:[[:space:]]*//p'
      done | sed -E 's/[[:space:]]*$//; s/^["'"'"']//; s/["'"'"']$//' | sort -u)"
    local both
    both="$(comm -12 <(echo "$base_ids") <(echo "$head_ids"))"
    RULES_MODIFIED="$(comm -12 <(echo "$changed_ids") <(echo "$both") | grep -v '^$' || true)"
  fi
  if ! git diff --quiet "$BASE_SHA" "$HEAD_SHA" -- internal/rules/propagators.go; then
    PROPAGATORS_CHANGED=1
  fi
  return 0
}

# --------------------------------------------------------------------------- #
# Worktrees — materialize both revisions so each builds independently.
# --------------------------------------------------------------------------- #

setup_worktrees() {
  log "adding worktrees (base=$BASE_SHORT head=$HEAD_SHORT)"
  git worktree add --quiet --detach "$BASE_WT" "$BASE_SHA" || die "git worktree add base failed"
  BASE_ADDED=1
  git worktree add --quiet --detach "$HEAD_WT" "$HEAD_SHA" || die "git worktree add head failed"
  HEAD_ADDED=1
}

# --------------------------------------------------------------------------- #
# Metric 2 — corpus TP/FP/FN
# --------------------------------------------------------------------------- #

# Runs the scorer in a worktree and echoes "N TP FP FN precision recall F1",
# or "ERR" if the log line could not be parsed.
run_corpus() {
  local wt="$1" out line
  out="$(cd "$wt" && go test ./test/corpus/ -run TestCorpusSignalToNoise -count=1 -v 2>&1)" || true
  line="$(echo "$out" | grep -oE 'signal/noise over [0-9]+ samples: TP=[0-9]+ FP=[0-9]+ FN=[0-9]+ \| precision=[0-9.]+ recall=[0-9.]+ F1=[0-9.]+' | tail -1)"
  if [[ -z "$line" ]]; then echo "ERR"; return; fi
  echo "$line" | sed -E 's#signal/noise over ([0-9]+) samples: TP=([0-9]+) FP=([0-9]+) FN=([0-9]+) \| precision=([0-9.]+) recall=([0-9.]+) F1=([0-9.]+)#\1 \2 \3 \4 \5 \6 \7#'
}

CORPUS_BASE=""; CORPUS_HEAD=""
compute_corpus() {
  log "scoring corpus (base)"; CORPUS_BASE="$(run_corpus "$BASE_WT")"
  log "scoring corpus (head)"; CORPUS_HEAD="$(run_corpus "$HEAD_WT")"
  return 0
}

# --------------------------------------------------------------------------- #
# Metric 4a — Go hot-path benchmarks (benchstat)
# --------------------------------------------------------------------------- #

run_bench() { # wt outfile
  local wt="$1" out="$2"
  (cd "$wt" && go test -run '^$' -bench . -benchmem -count="$BENCH_COUNT" "${BENCH_PKGS[@]}") >"$out" 2>/dev/null
}

BENCH_TEXT=""; BENCH_STATUS="skipped"
compute_bench() {
  [[ $DO_BENCH -eq 1 ]] || { BENCH_STATUS="skipped (--no-bench)"; return; }
  if [[ $HAVE_BENCHSTAT -eq 0 ]]; then
    BENCH_STATUS="skipped (benchstat not installed: go install golang.org/x/perf/cmd/benchstat@latest)"
    return
  fi
  log "benchmarking (base, count=$BENCH_COUNT)"; run_bench "$BASE_WT" "$WORK/bench-base.txt" || { BENCH_STATUS="error running base benchmarks"; return; }
  log "benchmarking (head, count=$BENCH_COUNT)"; run_bench "$HEAD_WT" "$WORK/bench-head.txt" || { BENCH_STATUS="error running head benchmarks"; return; }
  BENCH_TEXT="$("$BENCHSTAT" "$WORK/bench-base.txt" "$WORK/bench-head.txt" 2>/dev/null || true)"
  BENCH_STATUS="ok"
  # Gate on TIME (sec/op) and MEMORY (B/op, allocs/op). Parse benchstat's CSV,
  # which prints one table per metric; flag a significant positive delta above the
  # metric's threshold on a key benchmark. benchstat prints "~" when the change is
  # not significant at alpha=0.05, so any numeric % is already significant.
  local csv
  csv="$("$BENCHSTAT" -format csv "$WORK/bench-base.txt" "$WORK/bench-head.txt" 2>/dev/null || true)"
  local key_re
  key_re="$(IFS='|'; echo "${KEY_BENCHMARKS[*]}")"
  while IFS= read -r reason; do
    [[ -n "$reason" ]] && GATE_FAILURES+=("perf(bench): $reason")
  done < <(echo "$csv" | awk -F',' -v tthr="$PERF_THRESHOLD" -v mthr="$MEM_THRESHOLD" -v keyre="$key_re" '
    /^,sec\/op,/    { metric="time";   unit="sec/op";    next }
    /^,B\/op,/      { metric="bytes";  unit="B/op";      next }
    /^,allocs\/op,/ { metric="allocs"; unit="allocs/op"; next }
    metric != "" && $1 != "" && $1 != "geomean" {
      name=$1; vs=$6;
      if (name !~ ("(" keyre ")")) next;
      if (vs ~ /^\+[0-9.]+%$/) {
        pct=vs; gsub(/[+%]/,"",pct);
        thr=(metric=="time") ? tthr : mthr;
        if (pct+0 > thr+0)
          printf "%s %s regressed %s (> %s%% threshold)\n", name, unit, vs, thr;
      }
    }')
  return 0
}

# --------------------------------------------------------------------------- #
# Metric 4b — full-pipeline wall clock (cross-language)
# --------------------------------------------------------------------------- #

# Median wall-clock seconds for `<bin> scan -quiet <sample>` over $RUNS runs.
# Prefers hyperfine; falls back to a portable bash timer.
median_scan_secs() { # bin sample
  local bin="$1" sample="$2"
  if [[ $HAVE_HYPERFINE -eq 1 ]]; then
    local json="$WORK/hf.json"
    hyperfine --warmup 2 --runs "$RUNS" --shell=none --ignore-failure \
      --export-json "$json" "$bin scan -quiet $sample" >/dev/null 2>&1 || { echo "ERR"; return; }
    jq -r '.results[0].median' "$json" 2>/dev/null || echo "ERR"
    return
  fi
  # Fallback: warm up once, then time $RUNS runs and take the median.
  "$bin" scan -quiet "$sample" >/dev/null 2>&1 || true
  local i start end times=()
  for ((i=0; i<RUNS; i++)); do
    start="$(date +%s.%N)"
    "$bin" scan -quiet "$sample" >/dev/null 2>&1 || true
    end="$(date +%s.%N)"
    times+=("$(awk -v s="$start" -v e="$end" 'BEGIN{printf "%.6f", e-s}')")
  done
  printf '%s\n' "${times[@]}" | sort -n \
    | awk '{a[NR]=$1} END{ if(NR==0){print "ERR"} else if(NR%2){print a[(NR+1)/2]} else {printf "%.6f",(a[NR/2]+a[NR/2+1])/2} }'
}

build_binary() { # wt outbin
  (cd "$1" && go build -o "$2" ./cmd/godzilla) || return 1
}

# Wall clock is INFORMATIONAL ONLY — it is too noisy on shared runners to gate on
# (JVM/rustc startup jitter alone can swing double digits). We report the median
# scan time per revision for context and do NOT compute a delta or trip the gate.
# Rows: "lang base_secs head_secs" or "lang SKIP <reason>".
WALL_ROWS=()
WALL_STATUS="ok"
compute_wall() {
  [[ $DO_WALL -eq 1 ]] || { WALL_STATUS="skipped (--no-wall)"; return; }
  local bin_base="$WORK/godzilla-base" bin_head="$WORK/godzilla-head"
  log "building binaries for wall-clock (informational)"
  build_binary "$BASE_WT" "$bin_base" || { WALL_STATUS="error building base binary"; return; }
  build_binary "$HEAD_WT" "$bin_head" || { WALL_STATUS="error building head binary"; return; }
  # Neutralize subprocess-frontend variance.
  unset GODZILLA_SPRING_E2E GODZILLA_RUST_E2E GODZILLA_ALLOW_BUILD GODZILLA_CVE_BENCH 2>/dev/null || true
  local lang tool sample b h
  for lang in "${PERF_LANGS[@]}"; do
    tool="${PERF_TOOL[$lang]:-}"
    if [[ -n "$tool" ]] && ! command -v "$tool" >/dev/null 2>&1; then
      WALL_ROWS+=("$lang SKIP toolchain-absent($tool)"); continue
    fi
    sample="test/$lang/command_injection"
    if [[ ! -e "$BASE_WT/$sample" || ! -e "$HEAD_WT/$sample" ]]; then
      WALL_ROWS+=("$lang SKIP sample-missing"); continue
    fi
    b="$(median_scan_secs "$bin_base" "$BASE_WT/$sample")"
    h="$(median_scan_secs "$bin_head" "$HEAD_WT/$sample")"
    if [[ "$b" == "ERR" || "$h" == "ERR" ]]; then
      WALL_ROWS+=("$lang SKIP timing-error"); continue
    fi
    WALL_ROWS+=("$lang $b $h")
  done
  return 0
}

# --------------------------------------------------------------------------- #
# Corpus gate (precision/recall must not regress)
# --------------------------------------------------------------------------- #

gate_corpus() {
  [[ "$CORPUS_BASE" == "ERR" || "$CORPUS_HEAD" == "ERR" ]] && return
  read -r _ _ fp_b _ _ _ _ <<<"$CORPUS_BASE"
  read -r _ tp_h fp_h fn_h _ _ _ <<<"$CORPUS_HEAD"
  read -r _ tp_b _ fn_b _ _ _ <<<"$CORPUS_BASE"
  (( fp_h > fp_b )) && GATE_FAILURES+=("corpus: FP increased ${fp_b} → ${fp_h} (precision regression)")
  # Recall dropped iff FN rose relative to the same true-positive universe.
  local recall_b recall_h
  recall_b="$(awk -v tp="$tp_b" -v fn="$fn_b" 'BEGIN{d=tp+fn; printf "%.4f", (d>0)?tp/d:1}')"
  recall_h="$(awk -v tp="$tp_h" -v fn="$fn_h" 'BEGIN{d=tp+fn; printf "%.4f", (d>0)?tp/d:1}')"
  awk -v a="$recall_h" -v b="$recall_b" 'BEGIN{exit !(a+0 < b+0-1e-9)}' \
    && GATE_FAILURES+=("corpus: recall dropped ${recall_b} → ${recall_h}")
  return 0
}

# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #

pass_fail_text() { [[ ${#GATE_FAILURES[@]} -eq 0 ]] && echo "✅ PASS" || echo "❌ FAIL"; }

emit_md() {
  echo "## 🛡️ Quality Gate — \`${BASE_SHORT}\`..\`${HEAD_SHORT}\`"
  echo
  if [[ $DO_GATE -eq 1 ]]; then
    echo "**Result: $(pass_fail_text)**"
  else
    echo "**Result: informational (\`--no-gate\`)**"
  fi
  if [[ ${#GATE_FAILURES[@]} -gt 0 ]]; then
    echo
    for f in "${GATE_FAILURES[@]}"; do echo "- ❌ $f"; done
  fi
  echo

  # --- Metric 1 --------------------------------------------------------------
  echo "### 1 · Lines changed (excluding tests)"
  echo
  echo "Net **+${LOC_ADDED} / −${LOC_REMOVED}** across **${LOC_FILES}** product-source file(s)."
  # Guard on LOC_FILES (an int), not ${#LOC_DIR_ADDED[@]}: reading the length of
  # an empty `declare -A` associative array trips `set -u` in bash.
  if [[ $LOC_FILES -gt 0 ]]; then
    echo
    echo "| Area | + | − |"
    echo "|---|--:|--:|"
    for d in $(printf '%s\n' "${!LOC_DIR_ADDED[@]}" | sort); do
      echo "| \`$d/\` | ${LOC_DIR_ADDED[$d]:-0} | ${LOC_DIR_REMOVED[$d]:-0} |"
    done
  fi
  echo
  echo "> Counts \`${LOC_INCLUDES[*]}\`; excludes \`*_test.go\`, \`testdata/\`, \`test/\`, generated \`*.pb.go\`."
  echo

  # --- Metric 2 --------------------------------------------------------------
  echo "### 2 · Corpus signal/noise (TP / FP / FN)"
  echo
  if [[ $DO_CORPUS -eq 0 ]]; then
    echo "_skipped (\`--no-corpus\`)._"
  elif [[ "$CORPUS_BASE" == "ERR" || "$CORPUS_HEAD" == "ERR" ]]; then
    echo "⚠️ Could not parse the scorer output on one side (base=\`${CORPUS_BASE}\`, head=\`${CORPUS_HEAD}\`)."
  else
    read -r n_b tp_b fp_b fn_b p_b r_b f_b <<<"$CORPUS_BASE"
    read -r n_h tp_h fp_h fn_h p_h r_h f_h <<<"$CORPUS_HEAD"
    echo "| Metric | Base | Head | Δ |"
    echo "|---|--:|--:|--:|"
    echo "| TP | $tp_b | $tp_h | $((tp_h - tp_b)) |"
    echo "| FP | $fp_b | $fp_h | $((fp_h - fp_b)) |"
    echo "| FN | $fn_b | $fn_h | $((fn_h - fn_b)) |"
    echo "| Precision | $p_b | $p_h | $(awk -v a="$p_b" -v b="$p_h" 'BEGIN{printf "%+.3f",b-a}') |"
    echo "| Recall | $r_b | $r_h | $(awk -v a="$r_b" -v b="$r_h" 'BEGIN{printf "%+.3f",b-a}') |"
    echo "| F1 | $f_b | $f_h | $(awk -v a="$f_b" -v b="$f_h" 'BEGIN{printf "%+.3f",b-a}') |"
    echo
    if [[ "$n_b" != "$n_h" ]]; then
      echo "> ⚠️ Sample count differs (base N=$n_b, head N=$n_h) — a toolchain/env drift; interpret deltas with care."
    else
      echo "> Scored over N=$n_b samples on both revisions."
    fi
  fi
  echo

  # --- Metric 3 --------------------------------------------------------------
  echo "### 3 · Rule changes"
  echo
  local none=1
  if [[ -n "$RULES_ADDED" ]];    then echo "- **Added:** $(echo "$RULES_ADDED" | paste -sd',' - | sed 's/,/, /g')"; none=0; fi
  if [[ -n "$RULES_REMOVED" ]];  then echo "- **Removed:** $(echo "$RULES_REMOVED" | paste -sd',' - | sed 's/,/, /g')"; none=0; fi
  if [[ -n "$RULES_MODIFIED" ]]; then echo "- **Modified:** $(echo "$RULES_MODIFIED" | paste -sd',' - | sed 's/,/, /g')"; none=0; fi
  if [[ $PROPAGATORS_CHANGED -eq 1 ]]; then
    echo "- **Default propagators** (\`internal/rules/propagators.go\`) changed — affects every rule."
    none=0
  fi
  [[ $none -eq 1 ]] && echo "_No rule additions, removals, or modifications._"
  echo

  # --- Metric 4 --------------------------------------------------------------
  echo "### 4 · Performance"
  echo
  echo "#### Go hot-path microbenchmarks — benchstat, count=${BENCH_COUNT} · **gated**"
  echo
  if [[ "$BENCH_STATUS" != "ok" ]]; then
    echo "_${BENCH_STATUS}._"
  else
    echo '```'
    echo "$BENCH_TEXT"
    echo '```'
    echo
    echo "> Gate blocks on a significant regression (benchstat marks noise as \`~\`) on: $(IFS=', '; echo "${KEY_BENCHMARKS[*]}") — time \`sec/op\` > ${PERF_THRESHOLD}%, memory \`B/op\`/\`allocs/op\` > ${MEM_THRESHOLD}%."
  fi
  echo
  echo "#### Full-pipeline scan wall-clock — median of ${RUNS} runs ($([[ $HAVE_HYPERFINE -eq 1 ]] && echo hyperfine || echo 'builtin timer')) · _informational_"
  echo
  if [[ "$WALL_STATUS" != "ok" ]]; then
    echo "_${WALL_STATUS}._"
  else
    echo "| Language | Base (s) | Head (s) |"
    echo "|---|--:|--:|"
    for row in "${WALL_ROWS[@]}"; do
      read -r lang c2 c3 <<<"$row"
      if [[ "$c2" == "SKIP" ]]; then
        echo "| $lang | — | _skip: ${c3}_ |"
      else
        printf '| %s | %.3f | %.3f |\n' "$lang" "$c2" "$c3"
      fi
    done
    echo
    echo "> Wall clock is reported for context only — too noisy on shared runners to gate on."
  fi
  echo
  echo "---"
  echo "_Both revisions were built and measured back-to-back on this runner; numbers are only comparable within a single run._"
}

json_str_array() { # newline-separated -> JSON array
  local items=() line
  while IFS= read -r line; do [[ -n "$line" ]] && items+=("\"$line\""); done <<<"$1"
  local IFS=,; echo "[${items[*]}]"
}

emit_json() {
  local corpus_json='null'
  if [[ "$CORPUS_BASE" != "ERR" && "$CORPUS_HEAD" != "ERR" && $DO_CORPUS -eq 1 ]]; then
    read -r n_b tp_b fp_b fn_b p_b r_b f_b <<<"$CORPUS_BASE"
    read -r n_h tp_h fp_h fn_h p_h r_h f_h <<<"$CORPUS_HEAD"
    corpus_json="{\"base\":{\"n\":$n_b,\"tp\":$tp_b,\"fp\":$fp_b,\"fn\":$fn_b,\"precision\":$p_b,\"recall\":$r_b,\"f1\":$f_b},\"head\":{\"n\":$n_h,\"tp\":$tp_h,\"fp\":$fp_h,\"fn\":$fn_h,\"precision\":$p_h,\"recall\":$r_h,\"f1\":$f_h}}"
  fi
  local wall_items=() row
  for row in "${WALL_ROWS[@]}"; do
    read -r lang c2 c3 <<<"$row"
    if [[ "$c2" == "SKIP" ]]; then
      wall_items+=("{\"lang\":\"$lang\",\"skipped\":\"$c3\"}")
    else
      wall_items+=("{\"lang\":\"$lang\",\"base_s\":$c2,\"head_s\":$c3}")
    fi
  done
  local wall_json; local IFS=,; wall_json="[${wall_items[*]}]"; unset IFS
  local pass=true; [[ ${#GATE_FAILURES[@]} -gt 0 && $DO_GATE -eq 1 ]] && pass=false
  local failures_json='[]'
  if [[ ${#GATE_FAILURES[@]} -gt 0 ]]; then
    local f_items=() f; for f in "${GATE_FAILURES[@]}"; do f_items+=("\"${f//\"/\\\"}\""); done
    local IFS=,; failures_json="[${f_items[*]}]"; unset IFS
  fi
  cat <<EOF
{
  "base": "$BASE_SHORT",
  "head": "$HEAD_SHORT",
  "gate": {"enabled": $([[ $DO_GATE -eq 1 ]] && echo true || echo false), "passed": $pass, "failures": $failures_json},
  "loc": {"added": $LOC_ADDED, "removed": $LOC_REMOVED, "files": $LOC_FILES},
  "corpus": $corpus_json,
  "rules": {
    "added": $(json_str_array "$RULES_ADDED"),
    "removed": $(json_str_array "$RULES_REMOVED"),
    "modified": $(json_str_array "$RULES_MODIFIED"),
    "propagators_changed": $([[ $PROPAGATORS_CHANGED -eq 1 ]] && echo true || echo false)
  },
  "perf": {"wall": $wall_json, "bench_status": "$BENCH_STATUS"}
}
EOF
}

# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

log "quality gate ${BASE_SHORT}..${HEAD_SHORT}"
compute_loc
compute_rules

if [[ $DO_CORPUS -eq 1 || $DO_BENCH -eq 1 || $DO_WALL -eq 1 ]]; then
  setup_worktrees
fi
[[ $DO_CORPUS -eq 1 ]] && compute_corpus
compute_bench
compute_wall
[[ $DO_CORPUS -eq 1 ]] && gate_corpus

REPORT=""
if [[ "$FORMAT" == json ]]; then
  REPORT="$(emit_json)"
else
  REPORT="$(emit_md)"
fi

if [[ -n "$OUTPUT" ]]; then
  echo "$REPORT" >"$OUTPUT"
  log "report written to $OUTPUT"
else
  echo "$REPORT"
fi

if [[ $DO_GATE -eq 1 && ${#GATE_FAILURES[@]} -gt 0 ]]; then
  log "gate FAILED: ${#GATE_FAILURES[@]} hard-gate trip(s)"
  exit 1
fi
log "gate passed"
exit 0
