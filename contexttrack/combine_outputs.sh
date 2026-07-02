#!/usr/bin/env bash
# Combine per-test output files into a single events.jsonl and tests.log.
# Usage: bash combine_outputs.sh [OUTPUT_DIR]
set -euo pipefail

OUTPUT_DIR="${1:-$(dirname "$0")/events}"
EVENTS_OUT="${OUTPUT_DIR}/events.jsonl"
TESTS_OUT="${OUTPUT_DIR}/tests.log"

if [[ ! -d "$OUTPUT_DIR" ]]; then
    echo "Error: output directory not found: ${OUTPUT_DIR}" >&2
    exit 1
fi

# Combine all per-test .jsonl files into one, preserving newlines between files.
echo "==> Combining event files into ${EVENTS_OUT}..."
: > "$EVENTS_OUT"
count=0
for f in "${OUTPUT_DIR}"/*.jsonl; do
    [[ "$f" == "$EVENTS_OUT" ]] && continue
    [[ -s "$f" ]] || continue
    cat "$f" >> "$EVENTS_OUT"
    (( count++ )) || true
done
echo "    ${count} event files merged ($(wc -l < "$EVENTS_OUT") total events)."

# Combine all per-test .log files into one, with a header per test.
echo "==> Combining log files into ${TESTS_OUT}..."
: > "$TESTS_OUT"
nlog=0
for f in "${OUTPUT_DIR}"/*.log; do
    [[ "$f" == "$TESTS_OUT" ]] && continue
    test_name="$(basename "$f" .log)"
    printf '=%.0s' {1..72} >> "$TESTS_OUT"
    printf '\n=== %s\n' "$test_name" >> "$TESTS_OUT"
    printf '=%.0s' {1..72} >> "$TESTS_OUT"
    printf '\n' >> "$TESTS_OUT"
    cat "$f" >> "$TESTS_OUT"
    printf '\n' >> "$TESTS_OUT"
    (( nlog++ )) || true
done
echo "    ${nlog} log files merged."
