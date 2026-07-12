#!/usr/bin/env bash
# Run Prometheus test packages under Delve, driven by the contexttrack client,
# producing one events/<pkg>.jsonl + <pkg>.log pair per package.
#
# Unlike run_tests.sh (Caddy), this splits work by *package*, not by individual
# test function: Prometheus has ~90 test packages (vs. Caddy's one integration
# package), and per-package dlv sessions keep startup/breakpoint-set overhead
# from dominating. All tests in a package share one dlv session and one output
# file; combine_outputs.sh doesn't care about that granularity.
#
# Usage: bash run_tests_prometheus.sh [--pkg-filter REGEX] [--test-filter REGEX]
#                                      [--jobs N] [--rebuild]
#                                      [--test-timeout DURATION] [--wall-timeout DURATION]
set -euo pipefail

PROM_DIR="${PROM_DIR:-/home/tcr6/prometheus-src}"
CONFTAMER_DIR="${CONFTAMER_DIR:-/home/tcr6/conftamer}"
OUTPUT_DIR="${OUTPUT_DIR:-${CONFTAMER_DIR}/contexttrack/events}"
BIN_DIR="${BIN_DIR:-/tmp/prom-dlv-$(id -un)}"
GO="${GO:-go}"
DLV="${DLV:-/home/tcr6/go/bin/dlv}"
CLIENT_BIN="${CLIENT_BIN:-/tmp/contexttrack-client-$(id -un)}"

JOBS=1
BASE_PORT=2345
PKG_FILTER='.*'
TEST_FILTER='.*'
FORCE_REBUILD=0
TEST_PARALLEL=1
TEST_TIMEOUT=900s
WALL_TIMEOUT=1020s # test-timeout + 120s grace; hard-kills a wedged dlv+test.

while [[ $# -gt 0 ]]; do
    case $1 in
        --base-port)     BASE_PORT="$2";     shift 2 ;;
        --pkg-filter)    PKG_FILTER="$2";    shift 2 ;;
        --test-filter)   TEST_FILTER="$2";   shift 2 ;;
        --jobs)          JOBS="$2";          shift 2 ;;
        --rebuild)       FORCE_REBUILD=1;    shift   ;;
        --test-parallel) TEST_PARALLEL="$2"; shift 2 ;;
        --test-timeout)  TEST_TIMEOUT="$2";  shift 2 ;;
        --wall-timeout)  WALL_TIMEOUT="$2";  shift 2 ;;
        *) echo "Unknown arg: $1" >&2; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR" "$BIN_DIR"

echo "==> Building delve client..."
( cd "$CONFTAMER_DIR" && "$GO" build -o "$CLIENT_BIN" ./contexttrack/client )

echo "==> Enumerating packages with tests under ${PROM_DIR} (pkg-filter: ${PKG_FILTER})..."
cd "$PROM_DIR"
mapfile -t PKGS < <(
    "$GO" list -f '{{if .TestGoFiles}}{{.ImportPath}}{{end}}' ./... \
        | grep -v '/vendor/' \
        | grep -E "$PKG_FILTER" || true
)
echo "    ${#PKGS[@]} packages match."
[[ ${#PKGS[@]} -gt 0 ]] || { echo "No packages matched; nothing to do."; exit 0; }

# Port slot locks: up to JOBS dlv instances run concurrently, each pinned to
# its own port for its whole run (claimed via flock, held on a bash-managed fd).
LOCK_DIR="${BIN_DIR}/locks"
rm -rf "$LOCK_DIR" # drop stale slots from a prior run with a different --base-port/--jobs
mkdir -p "$LOCK_DIR"
for ((i = 0; i < JOBS; i++)); do : >"${LOCK_DIR}/$((BASE_PORT + i))"; done

run_pkg() {
    local pkg="$1"
    local safe_name test_bin
    safe_name="$(echo "$pkg" | sed 's#[/.]#_#g')"
    test_bin="${BIN_DIR}/${safe_name}.test"

    if [[ $FORCE_REBUILD -eq 1 || ! -f "$test_bin" ]]; then
        if ! "$GO" test -c -gcflags="net/http=-l" -o "$test_bin" "$pkg" \
            2>"${OUTPUT_DIR}/${safe_name}.build.log"; then
            echo "[SKIP] ${pkg} (build failed, see ${safe_name}.build.log)"
            return
        fi
    fi
    # go test -c writes no binary for packages with no runnable tests.
    if [[ ! -f "$test_bin" ]]; then
        echo "[SKIP] ${pkg} (no test binary produced)"
        return
    fi

    # Claim a free port slot, holding the flock for the whole dlv run.
    local port lockfd
    while true; do
        local claimed=0
        for f in "${LOCK_DIR}"/*; do
            exec {lockfd}>"$f"
            if flock -n "$lockfd"; then
                port="$(basename "$f")"
                claimed=1
                break
            fi
            exec {lockfd}>&-
        done
        [[ $claimed -eq 1 ]] && break
        sleep 0.2
    done

    local logfile="${OUTPUT_DIR}/${safe_name}.log"
    local outfile="${OUTPUT_DIR}/${safe_name}.jsonl"
    : >"$logfile"

    timeout "$WALL_TIMEOUT" "$DLV" exec --headless "--listen=:${port}" --api-version=2 \
        --allow-non-terminal-interactive=true --accept-multiclient \
        "$test_bin" -- \
        -test.v -test.timeout "$TEST_TIMEOUT" -test.parallel "$TEST_PARALLEL" -test.run "$TEST_FILTER" \
        </dev/null >>"$logfile" 2>&1 &
    local dlv_pid=$!

    for _ in $(seq 300); do
        (echo >"/dev/tcp/127.0.0.1/${port}") 2>/dev/null && break
        sleep 0.05
    done

    "$CLIENT_BIN" --addr "localhost:${port}" --output "$outfile"
    wait "$dlv_pid" || true

    exec {lockfd}>&- # release the port slot

    # A compiled test binary run directly (not via `go test`) prints a bare
    # PASS/FAIL on its own last line, not the `go test` "ok  pkg  0.01s" wrapper.
    if grep -qE '^(PASS|FAIL)$' "$logfile"; then
        echo "[$(grep -E '^(PASS|FAIL)$' "$logfile" | tail -1)] ${pkg}"
    else
        echo "[????] ${pkg} (no result line found — check ${safe_name}.log)"
    fi
}

export -f run_pkg
export GO DLV CLIENT_BIN OUTPUT_DIR BIN_DIR LOCK_DIR FORCE_REBUILD TEST_FILTER TEST_TIMEOUT WALL_TIMEOUT TEST_PARALLEL

cleanup() {
    echo ""
    echo ">>> Interrupted — killing dlv/test processes..."
    pkill -f "dlv exec.*${BIN_DIR}" 2>/dev/null || true
    pkill -f "${CLIENT_BIN}" 2>/dev/null || true
    exit 1
}
trap cleanup INT TERM

START_TIME=$(date +%s)
printf '%s\n' "${PKGS[@]}" | xargs -P "$JOBS" -I{} bash -c 'run_pkg "$@"' _ {}
ELAPSED=$(($(date +%s) - START_TIME))

echo ""
echo "Elapsed: ${ELAPSED}s ($((ELAPSED / 60))m$((ELAPSED % 60))s). Events: ${OUTPUT_DIR}/"
echo "    $(ls "${OUTPUT_DIR}"/*.jsonl 2>/dev/null | wc -l) event files written."
