#!/usr/bin/env bash
# Run caddy integration tests in parallel under delve, one per network namespace.
# Requires: sudo unshare (add to sudoers: ALL=(root) NOPASSWD: /usr/bin/unshare)
# Usage: bash run_tests.sh [--filter PATTERN] [--jobs N] [--rebuild] [--test-timeout DURATION]
set -euo pipefail

CADDY_DIR=/home/tcr6/caddy
CONFTAMER_DIR=/home/tcr6/conftamer
OUTPUT_DIR="${CONFTAMER_DIR}/contexttrack/events"
TEST_BIN=/tmp/integration-$(id -un).test
CLIENT_BIN=/tmp/contexttrack-client-$(id -un)
GO=/usr/lib/go-1.22/bin/go
DLV=/home/tcr6/go/bin/dlv
JOBS=$(nproc)
FILTER='.*'
FORCE_REBUILD=0
TEST_TIMEOUT=300s
WALL_TIMEOUT=360s   # hard kill if dlv+test don't finish (TEST_TIMEOUT + 60s grace)

while [[ $# -gt 0 ]]; do
    case $1 in
        --filter)       FILTER="$2";       shift 2 ;;
        --jobs)         JOBS="$2";         shift 2 ;;
        --rebuild)      FORCE_REBUILD=1;   shift   ;;
        --test-timeout) TEST_TIMEOUT="$2"; shift 2 ;;
        --wall-timeout) WALL_TIMEOUT="$2"; shift 2 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

# build

# Skip rebuilding if the binaries are newer than their sources.
# Pass --rebuild to force a fresh build.

needs_rebuild() {
    local bin="$1"; shift
    [[ $FORCE_REBUILD -eq 1 ]] && return 0
    [[ ! -f "$bin" ]] && return 0
    # If any source file is newer than the binary, rebuild.
    find "$@" -newer "$bin" -name '*.go' | grep -q . && return 0
    return 1
}

if needs_rebuild "$CLIENT_BIN" "$CONFTAMER_DIR/contexttrack"; then
    echo "==> Building delve client..."
    cd "$CONFTAMER_DIR"
    $GO build -o "$CLIENT_BIN" ./contexttrack/client
else
    echo "==> Delve client up to date, skipping build."
fi

if needs_rebuild "$TEST_BIN" "$CADDY_DIR/caddytest/integration" "$CADDY_DIR/caddytest"; then
    echo "==> Compiling test binary (this is the slow step)..."
    cd "$CADDY_DIR"
    $GO test -c -gcflags="net/http=-l" -o "$TEST_BIN" ./caddytest/integration/
else
    echo "==> Test binary up to date, skipping compile."
fi

echo "==> Listing tests matching '${FILTER}'..."
TESTS=$("$TEST_BIN" -test.list "$FILTER" 2>/dev/null | grep '^Test' || true)
N=$(echo "$TESTS" | wc -l)
echo "    Found ${N} tests, running ${JOBS} in parallel."

mkdir -p "$OUTPUT_DIR"

# per-test runner

run_one() {
    local test="$1"
    local logfile="${OUTPUT_DIR}/${test}.log"
    local outfile="${OUTPUT_DIR}/${test}.jsonl"

    # Wall-clock timeout: kills dlv+test unconditionally if they don't finish.
    # -test.timeout alone isn't reliable under dlv because the Go timer goroutines
    # are paused whenever dlv stops the process at a breakpoint.
    timeout "${WALL_TIMEOUT}" sudo unshare --net bash -c "
        set -euo pipefail
        # Redirect all stderr inside this shell to logfile
        exec 2>>'${logfile}'
        ip link set lo up

        # Run from the integration test package directory
        cd '${CADDY_DIR}/caddytest/integration'

        # Give each test its own Caddy storage directory so that parallel tests
        # don't contend on the shared bbolt ACME database or the internal CA
        # cert files under ~/.local/share/caddy.
        export XDG_DATA_HOME=\$(mktemp -d)
        trap 'rm -rf \"\$XDG_DATA_HOME\"' EXIT

        # Start delve in the background inside this namespace.
        # --accept-multiclient: prevents dlv from exiting if TCP readiness
        # probe (echo > /dev/tcp) opens and immediately closes a connection.
        # Redirect stdin from /dev/null so delve doesn't exit when xargs closes the pipe.
        '${DLV}' exec --headless --listen=:2345 --api-version=2 \
            --allow-non-terminal-interactive=true \
            --accept-multiclient \
            '${TEST_BIN}' -- \
            -test.v -test.timeout '${TEST_TIMEOUT}' -test.run '^${test}\$' \
            < /dev/null >> '${logfile}' 2>&1 &
        DLV_PID=\$!

        # Wait until delve's RPC port is accepting connections.
        for i in \$(seq 300); do
            (echo > /dev/tcp/127.0.0.1/2345) 2>/dev/null && break
            sleep 0.05
        done

        # Run the delve client; it drives the test to completion.
        '${CLIENT_BIN}' --addr localhost:2345 --output '${outfile}'

        wait \$DLV_PID || true
    "

    if grep -q "^--- PASS: ${test}" "${logfile}" 2>/dev/null; then
        echo "[PASS] ${test}"
    elif grep -q "^--- FAIL: ${test}" "${logfile}" 2>/dev/null; then
        echo "[FAIL] ${test}"
    else
        echo "[????] ${test} (no result found in log)"
    fi
}

export -f run_one
export TEST_BIN CLIENT_BIN OUTPUT_DIR DLV TEST_TIMEOUT WALL_TIMEOUT CADDY_DIR

cleanup() {
    echo ""
    echo ">>> Interrupted — killing all test processes..."
    kill "$XARGS_PID" 2>/dev/null || true
    sudo pkill -f 'dlv exec' 2>/dev/null || true
    sudo pkill -f "$(basename "$TEST_BIN")" 2>/dev/null || true
    sudo pkill -f "$(basename "$CLIENT_BIN")" 2>/dev/null || true
    exit 1
}
trap cleanup INT TERM

START_TIME=$(date +%s)

# Print elapsed time every 60 seconds
progress_ticker() {
    while kill -0 "$1" 2>/dev/null; do
        sleep 60
        kill -0 "$1" 2>/dev/null || break
        elapsed=$(( $(date +%s) - START_TIME ))
        printf ">>> [%dm%02ds elapsed]\n" $(( elapsed / 60 )) $(( elapsed % 60 ))
    done
}

echo "$TESTS" | xargs -P "$JOBS" -I{} bash -c 'run_one "$@"' _ {} &
XARGS_PID=$!
progress_ticker $XARGS_PID &
TICKER_PID=$!
wait $XARGS_PID
kill $TICKER_PID 2>/dev/null; wait $TICKER_PID 2>/dev/null

ELAPSED=$(( $(date +%s) - START_TIME ))
echo ""
echo "Elapsed: ${ELAPSED}s ($(( ELAPSED / 60 ))m$(( ELAPSED % 60 ))s). Events: ${OUTPUT_DIR}/"
echo "    $(ls "${OUTPUT_DIR}"/*.jsonl 2>/dev/null | wc -l) event files written."
