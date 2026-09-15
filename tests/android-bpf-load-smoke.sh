#!/system/bin/sh
# Load the shipped BPF programs on the target kernel, then prove ip_output ran.
# Run through a root shell. Logs survive failures for verifier diagnosis.
set -eu

BIN="${1:?usage: android-bpf-load-smoke.sh BINARY OUTPUT_DIRECTORY}"
OUT="${2:?usage: android-bpf-load-smoke.sh BINARY OUTPUT_DIRECTORY}"
TRACE_PID=""
WATCHDOG_PID=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

cleanup() {
    [ -z "$WATCHDOG_PID" ] || kill "$WATCHDOG_PID" 2>/dev/null || true
    [ -z "$TRACE_PID" ] || kill "$TRACE_PID" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

[ "$(id -u)" = 0 ] || fail "run in a root shell"
[ -x "$BIN" ] || fail "binary is not executable: $BIN"
[ -r /sys/kernel/btf/vmlinux ] || fail "kernel BTF is required"
command -v nc >/dev/null 2>&1 || fail "nc is required to generate UDP"
# Refuse reuse: an old success marker or event must never satisfy this run.
[ ! -e "$OUT" ] || fail "output directory already exists: $OUT"
mkdir -p "$OUT"
"$BIN" --version > "$OUT/version.txt" 2>&1
uname -a > "$OUT/kernel.txt"
printf 'anettrace-bpf-stack-smoke\n' > "$OUT/payload.txt"
PORT=$((49000 + $$ % 1000))

run_profile() {
    profile="$1"
    shift
    log="$OUT/$profile.log"
    events="$OUT/$profile.jsonl"
    expired="$OUT/$profile.timeout"
    "$BIN" --perfetto-events "$events" --duration 5 --uid 0 --port "$PORT" \
        --libbpf-debug "$@" > "$log" 2>&1 &
    TRACE_PID=$!
    (
        remaining=60
        while [ "$remaining" -gt 0 ]; do
            sleep 1
            remaining=$((remaining - 1))
        done
        echo timeout > "$expired"
        kill -KILL "$TRACE_PID" 2>/dev/null || true
    ) &
    WATCHDOG_PID=$!

    ready=0
    attempts=0
    while kill -0 "$TRACE_PID" 2>/dev/null; do
        attempts=$((attempts + 1))
        [ "$attempts" -le 65 ] || break
        [ ! -e "$expired" ] || break
        # mksh may keep an exited background child visible until wait.
        grep -q "ERROR:.*failed to load" "$log" && break
        if grep -q 'begin trace' "$log"; then
            ready=1
            break
        fi
        sleep 1
    done
    if [ "$ready" = 1 ]; then
        # Sending to an unused loopback port still traverses IPv4 ip_output.
        # nc may report the subsequent ICMP rejection; the trace is the proof.
        timeout -s KILL 2 nc -u -w 1 127.0.0.1 "$PORT" < "$OUT/payload.txt" \
            > "$OUT/$profile-workload.log" 2>&1 || true
    fi
    result=0
    wait "$TRACE_PID" || result=$?
    TRACE_PID=""
    kill "$WATCHDOG_PID" 2>/dev/null || true
    wait "$WATCHDOG_PID" 2>/dev/null || true
    WATCHDOG_PID=""
    [ ! -e "$expired" ] || fail "$profile timed out; inspect $log"
    [ "$result" = 0 ] || fail "$profile exited $result; inspect $log"
    [ "$ready" = 1 ] || fail "$profile never became ready; inspect $log"
    # Loading succeeds even when a tracepoint attach is rejected. That is a
    # coverage failure, not a successful smoke test (e.g. short TP contexts).
    if grep -Eq 'failed to (auto|manually) attach|failed to attach to tracepoint|tracepoint .* unavailable:' "$log"; then
        fail "$profile has missing probe coverage; inspect $log"
    fi
    [ -s "$events" ] || fail "$profile produced no event file"
    if [ "$profile" = compact ]; then
        stage='UDP packet send'
    else
        stage='ip_output'
    fi
    # Require all fields on the same packet, not unrelated lines in the log.
    grep '"type":"packet_event"' "$events" | grep '"proto_l4":17' | \
        grep "\"dport\":$PORT" | grep "\"stage\":\"$stage\"" >/dev/null || \
        fail "$profile did not capture the test UDP packet at ip_output"
    echo "PASS: $profile BPF load and IPv4 UDP ip_output"
}

run_profile compact
run_profile detailed --trace-detail
echo "Android BPF load smoke: PASS ($OUT)"
