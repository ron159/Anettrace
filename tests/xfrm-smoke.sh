#!/bin/sh
# SPDX-License-Identifier: MulanPSL-2.0
# Supplement the ordinary BPF smoke with isolated IPv4/IPv6 XFRM slow paths.
set -eu

BIN="${1:?usage: xfrm-smoke.sh BINARY OUTPUT_DIRECTORY WORKLOAD}"
OUT="${2:?usage: xfrm-smoke.sh BINARY OUTPUT_DIRECTORY WORKLOAD}"
WORKLOAD="${3:?usage: xfrm-smoke.sh BINARY OUTPUT_DIRECTORY WORKLOAD}"
TRACE_PID=""
WATCHDOG_PID=""

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

skip() {
    echo "SKIP: $*" >&2
    exit 77
}

cleanup() {
    if [ -n "$WATCHDOG_PID" ]; then
        kill "$WATCHDOG_PID" 2>/dev/null || true
        wait "$WATCHDOG_PID" 2>/dev/null || true
    fi
    if [ -n "$TRACE_PID" ]; then
        kill -KILL "$TRACE_PID" 2>/dev/null || true
        wait "$TRACE_PID" 2>/dev/null || true
    fi
}
trap cleanup 0
trap 'exit 130' INT TERM

[ "$(id -u)" = 0 ] || fail "run in a root shell"
[ -x "$BIN" ] || fail "binary is not executable: $BIN"
[ -x "$WORKLOAD" ] || fail "XFRM workload is not executable: $WORKLOAD"
[ -r /sys/kernel/btf/vmlinux ] || fail "kernel BTF is required"
for tool in awk grep ip readlink timeout unshare; do
    command -v "$tool" >/dev/null 2>&1 || skip "required environment tool is unavailable: $tool"
done
[ ! -e "$OUT" ] || fail "output directory already exists: $OUT"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"
case "$BIN" in
    /*) ;;
    *) BIN="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")" ;;
esac
case "$WORKLOAD" in
    /*) ;;
    *) WORKLOAD="$(cd "$(dirname "$WORKLOAD")" && pwd)/$(basename "$WORKLOAD")" ;;
esac
"$BIN" --version > "$OUT/version.txt" 2>&1
uname -a > "$OUT/kernel.txt"
PORT=$((50000 + $$ % 1000))
HOST_NETNS="$(readlink /proc/self/ns/net)"
[ -n "$HOST_NETNS" ] || fail "cannot identify the invoking network namespace"

# The kernel counts all same-name records, even when kallsyms hides addresses.
if [ -r /proc/kallsyms ]; then
    count="$(awk '$3 == "xfrm4_policy_check" { count++ } END { print count+0 }' /proc/kallsyms)"
    printf 'xfrm4_policy_check_records=%s\n' "$count" > "$OUT/ambiguity.txt"
    if [ "$count" -gt 1 ]; then
        result=0
        timeout -s KILL 20 "$BIN" --perfetto-events "$OUT/ambiguous.jsonl" \
            --trace xfrm4_policy_check --trace-detail --proto udp --port "$PORT" \
            --duration 1 > "$OUT/ambiguous.log" 2>&1 || result=$?
        [ "$result" != 124 ] && [ "$result" != 137 ] || \
            fail "explicit ambiguous probe check timed out; inspect $OUT/ambiguous.log"
        [ "$result" -ne 0 ] || fail "explicit duplicate xfrm4_policy_check unexpectedly succeeded"
        grep -q 'ambiguous symbol' "$OUT/ambiguous.log" || \
            fail "explicit duplicate probe failed without its ambiguity diagnostic"
        echo "PASS: explicit duplicate xfrm4_policy_check is rejected"
    else
        echo "NOT RUN: duplicate-name subcheck needs multiple xfrm4_policy_check records"
    fi
else
    echo "NOT RUN: /proc/kallsyms is unreadable for the duplicate-name subcheck"
fi

# The workload runs only in a new network namespace. Its socket policies
# disappear on close; no global policies or sysctls are changed.
# shellcheck disable=SC2016 # Expanded only by the isolated child shell.
NS_SETUP='
set -eu
parent_netns=$1
current_netns=$(readlink /proc/self/ns/net)
[ -n "$current_netns" ] && [ "$current_netns" != "$parent_netns" ] || {
    echo "network namespace isolation was not established" >&2
    exit 1
}
printf "namespace=%s\n" "$current_netns"
ip link set lo up
'

namespace_failure() {
    log="$1"
    # A failed datagram/payload check is a real regression, even if its errno
    # mentions a permission. Only namespace setup or policy capability can skip.
    if grep -q '^FAIL: family=' "$log" && \
        ! grep -Eq 'operation=(IP_XFRM_POLICY|IPV6_XFRM_POLICY) ' "$log"; then
        fail "XFRM socket workload failed; inspect $log"
    fi
    if grep -Eiq 'operation not permitted|permission denied|not supported|not implemented|protocol not available' "$log"; then
        reason="$(grep -Ei 'operation not permitted|permission denied|not supported|not implemented|protocol not available' "$log" | head -n 1)"
        skip "isolated XFRM environment rejected: $reason (see $log)"
    fi
    fail "isolated namespace setup/workload failed; inspect $log"
}

if ! timeout -s KILL 10 unshare -n sh -c "$NS_SETUP" sh "$HOST_NETNS" \
    > "$OUT/namespace-check.log" 2>&1; then
    namespace_failure "$OUT/namespace-check.log"
fi

LOG="$OUT/xfrm.log"
EVENTS="$OUT/xfrm.jsonl"
EXPIRED="$OUT/xfrm.timeout"
"$BIN" --perfetto-events "$EVENTS" --trace __xfrm_policy_check \
    --trace-detail --proto udp --port "$PORT" --duration 6 > "$LOG" 2>&1 &
TRACE_PID=$!
(
    remaining=60
    while [ "$remaining" -gt 0 ]; do
        sleep 1
        remaining=$((remaining - 1))
    done
    echo timeout > "$EXPIRED"
    kill -KILL "$TRACE_PID" 2>/dev/null || true
) &
WATCHDOG_PID=$!

ready=0
attempts=0
while kill -0 "$TRACE_PID" 2>/dev/null; do
    attempts=$((attempts + 1))
    [ "$attempts" -le 60 ] && [ ! -e "$EXPIRED" ] || break
    if grep -q 'begin trace' "$LOG"; then
        ready=1
        break
    fi
    grep -Eq 'ERROR:|failed to load|failed to attach' "$LOG" && break
    sleep 1
done
[ "$ready" = 1 ] || fail "XFRM trace never became ready; inspect $LOG"

# shellcheck disable=SC2016 # Expanded only by the isolated child shell.
NS_WORKLOAD='
exec "$3" "$2"
'
if ! timeout -s KILL 8 unshare -n sh -c "$NS_SETUP$NS_WORKLOAD" sh "$HOST_NETNS" "$PORT" "$WORKLOAD" \
    > "$OUT/workload.log" 2>&1; then
    namespace_failure "$OUT/workload.log"
fi

result=0
wait "$TRACE_PID" || result=$?
TRACE_PID=""
kill "$WATCHDOG_PID" 2>/dev/null || true
wait "$WATCHDOG_PID" 2>/dev/null || true
WATCHDOG_PID=""
[ ! -e "$EXPIRED" ] || fail "XFRM capture timed out; inspect $LOG"
[ "$result" = 0 ] || fail "XFRM capture exited $result; inspect $LOG"
if grep -Eq 'failed to (auto|manually) attach|failed to attach to tracepoint|tracepoint .* unavailable:' "$LOG"; then
    fail "XFRM capture has missing probe coverage; inspect $LOG"
fi
[ -s "$EVENTS" ] || fail "XFRM capture produced no events"

# All required fields must occur on the same actual packet_event. The shared
# policy slow path has no trusted TX/RX direction; preserve unknown explicitly.
if ! awk -v port="$PORT" '
    /"type":"packet_event"/ && /"stage":"__xfrm_policy_check"/ &&
    /"proto_l4":17([,}])/ && $0 ~ "\"dport\":" port "([,}])" {
        if ($0 !~ /"direction":"unknown"/) bad_direction++
        if (/"proto_l3":2048([,}])/ && /"saddr":"127\.0\.0\.1"/) v4++
        if (/"proto_l3":34525([,}])/ && /"saddr":"::1"/) v6++
    }
    END {
        printf "ipv4_policy_packets=%d ipv6_policy_packets=%d unexpected_direction=%d\n", v4, v6, bad_direction
        if (!v4 || !v6 || bad_direction) exit 1
    }
' "$EVENTS" > "$OUT/evidence.txt"; then
    cat "$OUT/evidence.txt" >&2
    fail "missing IPv4/IPv6 policy slow-path evidence; inspect $EVENTS"
fi
cat "$OUT/evidence.txt"
echo "XFRM IPv4/IPv6 slow-path smoke: PASS ($OUT)"
