#!/system/bin/sh
# SPDX-License-Identifier: MulanPSL-2.0

set -eu

BIN="${1:-./anettrace}"
OUT="${2:-/data/local/tmp/anettrace-smoke}"
TRACE_PID=""
WATCHDOG_PID=""
PING_TARGET=""

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

cleanup() {
	[ -z "$TRACE_PID" ] || kill "$TRACE_PID" 2>/dev/null || true
	[ -z "$WATCHDOG_PID" ] || kill "$WATCHDOG_PID" 2>/dev/null || true
}

trap cleanup EXIT INT TERM

[ "$(id -u)" = "0" ] || fail "run as root"
[ -x "$BIN" ] || fail "binary is not executable: $BIN"
[ -r /sys/kernel/btf/vmlinux ] || fail "missing readable /sys/kernel/btf/vmlinux"
mkdir -p "$OUT"

PING_TARGET="$(ip route get 1.1.1.1 2>/dev/null | awk '
	{
		for (i = 1; i <= NF; i++) {
			if ($i == "src") {
				print $(i + 1)
				exit
			}
		}
	}')"
[ -n "$PING_TARGET" ] || fail "unable to determine a local IPv4 address"

"$BIN" --version | tee "$OUT/version.txt"
"$BIN" -h > "$OUT/help.txt"

if "$BIN" --date --timestamp > "$OUT/conflict.txt" 2>&1; then
	fail "--date and --timestamp unexpectedly succeeded together"
fi
grep -q -- '--date and --timestamp cannot be used together' \
	"$OUT/conflict.txt" || fail "missing conflicting time option error"

"$BIN" -t '?' --debug > "$OUT/capabilities.txt" 2>&1 ||
	fail "capability probe failed"

run_icmp_trace() {
	name="$1"
	shift
	log="$OUT/$name.txt"

	"$BIN" --basic -t ip_rcv -p icmp --uid 0 -c 2 "$@" > "$log" 2>&1 &
	TRACE_PID=$!
	(
		sleep 15
		kill "$TRACE_PID" 2>/dev/null || true
	) &
	WATCHDOG_PID=$!
	sleep 1
	if ! ping -c 2 "$PING_TARGET" >/dev/null 2>&1; then
		fail "unable to generate local ICMP traffic via $PING_TARGET"
	fi
	if ! wait "$TRACE_PID"; then
		TRACE_PID=""
		kill "$WATCHDOG_PID" 2>/dev/null || true
		WATCHDOG_PID=""
		fail "$name trace failed or timed out; inspect $log"
	fi
	TRACE_PID=""
	kill "$WATCHDOG_PID" 2>/dev/null || true
	wait "$WATCHDOG_PID" 2>/dev/null || true
	WATCHDOG_PID=""
}

run_icmp_trace local --detail --id --mark
grep -Eq '^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}\]' "$OUT/local.txt" ||
	fail "default local time format missing"
grep -q 'uid:0' "$OUT/local.txt" || fail "UID 0 output missing"
grep -q 'id:0x' "$OUT/local.txt" || fail "IPv4 ID output missing"
grep -q 'mark:0x' "$OUT/local.txt" || fail "skb mark output missing"

run_icmp_trace date --date
grep -Eq '^\[[0-9]{4}-[0-9]{2}-[0-9]{2} ' "$OUT/date.txt" ||
	fail "date format missing"

run_icmp_trace timestamp --timestamp
grep -Eq '^\[[0-9]+\.[0-9]{6}\]' "$OUT/timestamp.txt" ||
	fail "monotonic timestamp format missing"

echo "Android KPROBE smoke test: PASS ($OUT)"
