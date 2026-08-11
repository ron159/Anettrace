#!/system/bin/sh
# SPDX-License-Identifier: MulanPSL-2.0

set -eu

BIN="${1:-./anettrace}"
OUT="${2:-/data/local/tmp/anettrace-smoke}"
TRACE_PID=""
WATCHDOG_PID=""
PING_TARGET=""
SERVER_PID=""

fail() {
	echo "FAIL: $*" >&2
	exit 1
}

cleanup() {
	[ -z "$TRACE_PID" ] || kill "$TRACE_PID" 2>/dev/null || true
	[ -z "$WATCHDOG_PID" ] || kill "$WATCHDOG_PID" 2>/dev/null || true
	[ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
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
grep -q -- '--trace-detail' "$OUT/help.txt" || fail "--trace-detail help missing"
for section in \
	"Packet and owner filters" \
	"Analysis modes" \
	"Trace capture and export" \
	"Event display" \
	"Advanced trace controls" \
	"Diagnostics and general"; do
	grep -q "^${section}:$" "$OUT/help.txt" ||
		fail "help section missing: $section"
done

if "$BIN" --trace-detail > "$OUT/trace-detail-invalid.txt" 2>&1; then
	fail "--trace-detail unexpectedly succeeded without trace export"
fi
grep -q -- '--trace-detail requires --capture-trace or --perfetto-events' \
	"$OUT/trace-detail-invalid.txt" || fail "missing --trace-detail scope error"

if "$BIN" --traffic --capture-trace > "$OUT/traffic-trace-conflict.txt" 2>&1; then
	fail "standalone --traffic unexpectedly combined with trace capture"
fi
grep -q -- '--traffic is standalone' "$OUT/traffic-trace-conflict.txt" ||
	fail "missing standalone traffic error"

if "$BIN" --capture-trace --trace tcp > "$OUT/capture-trace-conflict.txt" 2>&1; then
	fail "standalone --capture-trace unexpectedly combined with --trace"
fi
grep -q -- '--capture-trace and --trace are standalone' \
	"$OUT/capture-trace-conflict.txt" || fail "missing standalone capture error"

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

run_tcp_traffic_report() {
	name="$1"
	shift
	log="$OUT/$name.txt"
	port=$((46000 + $$ % 1000))

	"$BIN" --traffic --interval 1 -c 4 --uid 0 "$@" > "$log" 2>&1 &
	TRACE_PID=$!
	(
		sleep 20
		kill "$TRACE_PID" 2>/dev/null || true
	) &
	WATCHDOG_PID=$!
	sleep 1
	nc -l -s "$PING_TARGET" -p "$port" >/dev/null 2>&1 &
	SERVER_PID=$!
	sleep 1
	if ! dd if=/dev/zero bs=1024 count=8 2>/dev/null |
		nc -w 3 "$PING_TARGET" "$port" >/dev/null 2>&1; then
		fail "unable to generate local TCP traffic"
	fi
	wait "$SERVER_PID" 2>/dev/null || true
	SERVER_PID=""
	if ! wait "$TRACE_PID"; then
		TRACE_PID=""
		kill "$WATCHDOG_PID" 2>/dev/null || true
		WATCHDOG_PID=""
		fail "$name traffic report failed or timed out; inspect $log"
	fi
	TRACE_PID=""
	kill "$WATCHDOG_PID" 2>/dev/null || true
	wait "$WATCHDOG_PID" 2>/dev/null || true
	WATCHDOG_PID=""
}

run_tcp_traffic_report traffic-all
grep -q 'Traffic TCP/UDP' "$OUT/traffic-all.txt" ||
	fail "whole-device traffic heading missing"
grep -q 'PID.*TID.*COMM.*LADDR:PORT.*RADDR:PORT.*APP_TX_KB.*APP_RX_KB' \
	"$OUT/traffic-all.txt" || fail "traffic columns missing"
grep -q ' TCP ' "$OUT/traffic-all.txt" || fail "TCP flow row missing"
grep -q "$PING_TARGET" "$OUT/traffic-all.txt" ||
	fail "traffic endpoint missing"
awk '
	/ (TCP|UDP) [46] / {
		seen = 1
		if ($(NF - 1) > 1048576 || $NF > 1048576)
			exit 1
	}
	END { if (!seen) exit 2 }
' "$OUT/traffic-all.txt" || fail "implausible traffic byte count"

run_tcp_traffic_report traffic-tcp --proto tcp
grep -q 'Traffic TCP ' "$OUT/traffic-tcp.txt" ||
	fail "TCP protocol filter heading missing"
grep -q ' TCP ' "$OUT/traffic-tcp.txt" ||
	fail "TCP protocol filter produced no flow rows"

echo "Android KPROBE smoke test: PASS ($OUT)"
