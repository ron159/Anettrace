#!/usr/bin/env bash
# SPDX-License-Identifier: MulanPSL-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ANETTRACE_BIN="$ROOT/src/anettrace"
TARGET_UID=""
TARGET_PID=""
DURATION=10
OUTPUT_DIR="$ROOT/output/perfetto-capture"
DEVICE=""
TRACE_PID=""
PERFETTO_PID=""
REMOTE_BASE="/data/local/tmp/anettrace-perfetto-$$"
REMOTE_BIN="$REMOTE_BASE/anettrace"
REMOTE_EVENTS="$REMOTE_BASE/anettrace-events.jsonl"
REMOTE_LOG="$REMOTE_BASE/anettrace.log"
REMOTE_CONFIG="/data/misc/perfetto-configs/anettrace-perfetto-$$.pbtxt"
REMOTE_SYSTEM_TRACE="/data/misc/perfetto-traces/anettrace-perfetto-$$.pftrace"
LOCAL_TMP=""

usage() {
	cat <<'EOF'
Usage: tools/capture_android_perfetto.sh (--uid UID | --pid TID) [options]

Options:
  --uid UID          Trace events first matched in this Android UID.
  --pid TID          Trace events first matched in this thread ID.
  --duration SEC     Capture duration in seconds (default: 10).
  --out DIR          Output directory (default: output/perfetto-capture).
  --anettrace PATH   Android arm64 Anettrace binary (default: src/anettrace).
  --device SERIAL    adb device serial.
  -h, --help         Show this help.

The capture contains socket/packet metadata and scheduler state only. It does
not contain packet payload bytes.
EOF
}

fail() {
	echo "error: $*" >&2
	exit 1
}

adb_cmd() {
	if [[ -n "$DEVICE" ]]; then
		adb -s "$DEVICE" "$@"
	else
		adb "$@"
	fi
}

cleanup() {
	if [[ -n "$TRACE_PID" ]]; then
		adb_cmd shell "kill -INT $TRACE_PID" >/dev/null 2>&1 || true
	fi
	if [[ -n "$PERFETTO_PID" ]]; then
		adb_cmd shell "kill -TERM $PERFETTO_PID" >/dev/null 2>&1 || true
	fi
	adb_cmd shell "rm -rf '$REMOTE_BASE'" >/dev/null 2>&1 || true
	adb_cmd shell "rm -f '$REMOTE_CONFIG'" >/dev/null 2>&1 || true
	adb_cmd shell "rm -f '$REMOTE_SYSTEM_TRACE'" >/dev/null 2>&1 || true
	if [[ -n "$LOCAL_TMP" && -d "$LOCAL_TMP" ]]; then
		rm -rf "$LOCAL_TMP"
	fi
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--uid)
		[[ $# -ge 2 ]] || fail "--uid needs a value"
		TARGET_UID="$2"
		shift 2
		;;
	--pid)
		[[ $# -ge 2 ]] || fail "--pid needs a value"
		TARGET_PID="$2"
		shift 2
		;;
	--duration)
		[[ $# -ge 2 ]] || fail "--duration needs a value"
		DURATION="$2"
		shift 2
		;;
	--out)
		[[ $# -ge 2 ]] || fail "--out needs a value"
		OUTPUT_DIR="$2"
		shift 2
		;;
	--anettrace)
		[[ $# -ge 2 ]] || fail "--anettrace needs a value"
		ANETTRACE_BIN="$2"
		shift 2
		;;
	--device)
		[[ $# -ge 2 ]] || fail "--device needs a value"
		DEVICE="$2"
		shift 2
		;;
	-h | --help)
		usage
		exit 0
		;;
	*)
		fail "unknown argument: $1"
		;;
	esac
done

[[ -n "$TARGET_UID" || -n "$TARGET_PID" ]] ||
	fail "specify --uid or --pid to bound the capture"
[[ "$TARGET_UID" =~ ^[0-9]+$ || -z "$TARGET_UID" ]] || fail "invalid UID"
[[ "$TARGET_PID" =~ ^[0-9]+$ || -z "$TARGET_PID" ]] || fail "invalid TID"
[[ -z "$TARGET_UID" || "$TARGET_UID" != "0" ]] ||
	fail "--uid 0 is too broad for this helper; use --pid"
[[ -z "$TARGET_PID" || "$TARGET_PID" != "0" ]] || fail "TID must be greater than zero"
[[ "$DURATION" =~ ^[1-9][0-9]*$ ]] || fail "duration must be a positive integer"
[[ -x "$ANETTRACE_BIN" ]] || fail "Anettrace binary is not executable: $ANETTRACE_BIN"
command -v adb >/dev/null || fail "adb is not installed"
adb_cmd get-state | grep -q '^device$' || fail "Android device is not ready"
[[ "$(adb_cmd shell id -u | tr -d '\r')" == "0" ]] || fail "adb shell must be root"

mkdir -p "$OUTPUT_DIR"
OUTPUT_DIR="$(cd "$OUTPUT_DIR" && pwd)"
LOCAL_TMP="$(mktemp -d)"
LOCAL_CONFIG="$LOCAL_TMP/perfetto.pbtxt"
trap cleanup EXIT INT TERM

cat >"$LOCAL_CONFIG" <<EOF
buffers: {
  size_kb: 32768
  fill_policy: RING_BUFFER
}
data_sources: {
  config {
    name: "linux.ftrace"
    target_buffer: 0
    ftrace_config {
      ftrace_events: "sched/sched_switch"
      ftrace_events: "sched/sched_waking"
      ftrace_events: "sched/sched_process_exec"
      ftrace_events: "sched/sched_process_exit"
      ftrace_events: "power/suspend_resume"
      compact_sched { enabled: true }
    }
  }
}
data_sources: {
  config {
    name: "linux.process_stats"
    target_buffer: 0
    process_stats_config {
      scan_all_processes_on_start: true
      proc_stats_poll_ms: 1000
    }
  }
}
duration_ms: $((DURATION * 1000))
EOF

adb_cmd shell "mkdir -p '$REMOTE_BASE'"
adb_cmd push "$ANETTRACE_BIN" "$REMOTE_BIN" >/dev/null
adb_cmd push "$LOCAL_CONFIG" "$REMOTE_CONFIG" >/dev/null
adb_cmd shell "chmod 0755 '$REMOTE_BIN'"

FILTER_ARGS=""
if [[ -n "$TARGET_UID" ]]; then
	FILTER_ARGS="$FILTER_ARGS --uid $TARGET_UID"
fi
if [[ -n "$TARGET_PID" ]]; then
	FILTER_ARGS="$FILTER_ARGS --pid $TARGET_PID"
fi

TRACE_PID="$(adb_cmd shell \
	"'$REMOTE_BIN' --perfetto-events '$REMOTE_EVENTS'$FILTER_ARGS -v >'$REMOTE_LOG' 2>&1 & echo \$!" \
	| tr -d '\r')"
[[ "$TRACE_PID" =~ ^[0-9]+$ ]] || fail "failed to start Anettrace: $TRACE_PID"

PERFETTO_PID="$(adb_cmd shell perfetto --background-wait --txt \
	-c "$REMOTE_CONFIG" -o "$REMOTE_SYSTEM_TRACE" | tr -d '\r')"
[[ "$PERFETTO_PID" =~ ^[0-9]+$ ]] || fail "failed to start Perfetto: $PERFETTO_PID"

echo "capturing for ${DURATION}s (Anettrace pid=$TRACE_PID, Perfetto pid=$PERFETTO_PID)"
sleep "$DURATION"
sleep 1
adb_cmd shell "kill -INT $TRACE_PID" >/dev/null 2>&1 || true
for _ in $(seq 1 50); do
	if ! adb_cmd shell "kill -0 $TRACE_PID" >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
if adb_cmd shell "kill -0 $TRACE_PID" >/dev/null 2>&1; then
	fail "Anettrace did not stop after SIGINT"
fi
TRACE_PID=""

for _ in $(seq 1 30); do
	if adb_cmd shell "test -s '$REMOTE_EVENTS' && test -s '$REMOTE_SYSTEM_TRACE'"; then
		break
	fi
	sleep 0.2
done

adb_cmd pull "$REMOTE_EVENTS" "$OUTPUT_DIR/anettrace-events.jsonl" >/dev/null
adb_cmd pull "$REMOTE_SYSTEM_TRACE" "$OUTPUT_DIR/system.pftrace" >/dev/null
adb_cmd pull "$REMOTE_LOG" "$OUTPUT_DIR/anettrace.log" >/dev/null
[[ -s "$OUTPUT_DIR/anettrace-events.jsonl" ]] || fail "empty Anettrace event file"
[[ -s "$OUTPUT_DIR/system.pftrace" ]] || fail "empty system Perfetto trace"

if python3 -c 'import perfetto' >/dev/null 2>&1; then
	python3 "$ROOT/tools/anettrace_to_perfetto.py" \
		"$OUTPUT_DIR/anettrace-events.jsonl" "$OUTPUT_DIR/anettrace.pftrace"
elif command -v uv >/dev/null; then
	uv run --with perfetto==0.57.2 python "$ROOT/tools/anettrace_to_perfetto.py" \
		"$OUTPUT_DIR/anettrace-events.jsonl" "$OUTPUT_DIR/anettrace.pftrace"
else
	fail "install perfetto==0.57.2 or uv to run the converter"
fi

cat "$OUTPUT_DIR/system.pftrace" "$OUTPUT_DIR/anettrace.pftrace" \
	>"$OUTPUT_DIR/anettrace-combined.pftrace"

echo "wrote $OUTPUT_DIR/anettrace-combined.pftrace"
echo "open it at https://ui.perfetto.dev"
