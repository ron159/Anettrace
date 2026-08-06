#!/usr/bin/env bash
# SPDX-License-Identifier: MulanPSL-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

require_text() {
	local text="$1"
	local path="$2"

	if ! grep -Fq -- "$text" "$ROOT/$path"; then
		echo "missing source contract in $path: $text" >&2
		exit 1
	fi
}

require_text '.set = &bpf_args->uid_enabled' src/anettrace.c
require_text 'bpf_args->uid_enabled' src/trace.c
require_text 'pid_tgid = bpf_get_current_pid_tgid();' src/progs/core.c
require_text 'u32 uid = (u32)bpf_get_current_uid_gid();' src/progs/core.c
require_text 'e->tid = tid;' src/progs/core.c
require_text 'args->uid_enabled && args->uid != uid' src/progs/core.c
require_text '.tid = (u32)bpf_get_current_pid_tgid()' src/progs/kprobe.c
require_text 'e->event.tid' src/trace_probe.c
require_text 'ANETTRACE_ANDROID_TARGET=1' common.mk
require_text 'packet mark must remain the final field' src/progs/skb_shared.h
require_text 'pkt->mark = _C(skb, mark);' src/progs/skb_parse.h
require_text 'pkt->l3.ipv4.id = bpf_ntohs(_C(ipv4, id));' src/progs/skb_parse.h
require_text '--date and --timestamp cannot be used together' src/anettrace.c
require_text 'TIME_MODE_MONOTONIC' src/output.c
require_text '"/system/bin/date"' src/output.c
require_text 'id:0x%x' src/output.c
require_text 'mark:0x%x' src/output.c
require_text 'bpf_program__attach_kprobe' src/trace_probe.c
require_text 'progs/kprobe' src/Makefile
require_text '.lname = "traffic"' src/anettrace.c
require_text '.lname = "interval"' src/anettrace.c
require_text 'progs/traffic' src/Makefile
require_text 'SEC("kprobe/tcp_sendmsg")' src/progs/traffic.c
require_text 'SEC("kretprobe/tcp_recvmsg")' src/progs/traffic.c
require_text 'SEC("kprobe/udp_sendmsg")' src/progs/traffic.c
require_text 'SEC("kprobe/udpv6_recvmsg")' src/progs/traffic.c
require_text 'BPF_MAP_TYPE_LRU_HASH' src/progs/traffic.c
require_text '(s32)PT_REGS_RC(ctx)' src/progs/traffic.c
require_text 'TX_KB' src/traffic.c
require_text 'LADDR:PORT' src/traffic.c
require_text 'traffic_print_snapshot' src/traffic.c
require_text '.lname = "perfetto-events"' src/anettrace.c
require_text 'bool perfetto;' src/progs/shared.h
require_text 'SEC("kprobe/sk_alloc")' src/progs/core.c
require_text 'DEFINE_TP_SK(inet_sock_set_state' src/progs/core.c
require_text 'perfetto_export_event(data, cpu, size);' src/trace.c
require_text '\"type\":\"packet_event\"' src/perfetto_export.c
require_text '\"skb_id\":' src/perfetto_export.c
require_text '--uid 0 is too broad for Perfetto capture' src/trace.c
require_text '--uid 0 alone is too broad; add --pid' \
	tools/capture_android_trace.py
require_text 'sched/sched_switch' tools/capture_android_trace.py
require_text 'sched/sched_waking' tools/capture_android_trace.py
require_text 'android.surfaceflinger.frametimeline' tools/capture_android_trace.py
require_text 'simpleperf' tools/capture_android_trace.py
require_text 'session-manifest.json' tools/capture_android_trace.py
require_text 'capture_android_trace.py' tools/capture_android_perfetto.sh
require_text 'perfetto==0.57.2' tools/requirements-perfetto.txt
require_text 'anettrace-0.4.0-android-arm64-dual.tar.bz2' \
	.github/workflows/build-android-arm64.yml

echo "source contracts: ok"
