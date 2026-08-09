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
require_text $'\t\t} ipv4;\n#ifndef NT_DISABLE_IPV6\n\t\tstruct {' \
	src/progs/skb_shared.h
require_text $'\t\t} ipv4;\n#if 0\n\t\tstruct {' src/progs/skb_shared.h
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
require_text 'owner_socket_key' src/progs/shared.h
require_text 'PACKET_DIRECTION_RX' src/progs/shared.h
require_text 'FUNC_STATUS_RX' src/progs/shared.h
require_text 'FUNC_STATUS_TX' src/progs/shared.h
require_text 'm_perfetto_socket_owner' src/progs/core.c
require_text 'm_perfetto_flow_owner' src/progs/core.c
require_text 'm_perfetto_scratch' src/progs/core.c
require_text 'pkt->l4.min.sport == bpf_htons(53)' src/progs/core.c
require_text 'pkt->l4.min.dport == bpf_htons(53)' src/progs/core.c
require_text 'SEC("kprobe/sk_alloc")' src/progs/core.c
require_text 'DEFINE_TP_SK(inet_sock_set_state' src/progs/core.c
require_text 'perfetto_export_event(data, cpu, size);' src/trace.c
require_text '\"type\":\"packet_event\"' src/perfetto_export.c
require_text 'format_packet_flow_label(flow_id, pkt, flow_tag, sizeof(flow_tag));' \
	src/perfetto_export.c
require_text 'flow->display_index = ++tcp_flow_count;' src/perfetto_export.c
require_text 'flow->display_index = ++dns_flow_count;' src/perfetto_export.c
require_text 'flow->display_index = ++udp_flow_count;' src/perfetto_export.c
require_text 'native_annotation_string(&track_event, "stage", trace->name);' \
	src/perfetto_export.c
require_text 'native_event_correlation(&track_event, flow_id);' \
	src/perfetto_export.c
require_text '"rx_read_start"' src/perfetto_export.c
require_text '"rx_read_end"' src/perfetto_export.c
require_text '"tx_write_start"' src/perfetto_export.c
require_text '"tx_write_end"' src/perfetto_export.c
require_text '"anettrace.rx.read"' src/perfetto_export.c
require_text '"anettrace.flow"' src/perfetto_export.c
require_text '"idle_timeout"' src/perfetto_export.c
require_text 'flow->tx_bytes += bytes;' src/perfetto_export.c
require_text 'flow->rx_bytes += bytes;' src/perfetto_export.c
require_text 'if (flows[capacity].closed)' src/perfetto_export.c
require_text 'flow->closed = !strcmp(reason, "tcp_close");' \
	src/perfetto_export.c
require_text 'ipv6_is_v4_mapped' src/perfetto_export.c
require_text 'pending_io_find_logical' src/perfetto_export.c
require_text '!strcmp(trace->name, "ip_output")' src/perfetto_export.c
require_text 'sock->proto_l3 != ETH_P_IP' src/perfetto_export.c
require_text 'if ((args->pid || args->uid_enabled) && !current_matches' \
	src/progs/core.c
require_text '\"skb_id\":' src/perfetto_export.c
require_text 'CLOCK_SNAPSHOT_INTERVAL_NS' src/perfetto_export.c
require_text 'perfetto_export_tick();' src/trace.c
require_text '.lname = "capture-trace"' src/anettrace.c
require_text '.lname = "trace-profile"' src/anettrace.c
require_text 'trace_args->trace_profile = "full"' src/anettrace.c
require_text '.lname = "duration"' src/anettrace.c
require_text '.lname = "output"' src/anettrace.c
require_text 'perfetto_export_native_open' src/anettrace.c
require_text 'Trace.packet' src/perfetto_export.c
require_text 'trace_capture_finish' src/anettrace.c
require_text 'sched/sched_switch' src/trace_capture.c
require_text 'atrace_apps: \"*\"' src/trace_capture.c
require_text 'atrace_categories: \"binder_driver\"' src/trace_capture.c
require_text 'atrace_categories: \"ftrace_print\"' src/trace_capture.c
require_text 'ftrace_events: \"ftrace/print\"' src/trace_capture.c
require_text 'android.surfaceflinger.frametimeline' src/trace_capture.c
require_text 'android.statsd' src/trace_capture.c
require_text 'tcp_rcv_established' src/trace.c
require_text 'udp_recvmsg,udpv6_recvmsg' src/trace.c
require_text 'udp_send_skb:0' src/trace.yaml
require_text 'udp_v6_send_skb:0' src/trace.yaml
require_text 'tcp_sendmsg/0' src/trace.yaml
require_text 'udp_sendmsg/0' src/trace.yaml
require_text 'udpv6_sendmsg/0' src/trace.yaml
require_text 'perfetto_poll_handler(ctx, cpu, data, size);' src/trace.c
require_text 'trace && trace_using_sk(trace)' src/analysis.c
require_text 'packet.timestamp_clock_id = CLOCK_MONOTONIC' \
	tools/anettrace_to_perfetto.py
require_text 'packet_record["flow_tag"] = self.flow_label' \
	tools/anettrace_to_perfetto.py
require_text 'track_event.correlation_id = correlation_id' \
	tools/anettrace_to_perfetto.py
require_text '--uid 0 is too broad for Perfetto capture' src/trace.c
require_text '--uid 0 alone is too broad; add --pid' \
	tools/capture_android_trace.py
require_text 'sched/sched_switch' tools/capture_android_trace.py
require_text 'sched/sched_waking' tools/capture_android_trace.py
require_text 'android.surfaceflinger.frametimeline' tools/capture_android_trace.py
require_text 'simpleperf' tools/capture_android_trace.py
require_text 'session-manifest.json' tools/capture_android_trace.py
require_text 'merge_trace_with_anettrace.py' tools/capture_android_trace.py
require_text 'clock_sync_failure_no_path' \
	tools/perfetto_sql/anettrace_integrity.sql
require_text 'raw_native_tracepacket_concat' \
	tools/merge_trace_with_anettrace.py
require_text 'capture_android_trace.py' tools/capture_android_perfetto.sh
require_text 'perfetto==0.57.2' tools/requirements-perfetto.txt
require_text 'anettrace-0.4.0-android-arm64-dual.tar.bz2' \
	.github/workflows/build-android-arm64.yml

echo "source contracts: ok"
