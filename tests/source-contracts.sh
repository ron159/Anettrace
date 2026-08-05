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

require_text '.set = &bpf_args->uid_enabled' src/nettrace.c
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
require_text '--date and --timestamp cannot be used together' src/nettrace.c
require_text 'TIME_MODE_MONOTONIC' src/output.c
require_text '"/system/bin/date"' src/output.c
require_text 'id:0x%x' src/output.c
require_text 'mark:0x%x' src/output.c
require_text 'bpf_program__attach_kprobe' src/trace_probe.c
require_text 'progs/kprobe' src/Makefile
require_text 'anettrace-0.4.0-android-arm64-dual.tar.bz2' \
	.github/workflows/build-android-arm64.yml

echo "source contracts: ok"
