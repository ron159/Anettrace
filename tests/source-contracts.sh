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

forbid_text() {
	local text="$1"
	local path="$2"

	if grep -Fq -- "$text" "$ROOT/$path"; then
		echo "forbidden source contract in $path: $text" >&2
		exit 1
	fi
}

require_text '.set = &bpf_args->uid_enabled' src/anettrace.c
require_text 'bpf_args->uid_enabled' src/trace.c
require_text 'pid_tgid = bpf_get_current_pid_tgid();' src/progs/tracing.c
require_text 'uid_gid = bpf_get_current_uid_gid();' src/progs/tracing.c
require_text 'e->tid = (u32)pid_tgid;' src/progs/tracing.c
require_text 'e->tgid = (u32)(pid_tgid >> 32);' src/progs/tracing.c
require_text 'm_config.uid_enabled && m_config.uid != e->uid' src/progs/tracing.c
require_text 'ANETTRACE_ANDROID_TARGET=1' src/Makefile
require_text 'Android tracing requires Linux 6.6 or newer' src/trace.c
require_text 'packet mark must remain the final field' src/progs/skb_shared.h
require_text 'pkt->mark = skb->mark;' src/progs/skb_parse.h
require_text 'pkt->l3.ipv4.id = bpf_ntohs(ipv4->id);' src/progs/skb_parse.h
require_text '--date and --timestamp cannot be used together' src/anettrace.c
require_text 'TIME_MODE_MONOTONIC' src/output.c
require_text '"/system/bin/date"' src/output.c
require_text 'id:0x%x' src/output.c
require_text 'mark:0x%x' src/output.c
require_text 'anettrace-0.4.0-android-arm64-tracing.tar.bz2' \
	.github/workflows/build-android-arm64.yml
forbid_text 'COMPAT=1' .github/workflows/c-cpp.yml

echo "source contracts: ok"
