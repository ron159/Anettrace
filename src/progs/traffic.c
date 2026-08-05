// SPDX-License-Identifier: MulanPSL-2.0

#include <kheaders.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "skb_macro.h"
#include "traffic_shared.h"

const volatile traffic_config_t traffic_config = {};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, traffic_inflight_key_t);
	__type(value, traffic_flow_key_t);
} traffic_inflight SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, TRAFFIC_MAX_FLOWS);
	__type(key, traffic_flow_key_t);
	__type(value, traffic_flow_value_t);
} traffic_flows SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, TRAFFIC_STAT_MAX);
	__type(key, u32);
	__type(value, u64);
} traffic_stats SEC(".maps");

static __always_inline void traffic_stat_inc(u32 index)
{
	u64 *value = bpf_map_lookup_elem(&traffic_stats, &index);

	if (value)
		__sync_fetch_and_add(value, 1);
}

static __always_inline int traffic_fill_key(struct sock *sk, u8 protocol,
					     u16 expected_family,
					     traffic_flow_key_t *key)
{
	struct sock_common *common = (void *)sk;
	struct inet_sock *inet = (void *)sk;
	struct in6_addr address = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 uid = (u32)bpf_get_current_uid_gid();

	if (!sk)
		return -1;
	if (traffic_config.protocol && traffic_config.protocol != protocol)
		return -1;
	if (traffic_config.tid && traffic_config.tid != (u32)pid_tgid)
		return -1;
	if (traffic_config.uid_enabled && traffic_config.uid != uid)
		return -1;

	key->tgid = (u32)(pid_tgid >> 32);
	key->tid = (u32)pid_tgid;
	key->protocol = protocol;
	key->family = BPF_CORE_READ(common, skc_family);
	if (expected_family && key->family != expected_family)
		return -1;
	key->lport = BPF_CORE_READ(common, skc_num);
	if (!key->lport)
		key->lport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	key->rport = bpf_ntohs(BPF_CORE_READ(common, skc_dport));
	bpf_get_current_comm(key->comm, sizeof(key->comm));

	switch (key->family) {
	case AF_INET:
		key->laddr.v4 = BPF_CORE_READ(common, skc_rcv_saddr);
		key->raddr.v4 = BPF_CORE_READ(common, skc_daddr);
		break;
	case AF_INET6:
		BPF_CORE_READ_INTO(&address, common, skc_v6_rcv_saddr);
		__builtin_memcpy(key->laddr.v6, &address, sizeof(address));
		BPF_CORE_READ_INTO(&address, common, skc_v6_daddr);
		__builtin_memcpy(key->raddr.v6, &address, sizeof(address));
		break;
	default:
		return -1;
	}

	return 0;
}

static __always_inline int traffic_enter(struct sock *sk, u8 protocol,
					  u16 expected_family, u32 operation)
{
	traffic_inflight_key_t inflight_key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.operation = operation,
	};
	traffic_flow_key_t flow = {};

	if (traffic_fill_key(sk, protocol, expected_family, &flow))
		return 0;
	if (bpf_map_update_elem(&traffic_inflight, &inflight_key, &flow,
				BPF_ANY))
		traffic_stat_inc(TRAFFIC_STAT_INFLIGHT_DROP);
	return 0;
}

static __always_inline void traffic_account(const traffic_flow_key_t *flow,
					     u64 bytes, bool tx)
{
	traffic_flow_value_t zero = {
		.last_seen_ns = bpf_ktime_get_ns(),
	};
	traffic_flow_value_t *value;

	value = bpf_map_lookup_elem(&traffic_flows, flow);
	if (!value) {
		bpf_map_update_elem(&traffic_flows, flow, &zero, BPF_NOEXIST);
		value = bpf_map_lookup_elem(&traffic_flows, flow);
	}
	if (!value) {
		traffic_stat_inc(TRAFFIC_STAT_FLOW_DROP);
		return;
	}

	if (tx)
		__sync_fetch_and_add(&value->tx_bytes, bytes);
	else
		__sync_fetch_and_add(&value->rx_bytes, bytes);
	value->last_seen_ns = bpf_ktime_get_ns();
}

static __always_inline int traffic_exit(struct pt_regs *ctx, u32 operation,
					 bool tx)
{
	traffic_inflight_key_t inflight_key = {
		.pid_tgid = bpf_get_current_pid_tgid(),
		.operation = operation,
	};
	traffic_flow_key_t *stored, flow = {};
	/*
	 * These sendmsg/recvmsg helpers return int. On arm64, a negative
	 * 32-bit return value can be observed zero-extended in the return
	 * register, so cast to the declared return type before testing it.
	 */
	s32 bytes = (s32)PT_REGS_RC(ctx);

	stored = bpf_map_lookup_elem(&traffic_inflight, &inflight_key);
	if (!stored)
		return 0;
	__builtin_memcpy(&flow, stored, sizeof(flow));
	bpf_map_delete_elem(&traffic_inflight, &inflight_key);
	if (bytes > 0)
		traffic_account(&flow, (u64)bytes, tx);
	return 0;
}

SEC("kprobe/tcp_sendmsg")
int traffic_tcp_send_entry(struct pt_regs *ctx)
{
	return traffic_enter((void *)PT_REGS_PARM1(ctx), IPPROTO_TCP, 0,
			     TRAFFIC_OP_TCP_TX);
}

SEC("kretprobe/tcp_sendmsg")
int traffic_tcp_send_exit(struct pt_regs *ctx)
{
	return traffic_exit(ctx, TRAFFIC_OP_TCP_TX, true);
}

SEC("kprobe/tcp_recvmsg")
int traffic_tcp_recv_entry(struct pt_regs *ctx)
{
	return traffic_enter((void *)PT_REGS_PARM1(ctx), IPPROTO_TCP, 0,
			     TRAFFIC_OP_TCP_RX);
}

SEC("kretprobe/tcp_recvmsg")
int traffic_tcp_recv_exit(struct pt_regs *ctx)
{
	return traffic_exit(ctx, TRAFFIC_OP_TCP_RX, false);
}

SEC("kprobe/udp_sendmsg")
int traffic_udp4_send_entry(struct pt_regs *ctx)
{
	return traffic_enter((void *)PT_REGS_PARM1(ctx), IPPROTO_UDP, AF_INET,
			     TRAFFIC_OP_UDP4_TX);
}

SEC("kretprobe/udp_sendmsg")
int traffic_udp4_send_exit(struct pt_regs *ctx)
{
	return traffic_exit(ctx, TRAFFIC_OP_UDP4_TX, true);
}

SEC("kprobe/udp_recvmsg")
int traffic_udp4_recv_entry(struct pt_regs *ctx)
{
	return traffic_enter((void *)PT_REGS_PARM1(ctx), IPPROTO_UDP, AF_INET,
			     TRAFFIC_OP_UDP4_RX);
}

SEC("kretprobe/udp_recvmsg")
int traffic_udp4_recv_exit(struct pt_regs *ctx)
{
	return traffic_exit(ctx, TRAFFIC_OP_UDP4_RX, false);
}

SEC("kprobe/udpv6_sendmsg")
int traffic_udp6_send_entry(struct pt_regs *ctx)
{
	return traffic_enter((void *)PT_REGS_PARM1(ctx), IPPROTO_UDP, AF_INET6,
			     TRAFFIC_OP_UDP6_TX);
}

SEC("kretprobe/udpv6_sendmsg")
int traffic_udp6_send_exit(struct pt_regs *ctx)
{
	return traffic_exit(ctx, TRAFFIC_OP_UDP6_TX, true);
}

SEC("kprobe/udpv6_recvmsg")
int traffic_udp6_recv_entry(struct pt_regs *ctx)
{
	return traffic_enter((void *)PT_REGS_PARM1(ctx), IPPROTO_UDP, AF_INET6,
			     TRAFFIC_OP_UDP6_RX);
}

SEC("kretprobe/udpv6_recvmsg")
int traffic_udp6_recv_exit(struct pt_regs *ctx)
{
	return traffic_exit(ctx, TRAFFIC_OP_UDP6_RX, false);
}

char LICENSE[] SEC("license") = "GPL";
