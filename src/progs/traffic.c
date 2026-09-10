// SPDX-License-Identifier: MulanPSL-2.0

#include <kheaders.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "skb_macro.h"
#include "traffic_shared.h"

const volatile traffic_config_t traffic_config = {};

struct traffic_inflight_value {
	traffic_flow_key_t flow;
	struct sock *sk;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, traffic_inflight_key_t);
	__type(value, struct traffic_inflight_value);
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
	bpf_get_current_comm(key->comm, sizeof(key->comm));
	if (protocol == IPPROTO_UDP) {
		/* An unconnected socket does not hold the datagram's endpoints. */
		key->flags = TRAFFIC_ENDPOINT_UNKNOWN;
		return 0;
	}
	key->lport = BPF_CORE_READ(common, skc_num);
	if (!key->lport)
		key->lport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
	key->rport = bpf_ntohs(BPF_CORE_READ(common, skc_dport));

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
	struct traffic_inflight_value value = { .sk = sk };

	if (traffic_fill_key(sk, protocol, expected_family, &value.flow))
		return 0;
	if (bpf_map_update_elem(&traffic_inflight, &inflight_key, &value,
				BPF_ANY))
		traffic_stat_inc(TRAFFIC_STAT_INFLIGHT_DROP);
	return 0;
}

static __always_inline traffic_flow_key_t *traffic_udp_flow(struct sock *sk,
							  bool tx)
{
	traffic_inflight_key_t key = { .pid_tgid = bpf_get_current_pid_tgid() };
	struct traffic_inflight_value *value;
	u16 family;

	if (!sk)
		return NULL;
	if (traffic_config.tid && traffic_config.tid != (u32)key.pid_tgid)
		return NULL;
	if (traffic_config.uid_enabled &&
	    traffic_config.uid != (u32)bpf_get_current_uid_gid())
		return NULL;
	family = BPF_CORE_READ(sk, __sk_common.skc_family);
	if (family == AF_INET)
		key.operation = tx ? TRAFFIC_OP_UDP4_TX : TRAFFIC_OP_UDP4_RX;
	else if (family == AF_INET6)
		key.operation = tx ? TRAFFIC_OP_UDP6_TX : TRAFFIC_OP_UDP6_RX;
	else
		return NULL;
	value = bpf_map_lookup_elem(&traffic_inflight, &key);
	if (!value || value->sk != sk)
		return NULL;
	return &value->flow;
}

/* IP/UDP headers are not yet constructed at the send_skb entry probes.
 * The route's flowi already contains the selected source and destination.
 */
SEC("kprobe/udp_send_skb")
int traffic_udp4_endpoints(struct pt_regs *ctx)
{
	struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
	struct flowi4 *route = (void *)PT_REGS_PARM2(ctx);
	traffic_flow_key_t *stored, flow;
	struct { u16 dest, source; } ports;

	stored = traffic_udp_flow(BPF_CORE_READ(skb, sk), true);
	if (!stored)
		return 0;
	flow = *stored;
	/* Also normalize IPv4-mapped IPv6 sockets to the wire family. */
	__builtin_memset(&flow.laddr, 0, sizeof(flow.laddr));
	__builtin_memset(&flow.raddr, 0, sizeof(flow.raddr));
	if (BPF_CORE_READ_INTO(&flow.laddr.v4, route, saddr) ||
	    BPF_CORE_READ_INTO(&flow.raddr.v4, route, daddr) ||
	    BPF_CORE_READ_INTO(&ports, route, uli.ports))
		return 0;
	flow.family = AF_INET;
	flow.lport = bpf_ntohs(ports.source);
	flow.rport = bpf_ntohs(ports.dest);
	flow.flags = 0;
	*stored = flow;
	return 0;
}

SEC("kprobe/udp_v6_send_skb")
int traffic_udp6_endpoints(struct pt_regs *ctx)
{
	struct sk_buff *skb = (void *)PT_REGS_PARM1(ctx);
	struct flowi6 *route = (void *)PT_REGS_PARM2(ctx);
	traffic_flow_key_t *stored, flow;
	struct { u16 dest, source; } ports;

	stored = traffic_udp_flow(BPF_CORE_READ(skb, sk), true);
	if (!stored)
		return 0;
	flow = *stored;
	if (BPF_CORE_READ_INTO(&flow.laddr.v6, route, saddr) ||
	    BPF_CORE_READ_INTO(&flow.raddr.v6, route, daddr) ||
	    BPF_CORE_READ_INTO(&ports, route, uli.ports))
		return 0;
	flow.family = AF_INET6;
	flow.lport = bpf_ntohs(ports.source);
	flow.rport = bpf_ntohs(ports.dest);
	flow.flags = 0;
	*stored = flow;
	return 0;
}

/* Runs before the successfully received skb is released, including recv()
 * with no msg_name and MSG_PEEK. Accounting still uses recvmsg's return value.
 */
SEC("kprobe/skb_consume_udp")
int traffic_udp_receive_endpoints(struct pt_regs *ctx)
{
	struct sock *sk = (void *)PT_REGS_PARM1(ctx);
	struct sk_buff *skb = (void *)PT_REGS_PARM2(ctx);
	traffic_flow_key_t *stored, flow;
	struct udphdr udp;
	unsigned char *head, *network;
	u16 network_offset, transport_offset;
	u8 version;

	stored = traffic_udp_flow(sk, false);
	if (!stored)
		return 0;
	if (BPF_CORE_READ_INTO(&head, skb, head) ||
	    BPF_CORE_READ_INTO(&network_offset, skb, network_header) ||
	    BPF_CORE_READ_INTO(&transport_offset, skb, transport_header))
		return 0;
	network = head + network_offset;
	if (bpf_probe_read_kernel(&version, sizeof(version), network) ||
	    bpf_probe_read_kernel(&udp, sizeof(udp), head + transport_offset))
		return 0;
	flow = *stored;
	if ((version >> 4) == 4) {
		struct iphdr ip;

		if (bpf_probe_read_kernel(&ip, sizeof(ip), network))
			return 0;
		__builtin_memset(&flow.laddr, 0, sizeof(flow.laddr));
		__builtin_memset(&flow.raddr, 0, sizeof(flow.raddr));
		flow.family = AF_INET;
		flow.laddr.v4 = ip.daddr;
		flow.raddr.v4 = ip.saddr;
	} else if ((version >> 4) == 6) {
		struct ipv6hdr ip;

		if (bpf_probe_read_kernel(&ip, sizeof(ip), network))
			return 0;
		flow.family = AF_INET6;
		__builtin_memcpy(flow.laddr.v6, &ip.daddr, sizeof(ip.daddr));
		__builtin_memcpy(flow.raddr.v6, &ip.saddr, sizeof(ip.saddr));
	} else {
		return 0;
	}
	flow.lport = bpf_ntohs(udp.dest);
	flow.rport = bpf_ntohs(udp.source);
	flow.flags = 0;
	*stored = flow;
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
	struct traffic_inflight_value *stored;
	traffic_flow_key_t flow = {};
	/*
	 * These sendmsg/recvmsg helpers return int. On arm64, a negative
	 * 32-bit return value can be observed zero-extended in the return
	 * register, so cast to the declared return type before testing it.
	 */
	s32 bytes = (s32)PT_REGS_RC(ctx);

	stored = bpf_map_lookup_elem(&traffic_inflight, &inflight_key);
	if (!stored)
		return 0;
	__builtin_memcpy(&flow, &stored->flow, sizeof(flow));
	bpf_map_delete_elem(&traffic_inflight, &inflight_key);
	if (bytes > 0) {
		if (flow.flags & TRAFFIC_ENDPOINT_UNKNOWN)
			traffic_stat_inc(TRAFFIC_STAT_UDP_ENDPOINT_MISS);
		traffic_account(&flow, (u64)bytes, tx);
	}
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
