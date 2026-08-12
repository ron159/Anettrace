#define KBUILD_MODNAME ""
#include <kheaders.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "skb_parse.h"
#include "shared.h"
#include "core.h"

#ifdef KERN_VER
__u32 kern_ver SEC("version") = KERN_VER;
#endif

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(int));
	__uint(max_entries, 1024);
} m_ret SEC(".maps");

#ifdef __F_STACK_TRACE
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 16384);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(stack_trace_t));
} m_stack SEC(".maps");
#endif

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(max_entries, 102400);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(match_val_t));
} m_matched SEC(".maps");

typedef struct {
	u64 socket_key;
	u32 tid;
	u32 tgid;
	u32 uid;
	u32 socket_generation;
	u8 dns;
	u8 pad[3];
} perfetto_owner_t;

typedef struct {
	u32 saddr[4];
	u32 daddr[4];
	u16 sport;
	u16 dport;
	u16 proto_l3;
	u8 proto_l4;
	u8 pad;
} perfetto_flow_key_t;

typedef struct {
	perfetto_owner_t owner;
	u8 direction;
	u8 pad[3];
} perfetto_flow_owner_t;

typedef struct {
	perfetto_owner_t owner;
	perfetto_flow_key_t flow_key;
	perfetto_flow_owner_t flow_value;
} perfetto_scratch_t;

typedef struct {
	u64 attempt_key;
	u64 start_ts;
	u64 socket_key;
	u32 socket_generation;
	s32 fd;
	u32 tid;
	u32 tgid;
	u32 uid;
	u16 family;
	u16 remote_port;
	u8 remote_addr[16];
} connect_pending_t;

typedef struct {
	u32 tgid;
	s32 fd;
} connect_fd_key_t;

typedef struct {
	connect_pending_t pending;
	u64 optval;
} connect_getsockopt_t;

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(perfetto_owner_t));
	__uint(max_entries, 16384);
} m_perfetto_socket_owner SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 65536);
} m_perfetto_socket_generation SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} m_perfetto_socket_generation_counter SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(perfetto_flow_key_t));
	__uint(value_size, sizeof(perfetto_flow_owner_t));
	__uint(max_entries, 32768);
} m_perfetto_flow_owner SEC(".maps");

/* Keep the owner/flow working set off the 512-byte BPF stack. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(perfetto_scratch_t));
	__uint(max_entries, 1);
} m_perfetto_scratch SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(connect_pending_t));
	__uint(max_entries, 16384);
} m_connect_pending SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(connect_fd_key_t));
	__uint(value_size, sizeof(connect_pending_t));
	__uint(max_entries, 16384);
} m_connect_fd SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(connect_getsockopt_t));
	__uint(max_entries, 16384);
} m_connect_getsockopt SEC(".maps");

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(connect_pending_t));
	__uint(max_entries, 16384);
} m_connect_socket SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u64));
	__uint(max_entries, 512);
} m_stats SEC(".maps");

#ifdef __F_STACK_TRACE
static inline void try_trace_stack(context_info_t *info)
{
	if (!info->args->stack || !(info->func_status & FUNC_STATUS_STACK))
		return;

	info->e->stack_id = bpf_get_stackid(info->ctx, &m_stack, 0);
}
#else
static inline void try_trace_stack(context_info_t *info) { }
#endif

static inline int filter_by_netns(context_info_t *info)
{	
	return 0;
}

static __always_inline void do_event_output(context_info_t *info,
					    const int size)
{
	EVENT_OUTPUT_PTR(info->ctx, info->e, size);
}

static __always_inline int check_rate_limit(bpf_args_t *args)
{
	u64 last_ts = args->__last_update, ts = 0;
	int budget = args->__rate_limit;
	int limit = args->rate_limit;

	if (!limit)
		return 0;

	if (!last_ts) {
		last_ts = bpf_ktime_get_ns();
		args->__last_update = last_ts;
	}

	if (budget <= 0) {
		ts = bpf_ktime_get_ns();
		budget = (((ts - last_ts) / 1000000) * limit) / 1000;
		budget = budget < limit ? budget : limit;
		if (budget <= 0)
			return -1;
		args->__last_update = ts;
	}

	budget--;
	args->__rate_limit = budget;

	return 0;
}

static inline void handle_tiny_output(context_info_t *info)
{
	tiny_event_t e = {
		.func = info->func,
		.meta = FUNC_TYPE_TINY,
#ifdef __PROG_TYPE_TRACING
		.key = (u64)(void *)_(info->skb),
#else
		.key = (u64)(void *)info->skb,
#endif
		.ts = bpf_ktime_get_ns(),
	};

	EVENT_OUTPUT(info->ctx, e);
}

static inline bool mode_has_context(bpf_args_t *args)
{
	return args->trace_mode & TRACE_MODE_BPF_CTX_MASK;
}

static __always_inline u8 get_func_status(bpf_args_t *args, u16 func)
{
	if (func >= TRACE_MAX)
		return 0;

	return args->trace_status[func];
}

static inline bool func_is_free(u8 status)
{
	return status & (FUNC_STATUS_FREE | FUNC_STATUS_CFREE);
}

static inline bool func_is_cfree(u8 status)
{
	return status & FUNC_STATUS_CFREE;
}

static __always_inline u8 perfetto_status_direction(u8 status)
{
	if (status & FUNC_STATUS_RX)
		return PACKET_DIRECTION_RX;
	if (status & FUNC_STATUS_TX)
		return PACKET_DIRECTION_TX;
	return PACKET_DIRECTION_UNKNOWN;
}

static __always_inline bool perfetto_current_matches(bpf_args_t *args,
						      u32 tid, u32 uid)
{
	return !args_check(args, pid, tid) &&
	       (!args->uid_enabled || args->uid == uid);
}

static __always_inline bool perfetto_owner_matches(bpf_args_t *args,
						    perfetto_owner_t *owner)
{
	if (args->pid && args->pid != owner->tid)
		return false;
	if (args->uid_enabled && args->uid != owner->uid)
		return false;
	return true;
}

static __always_inline bool perfetto_packet_supported(packet_t *pkt)
{
	if (pkt->proto_l4 == IPPROTO_TCP)
		return true;
	if (pkt->proto_l4 != IPPROTO_UDP)
		return false;
	return pkt->l4.min.sport == bpf_htons(53) ||
	       pkt->l4.min.dport == bpf_htons(53);
}

static __always_inline bool perfetto_packet_is_dns(packet_t *pkt)
{
	return pkt->proto_l4 == IPPROTO_UDP &&
	       (pkt->l4.min.sport == bpf_htons(53) ||
		pkt->l4.min.dport == bpf_htons(53));
}

static __always_inline bool perfetto_socket_supported(sock_t *sock)
{
	if (sock->proto_l4 == IPPROTO_TCP)
		return true;
	if (sock->proto_l4 != IPPROTO_UDP)
		return false;
	return sock->l4.min.sport == bpf_htons(53) ||
	       sock->l4.min.dport == bpf_htons(53);
}

static __always_inline bool perfetto_socket_io(u16 func)
{
	return func == INDEX_tcp_sendmsg || func == INDEX_tcp_recvmsg ||
	       func == INDEX_udp_sendmsg || func == INDEX_udpv6_sendmsg ||
	       func == INDEX_udp_recvmsg || func == INDEX_udpv6_recvmsg;
}

static __always_inline void perfetto_flow_key(packet_t *pkt,
					       perfetto_flow_key_t *key)
{
	key->proto_l3 = pkt->proto_l3;
	key->proto_l4 = pkt->proto_l4;
	key->sport = pkt->l4.min.sport;
	key->dport = pkt->l4.min.dport;
	if (pkt->proto_l3 == ETH_P_IPV6) {
#ifndef NT_DISABLE_IPV6
		__builtin_memcpy(key->saddr, pkt->l3.ipv6.saddr, 16);
		__builtin_memcpy(key->daddr, pkt->l3.ipv6.daddr, 16);
#endif
	} else {
		key->saddr[0] = pkt->l3.ipv4.saddr;
		key->daddr[0] = pkt->l3.ipv4.daddr;
	}
}

static __always_inline perfetto_flow_owner_t *perfetto_lookup_flow(
	packet_t *pkt, perfetto_flow_key_t *key)
{
	if (!perfetto_packet_supported(pkt))
		return NULL;
	__builtin_memset(key, 0, sizeof(*key));
	perfetto_flow_key(pkt, key);
	return bpf_map_lookup_elem(&m_perfetto_flow_owner, key);
}

static __always_inline void perfetto_store_flow(packet_t *pkt,
							 perfetto_owner_t *owner,
							 u8 direction,
							 perfetto_flow_key_t *key,
							 perfetto_flow_owner_t *value)
{
	u32 address;
	u16 port;
	int i;

	if (!direction || !perfetto_packet_supported(pkt))
		return;
	__builtin_memset(key, 0, sizeof(*key));
	value->owner = *owner;
	value->direction = direction;
	perfetto_flow_key(pkt, key);
	bpf_map_update_elem(&m_perfetto_flow_owner, key, value, BPF_ANY);

#pragma clang loop unroll(full)
	for (i = 0; i < 4; i++) {
		address = key->saddr[i];
		key->saddr[i] = key->daddr[i];
		key->daddr[i] = address;
	}
	port = key->sport;
	key->sport = key->dport;
	key->dport = port;
	value->direction = direction == PACKET_DIRECTION_TX ?
				   PACKET_DIRECTION_RX : PACKET_DIRECTION_TX;
	bpf_map_update_elem(&m_perfetto_flow_owner, key, value, BPF_ANY);
}

static __always_inline void perfetto_store_socket_owner(struct sock *sk,
							 perfetto_owner_t *owner)
{
	u64 key = (u64)(void *)sk;

	if (sk)
		bpf_map_update_elem(&m_perfetto_socket_owner, &key, owner,
				    BPF_ANY);
}

static __always_inline u32 perfetto_socket_generation(struct sock *sk,
						       bool created)
{
	u64 key = (u64)(void *)sk;
	u32 counter_key = 0;
	u32 *counter;
	u32 *stored;
	u32 generation;

	if (!sk)
		return 0;
	stored = bpf_map_lookup_elem(&m_perfetto_socket_generation, &key);
	if (stored && !created)
		return *stored;
	counter = bpf_map_lookup_elem(&m_perfetto_socket_generation_counter,
				      &counter_key);
	if (!counter)
		return 1;
	__sync_fetch_and_add(counter, 1);
	generation = *counter;
	if (!generation) {
		__sync_fetch_and_add(counter, 1);
		generation = *counter;
	}
	bpf_map_update_elem(&m_perfetto_socket_generation, &key,
			    &generation, created ? BPF_ANY : BPF_NOEXIST);
	stored = bpf_map_lookup_elem(&m_perfetto_socket_generation, &key);
	if (stored)
		return *stored;
	return generation;
}

static __always_inline bool perfetto_resolve_socket_owner(
	struct sock *sk, bool trust_current, perfetto_owner_t *owner,
	u32 tid, u32 tgid, u32 uid)
{
	perfetto_owner_t *cached;
	u64 key;
	u32 sk_uid;

	if (!sk)
		return false;
	key = (u64)(void *)sk;
	sk_uid = _C(sk, sk_uid.val);
	cached = bpf_map_lookup_elem(&m_perfetto_socket_owner, &key);
	if (cached && cached->uid == sk_uid) {
		*owner = *cached;
		if (trust_current && uid == sk_uid && !owner->tid) {
			owner->tid = tid;
			owner->tgid = tgid;
			perfetto_store_socket_owner(sk, owner);
		}
		return true;
	}

	owner->socket_key = key;
	owner->socket_generation = perfetto_socket_generation(sk, false);
	owner->uid = sk_uid;
	if (trust_current && uid == sk_uid) {
		owner->tid = tid;
		owner->tgid = tgid;
		perfetto_store_socket_owner(sk, owner);
	}
	return true;
}

static __attribute__((noinline)) int perfetto_handle_owner(
	context_info_t *info, struct sock *sk, detail_event_t *detail, bool filter)
{
	bpf_args_t *args = info->args;
	event_t *event = info->e;
	struct sk_buff *skb = info->skb;
	perfetto_scratch_t *scratch;
	perfetto_owner_t *owner;
	perfetto_flow_owner_t *flow_owner;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 uid = (u32)bpf_get_current_uid_gid();
	u8 direction = perfetto_status_direction(info->func_status);
	bool current_matches = perfetto_current_matches(args, tid, uid);
	bool owner_valid;
	u32 scratch_key = 0;

	scratch = bpf_map_lookup_elem(&m_perfetto_scratch, &scratch_key);
	if (!scratch)
		return -1;
	owner = &scratch->owner;
	__builtin_memset(owner, 0, sizeof(*owner));

	if (!sk && skb)
		sk = _C(skb, sk);
	owner_valid = perfetto_resolve_socket_owner(
		sk, direction == PACKET_DIRECTION_TX ||
		    (info->func_status & FUNC_STATUS_RET), owner,
		tid, tgid, uid);

	if (skb) {
		if (!perfetto_packet_supported(&event->pkt))
			return -1;
		flow_owner = perfetto_lookup_flow(&event->pkt,
						  &scratch->flow_key);
		if (flow_owner) {
			if (!owner_valid ||
			    (!owner->tid && owner->uid == flow_owner->owner.uid))
				*owner = flow_owner->owner;
			owner_valid = true;
			if (!direction)
				direction = flow_owner->direction;
		}
	} else if (!perfetto_socket_supported(&event->ske) &&
		   !perfetto_socket_io(info->func) &&
		   !(owner_valid && owner->dns)) {
		return -1;
	}

	if ((args->pid || args->uid_enabled) && !current_matches &&
	    (!owner_valid || !perfetto_owner_matches(args, owner)))
		return -1;

	if (!owner_valid && current_matches) {
		*owner = (perfetto_owner_t) {
			.tid = tid,
			.tgid = tgid,
			.uid = uid,
			.socket_key = (u64)(void *)sk,
			.socket_generation =
				perfetto_socket_generation(sk, false),
		};
		owner_valid = true;
		if (sk && (direction == PACKET_DIRECTION_TX ||
			   (info->func_status & FUNC_STATUS_RET)))
			perfetto_store_socket_owner(sk, owner);
	}

	if (owner_valid && skb) {
		if (perfetto_packet_is_dns(&event->pkt)) {
			owner->dns = 1;
			if (sk)
				perfetto_store_socket_owner(sk, owner);
		}
		perfetto_store_flow(&event->pkt, owner, direction,
				    &scratch->flow_key, &scratch->flow_value);
	}

	detail->direction = direction;
	detail->owner_valid = owner_valid;
	if (owner_valid) {
		detail->owner_tid = owner->tid;
		detail->owner_tgid = owner->tgid;
		detail->owner_uid = owner->uid;
		detail->owner_socket_key = owner->socket_key;
		detail->owner_socket_generation = owner->socket_generation;
	}
	return 0;
}

static inline void consume_map_ctx(bpf_args_t *args, void *key)
{
	bpf_map_delete_elem(&m_matched, key);
	args->event_count++;
}

static inline void free_map_ctx(bpf_args_t *args, void *key)
{
	bpf_map_delete_elem(&m_matched, key);
}

static inline void init_ctx_match(void *skb, u16 func, bool ts)
{
	match_val_t matched = {
		.ts1 = ts ? bpf_ktime_get_ns() / 1000 : 0,
		.func1 = func,
	};

	bpf_map_update_elem(&m_matched, &skb, &matched, 0);
}

static __always_inline void update_stats_key(u32 key)
{
	u64 *stats = bpf_map_lookup_elem(&m_stats, &key);

	if (stats)
		(*stats)++;
}

static __always_inline void update_stats_log(u32 val)
{
	u32 key = 0, i = 0, tmp = 2;

	#pragma clang loop unroll_count(LAST_STATS_BUCKET)
	for (; i < LAST_STATS_BUCKET; i++) {
		if (val < tmp)
			break;
		tmp <<= 1;
		key++;
	}

	update_stats_key(key);
}

static inline int pre_tiny_output(context_info_t *info)
{
	handle_tiny_output(info);
	if (func_is_free(info->func_status))
		consume_map_ctx(info->args, &info->skb);
	else
		get_ret(info);
	return 1;
}

static inline int pre_handle_latency(context_info_t *info,
				     match_val_t *match_val)
{
	bpf_args_t *args = (void *)info->args;
	u32 delta;

	if (match_val) {
		if (args->latency_free || !func_is_free(info->func_status) ||
		    func_is_cfree(info->func_status)) {
			match_val->ts2 = bpf_ktime_get_ns() / 1000;
			match_val->func2 = info->func;
		}

		/* reentry the matcher, or the free of skb is not traced. */
		if (info->func_status & FUNC_STATUS_MATCHER &&
		    match_val->func1 == info->func)
			match_val->ts1 = bpf_ktime_get_ns() / 1000;

		if (func_is_free(info->func_status)) {
			delta = match_val->ts2 - match_val->ts1;
			/* skip a single match function */
			if (!match_val->func2 || delta < args->latency_min) {
				free_map_ctx(info->args, &info->skb);
				return 1;
			}
			if (args->latency_summary) {
				update_stats_log(delta);
				consume_map_ctx(info->args, &info->skb);
				return 1;
			}
			info->match_val = *match_val;
			return 0;
		}
		return 1;
	} else {
		/* skip single free function for latency total mode */
		if (func_is_free(info->func_status))
			return 1;
		/* if there isn't any filter, skip handle_entry() */
		if (!args->has_filter) {
			init_ctx_match(info->skb, info->func, true);
			return 1;
		}
	}
	info->no_event = true;
	return 0;
}

static inline bool trace_mode_latency(bpf_args_t *args)
{
	return args->trace_mode & TRACE_MODE_LATENCY_MASK;
}

/* return value:
 *   -1: invalid and return
 *    0: valid and continue
 *    1: valid and return
 */
static inline int pre_handle_entry(context_info_t *info, u16 func)
{
	bpf_args_t *args = (void *)info->args;
	int ret = 0;

	if (!args->ready || check_rate_limit(args))
		return -1;

	if (args->max_event && args->event_count >= args->max_event)
		return -1;

	info->func_status = get_func_status(info->args, func);
	if (mode_has_context(args) && info->skb) {
		match_val_t *match_val = bpf_map_lookup_elem(&m_matched,
							     &info->skb);

		if (!match_val) {
			/* skip no-matcher function in match mode if it is not
			 * matched.
			 */
			if (args->match_mode &&
			    !(info->func_status & FUNC_STATUS_MATCHER))
				return -1;
			/* If the first function is a free, just ignore it. */
			if (func_is_free(info->func_status))
				return -1;
		}

		/* skip handle_entry() for tiny case */
		if (match_val && args->tiny_output)
			ret = pre_tiny_output(info);
		else if (trace_mode_latency(args))
			ret = pre_handle_latency(info, match_val);
		else if (match_val)
			info->match_val = *match_val;
	}

	if (args->func_stats) {
		if (ret) {
			update_stats_key(func);
		} else if (!args->has_filter) {
			update_stats_key(func);
			args->event_count++;
			ret = 1;
		} else {
			info->no_event = true;
		}
	}

	return ret;
}

/* err:
 *   -1: not match
 *    0: match
 *    1: match and no output
 */
static inline void handle_entry_finish(context_info_t *info, int err)
{
	if (err < 0)
		return;

	if (mode_has_context(info->args) && info->skb) {
		if (func_is_free(info->func_status)) {
			if (info->matched)
				consume_map_ctx(info->args, &info->skb);
		} else if (!info->matched) {
			init_ctx_match(info->skb, info->func,
				       trace_mode_latency(info->args));
		}
	} else {
		info->args->event_count++;
	}

	if (info->args->func_stats)
		update_stats_key(info->func);
}

static inline void try_set_latency(bpf_args_t *args, event_t *e,
				   match_val_t *val)
{
	if (!val->func1 || !trace_mode_latency(args))
		return;

	e->latency = val->ts2 - val->ts1;
	e->latency_func1 = val->func1;
	e->latency_func2 = val->func2;
}

/* return value:
 *   -1: invalid
 *    0: valid
 *    1: valid and no output
 */
static int auto_inline handle_entry(context_info_t *info)
{
	bpf_args_t *args = (void *)info->args;
	struct sk_buff *skb = info->skb;
	struct sock *sk = info->sk;
	struct net_device *dev;
	detail_event_t *detail;
	event_t *e = info->e;
	pkt_args_t *pkt_args;
	bool mode_ctx, filter;
	packet_t *pkt;
	u8 direction;
	u32 tid;
	int err;

	pr_debug_skb("begin to handle, func=%d", info->func);
	u64 pid_tgid = bpf_get_current_pid_tgid();
	tid = (u32)pid_tgid;
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 uid = (u32)bpf_get_current_uid_gid();

	mode_ctx = mode_has_context(args) && skb;
	filter = !info->matched;
	direction = args->perfetto ? perfetto_status_direction(info->func_status) :
				       PACKET_DIRECTION_UNKNOWN;
	pkt_args = &args->pkt;
	pkt = &e->pkt;

	if (filter && !args->perfetto &&
	    (args_check(args, pid, tid) ||
	     (args->uid_enabled && args->uid != uid)))
		goto err;

	/* why we call probe_parse_skb double times? because in the inline
	 * mode, 4.15 kernel will be confused with pkt_args.
	 */
	if (!filter) {
		if (!skb) {
			if (!(info->func_status & FUNC_STATUS_SK)) {
				pr_bpf_debug("no skb available, func=%d", info->func);
				goto err;
			}
			if (probe_parse_sk(sk, &e->ske, NULL))
				goto err;
		} else {
			probe_parse_skb(skb,
				args->perfetto && direction == PACKET_DIRECTION_RX ?
				NULL : sk, pkt, NULL);
		}
	} else if (info->func_status & FUNC_STATUS_SK) {
		if (!info->sk) {
			pr_bpf_debug("no sock available, func=%d", info->func);
			goto err;
		}
		err = probe_parse_sk(info->sk, &e->ske, pkt_args);
	} else {
		if (!skb) {
			pr_bpf_debug("no skb available, func=%d", info->func);
			goto err;
		}
		err = probe_parse_skb(skb,
			args->perfetto && direction == PACKET_DIRECTION_RX ?
			NULL : info->sk, pkt, pkt_args);
	}

	if (filter && err)
		goto err;

	if (args->perfetto && perfetto_handle_owner(info, sk, (void *)e, filter))
		goto err;

	if (filter_by_netns(info) && filter)
		goto err;

	/* latency total mode with filter condition case */
	if (info->no_event)
		return 1;

	if (!args->detail)
		goto out;

	/* store more (detail) information about net or task. */
	detail = (void *)e;

	bpf_get_current_comm(detail->task, sizeof(detail->task));
	dev = skb ? _C(skb, dev) : NULL;
	if (dev) {
		bpf_core_read_str(detail->ifname, sizeof(detail->ifname) - 1,
				  &dev->name);
		detail->ifindex = _C(dev, ifindex);
	} else if (skb) {
		detail->ifindex = _C(skb, skb_iif);
		detail->ifname[0] = '\0';
	}

out:
	pr_debug_skb("pkt matched");
	try_trace_stack(info);
	pkt->ts = bpf_ktime_get_ns();
#ifdef __PROG_TYPE_TRACING
	e->key = skb ? (u64)(void *)_(skb) : (u64)(void *)_(info->sk);
#else
	e->key = skb ? (u64)(void *)skb : (u64)(void *)info->sk;
#endif
	if (args->perfetto && sk && !skb)
		e->key_generation = perfetto_socket_generation(sk, false);
	e->func = info->func;
	e->meta = info->is_return ? FUNC_TYPE_TRACING_RET : FUNC_TYPE_FUNC;
	e->tid = tid;
	e->tgid = tgid;
	e->uid = uid;

	try_set_latency(args, e, &info->match_val);

#ifdef __PROG_TYPE_TRACING
	e->retval = info->retval;
#endif
	if (args->perfetto && sk &&
	    (info->func == INDEX_tcp_close ||
	     info->func == INDEX_tcp_v4_destroy_sock)) {
		u64 socket_key = (u64)(void *)sk;

		bpf_map_delete_elem(&m_perfetto_socket_owner, &socket_key);
	}

	if (mode_ctx || (args->perfetto &&
			 (info->func_status & FUNC_STATUS_RET)))
		get_ret(info);
	return 0;
err:
	return -1;
}

static inline int default_handle_entry(context_info_t *info)
{
	bool detail = info->args->detail;
	detail_event_t __e;
#ifndef __F_INIT_EVENT
	int size;
#endif
	int err;

	info->e = (void *)&__e;

#ifndef __F_INIT_EVENT
	if (!detail) {
		size = sizeof(event_t);
		__builtin_memset(&__e, 0, size);
	} else {
		size = sizeof(__e);
		__builtin_memset(&__e, 0, size);
	}
#else
	/* the kernel of version 4.X can't spill const variable to stack,
	 * so we need to initialize the whole event.
	 */
	__builtin_memset(&__e, 0, sizeof(__e));
#endif

	err = handle_entry(info);
	if (!err) {
#ifdef __F_INIT_EVENT
#ifdef __F_OUTPUT_WHOLE
		/* output the whole detail event, as the compiler can save
		 * the size to stack sometimes.
		 */
		do_event_output(info, sizeof(__e));
#else
		do_event_output(info, detail ? sizeof(__e) : sizeof(event_t));
#endif
#else
		do_event_output(info, size);
#endif
	}

	return err;
}


/**********************************************************************
 * 
 * Following is the definntion of all kind of BPF program.
 * 
 * DEFINE_ALL_PROBES() will define all the default implement of BPF
 * program, and the customize handle of kernel function or tracepoint
 * is defined following.
 * 
 **********************************************************************/

DEFINE_ALL_PROBES(KPROBE_DEFAULT, TP_DEFAULT, FNC)


#ifdef __PROG_TYPE_TRACING
#define info_tp_args(info, offset, index) (void *)((u64 *)(info->ctx) + index)
#else
#define info_tp_args(info, offset, index) ((void *)(info->ctx) + offset)
#endif

DEFINE_TP(kfree_skb, skb, kfree_skb, 0, 8)
{
	int reason = 0;

	if (bpf_core_type_exists(enum skb_drop_reason)) {
		if (bpf_core_field_exists(struct trace_event_raw_kfree_skb, rx_sk))
			reason = *(int *)info_tp_args(info, 36, 3);
		else
			reason = *(int *)info_tp_args(info, 28, 2);
	} else if (info->args->drop_reason) {
		/* use probe, or we will fail if drop reason not supported */
		reason = _(*(int *)info_tp_args(info, 28, 0));
	}

	DECLARE_EVENT(drop_event_t, e)

	e->location = *(u64 *)info_tp_args(info, 16, 1);
	e->reason = reason;

	return handle_entry_output(info, e);
}

DEFINE_TP_SK(inet_sock_set_state, sock, inet_sock_set_state, 0, 8)
{
	DECLARE_EVENT(sock_state_event_t, e)

	e->oldstate = *(int *)info_tp_args(info, 16, 1);
	e->newstate = *(int *)info_tp_args(info, 20, 2);

	return handle_entry_output(info, e);
}

static inline int bpf_ipt_do_table(context_info_t *info, struct xt_table *table,
				   u32 hook)
{
	char *table_name;
	DECLARE_EVENT(nf_event_t, e)

	e->hook = hook;
	if (bpf_core_type_exists(struct xt_table))
		table_name = _C(table, name);
	else
		table_name = _(table->name);

	bpf_probe_read(e->table, sizeof(e->table) - 1, table_name);
	return handle_entry_output(info, e);
}

#if __KERN_MAJOR == 3
DEFINE_KPROBE_INIT(ipt_do_table_legacy, ipt_do_table, 0,
		   .skb = ctx_get_arg(ctx, 0))
{
	struct xt_table *table = info_get_arg(info, 3);
	u32 hook = (u64)info_get_arg(info, 1);

	return bpf_ipt_do_table(info, table, hook);
}
#else
DEFINE_KPROBE_INIT(ipt_do_table_legacy, ipt_do_table, 0,
		   .skb = ctx_get_arg(ctx, 0))
{
	struct nf_hook_state *state = info_get_arg(info, 1);
	struct xt_table *table = info_get_arg(info, 2);

	return bpf_ipt_do_table(info, table, _C(state, hook));
}
#endif

DEFINE_KPROBE_SKB(ipt_do_table, 1, 3)
{
	struct nf_hook_state *state = info_get_arg(info, 2);
	struct xt_table *table = info_get_arg(info, 0);

	return bpf_ipt_do_table(info, table, _C(state, hook));
}

DEFINE_KPROBE_SKB(nf_hook_slow, 0, 4)
{
	struct nf_hook_state *state;
	int err;

	state = info_get_arg(info, 1);
	if (!info->args->hooks) {
		DECLARE_EVENT(nf_event_t, e)

		err = handle_entry(info);
		if (err)
			return err;

		e->hook = _C(state, hook);
		e->pf = _C(state, pf);
		handle_event_output(info, e);
		return 0;
	}

#ifndef __F_NO_NF_HOOK_ENTRIES
	DECLARE_EVENT(nf_hooks_event_t, hooks_event)
	struct nf_hook_entries *entries;
	int num, i;

	err = handle_entry(info);
	if (err)
		return err;

	hooks_event->hook = _C(state, hook);
	hooks_event->pf = _C(state, pf);
	entries = info_get_arg(info, 2);
	num = _(entries->num_hook_entries);

#pragma clang loop unroll_count(6)
	for (i = 0; i < 6 && i < num; i++)
		_L(hooks_event->hooks + i, &entries->hooks[i].hook);
	handle_event_output(info, hooks_event);
#endif
	return 0;
}

static __always_inline int
bpf_qdisc_handle(context_info_t *info, struct Qdisc *q)
{
	struct netdev_queue *txq;
	unsigned long start;
	DECLARE_EVENT(qdisc_event_t, e)

	txq = _C(q, dev_queue);

	if (bpf_core_helper_exist(jiffies64)) {
		start = _C(txq, trans_start);
		if (start)
			e->last_update = bpf_jiffies64() - start;
	}

	e->qlen = _C(&(q->q), qlen);
	e->state = _C(txq, state);
	e->flags = _C(q, flags);

	return handle_entry_output(info, e);
}

DEFINE_TP(qdisc_dequeue, qdisc, qdisc_dequeue, 3, 32)
{
	struct Qdisc *q = *(struct Qdisc **)info_tp_args(info, 8, 0);
	return bpf_qdisc_handle(info, q);
}

DEFINE_TP(qdisc_enqueue, qdisc, qdisc_enqueue, 2, 24)
{
	struct Qdisc *q = *(struct Qdisc **)info_tp_args(info, 8, 0);
	return bpf_qdisc_handle(info, q);
}

#if !defined(NT_DISABLE_NFT)

/* use the 'ignored suffix rule' feature of CO-RE, as described in:
 * https://nakryiko.com/posts/bpf-core-reference-guide/#handling-incompatible-field-and-type-changes
 */
struct nft_pktinfo___new {
	struct sk_buff			*skb;
	const struct nf_hook_state	*state;
	u8				flags;
	u8				tprot;
	u16				fragoff;
	u16				thoff;
	u16				inneroff;
};

/**
 * This function is used to the kernel version that don't support
 * kernel module BTF.
 */
DEFINE_KPROBE_INIT(nft_do_chain, nft_do_chain, 2,
		   .skb = _(((struct nft_pktinfo *)ctx_get_arg(ctx, 0))->skb))
{
	struct nf_hook_state __attribute__((__unused__))*state;
	void *chain_name, *table_name;
	struct nft_chain *chain;
	struct nft_table *table;
	int err;
	DECLARE_EVENT(nf_event_t, e)

	err = handle_entry(info);
	if (err)
		return err;

#if __KERN_MAJOR == 3
	chain = _C((struct nf_hook_ops *)info_get_arg(info, 1), priv);
#else
	chain = info_get_arg(info, 1);
#endif

#ifdef __F_NFT_NAME_ARRAY
	table = _(chain->table);
	chain_name = &chain->name;
	table_name = &table->name;
#else
	if (bpf_core_type_exists(struct nft_chain)) {
		table = _C(chain, table);
		chain_name = _C(chain, name);
		table_name = _C(table, name);
	} else {
		table = _(chain->table);
		chain_name = _(chain->name);
		table_name = _(table->name);
	}
#endif

	bpf_probe_read_kernel_str(e->chain, sizeof(e->chain), chain_name);
	bpf_probe_read_kernel_str(e->table, sizeof(e->table), table_name);

	handle_event_output(info, e);
	return 0;
}
#endif

DEFINE_KPROBE_INIT(tcp_v4_send_reset, tcp_v4_send_reset, 3,
		   	.sk = ctx_get_arg(ctx, 0),
			.skb = ctx_get_arg(ctx, 1))
{
	struct sock *sk = info_get_arg(info, 0);
	struct sock_common skc_common = _C(sk, __sk_common);
	DECLARE_EVENT(reset_event_t, e)

	e->state = skc_common.skc_state;
	e->reason = (u64)info_get_arg(info, 2);

	return handle_entry_output(info, e);
}

DEFINE_KPROBE_INIT(tcp_v6_send_reset, tcp_v6_send_reset, 3,
			.sk = ctx_get_arg(ctx, 0),
 			.skb = ctx_get_arg(ctx, 1))
{
	struct sock *sk = info_get_arg(info, 0);
	struct sock_common skc_common = _C(sk, __sk_common);
	DECLARE_EVENT(reset_event_t, e)

	e->state = skc_common.skc_state;
	e->reason = (u64)info_get_arg(info, 2);

	return handle_entry_output(info, e);
}

DEFINE_KPROBE_INIT(tcp_send_active_reset, tcp_send_active_reset, 3,
			.sk = ctx_get_arg(ctx, 0))
{
	struct sock *sk = info_get_arg(info, 0);
	struct sock_common skc_common = _C(sk, __sk_common);
	DECLARE_EVENT(reset_event_t, e)

	e->state = skc_common.skc_state;
	e->reason = (u64)info_get_arg(info, 2);

	return handle_entry_output(info, e);
}

/*******************************************************************
 * 
 * Following is socket related custom BPF program.
 * 
 *******************************************************************/

#ifndef __PROG_TYPE_TRACING
#ifndef SOL_SOCKET
#define SOL_SOCKET 1
#endif
#ifndef SO_ERROR
#define SO_ERROR 4
#endif

static __always_inline bool connect_current_matches(bpf_args_t *args,
						     u32 tid, u32 uid)
{
	if (!args->ready || !args->perfetto || !args->connect_diagnostics)
		return false;
	if (args_check(args, pid, tid))
		return false;
	return !args->uid_enabled || args->uid == uid;
}

static __always_inline bool connect_read_endpoint(connect_pending_t *pending,
						   const void *address)
{
	u16 family = 0;

	if (!address || bpf_probe_read_user(&family, sizeof(family), address))
		return false;
	pending->family = family;
	if (family == AF_INET) {
		struct sockaddr_in ipv4 = {};

		if (bpf_probe_read_user(&ipv4, sizeof(ipv4), address))
			return false;
		pending->remote_port = bpf_ntohs(ipv4.sin_port);
		__builtin_memcpy(pending->remote_addr, &ipv4.sin_addr,
				 sizeof(ipv4.sin_addr));
		return true;
	}
#ifndef NT_DISABLE_IPV6
	if (family == AF_INET6) {
		struct sockaddr_in6 ipv6 = {};

		if (bpf_probe_read_user(&ipv6, sizeof(ipv6), address))
			return false;
		pending->remote_port = bpf_ntohs(ipv6.sin6_port);
		__builtin_memcpy(pending->remote_addr, &ipv6.sin6_addr,
				 sizeof(ipv6.sin6_addr));
		return true;
	}
#endif
	return false;
}

static __always_inline void connect_event_init(connect_event_t *event,
						 const connect_pending_t *pending,
						 u16 kind)
{
	event->meta = FUNC_TYPE_CONNECT;
	event->kind = kind;
	event->ts = bpf_ktime_get_ns();
	event->attempt_key = pending->attempt_key;
	event->socket_key = pending->socket_key;
	event->socket_generation = pending->socket_generation;
	event->fd = pending->fd;
	event->tid = pending->tid;
	event->tgid = pending->tgid;
	event->uid = pending->uid;
	event->family = pending->family;
	event->remote_port = pending->remote_port;
	__builtin_memcpy(event->remote_addr, pending->remote_addr,
			 sizeof(event->remote_addr));
	bpf_get_current_comm(event->task, sizeof(event->task));
}

static __always_inline void connect_forget(const connect_pending_t *pending)
{
	connect_fd_key_t fd_key = {
		.tgid = pending->tgid,
		.fd = pending->fd,
	};
	u64 socket_key = pending->socket_key;

	bpf_map_delete_elem(&m_connect_fd, &fd_key);
	if (socket_key)
		bpf_map_delete_elem(&m_connect_socket, &socket_key);
}

SEC("tp/raw_syscalls/sys_enter")
int TRACE_NAME(connect_sys_enter)(struct trace_event_raw_sys_enter *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 tgid = (u32)(pid_tgid >> 32);
	u32 uid = (u32)bpf_get_current_uid_gid();
	long syscall_id = _(ctx->id);
	s32 fd = (s32)_(ctx->args[0]);
	connect_fd_key_t fd_key = { .tgid = tgid, .fd = fd };

	if (!connect_current_matches(args, tid, uid))
		return 0;
	if (syscall_id == args->getsockopt_syscall_nr) {
		connect_pending_t *pending;
		connect_getsockopt_t get = {};
		int level = (int)_(ctx->args[1]);
		int optname = (int)_(ctx->args[2]);

		if (level != SOL_SOCKET || optname != SO_ERROR)
			return 0;
		pending = bpf_map_lookup_elem(&m_connect_fd, &fd_key);
		if (!pending)
			return 0;
		get.pending = *pending;
		get.optval = _(ctx->args[3]);
		bpf_map_update_elem(&m_connect_getsockopt, &pid_tgid, &get,
				    BPF_ANY);
		return 0;
	}
	if (syscall_id == args->connect_syscall_nr) {
		connect_pending_t pending = {};
		connect_event_t event = {};
		const void *address = (void *)_(ctx->args[1]);

		pending.start_ts = bpf_ktime_get_ns();
		pending.attempt_key = pending.start_ts ^
			(pid_tgid * 0x9e3779b97f4a7c15ULL);
		pending.fd = fd;
		pending.tid = tid;
		pending.tgid = tgid;
		pending.uid = uid;
		if (!connect_read_endpoint(&pending, address))
			return 0;
		bpf_map_update_elem(&m_connect_pending, &pid_tgid, &pending,
				    BPF_ANY);
		bpf_map_update_elem(&m_connect_fd, &fd_key, &pending, BPF_ANY);
		connect_event_init(&event, &pending, CONNECT_EVENT_START);
		EVENT_OUTPUT(ctx, event);
		args->event_count++;
	}
	return 0;
}

SEC("tp/raw_syscalls/sys_exit")
int TRACE_NAME(connect_sys_exit)(struct trace_event_raw_sys_exit *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	long syscall_id = _(ctx->id);
	s64 result = _(ctx->ret);

	if (!args->ready || !args->perfetto || !args->connect_diagnostics)
		return 0;
	if (syscall_id == args->getsockopt_syscall_nr) {
		connect_getsockopt_t *get;
		connect_event_t event = {};
		int so_error = 0;

		get = bpf_map_lookup_elem(&m_connect_getsockopt, &pid_tgid);
		if (!get)
			return 0;
		if (!result && get->optval &&
		    !bpf_probe_read_user(&so_error, sizeof(so_error),
					 (const void *)get->optval)) {
			connect_event_init(&event, &get->pending,
					   CONNECT_EVENT_SO_ERROR);
			event.result = so_error;
			EVENT_OUTPUT(ctx, event);
			args->event_count++;
			if (so_error != 115 && so_error != 114)
				connect_forget(&get->pending);
		}
		bpf_map_delete_elem(&m_connect_getsockopt, &pid_tgid);
		return 0;
	}
	if (syscall_id == args->connect_syscall_nr) {
		connect_pending_t *pending;
		connect_event_t event = {};
		bool async_pending;

		pending = bpf_map_lookup_elem(&m_connect_pending, &pid_tgid);
		if (!pending)
			return 0;
		connect_event_init(&event, pending, CONNECT_EVENT_RESULT);
		event.result = result;
		async_pending = result == -115 || result == -114;
		if (async_pending)
			event.flags |= CONNECT_EVENT_ASYNC_PENDING;
		EVENT_OUTPUT(ctx, event);
		args->event_count++;
		if (!async_pending)
			connect_forget(pending);
		bpf_map_delete_elem(&m_connect_pending, &pid_tgid);
	}
	return 0;
}

SEC("tp/tcp/tcp_retransmit_skb")
int TRACE_NAME(connect_tcp_retransmit)(
	struct trace_event_raw_tcp_event_sk_skb *ctx)
{
	context_info_t info = {
		.func = INDEX_connect_tcp_retransmit,
		.ctx = ctx,
		.args = (void *)CONFIG(),
		.sk = (struct sock *)_(ctx->skaddr),
	};

	if (pre_handle_entry(&info, INDEX_connect_tcp_retransmit))
		return 0;
	handle_entry_finish(&info, default_handle_entry(&info));
	return 0;
}

SEC("kprobe/tcp_close")
int TRACE_NAME(tcp_close)(struct pt_regs *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	struct sock *sk = ctx_get_arg(ctx, 0);
	u64 socket_key = (u64)(void *)sk;
	connect_pending_t *pending;
	connect_event_t event = {};
	u8 state = sk ? _C(sk, __sk_common.skc_state) : TCP_CLOSE;
	context_info_t info = {
		.func = INDEX_tcp_close,
		.ctx = ctx,
		.args = args,
		.sk = sk,
	};

	if (args->ready && args->perfetto && args->connect_diagnostics && sk) {
		pending = bpf_map_lookup_elem(&m_connect_socket, &socket_key);
		if (pending) {
			if (state == TCP_SYN_SENT || state == TCP_SYN_RECV ||
			    state == TCP_CLOSE) {
				connect_event_init(&event, pending,
						   CONNECT_EVENT_CANCEL);
				EVENT_OUTPUT(ctx, event);
				args->event_count++;
			}
			connect_forget(pending);
		}
	}
	if (pre_handle_entry(&info, INDEX_tcp_close))
		return 0;
	handle_entry_finish(&info, default_handle_entry(&info));
	return 0;
}

SEC("kprobe/inet_stream_connect")
int TRACE_NAME(inet_stream_connect)(struct pt_regs *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	connect_pending_t *pending;
	connect_pending_t updated;
	connect_event_t event = {};
	connect_fd_key_t fd_key;
	perfetto_owner_t owner = {};
	struct socket *socket;
	struct sock *sk;

	if (!args->ready || !args->perfetto || !args->connect_diagnostics)
		return 0;
	pending = bpf_map_lookup_elem(&m_connect_pending, &pid_tgid);
	if (!pending)
		return 0;
	socket = ctx_get_arg(ctx, 0);
	sk = socket ? _C(socket, sk) : NULL;
	if (!sk)
		return 0;
	updated = *pending;
	updated.socket_key = (u64)(void *)sk;
	updated.socket_generation = perfetto_socket_generation(sk, false);
	fd_key.tgid = updated.tgid;
	fd_key.fd = updated.fd;
	bpf_map_update_elem(&m_connect_pending, &pid_tgid, &updated, BPF_ANY);
	bpf_map_update_elem(&m_connect_fd, &fd_key, &updated, BPF_ANY);
	bpf_map_update_elem(&m_connect_socket, &updated.socket_key, &updated,
			    BPF_ANY);
	owner.socket_key = updated.socket_key;
	owner.socket_generation = updated.socket_generation;
	owner.tid = updated.tid;
	owner.tgid = updated.tgid;
	owner.uid = updated.uid;
	perfetto_store_socket_owner(sk, &owner);
	connect_event_init(&event, &updated, CONNECT_EVENT_SOCKET);
	probe_parse_sk(sk, &event.ske, &args->pkt);
	EVENT_OUTPUT(ctx, event);
	args->event_count++;
	return 0;
}

struct {
#ifdef BPF_MAP_TYPE_LRU_HASH
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
#else
	__uint(type, BPF_MAP_TYPE_HASH);
#endif
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1024);
} m_socket_create_start SEC(".maps");

SEC("kprobe/sk_alloc")
int TRACE_NAME(sk_alloc)(struct pt_regs *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 tid = (u32)pid_tgid;
	u32 uid = (u32)bpf_get_current_uid_gid();
	u64 start_ts;

	if (!args->ready || !args->perfetto || args_check(args, pid, tid) ||
	    (args->uid_enabled && args->uid != uid))
		return 0;
	start_ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&m_socket_create_start, &pid_tgid, &start_ts,
			    BPF_ANY);
	return 0;
}

SEC("kretprobe/sk_alloc")
int TRACE_RET_NAME(sk_alloc)(struct pt_regs *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	detail_socket_create_event_t event = {};
	perfetto_owner_t owner = {};
	u64 pid_tgid = bpf_get_current_pid_tgid();
	u64 *start_ts;
	struct sock *sk;

	if (!args->ready || !args->perfetto)
		return 0;
	start_ts = bpf_map_lookup_elem(&m_socket_create_start, &pid_tgid);
	if (!start_ts)
		return 0;
	sk = (void *)PT_REGS_RC(ctx);
	if (!sk)
		goto out;

	event.event.func = INDEX_sk_alloc;
	event.event.meta = FUNC_TYPE_FUNC;
	event.event.key = (u64)(void *)sk;
	event.event.key_generation = perfetto_socket_generation(sk, true);
	event.event.ske.ts = bpf_ktime_get_ns();
	event.event.tid = (u32)pid_tgid;
	event.event.tgid = (u32)(pid_tgid >> 32);
	event.event.uid = (u32)bpf_get_current_uid_gid();
	owner.tid = event.event.tid;
	owner.tgid = event.event.tgid;
	owner.uid = event.event.uid;
	owner.socket_key = (u64)(void *)sk;
	owner.socket_generation = event.event.key_generation;
	perfetto_store_socket_owner(sk, &owner);
	event.event.owner_tid = owner.tid;
	event.event.owner_tgid = owner.tgid;
	event.event.owner_uid = owner.uid;
	event.event.owner_socket_key = owner.socket_key;
	event.event.owner_socket_generation = owner.socket_generation;
	event.event.owner_valid = 1;
	bpf_get_current_comm(event.event.task, sizeof(event.event.task));
	event.start_ts = *start_ts;
	EVENT_OUTPUT(ctx, event);
	args->event_count++;
out:
	bpf_map_delete_elem(&m_socket_create_start, &pid_tgid);
	return 0;
}
#endif

DEFINE_KPROBE_INIT(inet_listen, inet_listen, 2,
		   .sk = _C((struct socket *)ctx_get_arg(ctx, 0), sk))
{
	return default_handle_entry(info);
}

DEFINE_KPROBE_INIT(tcp_ack_update_rtt, tcp_ack_update_rtt, 6,
		   .sk = ctx_get_arg(ctx, 0))
{
	u64 first_rtt, last_rtt;

	first_rtt = (u64)info_get_arg(info, 2);
	last_rtt = (u64)info_get_arg(info, 4);

	if ((long)first_rtt < 0)
		return -1;

	if (first_rtt < info->args->first_rtt || last_rtt < info->args->last_rtt)
		return -1;

	if (info->args->trace_mode & TRACE_MODE_RTT_MASK &&
	    !info->args->has_filter) {
		update_stats_log(first_rtt);
		return 0;
	}

	DECLARE_EVENT(rtt_event_t, e)

	if (handle_entry(info))
		return -1;

	if (info->args->trace_mode & TRACE_MODE_RTT_MASK) {
		update_stats_log(first_rtt);
		return 0;
	}

	e->first_rtt = first_rtt;
	e->last_rtt = last_rtt;

	handle_event_output(info, e);
	return 0;
}

char _license[] SEC("license") = "GPL";
