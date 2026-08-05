// SPDX-License-Identifier: MulanPSL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "trace.h"
#include "analysis.h"
#include "perfetto_export.h"

#ifndef CLOCK_BOOTTIME
#define CLOCK_BOOTTIME 7
#endif

#define PERFETTO_SCHEMA "anettrace.perfetto.v1"

static FILE *export_file;
static pthread_mutex_t export_lock = PTHREAD_MUTEX_INITIALIZER;
static u64 export_salt;
static u64 exported_events;
static u64 lost_events;

static u64 timespec_to_ns(const struct timespec *ts)
{
	return (u64)ts->tv_sec * 1000000000ULL + ts->tv_nsec;
}

static u64 hash_bytes(u64 hash, const void *data, size_t size)
{
	const unsigned char *bytes = data;
	size_t i;

	for (i = 0; i < size; i++) {
		hash ^= bytes[i];
		hash *= 1099511628211ULL;
	}
	return hash;
}

static u64 object_id(const char *kind, u32 key)
{
	u64 hash = 1469598103934665603ULL ^ export_salt;

	hash = hash_bytes(hash, kind, strlen(kind));
	return hash_bytes(hash, &key, sizeof(key));
}

static u64 packet_flow_id(const packet_t *pkt)
{
	u64 hash = 1469598103934665603ULL ^ export_salt;

	hash = hash_bytes(hash, &pkt->proto_l3, sizeof(pkt->proto_l3));
	hash = hash_bytes(hash, &pkt->proto_l4, sizeof(pkt->proto_l4));
	if (pkt->proto_l3 == ETH_P_IPV6) {
#ifndef NT_DISABLE_IPV6
		hash = hash_bytes(hash, pkt->l3.ipv6.saddr,
				  sizeof(pkt->l3.ipv6.saddr));
		hash = hash_bytes(hash, pkt->l3.ipv6.daddr,
				  sizeof(pkt->l3.ipv6.daddr));
#endif
	} else {
		hash = hash_bytes(hash, &pkt->l3.ipv4.saddr,
				  sizeof(pkt->l3.ipv4.saddr));
		hash = hash_bytes(hash, &pkt->l3.ipv4.daddr,
				  sizeof(pkt->l3.ipv4.daddr));
	}
	hash = hash_bytes(hash, &pkt->l4.min, sizeof(pkt->l4.min));
	return hash;
}

static u64 packet_id(const packet_t *pkt, u32 key)
{
	u64 hash;

	if (!pkt->proto_l3 || !pkt->proto_l4)
		return object_id("packet", key);
	hash = packet_flow_id(pkt);
	if (pkt->proto_l4 == IPPROTO_TCP) {
		hash = hash_bytes(hash, &pkt->l4.tcp.seq,
				  sizeof(pkt->l4.tcp.seq));
		hash = hash_bytes(hash, &pkt->l4.tcp.ack,
				  sizeof(pkt->l4.tcp.ack));
		hash = hash_bytes(hash, &pkt->l4.tcp.flags,
				  sizeof(pkt->l4.tcp.flags));
	} else if (pkt->proto_l3 == ETH_P_IP)
		hash = hash_bytes(hash, &pkt->l3.ipv4.id,
				  sizeof(pkt->l3.ipv4.id));
	return hash;
}

static u64 socket_flow_id(const sock_t *sock)
{
	u64 hash = 1469598103934665603ULL ^ export_salt;

	hash = hash_bytes(hash, &sock->proto_l3, sizeof(sock->proto_l3));
	hash = hash_bytes(hash, &sock->proto_l4, sizeof(sock->proto_l4));
	hash = hash_bytes(hash, &sock->l3.ipv4, sizeof(sock->l3.ipv4));
	hash = hash_bytes(hash, &sock->l4.min, sizeof(sock->l4.min));
	return hash;
}

static void json_escape(const char *source, char *dest, size_t size)
{
	size_t in = 0, out = 0;

	if (!size)
		return;
	while (source && source[in] && out + 1 < size) {
		unsigned char ch = source[in++];

		if ((ch == '"' || ch == '\\') && out + 2 < size) {
			dest[out++] = '\\';
			dest[out++] = ch;
		} else if (ch >= 0x20) {
			dest[out++] = ch;
		}
	}
	dest[out] = '\0';
}

static void packet_addresses(const packet_t *pkt, char *source,
			     size_t source_size, char *dest, size_t dest_size)
{
	source[0] = '\0';
	dest[0] = '\0';
	if (pkt->proto_l3 == ETH_P_IP) {
		inet_ntop(AF_INET, &pkt->l3.ipv4.saddr, source, source_size);
		inet_ntop(AF_INET, &pkt->l3.ipv4.daddr, dest, dest_size);
	} else if (pkt->proto_l3 == ETH_P_IPV6) {
#ifndef NT_DISABLE_IPV6
		inet_ntop(AF_INET6, pkt->l3.ipv6.saddr, source, source_size);
		inet_ntop(AF_INET6, pkt->l3.ipv6.daddr, dest, dest_size);
#endif
	}
}

static void socket_addresses(const sock_t *sock, char *source,
			     size_t source_size, char *dest, size_t dest_size)
{
	source[0] = '\0';
	dest[0] = '\0';
	if (sock->proto_l3 == ETH_P_IP) {
		inet_ntop(AF_INET, &sock->l3.ipv4.saddr, source, source_size);
		inet_ntop(AF_INET, &sock->l3.ipv4.daddr, dest, dest_size);
	}
}

static const char *tcp_state_name(int state)
{
	static const char *names[] = {
		[0] = "UNKNOWN",
		[TCP_ESTABLISHED] = "ESTABLISHED",
		[TCP_SYN_SENT] = "SYN_SENT",
		[TCP_SYN_RECV] = "SYN_RECV",
		[TCP_FIN_WAIT1] = "FIN_WAIT1",
		[TCP_FIN_WAIT2] = "FIN_WAIT2",
		[TCP_TIME_WAIT] = "TIME_WAIT",
		[TCP_CLOSE] = "CLOSE",
		[TCP_CLOSE_WAIT] = "CLOSE_WAIT",
		[TCP_LAST_ACK] = "LAST_ACK",
		[TCP_LISTEN] = "LISTEN",
		[TCP_CLOSING] = "CLOSING",
	};

	if (state < 0 || state >= (int)ARRAY_SIZE(names) || !names[state])
		return "UNKNOWN";
	return names[state];
}

static void write_clock_snapshot(void)
{
	struct timespec monotonic, boottime, realtime;

	if (clock_gettime(CLOCK_MONOTONIC, &monotonic) ||
	    clock_gettime(CLOCK_BOOTTIME, &boottime) ||
	    clock_gettime(CLOCK_REALTIME, &realtime)) {
		pr_warn("failed to capture Perfetto clock snapshot: %s\n",
			strerror(errno));
		return;
	}
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"clock_snapshot\","
		"\"monotonic_ns\":%llu,\"boottime_ns\":%llu,"
		"\"realtime_ns\":%llu}\n",
		PERFETTO_SCHEMA, timespec_to_ns(&monotonic),
		timespec_to_ns(&boottime), timespec_to_ns(&realtime));
}

int perfetto_export_open(const char *path)
{
	struct timespec now;
	int fd;

	if (!path)
		return 0;
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_err("failed to open Perfetto event file %s: %s\n", path,
		       strerror(errno));
		return -errno;
	}
	export_file = fdopen(fd, "w");
	if (!export_file) {
		int err = errno;

		close(fd);
		pr_err("failed to initialize Perfetto event file %s: %s\n",
		       path, strerror(err));
		return -err;
	}
	setvbuf(export_file, NULL, _IOLBF, 0);
	if (getrandom(&export_salt, sizeof(export_salt), 0) !=
	    sizeof(export_salt)) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		export_salt = timespec_to_ns(&now) ^ (u64)getpid();
	}
	write_clock_snapshot();
	return 0;
}

bool perfetto_export_enabled(void)
{
	return export_file != NULL;
}

static void export_socket_create(const detail_event_t *detail, u64 start_ts,
				 int cpu)
{
	const event_t *base = (const void *)detail;
	char task[64];

	json_escape(detail->task, task, sizeof(task));
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"socket_create\","
		"\"start_ts_ns\":%llu,\"ts_ns\":%llu,"
		"\"socket_id\":\"%016llx\",\"cpu\":%d,"
		"\"tid\":%u,\"tgid\":%u,\"uid\":%u,"
		"\"task\":\"%s\"}\n",
		PERFETTO_SCHEMA, start_ts, base->ske.ts,
		object_id("socket", base->key), cpu, base->tid, base->tgid,
		base->uid, task);
}

static void export_socket_state(const detail_event_t *detail, int oldstate,
				int newstate, int cpu)
{
	const event_t *base = (const void *)detail;
	char source[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN], task[64];

	socket_addresses(&base->ske, source, sizeof(source), dest, sizeof(dest));
	json_escape(detail->task, task, sizeof(task));
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"socket_state\","
		"\"ts_ns\":%llu,\"socket_id\":\"%016llx\","
		"\"flow_id\":\"%016llx\",\"cpu\":%d,"
		"\"tid\":%u,\"tgid\":%u,\"uid\":%u,"
		"\"task\":\"%s\",\"old_state\":%d,"
		"\"old_state_name\":\"%s\",\"new_state\":%d,"
		"\"new_state_name\":\"%s\",\"terminal\":%s,"
		"\"proto_l4\":%u,\"saddr\":\"%s\",\"sport\":%u,"
		"\"daddr\":\"%s\",\"dport\":%u}\n",
		PERFETTO_SCHEMA, base->ske.ts, object_id("socket", base->key),
		socket_flow_id(&base->ske), cpu, base->tid, base->tgid,
		base->uid, task, oldstate, tcp_state_name(oldstate), newstate,
		tcp_state_name(newstate),
		newstate == TCP_CLOSE ? "true" : "false",
		base->ske.proto_l4, source, ntohs(base->ske.l4.min.sport),
		dest, ntohs(base->ske.l4.min.dport));
}

static void export_socket_event(const detail_event_t *detail, trace_t *trace,
				int cpu)
{
	const event_t *event = (const void *)detail;
	char source[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];
	char task[64], ifname[64];
	bool terminal = !strcmp(trace->name, "tcp_close") ||
			!strcmp(trace->name, "tcp_v4_destroy_sock");

	socket_addresses(&event->ske, source, sizeof(source), dest, sizeof(dest));
	json_escape(detail->task, task, sizeof(task));
	json_escape(detail->ifname, ifname, sizeof(ifname));
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"socket_event\","
		"\"ts_ns\":%llu,\"socket_id\":\"%016llx\","
		"\"flow_id\":\"%016llx\",\"stage\":\"%s\","
		"\"terminal\":%s,\"cpu\":%d,\"tid\":%u,"
		"\"tgid\":%u,\"uid\":%u,\"task\":\"%s\","
		"\"ifname\":\"%s\",\"proto_l4\":%u,"
		"\"saddr\":\"%s\",\"sport\":%u,"
		"\"daddr\":\"%s\",\"dport\":%u}\n",
		PERFETTO_SCHEMA, event->ske.ts, object_id("socket", event->key),
		socket_flow_id(&event->ske), trace->name,
		terminal ? "true" : "false", cpu, event->tid, event->tgid,
		event->uid, task, ifname, event->ske.proto_l4, source,
		ntohs(event->ske.l4.min.sport), dest,
		ntohs(event->ske.l4.min.dport));
}

static void export_packet_event(const detail_event_t *detail, trace_t *trace,
				int cpu)
{
	const event_t *event = (const void *)detail;
	const packet_t *pkt = &event->pkt;
	char source[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];
	char task[64], ifname[64];
	bool dropped = TRACE_HAS_ANALYZER(trace, drop);
	bool terminal = dropped || TRACE_HAS_ANALYZER(trace, free) ||
			(trace->status & TRACE_CFREE);

	packet_addresses(pkt, source, sizeof(source), dest, sizeof(dest));
	json_escape(detail->task, task, sizeof(task));
	json_escape(detail->ifname, ifname, sizeof(ifname));
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"packet_event\","
		"\"ts_ns\":%llu,\"packet_id\":\"%016llx\","
		"\"skb_id\":\"%016llx\","
		"\"flow_id\":\"%016llx\",\"stage\":\"%s\","
		"\"terminal\":%s,\"dropped\":%s,\"cpu\":%d,"
		"\"tid\":%u,\"tgid\":%u,\"uid\":%u,"
		"\"task\":\"%s\",\"ifname\":\"%s\","
		"\"ifindex\":%u,\"netns\":%u,\"proto_l3\":%u,"
		"\"proto_l4\":%u,\"saddr\":\"%s\",\"sport\":%u,"
		"\"daddr\":\"%s\",\"dport\":%u,\"mark\":%u,"
		"\"tcp_seq\":%u,\"tcp_ack\":%u,\"tcp_flags\":%u}\n",
		PERFETTO_SCHEMA, pkt->ts, packet_id(pkt, event->key),
		object_id("skb", event->key), packet_flow_id(pkt), trace->name,
		terminal ? "true" : "false",
		dropped ? "true" : "false", cpu, event->tid, event->tgid,
		event->uid, task, ifname, detail->ifindex, detail->netns,
		pkt->proto_l3, pkt->proto_l4, source,
		ntohs(pkt->l4.min.sport), dest, ntohs(pkt->l4.min.dport),
		pkt->mark, pkt->l4.tcp.seq, pkt->l4.tcp.ack,
		pkt->l4.tcp.flags);
}

void perfetto_export_event(const void *data, int cpu, u32 size)
{
	const detail_event_t *detail = data;
	const event_t *event = data;
	trace_t *trace;

	if (!export_file || !data || size < sizeof(event_t) ||
	    event->meta != FUNC_TYPE_FUNC)
		return;
	trace = get_trace(event->func);
	if (!trace || size < sizeof(detail_event_t))
		return;

	pthread_mutex_lock(&export_lock);
	if (!strcmp(trace->name, "sk_alloc") &&
	    size >= sizeof(detail_socket_create_event_t)) {
		const detail_socket_create_event_t *create = data;

		export_socket_create(detail, create->start_ts, cpu);
	} else if (!strcmp(trace->name, "inet_sock_set_state") &&
		   size >= sizeof(detail_sock_state_event_t)) {
		const detail_sock_state_event_t *state = data;

		export_socket_state(detail, state->oldstate, state->newstate, cpu);
	} else if (trace_using_sk(trace)) {
		export_socket_event(detail, trace, cpu);
	} else {
		export_packet_event(detail, trace, cpu);
	}
	exported_events++;
	pthread_mutex_unlock(&export_lock);
}

void perfetto_export_lost(int cpu, u64 count)
{
	struct timespec monotonic;
	u64 ts = 0;

	if (!export_file)
		return;
	if (!clock_gettime(CLOCK_MONOTONIC, &monotonic))
		ts = timespec_to_ns(&monotonic);
	pthread_mutex_lock(&export_lock);
	lost_events += count;
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"lost_events\","
		"\"ts_ns\":%llu,\"cpu\":%d,\"count\":%llu}\n",
		PERFETTO_SCHEMA, ts, cpu, count);
	pthread_mutex_unlock(&export_lock);
}

void perfetto_export_close(u64 event_count)
{
	struct timespec monotonic;
	u64 end_ts = 0;

	if (!export_file)
		return;
	if (!clock_gettime(CLOCK_MONOTONIC, &monotonic))
		end_ts = timespec_to_ns(&monotonic);
	pthread_mutex_lock(&export_lock);
	fprintf(export_file,
		"{\"schema\":\"%s\",\"type\":\"trace_end\","
		"\"ts_ns\":%llu,"
		"\"event_count\":%llu,\"exported_events\":%llu,"
		"\"lost_events\":%llu}\n",
		PERFETTO_SCHEMA, end_ts, event_count, exported_events,
		lost_events);
	fclose(export_file);
	export_file = NULL;
	pthread_mutex_unlock(&export_lock);
}
