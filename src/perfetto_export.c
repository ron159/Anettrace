// SPDX-License-Identifier: MulanPSL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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
#define CLOCK_SNAPSHOT_INTERVAL_NS (5ULL * 1000 * 1000 * 1000)
#define NATIVE_PACKET_SEQUENCE_ID 0xa11e7001U

static FILE *export_file;
static FILE *native_file;
static pthread_mutex_t export_lock = PTHREAD_MUTEX_INITIALIZER;
static u64 export_salt;
static u64 exported_events;
static u64 lost_events;
static u64 last_clock_snapshot_ns;
static bool native_sequence_started;
static bool native_failed;

enum native_track_kind {
	NATIVE_TRACK_PROCESS,
	NATIVE_TRACK_THREAD,
	NATIVE_TRACK_SOCKET,
	NATIVE_TRACK_GLOBAL,
};

struct native_track {
	u64 uuid;
	u64 object;
	enum native_track_kind kind;
	bool active;
};

struct proto_buffer {
	unsigned char *data;
	size_t size;
	size_t capacity;
	bool failed;
};

static struct native_track *native_tracks;
static size_t native_track_count;
static size_t native_track_capacity;

static u64 hash_bytes(u64 hash, const void *data, size_t size);

static void proto_free(struct proto_buffer *buffer)
{
	free(buffer->data);
	memset(buffer, 0, sizeof(*buffer));
}

static bool proto_reserve(struct proto_buffer *buffer, size_t extra)
{
	size_t capacity;
	void *data;

	if (buffer->failed)
		return false;
	if (extra <= buffer->capacity - buffer->size)
		return true;
	capacity = buffer->capacity ? buffer->capacity : 256;
	while (capacity - buffer->size < extra) {
		if (capacity > SIZE_MAX / 2) {
			buffer->failed = true;
			return false;
		}
		capacity *= 2;
	}
	data = realloc(buffer->data, capacity);
	if (!data) {
		buffer->failed = true;
		return false;
	}
	buffer->data = data;
	buffer->capacity = capacity;
	return true;
}

static void proto_bytes(struct proto_buffer *buffer, const void *data,
			size_t size)
{
	if (!proto_reserve(buffer, size))
		return;
	memcpy(buffer->data + buffer->size, data, size);
	buffer->size += size;
}

static void proto_varint(struct proto_buffer *buffer, u64 value)
{
	unsigned char encoded[10];
	size_t count = 0;

	do {
		encoded[count] = value & 0x7f;
		value >>= 7;
		if (value)
			encoded[count] |= 0x80;
		count++;
	} while (value);
	proto_bytes(buffer, encoded, count);
}

static void proto_tag(struct proto_buffer *buffer, u32 field, u8 wire)
{
	proto_varint(buffer, ((u64)field << 3) | wire);
}

static void proto_uint(struct proto_buffer *buffer, u32 field, u64 value)
{
	proto_tag(buffer, field, 0);
	proto_varint(buffer, value);
}

static void proto_fixed64(struct proto_buffer *buffer, u32 field, u64 value)
{
	unsigned char encoded[8];
	int i;

	proto_tag(buffer, field, 1);
	for (i = 0; i < 8; i++)
		encoded[i] = value >> (i * 8);
	proto_bytes(buffer, encoded, sizeof(encoded));
}

static void proto_string(struct proto_buffer *buffer, u32 field,
			 const char *value)
{
	size_t size = value ? strlen(value) : 0;

	proto_tag(buffer, field, 2);
	proto_varint(buffer, size);
	proto_bytes(buffer, value, size);
}

static void proto_message(struct proto_buffer *buffer, u32 field,
			  const struct proto_buffer *message)
{
	if (message->failed) {
		buffer->failed = true;
		return;
	}
	proto_tag(buffer, field, 2);
	proto_varint(buffer, message->size);
	proto_bytes(buffer, message->data, message->size);
}

static void native_write_packet(struct proto_buffer *packet)
{
	struct proto_buffer trace = {};

	if (!native_file || native_failed)
		return;
	proto_message(&trace, 1, packet); /* Trace.packet */
	if (trace.failed || fwrite(trace.data, 1, trace.size, native_file) !=
	    trace.size)
		native_failed = true;
	proto_free(&trace);
}

static void native_sequence_packet(struct proto_buffer *packet)
{
	proto_uint(packet, 10, NATIVE_PACKET_SEQUENCE_ID);
	if (!native_sequence_started) {
		proto_uint(packet, 13, 1); /* SEQ_INCREMENTAL_STATE_CLEARED */
		native_sequence_started = true;
	}
}

static u64 native_uuid(const char *kind, u64 first, u64 second)
{
	u64 hash = 1469598103934665603ULL ^ export_salt;

	hash = hash_bytes(hash, kind, strlen(kind));
	hash = hash_bytes(hash, &first, sizeof(first));
	hash = hash_bytes(hash, &second, sizeof(second));
	return hash ?: 1;
}

static struct native_track *native_find_track(u64 uuid)
{
	size_t i;

	for (i = 0; i < native_track_count; i++)
		if (native_tracks[i].uuid == uuid)
			return &native_tracks[i];
	return NULL;
}

static struct native_track *native_add_track(u64 uuid, u64 object,
					      enum native_track_kind kind)
{
	struct native_track *tracks;
	size_t capacity;

	if (native_track_count == native_track_capacity) {
		capacity = native_track_capacity ? native_track_capacity * 2 : 64;
		tracks = realloc(native_tracks, capacity * sizeof(*tracks));
		if (!tracks) {
			native_failed = true;
			return NULL;
		}
		native_tracks = tracks;
		native_track_capacity = capacity;
	}
	native_tracks[native_track_count] = (struct native_track) {
		.uuid = uuid,
		.object = object,
		.kind = kind,
	};
	return &native_tracks[native_track_count++];
}

static void native_descriptor(u64 uuid, const char *name, u64 parent_uuid,
			      enum native_track_kind kind, u32 tgid, u32 tid)
{
	struct proto_buffer packet = {}, descriptor = {}, owner = {};

	native_sequence_packet(&packet);
	proto_uint(&descriptor, 1, uuid);
	proto_string(&descriptor, 2, name);
	if (parent_uuid)
		proto_uint(&descriptor, 5, parent_uuid);
	if (kind == NATIVE_TRACK_PROCESS) {
		proto_uint(&owner, 1, tgid);
		proto_string(&owner, 6, name);
		proto_message(&descriptor, 3, &owner);
	} else if (kind == NATIVE_TRACK_THREAD) {
		proto_uint(&owner, 1, tgid);
		proto_uint(&owner, 2, tid);
		proto_string(&owner, 5, name);
		proto_message(&descriptor, 4, &owner);
	}
	proto_message(&packet, 60, &descriptor);
	native_write_packet(&packet);
	proto_free(&owner);
	proto_free(&descriptor);
	proto_free(&packet);
}

static struct native_track *native_process_track(u32 tgid, const char *task)
{
	u64 uuid = native_uuid("process", tgid, 0);
	struct native_track *track = native_find_track(uuid);
	char fallback[32];

	if (track)
		return track;
	if (!task || !task[0]) {
		snprintf(fallback, sizeof(fallback), "pid %u", tgid);
		task = fallback;
	}
	track = native_add_track(uuid, tgid, NATIVE_TRACK_PROCESS);
	if (track)
		native_descriptor(uuid, task, 0, NATIVE_TRACK_PROCESS, tgid, 0);
	return track;
}

static struct native_track *native_thread_track(u32 tgid, u32 tid,
					  const char *task)
{
	u64 uuid = native_uuid("thread", tgid, tid);
	struct native_track *track = native_find_track(uuid);
	struct native_track *process;
	char fallback[32];

	if (track)
		return track;
	process = native_process_track(tgid, task);
	if (!process)
		return NULL;
	if (!task || !task[0]) {
		snprintf(fallback, sizeof(fallback), "tid %u", tid);
		task = fallback;
	}
	track = native_add_track(uuid, ((u64)tgid << 32) | tid,
				 NATIVE_TRACK_THREAD);
	if (track)
		native_descriptor(uuid, task, process->uuid, NATIVE_TRACK_THREAD,
				  tgid, tid);
	return track;
}

static struct native_track *native_socket_track(u64 socket_id, u32 tgid,
					  const char *task)
{
	u64 uuid = native_uuid("socket", socket_id, 0);
	struct native_track *track = native_find_track(uuid);
	struct native_track *process;
	char name[32];

	if (track)
		return track;
	process = native_process_track(tgid, task);
	if (!process)
		return NULL;
	snprintf(name, sizeof(name), "socket %08llx", socket_id & 0xffffffffULL);
	track = native_add_track(uuid, socket_id, NATIVE_TRACK_SOCKET);
	if (track)
		native_descriptor(uuid, name, process->uuid, NATIVE_TRACK_SOCKET,
				  tgid, 0);
	return track;
}

static struct native_track *native_global_track(void)
{
	u64 uuid = native_uuid("global", 0, 0);
	struct native_track *track = native_find_track(uuid);

	if (track)
		return track;
	track = native_add_track(uuid, 0, NATIVE_TRACK_GLOBAL);
	if (track)
		native_descriptor(uuid, "Anettrace metadata", 0,
				  NATIVE_TRACK_GLOBAL, 0, 0);
	return track;
}

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

static void native_event_start(struct proto_buffer *event, u32 type, u64 uuid,
			       const char *name, const char *category)
{
	proto_uint(event, 9, type);
	proto_uint(event, 11, uuid);
	if (name && name[0])
		proto_string(event, 23, name);
	if (category && category[0])
		proto_string(event, 22, category);
}

static void native_event_flow(struct proto_buffer *event, u64 flow_id,
			      bool terminating)
{
	if (!flow_id)
		return;
	proto_fixed64(event, terminating ? 48 : 47, flow_id);
}

static void native_annotation_string(struct proto_buffer *event,
				     const char *name, const char *value)
{
	struct proto_buffer annotation = {};

	proto_string(&annotation, 10, name);
	proto_string(&annotation, 6, value ?: "");
	proto_message(event, 4, &annotation);
	proto_free(&annotation);
}

static void native_annotation_uint(struct proto_buffer *event,
				   const char *name, u64 value)
{
	struct proto_buffer annotation = {};

	proto_string(&annotation, 10, name);
	proto_uint(&annotation, 3, value);
	proto_message(event, 4, &annotation);
	proto_free(&annotation);
}

static void native_annotation_bool(struct proto_buffer *event,
				   const char *name, bool value)
{
	struct proto_buffer annotation = {};

	proto_string(&annotation, 10, name);
	proto_uint(&annotation, 2, value);
	proto_message(event, 4, &annotation);
	proto_free(&annotation);
}

static void native_annotation_id(struct proto_buffer *event, const char *name,
				 u64 value)
{
	char id[24];

	snprintf(id, sizeof(id), "%016llx", value);
	native_annotation_string(event, name, id);
}

static void native_event_write(u64 timestamp_ns, struct proto_buffer *event)
{
	struct proto_buffer packet = {};

	native_sequence_packet(&packet);
	proto_uint(&packet, 8, timestamp_ns);
	proto_uint(&packet, 58, 3); /* BUILTIN_CLOCK_MONOTONIC */
	proto_message(&packet, 11, event);
	native_write_packet(&packet);
	proto_free(&packet);
}

static void native_slice(u64 timestamp_ns, u64 uuid, u32 type,
			 const char *name, const char *category, u64 flow_id,
			 bool terminating)
{
	struct proto_buffer event = {};

	native_event_start(&event, type, uuid, name, category);
	native_event_flow(&event, flow_id, terminating);
	native_event_write(timestamp_ns, &event);
	proto_free(&event);
}

static void native_close_socket(struct native_track *track, u64 timestamp_ns)
{
	if (!track || !track->active)
		return;
	native_slice(timestamp_ns, track->uuid, 2, NULL, "anettrace.socket",
		     track->object, true);
	track->active = false;
}

static void native_open_socket(struct native_track *track, u64 timestamp_ns)
{
	if (!track || track->active)
		return;
	native_slice(timestamp_ns, track->uuid, 1, "socket lifetime",
		     "anettrace.socket", track->object, false);
	track->active = true;
}

static void native_export_socket_create(const detail_event_t *detail,
					 u64 start_ts, int cpu)
{
	const event_t *event = (const void *)detail;
	u64 socket_id = object_id("socket", event->key);
	struct native_track *thread, *socket;
	struct proto_buffer allocation = {};

	thread = native_thread_track(event->tgid, event->tid, detail->task);
	socket = native_socket_track(socket_id, event->tgid, detail->task);
	if (!thread || !socket)
		return;
	native_event_start(&allocation, 1, thread->uuid, "socket allocation",
			   "anettrace.socket");
	native_event_flow(&allocation, socket_id, false);
	native_annotation_id(&allocation, "socket_id", socket_id);
	native_annotation_uint(&allocation, "cpu", cpu);
	native_annotation_uint(&allocation, "uid", event->uid);
	native_event_write(start_ts, &allocation);
	proto_free(&allocation);
	native_slice(event->ske.ts, thread->uuid, 2, NULL, "anettrace.socket",
		     socket_id, false);
	if (socket->active)
		native_close_socket(socket, start_ts);
	native_open_socket(socket, event->ske.ts);
}

static void native_export_socket_state(const detail_event_t *detail,
					int oldstate, int newstate, int cpu)
{
	const event_t *event = (const void *)detail;
	u64 socket_id = object_id("socket", event->key);
	struct native_track *socket;
	struct proto_buffer state = {};
	char source[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN], name[64];
	bool terminal = newstate == TCP_CLOSE;

	socket = native_socket_track(socket_id, event->tgid, detail->task);
	if (!socket)
		return;
	if (!terminal)
		native_open_socket(socket, event->ske.ts);
	socket_addresses(&event->ske, source, sizeof(source), dest, sizeof(dest));
	snprintf(name, sizeof(name), "%s -> %s", tcp_state_name(oldstate),
		 tcp_state_name(newstate));
	native_event_start(&state, 3, socket->uuid, name,
			   "anettrace.socket.state");
	native_event_flow(&state, socket_id, false);
	native_annotation_id(&state, "socket_id", socket_id);
	native_annotation_id(&state, "flow_id", socket_flow_id(&event->ske));
	native_annotation_uint(&state, "old_state", oldstate);
	native_annotation_uint(&state, "new_state", newstate);
	native_annotation_string(&state, "saddr", source);
	native_annotation_uint(&state, "sport", ntohs(event->ske.l4.min.sport));
	native_annotation_string(&state, "daddr", dest);
	native_annotation_uint(&state, "dport", ntohs(event->ske.l4.min.dport));
	native_annotation_uint(&state, "cpu", cpu);
	native_annotation_uint(&state, "tid", event->tid);
	native_annotation_uint(&state, "uid", event->uid);
	native_event_write(event->ske.ts, &state);
	proto_free(&state);
	if (terminal)
		native_close_socket(socket, event->ske.ts);
}

static void native_export_socket_event(const detail_event_t *detail,
					trace_t *trace, int cpu)
{
	const event_t *event = (const void *)detail;
	u64 socket_id = object_id("socket", event->key);
	struct native_track *thread, *socket;
	struct proto_buffer track_event = {};
	char source[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];
	bool terminal = !strcmp(trace->name, "tcp_close") ||
			!strcmp(trace->name, "tcp_v4_destroy_sock");

	thread = native_thread_track(event->tgid, event->tid, detail->task);
	socket = native_socket_track(socket_id, event->tgid, detail->task);
	if (!thread || !socket)
		return;
	if (!terminal)
		native_open_socket(socket, event->ske.ts);
	socket_addresses(&event->ske, source, sizeof(source), dest, sizeof(dest));
	native_event_start(&track_event, 3, thread->uuid, trace->name,
			   "anettrace.socket");
	native_event_flow(&track_event, socket_id, terminal);
	native_annotation_id(&track_event, "socket_id", socket_id);
	native_annotation_id(&track_event, "flow_id",
			     socket_flow_id(&event->ske));
	native_annotation_string(&track_event, "saddr", source);
	native_annotation_uint(&track_event, "sport",
			      ntohs(event->ske.l4.min.sport));
	native_annotation_string(&track_event, "daddr", dest);
	native_annotation_uint(&track_event, "dport",
			      ntohs(event->ske.l4.min.dport));
	native_annotation_uint(&track_event, "cpu", cpu);
	native_annotation_uint(&track_event, "uid", event->uid);
	native_event_write(event->ske.ts, &track_event);
	proto_free(&track_event);
	if (terminal)
		native_close_socket(socket, event->ske.ts);
}

static void native_export_packet_event(const detail_event_t *detail,
					trace_t *trace, int cpu)
{
	const event_t *event = (const void *)detail;
	const packet_t *pkt = &event->pkt;
	u64 id = packet_id(pkt, event->key);
	struct native_track *thread;
	struct proto_buffer track_event = {};
	char source[INET6_ADDRSTRLEN], dest[INET6_ADDRSTRLEN];
	bool dropped = TRACE_HAS_ANALYZER(trace, drop);
	bool terminal = dropped || TRACE_HAS_ANALYZER(trace, free) ||
			(trace->status & TRACE_CFREE);

	thread = native_thread_track(event->tgid, event->tid, detail->task);
	if (!thread)
		return;
	packet_addresses(pkt, source, sizeof(source), dest, sizeof(dest));
	native_event_start(&track_event, 3, thread->uuid, trace->name,
			   dropped ? "anettrace.packet.drop" :
			   "anettrace.packet");
	native_event_flow(&track_event, id, terminal);
	native_annotation_id(&track_event, "packet_id", id);
	native_annotation_id(&track_event, "skb_id",
			     object_id("skb", event->key));
	native_annotation_id(&track_event, "flow_id", packet_flow_id(pkt));
	native_annotation_bool(&track_event, "terminal", terminal);
	native_annotation_bool(&track_event, "dropped", dropped);
	native_annotation_uint(&track_event, "cpu", cpu);
	native_annotation_uint(&track_event, "uid", event->uid);
	native_annotation_string(&track_event, "ifname", detail->ifname);
	native_annotation_uint(&track_event, "ifindex", detail->ifindex);
	native_annotation_uint(&track_event, "netns", detail->netns);
	native_annotation_uint(&track_event, "proto_l3", pkt->proto_l3);
	native_annotation_uint(&track_event, "proto_l4", pkt->proto_l4);
	native_annotation_string(&track_event, "saddr", source);
	native_annotation_uint(&track_event, "sport", ntohs(pkt->l4.min.sport));
	native_annotation_string(&track_event, "daddr", dest);
	native_annotation_uint(&track_event, "dport", ntohs(pkt->l4.min.dport));
	native_annotation_uint(&track_event, "mark", pkt->mark);
	native_annotation_uint(&track_event, "tcp_seq", pkt->l4.tcp.seq);
	native_annotation_uint(&track_event, "tcp_ack", pkt->l4.tcp.ack);
	native_annotation_uint(&track_event, "tcp_flags", pkt->l4.tcp.flags);
	native_event_write(pkt->ts, &track_event);
	proto_free(&track_event);
}

static void native_export_meta(u64 timestamp_ns, const char *name, int cpu,
			       u64 first, const char *first_name, u64 second,
			       const char *second_name, u64 third,
			       const char *third_name)
{
	struct native_track *global = native_global_track();
	struct proto_buffer event = {};

	if (!global)
		return;
	native_event_start(&event, 3, global->uuid, name, "anettrace.metadata");
	if (cpu >= 0)
		native_annotation_uint(&event, "cpu", cpu);
	if (first_name)
		native_annotation_uint(&event, first_name, first);
	if (second_name)
		native_annotation_uint(&event, second_name, second);
	if (third_name)
		native_annotation_uint(&event, third_name, third);
	native_event_write(timestamp_ns, &event);
	proto_free(&event);
}

static void native_clock_snapshot(u64 monotonic_ns, u64 boottime_ns,
				  u64 realtime_ns)
{
	struct proto_buffer packet = {}, snapshot = {}, clock = {};
	const u32 ids[] = { 1, 3, 6 };
	const u64 timestamps[] = { realtime_ns, monotonic_ns, boottime_ns };
	size_t i;

	if (!native_file)
		return;
	for (i = 0; i < ARRAY_SIZE(ids); i++) {
		proto_uint(&clock, 1, ids[i]);
		proto_uint(&clock, 2, timestamps[i]);
		proto_message(&snapshot, 1, &clock);
		proto_free(&clock);
	}
	proto_uint(&snapshot, 2, 6); /* BUILTIN_CLOCK_BOOTTIME */
	proto_message(&packet, 6, &snapshot);
	native_write_packet(&packet);
	proto_free(&snapshot);
	proto_free(&packet);
}

static void write_clock_snapshot(void)
{
	struct timespec monotonic, boottime, realtime;
	u64 monotonic_ns;

	if (clock_gettime(CLOCK_MONOTONIC, &monotonic) ||
	    clock_gettime(CLOCK_BOOTTIME, &boottime) ||
	    clock_gettime(CLOCK_REALTIME, &realtime)) {
		pr_warn("failed to capture Perfetto clock snapshot: %s\n",
			strerror(errno));
		return;
	}
	monotonic_ns = timespec_to_ns(&monotonic);
	if (export_file)
		fprintf(export_file,
			"{\"schema\":\"%s\",\"type\":\"clock_snapshot\","
			"\"monotonic_ns\":%llu,\"boottime_ns\":%llu,"
			"\"realtime_ns\":%llu}\n",
			PERFETTO_SCHEMA, monotonic_ns,
			timespec_to_ns(&boottime), timespec_to_ns(&realtime));
	native_clock_snapshot(monotonic_ns, timespec_to_ns(&boottime),
			      timespec_to_ns(&realtime));
	last_clock_snapshot_ns = monotonic_ns;
}

static void write_clock_snapshot_if_due(void)
{
	struct timespec monotonic;
	u64 now;

	if (clock_gettime(CLOCK_MONOTONIC, &monotonic))
		return;
	now = timespec_to_ns(&monotonic);
	if (!last_clock_snapshot_ns ||
	    now - last_clock_snapshot_ns >= CLOCK_SNAPSHOT_INTERVAL_NS)
		write_clock_snapshot();
}

static void export_state_start(void)
{
	struct timespec now;

	if (export_file || native_file)
		return;
	exported_events = 0;
	lost_events = 0;
	last_clock_snapshot_ns = 0;
	native_sequence_started = false;
	native_failed = false;
	free(native_tracks);
	native_tracks = NULL;
	native_track_count = 0;
	native_track_capacity = 0;
	if (getrandom(&export_salt, sizeof(export_salt), 0) !=
	    sizeof(export_salt)) {
		clock_gettime(CLOCK_MONOTONIC, &now);
		export_salt = timespec_to_ns(&now) ^ (u64)getpid();
	}
}

int perfetto_export_open(const char *path)
{
	int fd;

	if (!path)
		return 0;
	export_state_start();
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
	write_clock_snapshot();
	return 0;
}

int perfetto_export_native_open(const char *path)
{
	int fd;

	if (!path)
		return -EINVAL;
	export_state_start();
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0) {
		pr_err("failed to open native Perfetto file %s: %s\n", path,
		       strerror(errno));
		return -errno;
	}
	native_file = fdopen(fd, "wb");
	if (!native_file) {
		int err = errno;

		close(fd);
		pr_err("failed to initialize native Perfetto file %s: %s\n",
		       path, strerror(err));
		return -err;
	}
	setvbuf(native_file, NULL, _IOFBF, 64 * 1024);
	write_clock_snapshot();
	return 0;
}

bool perfetto_export_enabled(void)
{
	return export_file != NULL || native_file != NULL;
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

	if ((!export_file && !native_file) || !data || size < sizeof(event_t) ||
	    event->meta != FUNC_TYPE_FUNC)
		return;
	trace = get_trace(event->func);
	if (!trace || size < sizeof(detail_event_t))
		return;

	pthread_mutex_lock(&export_lock);
	write_clock_snapshot_if_due();
	if (!strcmp(trace->name, "sk_alloc") &&
	    size >= sizeof(detail_socket_create_event_t)) {
		const detail_socket_create_event_t *create = data;

		if (export_file)
			export_socket_create(detail, create->start_ts, cpu);
		if (native_file)
			native_export_socket_create(detail, create->start_ts, cpu);
	} else if (!strcmp(trace->name, "inet_sock_set_state") &&
		   size >= sizeof(detail_sock_state_event_t)) {
		const detail_sock_state_event_t *state = data;

		if (export_file)
			export_socket_state(detail, state->oldstate, state->newstate,
					    cpu);
		if (native_file)
			native_export_socket_state(detail, state->oldstate,
						   state->newstate, cpu);
	} else if (trace_using_sk(trace)) {
		if (export_file)
			export_socket_event(detail, trace, cpu);
		if (native_file)
			native_export_socket_event(detail, trace, cpu);
	} else {
		if (export_file)
			export_packet_event(detail, trace, cpu);
		if (native_file)
			native_export_packet_event(detail, trace, cpu);
	}
	exported_events++;
	pthread_mutex_unlock(&export_lock);
}

void perfetto_export_lost(int cpu, u64 count)
{
	struct timespec monotonic;
	u64 ts = 0;

	if (!export_file && !native_file)
		return;
	if (!clock_gettime(CLOCK_MONOTONIC, &monotonic))
		ts = timespec_to_ns(&monotonic);
	pthread_mutex_lock(&export_lock);
	write_clock_snapshot_if_due();
	lost_events += count;
	if (export_file)
		fprintf(export_file,
			"{\"schema\":\"%s\",\"type\":\"lost_events\","
			"\"ts_ns\":%llu,\"cpu\":%d,\"count\":%llu}\n",
			PERFETTO_SCHEMA, ts, cpu, count);
	if (native_file)
		native_export_meta(ts, "lost_events", cpu, count, "count", 0,
				   NULL, 0, NULL);
	pthread_mutex_unlock(&export_lock);
}

void perfetto_export_tick(void)
{
	if (!export_file && !native_file)
		return;
	pthread_mutex_lock(&export_lock);
	if (export_file || native_file)
		write_clock_snapshot_if_due();
	pthread_mutex_unlock(&export_lock);
}

void perfetto_export_close(u64 event_count)
{
	struct timespec monotonic;
	u64 end_ts = 0;

	if (!export_file && !native_file)
		return;
	if (!clock_gettime(CLOCK_MONOTONIC, &monotonic))
		end_ts = timespec_to_ns(&monotonic);
	pthread_mutex_lock(&export_lock);
	write_clock_snapshot();
	if (native_file) {
		size_t i;

		for (i = 0; i < native_track_count; i++)
			if (native_tracks[i].kind == NATIVE_TRACK_SOCKET)
				native_close_socket(&native_tracks[i], end_ts);
		native_export_meta(end_ts, "trace_end", -1, event_count,
				   "event_count", exported_events,
				   "exported_events", lost_events,
				   "lost_events");
	}
	if (export_file) {
		fprintf(export_file,
			"{\"schema\":\"%s\",\"type\":\"trace_end\","
			"\"ts_ns\":%llu,"
			"\"event_count\":%llu,\"exported_events\":%llu,"
			"\"lost_events\":%llu}\n",
			PERFETTO_SCHEMA, end_ts, event_count, exported_events,
			lost_events);
		if (fclose(export_file))
			pr_warn("failed to close Perfetto event file: %s\n",
				strerror(errno));
		export_file = NULL;
	}
	if (native_file) {
		if (fclose(native_file))
			native_failed = true;
		native_file = NULL;
	}
	free(native_tracks);
	native_tracks = NULL;
	native_track_count = 0;
	native_track_capacity = 0;
	pthread_mutex_unlock(&export_lock);
}

bool perfetto_export_failed(void)
{
	return native_failed;
}
