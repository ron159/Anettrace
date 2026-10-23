// SPDX-License-Identifier: MulanPSL-2.0
#ifndef ANETTRACE_RX_CONTEXT_H
#define ANETTRACE_RX_CONTEXT_H

#include <stdlib.h>
#include <string.h>

#ifndef RX_CONTEXT_MAX_EVENTS
#define RX_CONTEXT_MAX_EVENTS 4096U
#endif
#ifndef RX_CONTEXT_MAX_BYTES
#define RX_CONTEXT_MAX_BYTES (8U * 1024 * 1024)
#endif
#ifndef RX_CONTEXT_WINDOW_NS
#define RX_CONTEXT_WINDOW_NS 1000000000ULL
#endif
#ifndef RX_CONTEXT_OWNER_SLOTS
#define RX_CONTEXT_OWNER_SLOTS 4096U
#endif

struct rx_context_pending {
	struct rx_context_pending *next;
	int cpu;
	u32 size;
	detail_event_t detail;
	/* Extended event data follows the base detail without losing its type. */
};

struct rx_context_owner {
	u64 key, timestamp, socket_key;
	u32 generation, socket_generation, tid, tgid, uid;
};

struct rx_context {
	struct rx_context_pending *head, *tail;
	struct rx_context_owner owners[RX_CONTEXT_OWNER_SLOTS];
	size_t count, bytes;
	u64 watermark, replayed, expired, capacity_dropped, unresolved;
};

typedef void (*rx_context_emit_fn)(const void *, int, u32);

static void rx_context_remove(struct rx_context *state,
			      struct rx_context_pending **link)
{
	struct rx_context_pending *entry = *link;
	*link = entry->next;
	state->count--;
	state->bytes -= sizeof(*entry) + entry->size - sizeof(entry->detail);
	free(entry);
	if (!state->head)
		state->tail = NULL;
}

/* Sort pending entries by event time, so expiry is amortized constant-time.
 * The watermark never moves backwards when perf buffers arrive out of order. */
static void rx_context_expire(struct rx_context *state, u64 timestamp)
{
	if (timestamp > state->watermark)
		state->watermark = timestamp;
	while (state->head && state->watermark >= state->head->detail.pkt.ts &&
	       state->watermark - state->head->detail.pkt.ts > RX_CONTEXT_WINDOW_NS) {
		rx_context_remove(state, &state->head);
		state->expired++;
	}
}

static void rx_context_apply(detail_event_t *detail,
			     const struct rx_context_owner *owner)
{
	detail->owner_pending = 0;
	detail->owner_evidence = 2;
	detail->owner_valid = 1;
	detail->owner_socket_key = owner->socket_key;
	detail->owner_socket_generation = owner->socket_generation;
	detail->owner_tid = owner->tid;
	detail->owner_tgid = owner->tgid;
	detail->owner_uid = owner->uid;
}

static bool rx_context_matches(const detail_event_t *detail,
			       const struct rx_context_owner *owner)
{
	return owner->key == detail->key && owner->generation == detail->key_generation &&
	       owner->timestamp >= detail->pkt.ts &&
	       owner->timestamp - detail->pkt.ts <= RX_CONTEXT_WINDOW_NS;
}

static void rx_context_feed(struct rx_context *state, const void *data,
			   int cpu, u32 size, rx_context_emit_fn emit)
{
	const detail_event_t *detail = data;
	struct rx_context_pending *entry, **link;
	struct rx_context_owner *owner;
	size_t allocation;

	if (size < sizeof(*detail))
		return;
	rx_context_expire(state, detail->pkt.ts);
	if (detail->direction != PACKET_DIRECTION_RX || !detail->key ||
	    !detail->key_generation) {
		if (detail->owner_pending)
			state->unresolved++;
		else
			emit(data, cpu, size);
		return;
	}
	owner = &state->owners[((detail->key >> 4) ^ detail->key_generation) %
			      RX_CONTEXT_OWNER_SLOTS];
	if (!detail->owner_pending) {
		if (detail->owner_evidence == 1 && detail->owner_valid &&
		    detail->owner_socket_key && detail->owner_socket_generation) {
			struct rx_context_owner evidence = {
				.key = detail->key, .generation = detail->key_generation,
				.timestamp = detail->pkt.ts, .socket_key = detail->owner_socket_key,
				.socket_generation = detail->owner_socket_generation,
				.tid = detail->owner_tid, .tgid = detail->owner_tgid,
				.uid = detail->owner_uid,
			};
			/* Collisions only evict evidence; they cannot assign another skb. */
			if (owner->key != evidence.key || owner->generation != evidence.generation ||
			    owner->timestamp <= evidence.timestamp)
				*owner = evidence;
			link = &state->head;
			state->tail = NULL;
			while ((entry = *link)) {
				if (rx_context_matches(&entry->detail, &evidence)) {
					rx_context_apply(&entry->detail, &evidence);
					emit(&entry->detail, entry->cpu, entry->size);
					state->replayed++;
					rx_context_remove(state, link);
				} else {
					state->tail = entry;
					link = &entry->next;
				}
			}
		}
		emit(data, cpu, size);
		return;
	}
	if (state->watermark - detail->pkt.ts > RX_CONTEXT_WINDOW_NS) {
		state->expired++;
		return;
	}
	allocation = sizeof(*entry) + size - sizeof(*detail);
	if (allocation + sizeof(state->owners) > RX_CONTEXT_MAX_BYTES) {
		state->capacity_dropped++;
		return;
	}
	entry = malloc(allocation);
	if (!entry) {
		state->capacity_dropped++;
		return;
	}
	entry->cpu = cpu;
	entry->size = size;
	memcpy(&entry->detail, data, size);
	if (rx_context_matches(detail, owner)) {
		rx_context_apply(&entry->detail, owner);
		emit(&entry->detail, cpu, size);
		state->replayed++;
		free(entry);
		return;
	}
	while (state->count >= RX_CONTEXT_MAX_EVENTS ||
	       state->bytes + allocation + sizeof(state->owners) > RX_CONTEXT_MAX_BYTES) {
		rx_context_remove(state, &state->head);
		state->capacity_dropped++;
	}
	if (!state->tail || state->tail->detail.pkt.ts <= detail->pkt.ts) {
		entry->next = NULL;
		if (state->tail)
			state->tail->next = entry;
		else
			state->head = entry;
		state->tail = entry;
	} else {
		link = &state->head;
		while (*link && (*link)->detail.pkt.ts <= detail->pkt.ts)
			link = &(*link)->next;
		entry->next = *link;
		*link = entry;
	}
	state->count++;
	state->bytes += allocation;
}

static void rx_context_finish(struct rx_context *state)
{
	while (state->head) {
		rx_context_remove(state, &state->head);
		state->unresolved++;
	}
	memset(state->owners, 0, sizeof(state->owners));
}

#endif
