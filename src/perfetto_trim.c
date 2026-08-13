// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "perfetto_trim.h"

#define PERFETTO_CLOCK_BOOTTIME 6
#define PERFETTO_CLOCK_MONOTONIC 3

struct byte_buffer {
	unsigned char *data;
	size_t size;
	size_t capacity;
};

struct wire_field {
	const unsigned char *start;
	const unsigned char *payload;
	const unsigned char *end;
	uint64_t key;
	uint64_t value;
	size_t payload_size;
	unsigned int number;
	unsigned int wire;
};

struct clock_default {
	struct clock_default *next;
	uint64_t sequence_id;
	uint64_t clock_id;
};

struct trim_state {
	struct clock_default *clock_defaults;
};

static int decode_varint(const unsigned char *cursor,
			 const unsigned char *end, uint64_t *value,
			 const unsigned char **next)
{
	uint64_t result = 0;
	unsigned int shift;

	for (shift = 0; shift < 64 && cursor < end; shift += 7) {
		unsigned char byte = *cursor++;

		if (shift == 63 && byte > 1)
			return -EBADMSG;
		result |= (uint64_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80)) {
			*value = result;
			*next = cursor;
			return 0;
		}
	}
	return -EBADMSG;
}

static int next_field(const unsigned char **cursor,
		      const unsigned char *end, struct wire_field *field)
{
	const unsigned char *position = *cursor;
	uint64_t length;
	int err;

	memset(field, 0, sizeof(*field));
	field->start = position;
	err = decode_varint(position, end, &field->key, &position);
	if (err || !field->key)
		return -EBADMSG;
	field->number = field->key >> 3;
	field->wire = field->key & 7;
	switch (field->wire) {
	case 0:
		err = decode_varint(position, end, &field->value, &position);
		if (err)
			return err;
		break;
	case 1:
		if ((size_t)(end - position) < 8)
			return -EBADMSG;
		position += 8;
		break;
	case 2:
		err = decode_varint(position, end, &length, &position);
		if (err || length > (uint64_t)(end - position))
			return -EBADMSG;
		field->payload = position;
		field->payload_size = (size_t)length;
		position += field->payload_size;
		break;
	case 5:
		if ((size_t)(end - position) < 4)
			return -EBADMSG;
		position += 4;
		break;
	default:
		return -EPROTOTYPE;
	}
	field->end = position;
	*cursor = position;
	return 0;
}

static int buffer_reserve(struct byte_buffer *buffer, size_t extra)
{
	size_t capacity;
	void *data;

	if (extra <= buffer->capacity - buffer->size)
		return 0;
	capacity = buffer->capacity ? buffer->capacity : 4096;
	while (capacity - buffer->size < extra) {
		if (capacity > SIZE_MAX / 2)
			return -EOVERFLOW;
		capacity *= 2;
	}
	data = realloc(buffer->data, capacity);
	if (!data)
		return -ENOMEM;
	buffer->data = data;
	buffer->capacity = capacity;
	return 0;
}

static int buffer_append(struct byte_buffer *buffer, const void *data,
			 size_t size)
{
	int err;

	if (!size)
		return 0;
	err = buffer_reserve(buffer, size);
	if (err)
		return err;
	memcpy(buffer->data + buffer->size, data, size);
	buffer->size += size;
	return 0;
}

static int buffer_varint(struct byte_buffer *buffer, uint64_t value)
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
	return buffer_append(buffer, encoded, count);
}

static int buffer_field(struct byte_buffer *buffer,
			const struct wire_field *field)
{
	return buffer_append(buffer, field->start,
			     (size_t)(field->end - field->start));
}

static int message_varint(const struct wire_field *message,
			  unsigned int number, uint64_t *value,
			  bool *present)
{
	const unsigned char *cursor = message->payload;
	const unsigned char *end = cursor + message->payload_size;

	*present = false;
	while (cursor < end) {
		struct wire_field field;
		int err = next_field(&cursor, end, &field);

		if (err)
			return err;
		if (field.number == number && field.wire == 0) {
			*value = field.value;
			*present = true;
		}
	}
	return 0;
}

static bool clock_default_get(const struct trim_state *state,
			      uint64_t sequence_id, uint64_t *clock_id)
{
	const struct clock_default *entry;

	for (entry = state->clock_defaults; entry; entry = entry->next) {
		if (entry->sequence_id != sequence_id)
			continue;
		*clock_id = entry->clock_id;
		return true;
	}
	return false;
}

static int clock_default_set(struct trim_state *state, uint64_t sequence_id,
			     uint64_t clock_id)
{
	struct clock_default *entry;

	for (entry = state->clock_defaults; entry; entry = entry->next) {
		if (entry->sequence_id == sequence_id) {
			entry->clock_id = clock_id;
			return 0;
		}
	}
	entry = malloc(sizeof(*entry));
	if (!entry)
		return -ENOMEM;
	entry->sequence_id = sequence_id;
	entry->clock_id = clock_id;
	entry->next = state->clock_defaults;
	state->clock_defaults = entry;
	return 0;
}

static void trim_state_free(struct trim_state *state)
{
	struct clock_default *entry = state->clock_defaults;

	while (entry) {
		struct clock_default *next = entry->next;

		free(entry);
		entry = next;
	}
}

static int event_timestamp(const struct wire_field *event,
			   uint64_t *timestamp, bool *present)
{
	const unsigned char *cursor = event->payload;
	const unsigned char *end = cursor + event->payload_size;

	*present = false;
	while (cursor < end) {
		struct wire_field field;
		int err = next_field(&cursor, end, &field);

		if (err)
			return err;
		if (field.number == 1 && field.wire == 0) {
			*timestamp = field.value;
			*present = true;
		}
	}
	return 0;
}

static int trim_ftrace_bundle(const struct wire_field *bundle,
			      uint64_t cutoff_ns,
			      struct byte_buffer *trimmed)
{
	const unsigned char *cursor = bundle->payload;
	const unsigned char *end = cursor + bundle->payload_size;

	while (cursor < end) {
		struct wire_field field;
		uint64_t timestamp = 0;
		bool present;
		int err = next_field(&cursor, end, &field);

		if (err)
			return err;
		if (field.number == 4)
			return -ENOTSUP;
		if (field.number != 2 || field.wire != 2) {
			err = buffer_field(trimmed, &field);
			if (err)
				return err;
			continue;
		}
		err = event_timestamp(&field, &timestamp, &present);
		if (err)
			return err;
		if (!present || timestamp >= cutoff_ns) {
			err = buffer_field(trimmed, &field);
			if (err)
				return err;
		}
	}
	return 0;
}

static int packet_metadata(const unsigned char *packet, size_t size,
			   uint64_t *timestamp, uint64_t *clock_id,
			   uint64_t *sequence_id,
			   uint64_t *default_clock_id,
			   bool *has_timestamp, bool *has_ftrace,
			   bool *has_sequence, bool *has_default_clock)
{
	const unsigned char *cursor = packet;
	const unsigned char *end = packet + size;

	*timestamp = 0;
	*clock_id = 0;
	*has_timestamp = false;
	*has_ftrace = false;
	*has_sequence = false;
	*has_default_clock = false;
	while (cursor < end) {
		struct wire_field field;
		int err = next_field(&cursor, end, &field);

		if (err)
			return err;
		if (field.number == 8 && field.wire == 0) {
			*timestamp = field.value;
			*has_timestamp = true;
		} else if (field.number == 58 && field.wire == 0) {
			*clock_id = field.value;
		} else if (field.number == 10 && field.wire == 0) {
			*sequence_id = field.value;
			*has_sequence = true;
		} else if (field.number == 1 && field.wire == 2) {
			*has_ftrace = true;
		} else if (field.number == 59 && field.wire == 2) {
			err = message_varint(&field, 58, default_clock_id,
					     has_default_clock);
			if (err)
				return err;
		} else if (field.number == 50 || field.number == 133) {
			return -EPROTONOSUPPORT;
		}
	}
	return 0;
}

static int trim_packet(const unsigned char *packet, size_t size,
		       uint64_t boottime_cutoff_ns,
		       uint64_t monotonic_cutoff_ns,
		       struct trim_state *state,
		       struct byte_buffer *trimmed,
		       bool *keep)
{
	const unsigned char *cursor = packet;
	const unsigned char *end = packet + size;
	uint64_t timestamp, clock_id, sequence_id = 0, default_clock_id = 0;
	bool has_timestamp, has_ftrace, has_sequence, has_default_clock;
	int err;

	*keep = false;
	err = packet_metadata(packet, size, &timestamp, &clock_id,
			      &sequence_id, &default_clock_id,
			      &has_timestamp, &has_ftrace,
			      &has_sequence, &has_default_clock);
	if (err)
		return err;
	if (has_sequence && has_default_clock) {
		err = clock_default_set(state, sequence_id, default_clock_id);
		if (err)
			return err;
	}
	if (!clock_id && has_sequence)
		clock_default_get(state, sequence_id, &clock_id);
	if (!has_ftrace && has_timestamp) {
		if ((!clock_id || clock_id == PERFETTO_CLOCK_BOOTTIME) &&
		    timestamp < boottime_cutoff_ns)
			return 0;
		if (clock_id == PERFETTO_CLOCK_MONOTONIC &&
		    timestamp < monotonic_cutoff_ns)
			return 0;
	}
	while (cursor < end) {
		struct wire_field field;

		err = next_field(&cursor, end, &field);
		if (err)
			return err;
		if (field.number == 1 && field.wire == 2) {
			struct byte_buffer bundle = {};

			err = trim_ftrace_bundle(&field, boottime_cutoff_ns,
						  &bundle);
			if (!err)
				err = buffer_varint(trimmed, field.key);
			if (!err)
				err = buffer_varint(trimmed, bundle.size);
			if (!err)
				err = buffer_append(trimmed, bundle.data,
						    bundle.size);
			free(bundle.data);
		} else {
			err = buffer_field(trimmed, &field);
		}
		if (err)
			return err;
	}
	*keep = true;
	return 0;
}

static int read_exact(int fd, void *data, size_t size)
{
	unsigned char *cursor = data;

	while (size) {
		ssize_t count = read(fd, cursor, size);

		if (count > 0) {
			cursor += count;
			size -= count;
			continue;
		}
		if (!count)
			return -EBADMSG;
		if (errno != EINTR)
			return -errno;
	}
	return 0;
}

static int read_varint_fd(int fd, uint64_t *value, bool *eof)
{
	uint64_t result = 0;
	unsigned int shift;

	*eof = false;
	for (shift = 0; shift < 64; shift += 7) {
		unsigned char byte;
		ssize_t count;

		do {
			count = read(fd, &byte, 1);
		} while (count < 0 && errno == EINTR);
		if (!count) {
			if (!shift) {
				*eof = true;
				return 0;
			}
			return -EBADMSG;
		}
		if (count < 0)
			return -errno;
		if (shift == 63 && byte > 1)
			return -EBADMSG;
		result |= (uint64_t)(byte & 0x7f) << shift;
		if (!(byte & 0x80)) {
			*value = result;
			return 0;
		}
	}
	return -EBADMSG;
}

static int write_exact(int fd, const void *data, size_t size)
{
	const unsigned char *cursor = data;

	while (size) {
		ssize_t count = write(fd, cursor, size);

		if (count > 0) {
			cursor += count;
			size -= count;
			continue;
		}
		if (count < 0 && errno == EINTR)
			continue;
		return errno ? -errno : -EIO;
	}
	return 0;
}

static int write_varint_fd(int fd, uint64_t value)
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
	return write_exact(fd, encoded, count);
}

static int trim_stream_packets(int input_fd, int output_fd,
			       uint64_t boottime_cutoff_ns,
			       uint64_t monotonic_cutoff_ns,
			       struct trim_state *state)
{
	for (;;) {
		struct byte_buffer trimmed = {};
		unsigned char *packet = NULL;
		uint64_t key, size;
		bool eof, keep;
		int err = read_varint_fd(input_fd, &key, &eof);

		if (err || eof)
			return err;
		if (key != ((uint64_t)1 << 3 | 2))
			return -EBADMSG;
		err = read_varint_fd(input_fd, &size, &eof);
		if (err || eof || size > SIZE_MAX)
			return err ? err : -EOVERFLOW;
		packet = malloc(size ? (size_t)size : 1);
		if (!packet)
			return -ENOMEM;
		err = read_exact(input_fd, packet, (size_t)size);
		if (!err)
			err = trim_packet(packet, (size_t)size,
					  boottime_cutoff_ns,
					  monotonic_cutoff_ns,
					  state,
					  &trimmed, &keep);
		free(packet);
		if (!err && keep)
			err = write_varint_fd(output_fd, key);
		if (!err && keep)
			err = write_varint_fd(output_fd, trimmed.size);
		if (!err && keep)
			err = write_exact(output_fd, trimmed.data, trimmed.size);
		free(trimmed.data);
		if (err)
			return err;
	}
}

static int trim_stream(int input_fd, int output_fd,
		       uint64_t boottime_cutoff_ns,
		       uint64_t monotonic_cutoff_ns)
{
	struct trim_state state = {};
	int err = trim_stream_packets(input_fd, output_fd,
				      boottime_cutoff_ns,
				      monotonic_cutoff_ns, &state);

	trim_state_free(&state);
	return err;
}

int perfetto_trim_file(const char *path, uint64_t boottime_cutoff_ns,
		       uint64_t monotonic_cutoff_ns)
{
	char temporary[PATH_MAX];
	int input_fd = -1, output_fd = -1, err, length;

	if (!path)
		return -EINVAL;
	length = snprintf(temporary, sizeof(temporary), "%s.trim.tmp", path);
	if (length < 0)
		return -EIO;
	if (length >= (int)sizeof(temporary))
		return -ENAMETOOLONG;
	input_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (input_fd < 0)
		return -errno;
	output_fd = open(temporary,
			 O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (output_fd < 0) {
		err = -errno;
		goto out;
	}
	err = trim_stream(input_fd, output_fd, boottime_cutoff_ns,
			  monotonic_cutoff_ns);
	if (!err && fsync(output_fd))
		err = -errno;
	if (close(output_fd) && !err)
		err = -errno;
	output_fd = -1;
	if (!err && rename(temporary, path))
		err = -errno;

out:
	if (input_fd >= 0)
		close(input_fd);
	if (output_fd >= 0)
		close(output_fd);
	if (err)
		unlink(temporary);
	return err;
}
