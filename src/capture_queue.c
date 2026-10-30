// SPDX-License-Identifier: MulanPSL-2.0
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "capture_queue.h"
#include "perfetto_export.h"

/* perf_event_header.size is u16, so a sample cannot exceed 64 KiB. */
#define MAX_SAMPLE_BYTES 65536U

struct queue_record {
	__u32 size;
	int cpu;
	__u64 lost;
};

static struct {
	pthread_mutex_t lock;
	pthread_cond_t available;
	pthread_t thread;
	unsigned char *data;
	size_t capacity, head, tail, used;
	__u64 dropped, kernel_lost;
	bool stopping, tick;
} queue = {
	.lock = PTHREAD_MUTEX_INITIALIZER,
	.available = PTHREAD_COND_INITIALIZER,
};

/* Both copies run under the short queue lock, never during export or I/O. */
static void queue_write(const void *data, size_t size)
{
	size_t first = queue.capacity - queue.head;
	if (first > size)
		first = size;
	memcpy(queue.data + queue.head, data, first);
	memcpy(queue.data, (const unsigned char *)data + first, size - first);
	queue.head = (queue.head + size) % queue.capacity;
	queue.used += size;
}

static void queue_read(void *data, size_t size)
{
	size_t first = queue.capacity - queue.tail;
	if (first > size)
		first = size;
	memcpy(data, queue.data + queue.tail, first);
	memcpy((unsigned char *)data + first, queue.data, size - first);
	queue.tail = (queue.tail + size) % queue.capacity;
	queue.used -= size;
}

static void *capture_export_worker(void *unused)
{
	/* Keep arbitrary event structs aligned after copying out of the byte ring. */
	union { uint64_t align; unsigned char data[MAX_SAMPLE_BYTES]; } sample;
	struct queue_record record;
	(void)unused;

	pthread_mutex_lock(&queue.lock);
	for (;;) {
		while (!queue.used && !queue.stopping && !queue.tick)
			pthread_cond_wait(&queue.available, &queue.lock);
		if (!queue.used) {
			bool stopping = queue.stopping;
			queue.tick = false;
			pthread_mutex_unlock(&queue.lock);
			perfetto_export_tick();
			if (stopping)
				break;
			pthread_mutex_lock(&queue.lock);
			continue;
		}
		queue_read(&record, sizeof(record));
		if (record.size)
			queue_read(sample.data, record.size);
		pthread_mutex_unlock(&queue.lock);
		if (record.lost)
			perfetto_export_lost(record.cpu, record.lost);
		else
			perfetto_export_event(sample.data, record.cpu, record.size);
		pthread_mutex_lock(&queue.lock);
	}
	/* Producer has stopped; retain counts even when a loss record did not fit. */
	if (queue.kernel_lost)
		perfetto_export_lost(-1, queue.kernel_lost);
	if (queue.dropped)
		perfetto_export_queue_lost(queue.dropped);
	return NULL;
}

int capture_queue_start(size_t capacity)
{
	int err;

	if (queue.data)
		return -EBUSY;
	if (capacity < sizeof(struct queue_record) + 1)
		return -EINVAL;
	queue.data = malloc(capacity);
	if (!queue.data)
		return -ENOMEM;
	/* Fault pages before enabling BPF, instead of on the producer hot path. */
	for (size_t i = 0; i < capacity; i += 4096)
		((volatile unsigned char *)queue.data)[i] = 0;
	queue.capacity = capacity;
	queue.head = queue.tail = queue.used = 0;
	queue.dropped = queue.kernel_lost = 0;
	queue.stopping = queue.tick = false;
	err = pthread_create(&queue.thread, NULL, capture_export_worker, NULL);
	if (err) {
		free(queue.data);
		queue.data = NULL;
		return -err;
	}
	return 0;
}

static void capture_queue_push(const void *data, struct queue_record record)
{
	pthread_mutex_lock(&queue.lock);
	if (record.size > MAX_SAMPLE_BYTES ||
	    sizeof(record) + (size_t)record.size > queue.capacity - queue.used) {
		if (record.lost)
			queue.kernel_lost += record.lost;
		else
			queue.dropped++;
	} else {
		bool empty = !queue.used;
		queue_write(&record, sizeof(record));
		if (record.size)
			queue_write(data, record.size);
		if (empty)
			pthread_cond_signal(&queue.available);
	}
	pthread_mutex_unlock(&queue.lock);
}

void capture_queue_event(const void *data, int cpu, __u32 size)
{
	capture_queue_push(data, (struct queue_record){.size = size, .cpu = cpu});
}

void capture_queue_lost(int cpu, __u64 count)
{
	if (count)
		capture_queue_push(NULL, (struct queue_record){.cpu = cpu, .lost = count});
}

void capture_queue_tick(void)
{
	pthread_mutex_lock(&queue.lock);
	queue.tick = true;
	pthread_cond_signal(&queue.available);
	pthread_mutex_unlock(&queue.lock);
}

void capture_queue_stop(void)
{
	if (!queue.data)
		return;
	pthread_mutex_lock(&queue.lock);
	queue.stopping = true;
	pthread_cond_signal(&queue.available);
	pthread_mutex_unlock(&queue.lock);
	pthread_join(queue.thread, NULL);
	free(queue.data);
	queue.data = NULL;
}
