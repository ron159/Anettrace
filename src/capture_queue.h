// SPDX-License-Identifier: MulanPSL-2.0
#ifndef ANETTRACE_CAPTURE_QUEUE_H
#define ANETTRACE_CAPTURE_QUEUE_H

#include <stddef.h>
#include <linux/types.h>

#define CAPTURE_QUEUE_BYTES (32U * 1024 * 1024)

/* Single producer; copies perf callback data before libbpf reuses it. */
int capture_queue_start(size_t capacity);
void capture_queue_event(const void *data, int cpu, __u32 size);
void capture_queue_lost(int cpu, __u64 count);
void capture_queue_tick(void);
/* Joins the exporter after draining all accepted records. */
void capture_queue_stop(void);

#endif
