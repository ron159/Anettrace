// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_PERFETTO_EXPORT
#define _H_PERFETTO_EXPORT

#include <stdbool.h>
#include <linux/types.h>

int perfetto_export_open(const char *path);
int perfetto_export_native_open(const char *path);
void perfetto_export_event(const void *data, int cpu, __u32 size);
void perfetto_export_lost(int cpu, __u64 count);
void perfetto_export_tick(void);
void perfetto_export_close(__u64 event_count);
bool perfetto_export_enabled(void);
bool perfetto_export_failed(void);

#endif
