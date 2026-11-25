// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_TRACE_CAPTURE
#define _H_TRACE_CAPTURE

#include <stdbool.h>
#include <signal.h>
#include <linux/types.h>

/* A combined capture prepares its network backend once while Perfetto starts.
 * Pass NULL for prepare_network when only the system trace is requested. */
int trace_capture_start(const char *output, __u32 duration_s,
			const char *profile, const char *perfetto_config,
			bool ring_buffer, int (*prepare_network)(void),
			const volatile sig_atomic_t *stop);
int trace_capture_wait_system(volatile sig_atomic_t *stop);
const char *trace_capture_network_path(void);
void trace_capture_stop(void);
int trace_capture_finish(void);
void trace_capture_abort(void);

#endif
