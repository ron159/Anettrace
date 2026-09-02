// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_TRACE_CAPTURE
#define _H_TRACE_CAPTURE

#include <stdbool.h>
#include <linux/types.h>

int trace_capture_start(const char *output, __u32 duration_s,
			const char *profile, const char *perfetto_config,
			bool ring_buffer);
const char *trace_capture_network_path(void);
void trace_capture_stop(void);
int trace_capture_finish(void);
void trace_capture_abort(void);

#endif
