// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_PERFETTO_TRIM
#define _H_PERFETTO_TRIM

#include <stdint.h>

/* Descriptors remain owned by the caller. Output is written at its current offset. */
int perfetto_trim_stream(int input_fd, int output_fd,
			uint64_t boottime_cutoff_ns, uint64_t monotonic_cutoff_ns);

int perfetto_trim_file(const char *path, uint64_t boottime_cutoff_ns,
		       uint64_t monotonic_cutoff_ns);

#endif
