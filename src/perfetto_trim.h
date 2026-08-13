// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_PERFETTO_TRIM
#define _H_PERFETTO_TRIM

#include <stdint.h>

int perfetto_trim_file(const char *path, uint64_t boottime_cutoff_ns,
		       uint64_t monotonic_cutoff_ns);

#endif
