// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_PERFETTO_CONFIG
#define _H_PERFETTO_CONFIG

#include <stdbool.h>
#include <stdint.h>

int perfetto_config_write_custom(int output_fd, const char *input_path,
				 uint32_t duration_s, bool ring_buffer);

#endif
