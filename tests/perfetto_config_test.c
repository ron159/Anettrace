// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "perfetto_config.h"

#define CHECK(condition) do { \
	if (!(condition)) { \
		fprintf(stderr, "check failed at %s:%d: %s\n", \
			__FILE__, __LINE__, #condition); \
		exit(1); \
	} \
} while (0)

static int write_all(int fd, const char *text)
{
	size_t left = strlen(text);

	while (left) {
		ssize_t written = write(fd, text, left);

		if (written > 0) {
			text += written;
			left -= written;
			continue;
		}
		if (written < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static char *render(const char *input, uint32_t duration_s, bool ring_buffer)
{
	char input_path[] = "/tmp/anettrace-config-input-XXXXXX";
	char output_path[] = "/tmp/anettrace-config-output-XXXXXX";
	char *result;
	ssize_t count;
	int input_fd = mkstemp(input_path);
	int output_fd = mkstemp(output_path);

	CHECK(input_fd >= 0);
	CHECK(output_fd >= 0);
	CHECK(write_all(input_fd, input) == 0);
	CHECK(close(input_fd) == 0);
	CHECK(perfetto_config_write_custom(output_fd, input_path, duration_s,
					  ring_buffer) == 0);
	CHECK(lseek(output_fd, 0, SEEK_SET) == 0);
	result = calloc(1, 16384);
	CHECK(result != NULL);
	count = read(output_fd, result, 16383);
	CHECK(count >= 0);
	CHECK(close(output_fd) == 0);
	CHECK(unlink(input_path) == 0);
	CHECK(unlink(output_path) == 0);
	return result;
}

static void test_finite_capture_owns_top_level_duration(void)
{
	const char *input =
		"buffers: { size_kb: 4096 }\n"
		"duration_ms: 1234\n"
		"data_sources: { config { name: \"vendor.test\" "
		"duration_ms: 55 } }\n"
		"data_sources: < config: < name: \"vendor.angle\" "
		"duration_ms: 66 > >\n"
		"# duration_ms: 9999\n"
		"unknown_field: \"duration_ms: 7777\"\n";
	char *output = render(input, 10, false);

	CHECK(strstr(output, "duration_ms: 1234") == NULL);
	CHECK(strstr(output, "duration_ms: 11000") != NULL);
	CHECK(strstr(output, "duration_ms: 55") != NULL);
	CHECK(strstr(output, "duration_ms: 66") != NULL);
	CHECK(strstr(output, "# duration_ms: 9999") != NULL);
	CHECK(strstr(output, "\"duration_ms: 7777\"") != NULL);
	free(output);
}

static void test_inline_duration_is_removed(void)
{
	const char *input =
		"buffers: { size_kb: 4096 } duration_ms : 0; "
		"data_sources: { config { name: \"linux.ftrace\" } }\n";
	char *output = render(input, 3, false);

	CHECK(strstr(output, "duration_ms : 0") == NULL);
	CHECK(strstr(output, "duration_ms: 4000") != NULL);
	CHECK(strstr(output, "linux.ftrace") != NULL);
	free(output);
}

static void test_ring_capture_removes_fixed_duration(void)
{
	char *output = render("buffers: {}\nduration_ms: 60000\n", 30, true);

	CHECK(strstr(output, "duration_ms") == NULL);
	CHECK(strstr(output, "buffers: {}") != NULL);
	free(output);
}

int main(void)
{
	test_finite_capture_owns_top_level_duration();
	test_inline_duration_is_removed();
	test_ring_capture_removes_fixed_duration();
	return 0;
}
