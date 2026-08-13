// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "perfetto_trim.h"

static int write_all(int fd, const unsigned char *data, size_t size)
{
	while (size) {
		ssize_t count = write(fd, data, size);

		if (count <= 0)
			return -1;
		data += count;
		size -= count;
	}
	return 0;
}

static int run_trim_test(void)
{
	static const unsigned char input[] = {
		0x0a, 0x02, 0x32, 0x00,
		0x0a, 0x02, 0x40, 0x64,
		0x0a, 0x03, 0x40, 0xc8, 0x01,
		0x0a, 0x0d, 0x0a, 0x0b, 0x08, 0x00,
		0x12, 0x02, 0x08, 0x64,
		0x12, 0x03, 0x08, 0xc8, 0x01,
	};
	static const unsigned char expected[] = {
		0x0a, 0x02, 0x32, 0x00,
		0x0a, 0x03, 0x40, 0xc8, 0x01,
		0x0a, 0x09, 0x0a, 0x07, 0x08, 0x00,
		0x12, 0x03, 0x08, 0xc8, 0x01,
	};
	unsigned char actual[sizeof(input)] = {};
	char path[] = "/tmp/anettrace-perfetto-trim.XXXXXX";
	ssize_t size;
	int fd = mkstemp(path);
	int result = 1;

	if (fd < 0 || write_all(fd, input, sizeof(input)) || close(fd))
		goto cleanup;
	fd = -1;
	if (perfetto_trim_file(path, 150, 150))
		goto cleanup;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto cleanup;
	size = read(fd, actual, sizeof(actual));
	if (size == (ssize_t)sizeof(expected) &&
	    !memcmp(actual, expected, sizeof(expected)))
		result = 0;

cleanup:
	if (fd >= 0)
		close(fd);
	unlink(path);
	return result;
}

static int run_compact_sched_rejection_test(void)
{
	static const unsigned char input[] = {
		0x0a, 0x04, 0x0a, 0x02, 0x22, 0x00,
	};
	unsigned char actual[sizeof(input)] = {};
	char path[] = "/tmp/anettrace-perfetto-compact.XXXXXX";
	ssize_t size;
	int fd = mkstemp(path);
	int result = 1;

	if (fd < 0 || write_all(fd, input, sizeof(input)) || close(fd))
		goto cleanup;
	fd = -1;
	if (perfetto_trim_file(path, 150, 150) != -ENOTSUP)
		goto cleanup;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto cleanup;
	size = read(fd, actual, sizeof(actual));
	if (size == (ssize_t)sizeof(input) &&
	    !memcmp(actual, input, sizeof(input)))
		result = 0;

cleanup:
	if (fd >= 0)
		close(fd);
	unlink(path);
	return result;
}

static int run_sequence_clock_default_test(void)
{
	static const unsigned char input[] = {
		0x0a, 0x08, 0x50, 0x07, 0xda, 0x03, 0x03, 0xd0, 0x03, 0x03,
		0x0a, 0x04, 0x50, 0x07, 0x40, 0x64,
		0x0a, 0x05, 0x50, 0x07, 0x40, 0xc8, 0x01,
	};
	static const unsigned char expected[] = {
		0x0a, 0x08, 0x50, 0x07, 0xda, 0x03, 0x03, 0xd0, 0x03, 0x03,
		0x0a, 0x05, 0x50, 0x07, 0x40, 0xc8, 0x01,
	};
	unsigned char actual[sizeof(input)] = {};
	char path[] = "/tmp/anettrace-perfetto-default.XXXXXX";
	ssize_t size;
	int fd = mkstemp(path);
	int result = 1;

	if (fd < 0 || write_all(fd, input, sizeof(input)) || close(fd))
		goto cleanup;
	fd = -1;
	if (perfetto_trim_file(path, 50, 150))
		goto cleanup;
	fd = open(path, O_RDONLY);
	if (fd < 0)
		goto cleanup;
	size = read(fd, actual, sizeof(actual));
	if (size == (ssize_t)sizeof(expected) &&
	    !memcmp(actual, expected, sizeof(expected)))
		result = 0;

cleanup:
	if (fd >= 0)
		close(fd);
	unlink(path);
	return result;
}

int main(int argc, char **argv)
{
	if (argc == 3) {
		uint64_t cutoff = strtoull(argv[2], NULL, 10);
		int err = perfetto_trim_file(argv[1], cutoff, cutoff);

		if (err)
			fprintf(stderr, "trim failed: %s (%d)\n", strerror(-err), err);
		return err ? 1 : 0;
	}
	if (run_trim_test()) {
		fprintf(stderr, "Perfetto time-window trim test failed\n");
		return 1;
	}
	if (run_compact_sched_rejection_test()) {
		fprintf(stderr, "compact sched rejection test failed\n");
		return 1;
	}
	if (run_sequence_clock_default_test()) {
		fprintf(stderr, "sequence clock default test failed\n");
		return 1;
	}
	return 0;
}
