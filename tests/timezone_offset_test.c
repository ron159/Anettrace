// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <stdio.h>

#include "utils/sys_utils.h"

struct offset_case {
	const char *input;
	int expected_status;
	long expected_seconds;
};

int main(void)
{
	static const struct offset_case cases[] = {
		{ "+0800", 0, 8 * 60 * 60 },
		{ "-0530\n", 0, -(5 * 60 * 60 + 30 * 60) },
		{ "+0000 ", 0, 0 },
		{ "0800", -EINVAL, 0 },
		{ "+08:00", -EINVAL, 0 },
		{ "+2400", -ERANGE, 0 },
		{ "+1260", -ERANGE, 0 },
		{ "+0800junk", -EINVAL, 0 },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		long seconds = 123;
		int status = timezone_parse_offset(cases[i].input, &seconds);

		if (status != cases[i].expected_status ||
		    (!status && seconds != cases[i].expected_seconds)) {
			fprintf(stderr, "case %zu failed: status=%d seconds=%ld\n",
				i, status, seconds);
			return 1;
		}
	}

	if (timezone_parse_offset(NULL, NULL) != -EINVAL) {
		fprintf(stderr, "NULL input validation failed\n");
		return 1;
	}

	return 0;
}
