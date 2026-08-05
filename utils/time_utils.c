// SPDX-License-Identifier: MulanPSL-2.0

#include <ctype.h>
#include <errno.h>
#include <string.h>

#include "time_utils.h"

int timezone_parse_offset(const char *value, long *seconds)
{
	int hours, minutes, sign;
	const char *tail;

	if (!value || !seconds || strlen(value) < 5 ||
	    (value[0] != '+' && value[0] != '-'))
		return -EINVAL;
	if (!isdigit((unsigned char)value[1]) ||
	    !isdigit((unsigned char)value[2]) ||
	    !isdigit((unsigned char)value[3]) ||
	    !isdigit((unsigned char)value[4]))
		return -EINVAL;

	hours = (value[1] - '0') * 10 + value[2] - '0';
	minutes = (value[3] - '0') * 10 + value[4] - '0';
	if (hours > 23 || minutes > 59)
		return -ERANGE;

	for (tail = value + 5; *tail; tail++) {
		if (!isspace((unsigned char)*tail))
			return -EINVAL;
	}

	sign = value[0] == '-' ? -1 : 1;
	*seconds = sign * (hours * 3600L + minutes * 60L);
	return 0;
}
