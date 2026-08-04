// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_NETTRACE
#define _H_NETTRACE

#include "output.h"

#define pr_version()							\
	pr_info("Anettrace " macro_to_str(VERSION)			\
		" (upstream nettrace btf " macro_to_str(UPSTREAM_BTF_COMMIT)\
		", " macro_to_str(BUILD_TYPE) ", "			\
		macro_to_str(TARGET_PLATFORM) ")\n")

#endif
