// SPDX-License-Identifier: MulanPSL-2.0

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stdarg.h>
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <limits.h>
#include <zlib.h>

#include "sys_utils.h"

int log_level = 0;

int exec(char *cmd, char *output)
{
	FILE *f = popen(cmd, "r");
	char buf[128];
	int status;

	if (output)
		output[0] = '\0';

	while (fgets(buf, sizeof(buf) - 1, f) != NULL) {
		if (!output)
			continue;
		strcat(output + strlen(output), buf);
	}

	status = pclose(f);
	pr_debug("command: %s, status:%d\n", cmd, WEXITSTATUS(status));
	return WEXITSTATUS(status);
}

int execf(char *output, char *fmt, ...)
{
	static char cmd[1024];
	va_list valist;

	va_start(valist, fmt);
	vsprintf(cmd, fmt, valist);
	va_end(valist);

	return exec(cmd, output);
}

int liberate_l()
{
	struct rlimit lim = {RLIM_INFINITY, RLIM_INFINITY};
	return setrlimit(RLIMIT_MEMLOCK, &lim);
}

bool fsearch(FILE *f, char *target)
{
	char tmp[128];

	while (fscanf(f, "%127s", tmp) == 1) {
		if (strstr(tmp, target))
			return true;
	}
	return false;
}

bool kernel_release_before(const char *release, const char *limit)
{
	unsigned int major, minor, limit_major, limit_minor;

	if (sscanf(release, "%u.%u", &major, &minor) != 2 ||
	    sscanf(limit, "%u.%u", &limit_major, &limit_minor) != 2)
		return false;
	return major < limit_major || (major == limit_major && minor < limit_minor);
}

int kernel_version()
{
	int major, minor, patch;
	struct utsname buf;

	uname(&buf);
	sscanf(buf.release, "%d.%d.%d", &major, &minor, &patch);

	return kv_to_num(major, minor, patch);
}

char *kernel_version_str()
{
	static char version[16];
	int major, minor, patch;
	struct utsname buf;

	uname(&buf);
	sscanf(buf.release, "%d.%d.%d", &major, &minor, &patch);
	sprintf(version, "%d.%d.%d", major, minor, patch);

	return version;
}

const char *get_tracing_path(void)
{
	if (file_exist("/sys/kernel/debug/tracing/events"))
		return "/sys/kernel/debug/tracing";
	if (file_exist("/sys/kernel/tracing/events"))
		return "/sys/kernel/tracing";
	return NULL;
}

bool debugfs_mounted()
{
	return get_tracing_path() != NULL;
}

bool tracepoint_format_has(const char *event, const char *text)
{
	const char *tracing_path = get_tracing_path();
	char path[256], *line = NULL;
	size_t capacity = 0;
	bool found = false;
	FILE *file;

	if (!tracing_path)
		return false;
	snprintf(path, sizeof(path), "%s/events/%s/format", tracing_path, event);
	file = fopen(path, "r");
	if (!file)
		return false;
	while (!found && getline(&line, &capacity, file) >= 0)
		found = strstr(line, text) != NULL;
	free(line);
	fclose(file);
	return found;
}

static bool config_read;
static bool config_btf_modules;
static int config_hz = -ENOTSUP;

static void kernel_read_config(void)
{
	char path[256], line[4096];
	struct utsname kernel;
	bool continuation = false;
	gzFile file;

	if (config_read)
		return;
	config_read = true;
	file = gzopen("/proc/config.gz", "rb");
	if (!file && !uname(&kernel)) {
		snprintf(path, sizeof(path), "/boot/config-%s", kernel.release);
		file = gzopen(path, "rb");
	}
	if (!file)
		return;
	while (gzgets(file, line, sizeof(line))) {
		if (!continuation) {
			if (!strcmp(line, "CONFIG_DEBUG_INFO_BTF_MODULES=y\n") ||
			    !strcmp(line, "CONFIG_DEBUG_INFO_BTF_MODULES=y"))
				config_btf_modules = true;
			if (!strncmp(line, "CONFIG_HZ=", sizeof("CONFIG_HZ=") - 1)) {
				char *end;
				long value = strtol(line + sizeof("CONFIG_HZ=") - 1, &end, 10);

				if (value > 0 && value <= INT_MAX && (*end == '\n' || !*end))
					config_hz = value;
			}
		}
		continuation = !strchr(line, '\n');
	}
	gzclose(file);
}

bool kernel_has_btf_modules(void)
{
	kernel_read_config();
	return config_btf_modules;
}

int kernel_hz()
{
	kernel_read_config();
	return config_hz;
}

u32 file_inode(char *path)
{
	char tmp1[128], tmp2[128];
	struct stat file_stat;
	char *__path = path;
	u32 inode;

	if (!file_exist(path))
		return 0;

again:
	if (sscanf(__path, "%*[^:]:[%u]", &inode) == 1)
		return inode;

	if (stat(__path, &file_stat) == -1)
		return 0;

	if (S_ISLNK(file_stat.st_mode)) {
		if (readlink(path, tmp1, sizeof(tmp1)) == -1)
			return 0;
		memcpy(tmp2, tmp1, sizeof(tmp1));
		__path = tmp2;
		goto again;
	}

	return file_stat.st_ino;
}
