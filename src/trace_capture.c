// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <sys_utils.h>

#include "output.h"
#include "trace_capture.h"

struct capture_state {
	pid_t perfetto_pid;
	char output[PATH_MAX];
	char system_trace[PATH_MAX];
	char network_trace[PATH_MAX];
	char config[PATH_MAX];
	bool started;
};

static struct capture_state capture;

static const char perfetto_config[] =
	"buffers: { size_kb: 32768 fill_policy: RING_BUFFER }\n"
	"data_sources: { config { name: \"linux.ftrace\" target_buffer: 0 "
	"ftrace_config {\n"
	"ftrace_events: \"sched/sched_switch\"\n"
	"ftrace_events: \"sched/sched_waking\"\n"
	"ftrace_events: \"sched/sched_wakeup\"\n"
	"ftrace_events: \"sched/sched_process_exec\"\n"
	"ftrace_events: \"sched/sched_process_exit\"\n"
	"ftrace_events: \"power/suspend_resume\"\n"
	"compact_sched { enabled: true }\n"
	"} } }\n"
	"data_sources: { config { name: \"linux.process_stats\" target_buffer: 0 "
	"process_stats_config { scan_all_processes_on_start: true "
	"proc_stats_poll_ms: 1000 } } }\n"
	"duration_ms: %llu\n";

static int make_default_name(char *path, size_t size, const char *directory)
{
	struct tm local = {};
	char timestamp[32];
	time_t now = time(NULL);

	if (!localtime_r(&now, &local) ||
	    !strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &local))
		return -EIO;
	if (snprintf(path, size, "%s/anettrace-%s.pftrace",
		     directory ? directory : ".", timestamp) >= (int)size)
		return -ENAMETOOLONG;
	return 0;
}

static int resolve_output(const char *requested)
{
	struct stat status;

	if (!requested)
		return make_default_name(capture.output, sizeof(capture.output), NULL);
	if (!stat(requested, &status) && S_ISDIR(status.st_mode))
		return make_default_name(capture.output, sizeof(capture.output),
				 requested);
	if (strlen(requested) >= sizeof(capture.output))
		return -ENAMETOOLONG;
	strcpy(capture.output, requested);
	return 0;
}

static int temporary_path(char *dest, size_t size, const char *suffix)
{
	if (snprintf(dest, size, "%s.%s.tmp", capture.output, suffix) >=
	    (int)size)
		return -ENAMETOOLONG;
	if (!access(dest, F_OK))
		return -EEXIST;
	return 0;
}

static int system_temporary_paths(void)
{
#ifdef ANETTRACE_ANDROID_TARGET
	struct timespec now;
	unsigned long long nonce;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return -errno;
	nonce = (unsigned long long)now.tv_nsec;
	if (snprintf(capture.system_trace, sizeof(capture.system_trace),
		     "/data/misc/perfetto-traces/anettrace-%d-%llu.pftrace",
		     getpid(), nonce) >= (int)sizeof(capture.system_trace) ||
	    snprintf(capture.config, sizeof(capture.config),
		     "/data/misc/perfetto-configs/anettrace-%d-%llu.pbtxt",
		     getpid(), nonce) >= (int)sizeof(capture.config))
		return -ENAMETOOLONG;
	if (!access(capture.system_trace, F_OK) || !access(capture.config, F_OK))
		return -EEXIST;
	return 0;
#else
	int err;

	err = temporary_path(capture.system_trace, sizeof(capture.system_trace),
			     "system");
	if (err)
		return err;
	return temporary_path(capture.config, sizeof(capture.config), "config");
#endif
}

static int write_all(int fd, const void *data, size_t size)
{
	const unsigned char *cursor = data;

	while (size) {
		ssize_t written = write(fd, cursor, size);

		if (written > 0) {
			cursor += written;
			size -= written;
			continue;
		}
		if (written < 0 && errno == EINTR)
			continue;
		return errno ? -errno : -EIO;
	}
	return 0;
}

static int write_config(__u32 duration_s)
{
	char config_text[2048];
	int length, fd, err;

	/* Keep the system trace alive slightly longer than the network capture. */
	length = snprintf(config_text, sizeof(config_text), perfetto_config,
			  ((unsigned long long)duration_s + 1) * 1000);
	if (length < 0 || length >= (int)sizeof(config_text))
		return -EOVERFLOW;
	fd = open(capture.config,
		  O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	err = write_all(fd, config_text, length);
	if (close(fd) && !err)
		err = -errno;
	return err;
}

static int wait_child(pid_t pid, unsigned int timeout_ms, int *status)
{
	unsigned int waited = 0;

	while (waited <= timeout_ms) {
		pid_t result = waitpid(pid, status, WNOHANG);

		if (result == pid)
			return 0;
		if (result < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (waited == timeout_ms)
			break;
		usleep(50000);
		waited += 50;
	}
	return -ETIMEDOUT;
}

static int file_nonempty(const char *path)
{
	struct stat status;

	if (stat(path, &status))
		return -errno;
	return status.st_size > 0 ? 0 : -ENODATA;
}

static int copy_file(int output_fd, const char *path)
{
	unsigned char buffer[64 * 1024];
	int input_fd, err = 0;

	input_fd = open(path, O_RDONLY | O_CLOEXEC);
	if (input_fd < 0)
		return -errno;
	for (;;) {
		ssize_t count = read(input_fd, buffer, sizeof(buffer));

		if (count > 0) {
			err = write_all(output_fd, buffer, count);
			if (err)
				break;
			continue;
		}
		if (!count)
			break;
		if (errno == EINTR)
			continue;
		err = -errno;
		break;
	}
	close(input_fd);
	return err;
}

static int merge_traces(void)
{
	char temporary[PATH_MAX];
	int fd, err;

	err = temporary_path(temporary, sizeof(temporary), "combined");
	if (err)
		return err;
	fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	err = copy_file(fd, capture.system_trace);
	if (!err)
		err = copy_file(fd, capture.network_trace);
	if (!err && fsync(fd))
		err = -errno;
	if (close(fd) && !err)
		err = -errno;
	if (!err && !access(capture.output, F_OK))
		err = -EEXIST;
	if (!err && rename(temporary, capture.output))
		err = -errno;
	if (err)
		unlink(temporary);
	return err;
}

static void cleanup_temporary(void)
{
	if (capture.system_trace[0])
		unlink(capture.system_trace);
	if (capture.network_trace[0])
		unlink(capture.network_trace);
	if (capture.config[0])
		unlink(capture.config);
}

int trace_capture_start(const char *output, __u32 duration_s)
{
	struct timespec startup_wait = { .tv_nsec = 250 * 1000 * 1000 };
	int status, err;

	memset(&capture, 0, sizeof(capture));
	if (!duration_s)
		return -EINVAL;
	err = resolve_output(output);
	if (err)
		goto fail;
	if (!access(capture.output, F_OK)) {
		err = -EEXIST;
		goto fail;
	}
	err = temporary_path(capture.network_trace, sizeof(capture.network_trace),
			     "anettrace");
	if (err)
		goto fail;
	err = system_temporary_paths();
	if (err)
		goto fail;
	err = write_config(duration_s);
	if (err)
		goto fail;

	capture.perfetto_pid = fork();
	if (capture.perfetto_pid < 0) {
		err = -errno;
		goto fail;
	}
	if (!capture.perfetto_pid) {
		execl("/system/bin/perfetto", "perfetto", "--txt", "-c",
		      capture.config, "-o", capture.system_trace, NULL);
		execlp("perfetto", "perfetto", "--txt", "-c", capture.config,
		       "-o", capture.system_trace, NULL);
		_exit(127);
	}
	capture.started = true;
	nanosleep(&startup_wait, NULL);
	err = waitpid(capture.perfetto_pid, &status, WNOHANG);
	if (err == capture.perfetto_pid) {
		capture.started = false;
		err = -ECHILD;
		goto fail;
	}
	if (err < 0) {
		err = -errno;
		goto fail;
	}
	pr_info("system Perfetto capture started (pid %d)\n",
		capture.perfetto_pid);
	return 0;

fail:
	trace_capture_abort();
	pr_err("failed to start combined trace capture: %s\n", strerror(-err));
	return err;
}

const char *trace_capture_network_path(void)
{
	return capture.network_trace[0] ? capture.network_trace : NULL;
}

int trace_capture_finish(void)
{
	int status = 0, err;

	if (!capture.started)
		return -EINVAL;
	err = wait_child(capture.perfetto_pid, 250, &status);
	if (err == -ETIMEDOUT) {
		kill(capture.perfetto_pid, SIGTERM);
		err = wait_child(capture.perfetto_pid, 5000, &status);
	}
	capture.started = false;
	if (err) {
		pr_err("system Perfetto did not stop cleanly: %s\n", strerror(-err));
		goto out;
	}
	err = file_nonempty(capture.system_trace);
	if (err) {
		pr_err("system Perfetto trace is missing or empty\n");
		goto out;
	}
	err = file_nonempty(capture.network_trace);
	if (err) {
		pr_err("Anettrace Perfetto trace is missing or empty\n");
		goto out;
	}
	err = merge_traces();
	if (err) {
		pr_err("failed to create combined trace %s: %s\n",
		       capture.output, strerror(-err));
		goto out;
	}
	pr_info("combined trace: %s\n", capture.output);

out:
	cleanup_temporary();
	return err;
}

void trace_capture_abort(void)
{
	int status;

	if (capture.started) {
		kill(capture.perfetto_pid, SIGTERM);
		if (wait_child(capture.perfetto_pid, 2000, &status) == -ETIMEDOUT) {
			kill(capture.perfetto_pid, SIGKILL);
			while (waitpid(capture.perfetto_pid, &status, 0) < 0 &&
			       errno == EINTR)
				;
		}
		capture.started = false;
	}
	cleanup_temporary();
}
