// SPDX-License-Identifier: MulanPSL-2.0

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef TCP_USER_TIMEOUT
#define TCP_USER_TIMEOUT 18
#endif

#ifndef TCP_SYNCNT
#define TCP_SYNCNT 7
#endif

#ifndef INADDR_LOOPBACK
#define INADDR_LOOPBACK 0x7f000001UL
#endif

static void fail(const char *message)
{
	perror(message);
	exit(1);
}

static void drop_to_uid(uid_t uid)
{
	if (setgid(uid) || setuid(uid))
		fail("setuid/setgid");
}

static int connect_numeric(const char *address, unsigned short port,
			   bool shorten_timeout)
{
	struct sockaddr_storage storage = {};
	struct sockaddr *peer = (void *)&storage;
	socklen_t peer_size;
	int family, fd, value = 1;

	if (strchr(address, ':')) {
		struct sockaddr_in6 *ipv6 = (void *)&storage;

		family = AF_INET6;
		peer_size = sizeof(*ipv6);
		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = htons(port);
		if (inet_pton(AF_INET6, address, &ipv6->sin6_addr) != 1)
			fail("invalid IPv6 address");
	} else {
		struct sockaddr_in *ipv4 = (void *)&storage;

		family = AF_INET;
		peer_size = sizeof(*ipv4);
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons(port);
		if (inet_pton(AF_INET, address, &ipv4->sin_addr) != 1)
			fail("invalid IPv4 address");
	}
	fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0)
		fail("socket");
	if (shorten_timeout) {
		int milliseconds = 4000;

		if (setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &value, sizeof(value)))
			fail("TCP_SYNCNT");
		if (setsockopt(fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &milliseconds,
			       sizeof(milliseconds)))
			fail("TCP_USER_TIMEOUT");
	}
	if (!connect(fd, peer, peer_size)) {
		close(fd);
		return 0;
	}
	value = errno;
	close(fd);
	return -value;
}

static int child_result(pid_t child)
{
	int status;

	if (waitpid(child, &status, 0) != child)
		fail("waitpid");
	return WIFEXITED(status) ? WEXITSTATUS(status) : 255;
}

static unsigned long long monotonic_ms(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		fail("clock_gettime");
	return (unsigned long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void sleep_milliseconds(int milliseconds)
{
	struct timespec delay = {
		.tv_sec = milliseconds / 1000,
		.tv_nsec = (long)(milliseconds % 1000) * 1000000,
	};

	while (nanosleep(&delay, &delay) && errno == EINTR)
		;
}

static int run_success(uid_t uid, bool quiet)
{
	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t size = sizeof(local);
	int listener, accepted;
	pid_t child;

	listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (listener < 0 || bind(listener, (void *)&local, sizeof(local)) ||
	    listen(listener, 1) || getsockname(listener, (void *)&local, &size))
		fail("success listener");
	child = fork();
	if (child < 0)
		fail("fork success");
	if (!child) {
		int result;

		drop_to_uid(uid);
		result = connect_numeric("127.0.0.1", ntohs(local.sin_port), false);
		if (!quiet) {
			printf("scenario=success result=%d errno=%d\n", result,
			       result < 0 ? -result : 0);
			fflush(stdout);
		}
		_exit(result == 0 ? 0 : 1);
	}
	accepted = accept(listener, NULL, NULL);
	if (accepted < 0)
		fail("accept");
	close(accepted);
	close(listener);
	return child_result(child);
}

static int unused_loopback_port(void)
{
	struct sockaddr_in local = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	socklen_t size = sizeof(local);
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (fd < 0 || bind(fd, (void *)&local, sizeof(local)) ||
	    getsockname(fd, (void *)&local, &size))
		fail("refused port");
	close(fd);
	return ntohs(local.sin_port);
}

static int run_expected_error(uid_t uid, const char *scenario,
			      const char *address, unsigned short port,
			      int expected_errno, bool shorten_timeout, bool quiet)
{
	pid_t child = fork();

	if (child < 0)
		fail("fork error scenario");
	if (!child) {
		int result;

		drop_to_uid(uid);
		result = connect_numeric(address, port, shorten_timeout);
		if (!quiet) {
			printf("scenario=%s result=%d errno=%d\n", scenario, result,
			       result < 0 ? -result : 0);
			fflush(stdout);
		}
		_exit(result == -expected_errno ? 0 : 1);
	}
	return child_result(child);
}

int main(int argc, char **argv)
{
	const char *scenario = NULL;
	const char *timeout_address = "192.0.2.1";
	uid_t uid = 0;
	int repeat = 1, run_seconds = 0, interval_ms = 0;
	int progress_every = 0, hold_seconds = 0, completed = 0, i;
	bool quiet = false;
	unsigned long long started_ms;

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--uid") && ++i < argc)
			uid = (uid_t)strtoul(argv[i], NULL, 10);
		else if (!strcmp(argv[i], "--scenario") && ++i < argc)
			scenario = argv[i];
		else if (!strcmp(argv[i], "--repeat") && ++i < argc)
			repeat = atoi(argv[i]);
		else if (!strcmp(argv[i], "--run-seconds") && ++i < argc)
			run_seconds = atoi(argv[i]);
		else if (!strcmp(argv[i], "--interval-ms") && ++i < argc)
			interval_ms = atoi(argv[i]);
		else if (!strcmp(argv[i], "--progress-every") && ++i < argc)
			progress_every = atoi(argv[i]);
		else if (!strcmp(argv[i], "--hold-seconds") && ++i < argc)
			hold_seconds = atoi(argv[i]);
		else if (!strcmp(argv[i], "--timeout-address") && ++i < argc)
			timeout_address = argv[i];
		else if (!strcmp(argv[i], "--quiet"))
			quiet = true;
		else {
			fprintf(stderr, "invalid argument: %s\n", argv[i]);
			return 2;
		}
	}
	if (!uid || !scenario || repeat < 1 || repeat > 1000000 ||
	    run_seconds < 0 || run_seconds > 86400 || interval_ms < 0 ||
	    interval_ms > 60000 || progress_every < 0 || hold_seconds < 0)
		return 2;
	started_ms = monotonic_ms();
	for (i = 0; i < repeat || run_seconds; i++) {
		int result;

		if (run_seconds && completed &&
		    monotonic_ms() - started_ms >= (unsigned long long)run_seconds * 1000)
			break;
		if (!strcmp(scenario, "success"))
			result = run_success(uid, quiet);
		else if (!strcmp(scenario, "refused"))
			result = run_expected_error(uid, scenario, "127.0.0.1",
						    unused_loopback_port(),
						    ECONNREFUSED, false, quiet);
		else if (!strcmp(scenario, "timeout"))
			result = run_expected_error(uid, scenario, timeout_address, 443,
						    ETIMEDOUT, true, quiet);
		else
			return 2;
		if (result)
			return result;
		completed++;
		if (progress_every && completed % progress_every == 0) {
			printf("scenario=%s completed=%d progress=true\n", scenario,
			       completed);
			fflush(stdout);
		}
		if (interval_ms)
			sleep_milliseconds(interval_ms);
	}
	printf("scenario=%s completed=%d elapsed_ms=%llu complete=true\n", scenario,
	       completed, monotonic_ms() - started_ms);
	fflush(stdout);
	if (hold_seconds)
		sleep((unsigned int)hold_seconds);
	return 0;
}
