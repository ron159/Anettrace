// SPDX-License-Identifier: MulanPSL-2.0
// Deterministic TCP/UDP echo traffic for socket-to-packet trace validation.
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_BYTES 4096
#define MAX_CHUNKS 16

struct options {
	const char *protocol, *host;
	int port, rounds, chunks, bytes, delay_ms, interval_ms, start_delay_ms;
	uid_t uid;
	bool set_uid;
};

static void fail(const char *message)
{
	perror(message);
	exit(1);
}

static void invalid(const char *message)
{
	fprintf(stderr, "%s\n", message);
	exit(2);
}

static void sleep_ms(int milliseconds)
{
	struct timespec delay = { milliseconds / 1000,
		(long)(milliseconds % 1000) * 1000000 };
	while (nanosleep(&delay, &delay))
		if (errno != EINTR)
			fail("nanosleep");
}

static unsigned long long monotonic_ns(void)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now))
		fail("clock_gettime");
	return (unsigned long long)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int number(const char *value, int minimum, int maximum)
{
	char *end;
	errno = 0;
	long result = strtol(value, &end, 10);
	if (errno || !*value || *end || result < minimum || result > maximum)
		invalid("invalid numeric argument");
	return (int)result;
}

static int open_socket(int family, int type)
{
	int fd = socket(family, type, 0), enabled = 1;
	struct timeval timeout = { .tv_sec = 5 };
	if (fd < 0)
		fail("socket");
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
	    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
		fail("socket timeout");
	if (type == SOCK_STREAM &&
	    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &enabled, sizeof(enabled)))
		fail("TCP_NODELAY");
	return fd;
}

static void send_bytes(int fd, const unsigned char *data, size_t size)
{
	while (size) {
		ssize_t count = send(fd, data, size, MSG_NOSIGNAL);
		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			fail("send");
		data += count;
		size -= (size_t)count;
	}
}

static void echo_server(int fd, int type, const struct options *options)
{
	unsigned char buffer[MAX_BYTES * MAX_CHUNKS];
	prctl(PR_SET_NAME, type == SOCK_STREAM ? "chain_tcp_srv" : "chain_udp_srv", 0, 0, 0);
	if (type == SOCK_STREAM) {
		int accepted = accept(fd, NULL, NULL);
		if (accepted < 0)
			fail("accept");
		close(fd);
		fd = accepted;
	}
	for (int received = 0; type == SOCK_STREAM || received < options->rounds * options->chunks;
	     received++) {
		struct sockaddr_storage peer;
		socklen_t peer_size = sizeof(peer);
		ssize_t count = type == SOCK_STREAM ? recv(fd, buffer, sizeof(buffer), 0) :
			recvfrom(fd, buffer, sizeof(buffer), 0, (void *)&peer, &peer_size);
		if (count < 0 && errno == EINTR) {
			received--;
			continue;
		}
		if (count < 0)
			fail("server receive");
		if (!count && type == SOCK_STREAM)
			break;
		/* Give the client time to enter a blocking receive before the echo. */
		sleep_ms(options->delay_ms);
		if (type == SOCK_STREAM)
			send_bytes(fd, buffer, (size_t)count);
		else if (sendto(fd, buffer, (size_t)count, 0, (void *)&peer, peer_size) != count)
			fail("server sendto");
	}
	close(fd);
	_exit(0);
}

static void run_protocol(int type, const struct options *options)
{
	struct sockaddr_storage peer = {};
	struct sockaddr_in *ipv4 = (void *)&peer;
	struct sockaddr_in6 *ipv6 = (void *)&peer;
	int family = options->host && strchr(options->host, ':') ? AF_INET6 : AF_INET;
	socklen_t peer_size = family == AF_INET ? sizeof(*ipv4) : sizeof(*ipv6);
	const char *host = options->host ? options->host : "127.0.0.1";
	const char *protocol = type == SOCK_STREAM ? "tcp" : "udp";
	pid_t server = -1;
	unsigned char expected[MAX_BYTES * MAX_CHUNKS], reply[MAX_BYTES * MAX_CHUNKS];
	int fd;

	if (family == AF_INET) {
		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons((uint16_t)options->port);
		if (inet_pton(AF_INET, host, &ipv4->sin_addr) != 1)
			invalid("--host must be a numeric IPv4 or IPv6 address");
	} else {
		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = htons((uint16_t)options->port);
		if (inet_pton(AF_INET6, host, &ipv6->sin6_addr) != 1)
			invalid("--host must be a numeric IPv4 or IPv6 address");
	}
	if (!options->host) {
		int listener = open_socket(family, type);
		if (bind(listener, (void *)&peer, peer_size) ||
		    getsockname(listener, (void *)&peer, &peer_size) ||
		    (type == SOCK_STREAM && listen(listener, 1)))
			fail("loopback listener");
		server = fork();
		if (server < 0)
			fail("fork");
		if (!server)
			echo_server(listener, type, options);
		close(listener);
	}
	fd = open_socket(family, type);
	if (connect(fd, (void *)&peer, peer_size))
		fail("connect");
	struct sockaddr_storage local;
	socklen_t local_size = sizeof(local);
	if (getsockname(fd, (void *)&local, &local_size))
		fail("getsockname");
	unsigned int local_port = family == AF_INET ?
		ntohs(((struct sockaddr_in *)&local)->sin_port) :
		ntohs(((struct sockaddr_in6 *)&local)->sin6_port);
	printf("flow protocol=%s pid=%d uid=%u fd=%d local_port=%u remote=%s remote_port=%u\n",
	       protocol, getpid(), getuid(), fd, local_port, host,
	       family == AF_INET ? ntohs(ipv4->sin_port) : ntohs(ipv6->sin6_port));

	for (int round = 0; round < options->rounds; round++) {
		size_t total = (size_t)options->bytes * options->chunks, received = 0;
		unsigned int seen = 0;
		unsigned long long start = monotonic_ns();
		for (int chunk = 0; chunk < options->chunks; chunk++) {
			unsigned char *payload = expected + chunk * options->bytes;
			uint32_t header[2] = { htonl((uint32_t)round), htonl((uint32_t)chunk) };
			memset(payload, (round + chunk) & 255, (size_t)options->bytes);
			memcpy(payload, header, sizeof(header));
			if (type == SOCK_STREAM)
				send_bytes(fd, payload, (size_t)options->bytes);
			else if (send(fd, payload, (size_t)options->bytes, 0) != options->bytes)
				fail("client UDP send");
		}
		while (received < total) {
			ssize_t count = recv(fd, reply + (type == SOCK_STREAM ? received : 0),
				type == SOCK_STREAM ? total - received : sizeof(reply), 0);
			if (count < 0 && errno == EINTR)
				continue;
			if (count <= 0)
				fail("client receive");
			if (type == SOCK_DGRAM) {
				uint32_t header[2];
				if (count != options->bytes)
					invalid("unexpected UDP echo length");
				memcpy(header, reply, sizeof(header));
				unsigned int chunk = ntohl(header[1]);
				if (ntohl(header[0]) != (unsigned int)round ||
				    chunk >= (unsigned int)options->chunks || (seen & (1U << chunk)) ||
				    memcmp(reply, expected + chunk * options->bytes, (size_t)count))
					invalid("UDP echo mismatch or duplicate");
				seen |= 1U << chunk;
			}
			received += (size_t)count;
		}
		if (type == SOCK_STREAM && memcmp(reply, expected, total))
			invalid("TCP echo mismatch");
		printf("round protocol=%s index=%d sends=%d bytes=%zu start_ns=%llu end_ns=%llu verified=true\n",
		       protocol, round, options->chunks, total, start, monotonic_ns());
		sleep_ms(options->interval_ms);
	}
	close(fd);
	if (server > 0) {
		int status;
		while (waitpid(server, &status, 0) < 0)
			if (errno != EINTR)
				fail("waitpid");
		if (!WIFEXITED(status) || WEXITSTATUS(status))
			invalid("loopback echo server failed");
	}
	printf("complete protocol=%s rounds=%d verified=true\n", protocol, options->rounds);
}

int main(int argc, char **argv)
{
	struct options options = { .protocol = "both", .rounds = 8, .chunks = 3,
		.bytes = 512, .delay_ms = 50, .interval_ms = 20, .start_delay_ms = 1000 };
	for (int i = 1; i < argc; i++) {
		const char *option = argv[i];
		if (!strcmp(option, "--help")) {
			puts("socket-chain-workload [--protocol tcp|udp|both] [--uid UID]\n"
			     "  [--host NUMERIC_IP --port PORT] [--rounds N] [--chunks N]\n"
			     "  [--bytes N] [--delay-ms N] [--interval-ms N] [--start-delay-ms N]\n"
			     "Default: fork loopback echo servers; delay-ms delays local echoes.\n"
			     "Remote mode requires a byte-for-byte TCP/UDP echo server.");
			return 0;
		}
		if (++i >= argc)
			invalid("missing option value");
		if (!strcmp(option, "--protocol")) options.protocol = argv[i];
		else if (!strcmp(option, "--host")) options.host = argv[i];
		else if (!strcmp(option, "--port")) options.port = number(argv[i], 1, 65535);
		else if (!strcmp(option, "--rounds")) options.rounds = number(argv[i], 1, 10000);
		else if (!strcmp(option, "--chunks")) options.chunks = number(argv[i], 1, MAX_CHUNKS);
		else if (!strcmp(option, "--bytes")) options.bytes = number(argv[i], 8, MAX_BYTES);
		else if (!strcmp(option, "--delay-ms")) options.delay_ms = number(argv[i], 0, 1000);
		else if (!strcmp(option, "--interval-ms")) options.interval_ms = number(argv[i], 0, 60000);
		else if (!strcmp(option, "--start-delay-ms")) options.start_delay_ms = number(argv[i], 0, 60000);
		else if (!strcmp(option, "--uid")) {
			options.uid = (uid_t)number(argv[i], 0, INT_MAX);
			options.set_uid = true;
		} else invalid("unknown option");
	}
	if (strcmp(options.protocol, "tcp") && strcmp(options.protocol, "udp") &&
	    strcmp(options.protocol, "both"))
		invalid("--protocol must be tcp, udp, or both");
	if ((options.host && !options.port) || (!options.host && options.port))
		invalid("--host and --port must be used together");
	setvbuf(stdout, NULL, _IOLBF, 0);
	prctl(PR_SET_NAME, "chain_client", 0, 0, 0);
	if (options.set_uid && (setgid(options.uid) || setuid(options.uid)))
		fail("setgid/setuid");
	printf("ready pid=%d uid=%u mode=%s start_delay_ms=%d\n", getpid(), getuid(),
	       options.host ? "remote" : "loopback", options.start_delay_ms);
	sleep_ms(options.start_delay_ms);
	if (!strcmp(options.protocol, "tcp") || !strcmp(options.protocol, "both"))
		run_protocol(SOCK_STREAM, &options);
	if (!strcmp(options.protocol, "udp") || !strcmp(options.protocol, "both"))
		run_protocol(SOCK_DGRAM, &options);
	return 0;
}
