// SPDX-License-Identifier: MulanPSL-2.0

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <linux/xfrm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef IP_XFRM_POLICY
#define IP_XFRM_POLICY 17
#endif
#ifndef IPV6_XFRM_POLICY
#define IPV6_XFRM_POLICY 35
#endif

static void fail(const char *family, const char *operation)
{
	int error = errno;

	fprintf(stderr, "FAIL: family=%s operation=%s errno=%d (%s)\n",
		family, operation, error, strerror(error));
	exit(1);
}

static void run_family(int family, unsigned short port)
{
	const char *label = family == AF_INET ? "ipv4" : "ipv6";
	const char *address = family == AF_INET ? "127.0.0.1" : "::1";
	const char *payload = family == AF_INET ? "anettrace-xfrm-v4" : "anettrace-xfrm-v6";
	struct sockaddr_storage local = {0}, peer = {0};
	struct xfrm_userpolicy_info policy = {0};
	struct timeval timeout = {.tv_sec = 2};
	socklen_t address_size, peer_size = sizeof(peer);
	char received[128];
	int receiver, sender, level, option;
	size_t length = strlen(payload);
	ssize_t result;

	policy.sel.family = family;
	policy.sel.proto = IPPROTO_UDP;
	policy.sel.dport = htons(port);
	policy.sel.dport_mask = htons(0xffff);
	policy.dir = XFRM_POLICY_IN;
	policy.action = XFRM_POLICY_ALLOW;
	policy.lft.soft_byte_limit = XFRM_INF;
	policy.lft.hard_byte_limit = XFRM_INF;
	policy.lft.soft_packet_limit = XFRM_INF;
	policy.lft.hard_packet_limit = XFRM_INF;
	/* Zero add/use expiration seconds means no elapsed-time expiration. */
	if (family == AF_INET) {
		struct sockaddr_in *ipv4 = (void *)&local;

		ipv4->sin_family = AF_INET;
		ipv4->sin_port = htons(port);
		if (inet_pton(AF_INET, address, &ipv4->sin_addr) != 1)
			fail(label, "inet_pton");
		policy.sel.saddr.a4 = ipv4->sin_addr.s_addr;
		policy.sel.daddr.a4 = ipv4->sin_addr.s_addr;
		policy.sel.prefixlen_s = policy.sel.prefixlen_d = 32;
		address_size = sizeof(*ipv4);
		level = IPPROTO_IP;
		option = IP_XFRM_POLICY;
	} else {
		struct sockaddr_in6 *ipv6 = (void *)&local;

		ipv6->sin6_family = AF_INET6;
		ipv6->sin6_port = htons(port);
		if (inet_pton(AF_INET6, address, &ipv6->sin6_addr) != 1)
			fail(label, "inet_pton");
		memcpy(policy.sel.saddr.a6, &ipv6->sin6_addr, sizeof(ipv6->sin6_addr));
		memcpy(policy.sel.daddr.a6, &ipv6->sin6_addr, sizeof(ipv6->sin6_addr));
		policy.sel.prefixlen_s = policy.sel.prefixlen_d = 128;
		address_size = sizeof(*ipv6);
		level = IPPROTO_IPV6;
		option = IPV6_XFRM_POLICY;
	}

	receiver = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (receiver < 0)
		fail(label, "receiver socket");
	if (bind(receiver, (void *)&local, address_size))
		fail(label, "receiver bind");
	if (setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
		fail(label, "SO_RCVTIMEO");
	/* This installs only sk->sk_policy[IN]; close/exit releases the policy. */
	if (setsockopt(receiver, level, option, &policy, sizeof(policy)))
		fail(label, family == AF_INET ? "IP_XFRM_POLICY" : "IPV6_XFRM_POLICY");

	sender = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (sender < 0)
		fail(label, "sender socket");
	if (setsockopt(sender, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)))
		fail(label, "SO_SNDTIMEO");
	result = sendto(sender, payload, length, 0, (void *)&local, address_size);
	if (result < 0)
		fail(label, "sendto");
	if ((size_t)result != length) {
		errno = EIO;
		fail(label, "short sendto");
	}
	result = recvfrom(receiver, received, sizeof(received), 0, (void *)&peer, &peer_size);
	if (result < 0)
		fail(label, "recvfrom (2 second timeout)");
	if ((size_t)result != length || memcmp(received, payload, length)) {
		errno = EBADMSG;
		fail(label, "payload mismatch");
	}
	if (peer.ss_family != family) {
		errno = EAFNOSUPPORT;
		fail(label, "peer family mismatch");
	}
	close(sender);
	close(receiver);
	printf("family=%s address=%s dport=%u bytes=%zu socket_policy=in/allow verified=true\n",
		label, address, port, length);
	fflush(stdout);
}

int main(int argc, char **argv)
{
	char *end;
	unsigned long port;

	if (argc != 2) {
		fprintf(stderr, "usage: %s PORT\n", argv[0]);
		return 2;
	}
	errno = 0;
	port = strtoul(argv[1], &end, 10);
	if (errno || end == argv[1] || *end || port == 0 || port > 65535) {
		fprintf(stderr, "invalid UDP port: %s\n", argv[1]);
		return 2;
	}
	if (geteuid() != 0) {
		fprintf(stderr, "FAIL: run the XFRM socket workload as root\n");
		return 1;
	}
	run_family(AF_INET, (unsigned short)port);
	run_family(AF_INET6, (unsigned short)port);
	puts("XFRM socket workload: PASS");
	return 0;
}
