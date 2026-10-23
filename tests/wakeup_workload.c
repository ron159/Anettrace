// SPDX-License-Identifier: MulanPSL-2.0
/* Controlled task-context wake -> UDP send, for the Linux BPF integration test. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#ifdef __linux__
#include <sched.h>
#include <sys/syscall.h>
#endif

enum { ITERATIONS = 32 };
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static pthread_cond_t ready = PTHREAD_COND_INITIALIZER;
static unsigned requested;
static uint64_t sender_tid;
static int sender_fd;
static struct sockaddr_in target;

static uint64_t current_tid(void)
{
#ifdef __linux__
	return syscall(SYS_gettid);
#else
	uint64_t tid;
	pthread_threadid_np(NULL, &tid);
	return tid;
#endif
}

static void *sender(void *unused)
{
	unsigned sent = 0;
	(void)unused;
	pthread_mutex_lock(&mutex);
	sender_tid = current_tid();
	pthread_cond_signal(&ready);
	while (sent < ITERATIONS) {
		while (requested == sent)
			pthread_cond_wait(&condition, &mutex);
		pthread_mutex_unlock(&mutex);
		/* No allocations, logging or other tasks between wake and send. */
		if (sendto(sender_fd, "wakeup-packet", 13, 0,
			   (struct sockaddr *)&target, sizeof(target)) != 13) {
			perror("sendto");
			exit(3);
		}
		pthread_mutex_lock(&mutex);
		sent++;
	}
	pthread_mutex_unlock(&mutex);
	return NULL;
}

int main(void)
{
	pthread_t thread;
	struct timeval timeout = {.tv_sec = 5};
	struct timespec pause = {.tv_nsec = 2000000};
	socklen_t length = sizeof(target);
	int server;
	char buffer[32];
#ifdef __linux__
	/* Same-CPU handoff reduces unrelated preemption before the send syscall. */
	cpu_set_t allowed, selected;
	if (!sched_getaffinity(0, sizeof(allowed), &allowed)) {
		for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
			if (!CPU_ISSET(cpu, &allowed))
				continue;
			CPU_ZERO(&selected);
			CPU_SET(cpu, &selected);
			(void)sched_setaffinity(0, sizeof(selected), &selected);
			break;
		}
	}
#endif
	server = socket(AF_INET, SOCK_DGRAM, 0);
	sender_fd = socket(AF_INET, SOCK_DGRAM, 0);
	target.sin_family = AF_INET;
	target.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (server < 0 || sender_fd < 0 ||
	    bind(server, (struct sockaddr *)&target, sizeof(target)) ||
	    getsockname(server, (struct sockaddr *)&target, &length) ||
	    setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) {
		perror("UDP setup");
		return 1;
	}
	if (pthread_create(&thread, NULL, sender, NULL))
		return 1;
	pthread_mutex_lock(&mutex);
	while (!sender_tid)
		pthread_cond_wait(&ready, &mutex);
	pthread_mutex_unlock(&mutex);
	printf("{\"waker_tid\":%" PRIu64 ",\"sender_tid\":%" PRIu64
	       ",\"tgid\":%d,\"sender_fd\":%d}\n",
	       current_tid(), sender_tid, getpid(), sender_fd);
	fflush(stdout);
	if (getchar() != 'g')
		return 2;
	for (unsigned i = 0; i < ITERATIONS; i++) {
		pthread_mutex_lock(&mutex);
		requested = i + 1;
		pthread_cond_signal(&condition);
		pthread_mutex_unlock(&mutex);
		if (recvfrom(server, buffer, sizeof(buffer), 0, NULL, NULL) != 13) {
			perror("recvfrom");
			return 3;
		}
		/* Let the sender sleep before the next controlled wake. */
		nanosleep(&pause, NULL);
	}
	pthread_join(thread, NULL);
	close(sender_fd);
	close(server);
	printf("{\"packets\":%u}\n", ITERATIONS);
	return 0;
}
