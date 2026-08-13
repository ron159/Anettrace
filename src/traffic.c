// SPDX-License-Identifier: MulanPSL-2.0

#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net_utils.h>
#include <sys_utils.h>

#include "output.h"
#include "traffic.h"
#include "progs/traffic_shared.h"

#ifndef NO_BTF
#include "progs/traffic.skel.h"

struct traffic_row {
	traffic_flow_key_t key;
	traffic_flow_value_t value;
};

#define TRAFFIC_MAX_LINKS 12

struct traffic_session {
	trace_args_t *args;
	struct traffic *skel;
	struct bpf_link *links[TRAFFIC_MAX_LINKS];
	struct traffic_row *rows;
	u64 previous_drops[TRAFFIC_STAT_MAX];
	u64 last_report_ns;
	u64 next_report_ns;
	u32 reports;
	int link_count;
	bool active;
	bool limit_reached;
};

static volatile sig_atomic_t traffic_exiting;
static struct traffic_session traffic_session;

static void traffic_signal_handler(int signal_number)
{
	(void)signal_number;
	traffic_exiting = 1;
}

static u64 traffic_monotonic_ns(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now))
		return 0;
	return (u64)now.tv_sec * 1000000000ULL + now.tv_nsec;
}

static int traffic_row_compare(const void *left, const void *right)
{
	const struct traffic_row *a = left;
	const struct traffic_row *b = right;
	u64 total_a = a->value.tx_bytes + a->value.rx_bytes;
	u64 total_b = b->value.tx_bytes + b->value.rx_bytes;

	if (total_a < total_b)
		return 1;
	if (total_a > total_b)
		return -1;
	return 0;
}

static const char *traffic_protocol_name(u8 protocol)
{
	if (protocol == IPPROTO_TCP)
		return "TCP";
	if (protocol == IPPROTO_UDP)
		return "UDP";
	return "?";
}

static int traffic_collect_rows(int map_fd, struct traffic_row *rows,
				int capacity, u64 since_ns, u64 now_ns)
{
	traffic_flow_key_t key, next;
	traffic_flow_value_t value;
	int count = 0, err;

	err = bpf_map_get_next_key(map_fd, NULL, &key);
	while (!err) {
		bool has_next = bpf_map_get_next_key(map_fd, &key, &next) == 0;

		if (!bpf_map_lookup_elem(map_fd, &key, &value)) {
			if (now_ns > value.last_seen_ns &&
			    now_ns - value.last_seen_ns > TRAFFIC_STALE_NS) {
				bpf_map_delete_elem(map_fd, &key);
			} else if (value.last_seen_ns > since_ns &&
				   count < capacity) {
				rows[count].key = key;
				rows[count].value = value;
				count++;
			}
		}

		if (!has_next)
			break;
		key = next;
	}

	return count;
}

static void traffic_format_endpoint(const struct traffic_row *row, bool local,
				    char *endpoint, size_t endpoint_size)
{
	char address[INET6_ADDRSTRLEN] = "?";
	const traffic_addr_t *addr = local ? &row->key.laddr : &row->key.raddr;
	u16 port = local ? row->key.lport : row->key.rport;

	if (row->key.family == AF_INET) {
		inet_ntop(AF_INET, &addr->v4, address, sizeof(address));
		snprintf(endpoint, endpoint_size, "%s:%u", address, port);
	} else if (row->key.family == AF_INET6) {
		inet_ntop(AF_INET6, addr->v6, address, sizeof(address));
		snprintf(endpoint, endpoint_size, "[%s]:%u", address, port);
	} else {
		snprintf(endpoint, endpoint_size, "?:%u", port);
	}
}

static void traffic_print_row(const struct traffic_row *row, int local_width,
			      int remote_width)
{
	char local[INET6_ADDRSTRLEN + 8];
	char remote[INET6_ADDRSTRLEN + 8];
	int af = row->key.family == AF_INET6 ? 6 : 4;

	traffic_format_endpoint(row, true, local, sizeof(local));
	traffic_format_endpoint(row, false, remote, sizeof(remote));

	printf("%-7u %-7u %-16.16s %-3s %-2d %-*s %-*s %10.2f %10.2f\n",
	       row->key.tgid, row->key.tid, row->key.comm,
	       traffic_protocol_name(row->key.protocol), af, local_width, local,
	       remote_width, remote,
	       row->value.tx_bytes / 1024.0, row->value.rx_bytes / 1024.0);
}

static int traffic_print_snapshot(struct traffic *skel, trace_args_t *args,
				  struct traffic_row *rows, u64 since_ns,
				  u64 now_ns)
{
	char timestamp[64];
	int flow_fd = bpf_map__fd(skel->maps.traffic_flows);
	int count, i, local_width = (int)strlen("LADDR:PORT");
	int remote_width = (int)strlen("RADDR:PORT");

	count = traffic_collect_rows(flow_fd, rows, TRAFFIC_MAX_FLOWS,
				     since_ns, now_ns);
	qsort(rows, count, sizeof(*rows), traffic_row_compare);
	for (i = 0; i < count; i++) {
		char local[INET6_ADDRSTRLEN + 8];
		char remote[INET6_ADDRSTRLEN + 8];
		int width;

		traffic_format_endpoint(&rows[i], true, local, sizeof(local));
		traffic_format_endpoint(&rows[i], false, remote, sizeof(remote));
		width = (int)strlen(local);
		if (width > local_width)
			local_width = width;
		width = (int)strlen(remote);
		if (width > remote_width)
			remote_width = width;
	}
	ts_print_ts(timestamp, now_ns, args->time_mode);
	printf("\n%sTraffic %s (cumulative application payload per flow)\n",
	       timestamp,
	       trace_ctx.bpf_args.pkt.l4_proto ?
	       traffic_protocol_name(trace_ctx.bpf_args.pkt.l4_proto) :
	       "TCP/UDP");
	printf("%-7s %-7s %-16s %-3s %-2s %-*s %-*s %10s %10s\n",
	       "PID", "TID", "COMM", "P", "AF", local_width,
	       "LADDR:PORT", remote_width, "RADDR:PORT", "APP_TX_KB",
	       "APP_RX_KB");
	for (i = 0; i < count; i++)
		traffic_print_row(&rows[i], local_width, remote_width);
	if (!count)
		printf("(no traffic in this interval)\n");
	fflush(stdout);
	return count;
}

static void traffic_report_drops(struct traffic *skel, u64 *previous)
{
	int map_fd = bpf_map__fd(skel->maps.traffic_stats);
	u32 index;

	for (index = 0; index < TRAFFIC_STAT_MAX; index++) {
		u64 current = 0;

		if (bpf_map_lookup_elem(map_fd, &index, &current) ||
		    current == previous[index])
			continue;
		pr_warn("traffic: %llu samples dropped in %s map\n",
			 current - previous[index],
			 index == TRAFFIC_STAT_INFLIGHT_DROP ? "inflight" : "flow");
		previous[index] = current;
	}
}

static int traffic_attach_pair(struct bpf_program *entry,
			       struct bpf_program *exit, const char *target,
			       struct bpf_link **links, int *link_count)
{
	struct bpf_link *entry_link, *exit_link;
	long err;

	exit_link = bpf_program__attach_kprobe(exit, true, target);
	err = libbpf_get_error(exit_link);
	if (err) {
		pr_warn("traffic: cannot attach kretprobe/%s: %s\n", target,
			strerror(-err));
		return -1;
	}

	entry_link = bpf_program__attach_kprobe(entry, false, target);
	err = libbpf_get_error(entry_link);
	if (err) {
		pr_warn("traffic: cannot attach kprobe/%s: %s\n", target,
			strerror(-err));
		bpf_link__destroy(exit_link);
		return -1;
	}

	links[(*link_count)++] = exit_link;
	links[(*link_count)++] = entry_link;
	pr_debug("traffic: attached kprobe/kretprobe pair for %s\n", target);
	return 0;
}

static int traffic_attach_probes(struct traffic *skel, u8 protocol,
				 struct bpf_link **links, int *link_count)
{
	int tcp_tx = 0, tcp_rx = 0, udp_tx = 0, udp_rx = 0;

	if (!protocol || protocol == IPPROTO_TCP) {
		tcp_tx = traffic_attach_pair(skel->progs.traffic_tcp_send_entry,
			skel->progs.traffic_tcp_send_exit, "tcp_sendmsg",
			links, link_count) == 0;
		tcp_rx = traffic_attach_pair(skel->progs.traffic_tcp_recv_entry,
			skel->progs.traffic_tcp_recv_exit, "tcp_recvmsg",
			links, link_count) == 0;
		if (!tcp_tx || !tcp_rx) {
			pr_err("traffic: TCP send/receive probes are incomplete\n");
			return -1;
		}
	}

	if (!protocol || protocol == IPPROTO_UDP) {
		udp_tx += traffic_attach_pair(skel->progs.traffic_udp4_send_entry,
			skel->progs.traffic_udp4_send_exit, "udp_sendmsg",
			links, link_count) == 0;
		udp_rx += traffic_attach_pair(skel->progs.traffic_udp4_recv_entry,
			skel->progs.traffic_udp4_recv_exit, "udp_recvmsg",
			links, link_count) == 0;
		udp_tx += traffic_attach_pair(skel->progs.traffic_udp6_send_entry,
			skel->progs.traffic_udp6_send_exit, "udpv6_sendmsg",
			links, link_count) == 0;
		udp_rx += traffic_attach_pair(skel->progs.traffic_udp6_recv_entry,
			skel->progs.traffic_udp6_recv_exit, "udpv6_recvmsg",
			links, link_count) == 0;
		if (!udp_tx || !udp_rx) {
			pr_err("traffic: UDP send/receive probes are incomplete\n");
			return -1;
		}
	}

	return 0;
}

static int traffic_validate_options(trace_args_t *args, bpf_args_t *bpf_args)
{
	pkt_args_t *pkt = &bpf_args->pkt;

	if (args->traffic_interval < 1 || args->traffic_interval > 3600) {
		pr_err("--interval must be between 1 and 3600 seconds\n");
		return -1;
	}
	if (pkt->l3_proto || (pkt->l4_proto && pkt->l4_proto != IPPROTO_TCP &&
			      pkt->l4_proto != IPPROTO_UDP)) {
		pr_err("--traffic supports only --proto tcp or --proto udp\n");
		return -1;
	}
	if (pkt->sport || pkt->dport || pkt->port || bpf_args->netns ||
	    args->netns_current || args->min_latency || args->pkt_len ||
	    args->tcp_flags) {
		pr_err("--traffic currently supports protocol, TID and UID filters only\n");
		return -1;
	}
	if (args->basic || args->intel || args->drop || args->sock ||
	    args->monitor || args->rtt || args->rtt_detail || args->latency ||
	    (args->traces && !args->capture_trace) || args->traces_stack) {
		pr_err("--traffic cannot be combined with packet or socket trace modes\n");
		return -1;
	}
	return 0;
}

static void traffic_release(void)
{
	struct traffic_session *session = &traffic_session;
	int i;

	for (i = 0; i < session->link_count; i++)
		bpf_link__destroy(session->links[i]);
	traffic__destroy(session->skel);
	free(session->rows);
	memset(session, 0, sizeof(*session));
}

static bool traffic_tick(bool force)
{
	struct traffic_session *session = &traffic_session;
	u64 now_ns;

	if (!session->active || session->limit_reached)
		return session->limit_reached;
	now_ns = traffic_monotonic_ns();
	if (!force && now_ns < session->next_report_ns)
		return false;

	traffic_print_snapshot(session->skel, session->args, session->rows,
			       session->last_report_ns, now_ns);
	traffic_report_drops(session->skel, session->previous_drops);
	session->last_report_ns = now_ns;
	session->next_report_ns = now_ns +
		(u64)session->args->traffic_interval * 1000000000ULL;
	session->reports++;
	session->limit_reached = session->args->count &&
		session->reports >= session->args->count;
	return session->limit_reached;
}

int traffic_start(trace_args_t *args, bpf_args_t *bpf_args)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = args->btf_path,
	);
	struct traffic_session *session = &traffic_session;

	if (session->active) {
		pr_err("traffic: session is already active\n");
		return -1;
	}
	if (traffic_validate_options(args, bpf_args))
		return -1;
	if (liberate_l())
		pr_warn("failed to set rlimit\n");

	session->args = args;
	session->rows = calloc(TRAFFIC_MAX_FLOWS, sizeof(*session->rows));
	if (!session->rows) {
		pr_err("traffic: failed to allocate flow rows\n");
		goto out;
	}

	session->skel = traffic__open_opts(&opts);
	if (!session->skel) {
		pr_err("traffic: failed to open BPF skeleton\n");
		goto out;
	}
	session->skel->rodata->traffic_config.tid = bpf_args->pid;
	session->skel->rodata->traffic_config.uid = bpf_args->uid;
	session->skel->rodata->traffic_config.uid_enabled =
		bpf_args->uid_enabled;
	session->skel->rodata->traffic_config.protocol = bpf_args->pkt.l4_proto;

	if (traffic__load(session->skel)) {
		pr_err("traffic: failed to load BPF programs\n");
		goto out;
	}
	if (traffic_attach_probes(session->skel, bpf_args->pkt.l4_proto,
				  session->links, &session->link_count))
		goto out;

	session->last_report_ns = traffic_monotonic_ns();
	session->next_report_ns = session->last_report_ns +
		(u64)args->traffic_interval * 1000000000ULL;
	session->active = true;
	pr_info("Tracing %s traffic every %u second(s)... Hit Ctrl-C to end.\n",
		bpf_args->pkt.l4_proto ?
		traffic_protocol_name(bpf_args->pkt.l4_proto) : "TCP/UDP",
		args->traffic_interval);
	pr_info("Traffic bytes are successful sendmsg/recvmsg application payload; "
		"Wireshark wire bytes also include headers, control packets, and retransmits.\n");
	if (args->capture_trace)
		pr_info("Trace capture runs in the background while traffic remains on stdout.\n");
	return 0;

out:
	traffic_release();
	return -1;
}

bool traffic_poll(void)
{
	return traffic_tick(false);
}

void traffic_stop(bool final_report)
{
	if (!traffic_session.active)
		return;
	if (final_report)
		traffic_tick(true);
	traffic_release();
}

int traffic_run(trace_args_t *args, bpf_args_t *bpf_args)
{
	if (traffic_start(args, bpf_args))
		return -1;

	traffic_exiting = 0;
	signal(SIGTERM, traffic_signal_handler);
	signal(SIGINT, traffic_signal_handler);
	while (!traffic_exiting) {
		struct timespec delay = {
			.tv_sec = args->traffic_interval,
		};

		while (nanosleep(&delay, &delay) && errno == EINTR &&
		       !traffic_exiting)
			;
		if (traffic_exiting || traffic_tick(true))
			break;
	}

	traffic_stop(true);
	return 0;
}

#else

int traffic_start(trace_args_t *args, bpf_args_t *bpf_args)
{
	(void)args;
	(void)bpf_args;
	pr_err("--traffic requires a BTF build\n");
	return -1;
}

bool traffic_poll(void)
{
	return false;
}

void traffic_stop(bool final_report)
{
	(void)final_report;
}

int traffic_run(trace_args_t *args, bpf_args_t *bpf_args)
{
	return traffic_start(args, bpf_args);
}

#endif
