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

static volatile sig_atomic_t traffic_exiting;

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

static void traffic_print_row(const struct traffic_row *row)
{
	char local[INET6_ADDRSTRLEN] = "?";
	char remote[INET6_ADDRSTRLEN] = "?";
	int af = row->key.family == AF_INET6 ? 6 : 4;

	if (row->key.family == AF_INET) {
		inet_ntop(AF_INET, &row->key.laddr.v4, local, sizeof(local));
		inet_ntop(AF_INET, &row->key.raddr.v4, remote, sizeof(remote));
	} else if (row->key.family == AF_INET6) {
		inet_ntop(AF_INET6, row->key.laddr.v6, local, sizeof(local));
		inet_ntop(AF_INET6, row->key.raddr.v6, remote, sizeof(remote));
	}

	printf("%-7u %-7u %-16.16s %-2s %-2d %-39s %-5u "
	       "%-39s %-5u %10.2f %10.2f\n",
	       row->key.tgid, row->key.tid, row->key.comm,
	       traffic_protocol_name(row->key.protocol), af, local,
	       row->key.lport, remote, row->key.rport,
	       row->value.tx_bytes / 1024.0, row->value.rx_bytes / 1024.0);
}

static int traffic_print_snapshot(struct traffic *skel, trace_args_t *args,
				  struct traffic_row *rows, u64 since_ns,
				  u64 now_ns)
{
	char timestamp[64];
	int flow_fd = bpf_map__fd(skel->maps.traffic_flows);
	int count, i;

	count = traffic_collect_rows(flow_fd, rows, TRAFFIC_MAX_FLOWS,
				     since_ns, now_ns);
	qsort(rows, count, sizeof(*rows), traffic_row_compare);
	ts_print_ts(timestamp, now_ns, args->time_mode);
	printf("\n%sTraffic %s (cumulative per flow)\n", timestamp,
	       trace_ctx.bpf_args.pkt.l4_proto ?
	       traffic_protocol_name(trace_ctx.bpf_args.pkt.l4_proto) :
	       "TCP/UDP");
	printf("%-7s %-7s %-16s %-2s %-2s %-39s %-5s %-39s %-5s "
	       "%10s %10s\n",
	       "PID", "TID", "COMM", "P", "AF", "LADDR", "LPORT",
	       "RADDR", "RPORT", "TX_KB", "RX_KB");
	for (i = 0; i < count; i++)
		traffic_print_row(&rows[i]);
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
	    args->traces || args->traces_stack) {
		pr_err("--traffic cannot be combined with packet or socket trace modes\n");
		return -1;
	}
	return 0;
}

int traffic_run(trace_args_t *args, bpf_args_t *bpf_args)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts,
		.btf_custom_path = args->btf_path,
	);
	struct bpf_link *links[12] = {};
	struct traffic_row *rows = NULL;
	struct traffic *skel = NULL;
	u64 previous_drops[TRAFFIC_STAT_MAX] = {};
	u64 last_report_ns, now_ns;
	u32 reports = 0;
	int link_count = 0, status = -1, i;

	if (traffic_validate_options(args, bpf_args))
		return -1;
	if (liberate_l())
		pr_warn("failed to set rlimit\n");

	rows = calloc(TRAFFIC_MAX_FLOWS, sizeof(*rows));
	if (!rows) {
		pr_err("traffic: failed to allocate flow rows\n");
		goto out;
	}

	skel = traffic__open_opts(&opts);
	if (!skel) {
		pr_err("traffic: failed to open BPF skeleton\n");
		goto out;
	}
	skel->rodata->traffic_config.tid = bpf_args->pid;
	skel->rodata->traffic_config.uid = bpf_args->uid;
	skel->rodata->traffic_config.uid_enabled = bpf_args->uid_enabled;
	skel->rodata->traffic_config.protocol = bpf_args->pkt.l4_proto;

	if (traffic__load(skel)) {
		pr_err("traffic: failed to load BPF programs\n");
		goto out;
	}
	if (traffic_attach_probes(skel, bpf_args->pkt.l4_proto, links,
				  &link_count))
		goto out;

	traffic_exiting = 0;
	signal(SIGTERM, traffic_signal_handler);
	signal(SIGINT, traffic_signal_handler);
	last_report_ns = traffic_monotonic_ns();
	pr_info("Tracing %s traffic every %u second(s)... Hit Ctrl-C to end.\n",
		bpf_args->pkt.l4_proto ?
		traffic_protocol_name(bpf_args->pkt.l4_proto) : "TCP/UDP",
		args->traffic_interval);

	while (!traffic_exiting) {
		struct timespec delay = {
			.tv_sec = args->traffic_interval,
		};

		while (nanosleep(&delay, &delay) && errno == EINTR &&
		       !traffic_exiting)
			;
		if (traffic_exiting)
			break;
		now_ns = traffic_monotonic_ns();
		traffic_print_snapshot(skel, args, rows, last_report_ns, now_ns);
		traffic_report_drops(skel, previous_drops);
		last_report_ns = now_ns;
		reports++;
		if (args->count && reports >= args->count)
			break;
	}

	status = 0;
out:
	for (i = 0; i < link_count; i++)
		bpf_link__destroy(links[i]);
	traffic__destroy(skel);
	free(rows);
	return status;
}

#else

int traffic_run(trace_args_t *args, bpf_args_t *bpf_args)
{
	(void)args;
	(void)bpf_args;
	pr_err("--traffic requires a BTF build\n");
	return -1;
}

#endif
