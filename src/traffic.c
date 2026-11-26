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
#include "traffic_display.h"
#include "traffic_history.h"
#include "progs/traffic_shared.h"

#ifndef NO_BTF
#include "progs/traffic.skel.h"

struct traffic_row {
	traffic_flow_key_t key;
	traffic_flow_value_t value;
};

struct traffic_process_row {
	traffic_process_key_t key;
	traffic_process_value_t value;
};

#define TRAFFIC_MAX_LINKS 15

struct traffic_session {
	trace_args_t *args;
	struct traffic *skel;
	struct bpf_link *links[TRAFFIC_MAX_LINKS];
	struct traffic_row *rows;
	struct traffic_row *previous_rows;
	struct traffic_process_row *process_rows, *previous_process_rows;
	struct traffic_display_row *flow_display_rows, *process_display_rows;
	u32 *process_flow_counts;
	int previous_row_count, previous_process_count;
	size_t flow_display_count, process_display_count;
	struct traffic_display display;
	struct traffic_display_snapshot snapshot;
	struct traffic_history flow_history, process_history;
	traffic_flow_value_t previous_totals;
	u64 start_ns, totals_sample_ns;
	char filter[64], warning[384];
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

static int traffic_flow_key_compare(const void *left, const void *right)
{
	const struct traffic_row *a = left, *b = right;

	return memcmp(&a->key, &b->key, sizeof(a->key));
}

static int traffic_process_key_compare(const void *left, const void *right)
{
	const struct traffic_process_row *a = left, *b = right;

	return memcmp(&a->key, &b->key, sizeof(a->key));
}

static int traffic_unique_flows(struct traffic_row *rows, int count)
{
	int i, unique = 0;

	qsort(rows, count, sizeof(*rows), traffic_flow_key_compare);
	for (i = 0; i < count; i++) {
		if (unique && !traffic_flow_key_compare(&rows[unique - 1], &rows[i])) {
			traffic_flow_value_t *old = &rows[unique - 1].value;
			traffic_flow_value_t *value = &rows[i].value;

			if (value->first_seen_ns > old->first_seen_ns ||
			    (value->first_seen_ns == old->first_seen_ns &&
			     value->last_seen_ns >= old->last_seen_ns))
				rows[unique - 1] = rows[i];
		} else {
			rows[unique++] = rows[i];
		}
	}
	return unique;
}

static int traffic_unique_processes(struct traffic_process_row *rows, int count)
{
	int i, unique = 0;

	qsort(rows, count, sizeof(*rows), traffic_process_key_compare);
	for (i = 0; i < count; i++) {
		if (unique && !traffic_process_key_compare(&rows[unique - 1], &rows[i])) {
			if (rows[i].value.counters.last_seen_ns >=
			    rows[unique - 1].value.counters.last_seen_ns)
				rows[unique - 1] = rows[i];
		} else {
			rows[unique++] = rows[i];
		}
	}
	return unique;
}

static void traffic_sample_deltas(const traffic_flow_value_t *value,
		const traffic_flow_value_t *previous, u64 since_ns,
		u64 *rx, u64 *tx, bool *incomplete)
{
	*rx = *tx = 0;
	if (previous && value->first_seen_ns == previous->first_seen_ns) {
		if (value->rx_bytes < previous->rx_bytes ||
		    value->tx_bytes < previous->tx_bytes) {
			*incomplete = true;
			return;
		}
		*rx = value->rx_bytes - previous->rx_bytes;
		*tx = value->tx_bytes - previous->tx_bytes;
	} else if (value->first_seen_ns && value->first_seen_ns >= since_ns) {
		*rx = value->rx_bytes;
		*tx = value->tx_bytes;
	} else {
		/* Missing or rebuilt entries can contain older accumulated bytes. */
		*incomplete = true;
	}
}

static int traffic_display_row_compare(const void *left, const void *right)
{
	const struct traffic_display_row *a = left, *b = right;
	double rate_a = a->rx_rate + a->tx_rate;
	double rate_b = b->rx_rate + b->tx_rate;

	if (rate_a != rate_b)
		return rate_a < rate_b ? 1 : -1;
	if (a->idle_seconds != b->idle_seconds)
		return a->idle_seconds > b->idle_seconds ? 1 : -1;
	if (a->pid != b->pid)
		return a->pid > b->pid ? 1 : -1;
	return (a->tid > b->tid) - (a->tid < b->tid);
}

static int traffic_collect_flow_sample(int map_fd, struct traffic_row *rows,
				       bool *incomplete)
{
	traffic_flow_key_t key, next;
	int count = 0, attempts = 0;
	int err = bpf_map_get_next_key(map_fd, NULL, &key);

	if (err && errno != ENOENT)
		*incomplete = true;
	while (!err && attempts++ < TRAFFIC_MAX_FLOWS * 2) {
		int next_err = bpf_map_get_next_key(map_fd, &key, &next);
		int next_errno = errno;

		if (bpf_map_lookup_elem(map_fd, &key, &rows[count].value)) {
			*incomplete = true;
		} else {
			rows[count++].key = key;
		}
		if (next_err) {
			if (next_errno != ENOENT)
				*incomplete = true;
			break;
		}
		if (count == TRAFFIC_MAX_FLOWS) {
			*incomplete = true;
			break;
		}
		key = next;
	}
	if (attempts > TRAFFIC_MAX_FLOWS * 2)
		*incomplete = true;
	return traffic_unique_flows(rows, count);
}

static int traffic_collect_process_sample(int map_fd,
		struct traffic_process_row *rows, bool *incomplete)
{
	traffic_process_key_t key, next;
	int count = 0, attempts = 0;
	int err = bpf_map_get_next_key(map_fd, NULL, &key);

	if (err && errno != ENOENT)
		*incomplete = true;
	while (!err && attempts++ < TRAFFIC_MAX_PROCESSES * 2) {
		int next_err = bpf_map_get_next_key(map_fd, &key, &next);
		int next_errno = errno;

		if (bpf_map_lookup_elem(map_fd, &key, &rows[count].value)) {
			*incomplete = true;
		} else {
			rows[count++].key = key;
		}
		if (next_err) {
			if (next_errno != ENOENT)
				*incomplete = true;
			break;
		}
		if (count == TRAFFIC_MAX_PROCESSES) {
			*incomplete = true;
			break;
		}
		key = next;
	}
	if (attempts > TRAFFIC_MAX_PROCESSES * 2)
		*incomplete = true;
	return traffic_unique_processes(rows, count);
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
	int count = 0, err, attempts = 0;

	err = bpf_map_get_next_key(map_fd, NULL, &key);
	while (!err && attempts++ < TRAFFIC_MAX_FLOWS * 2) {
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
	if (attempts > TRAFFIC_MAX_FLOWS * 2)
		pr_warn("traffic: flow snapshot incomplete during concurrent map updates\n");

	return count;
}

static void traffic_format_endpoint(const struct traffic_row *row, bool local,
				    char *endpoint, size_t endpoint_size)
{
	char address[INET6_ADDRSTRLEN] = "?";
	const traffic_addr_t *addr = local ? &row->key.laddr : &row->key.raddr;
	u16 port = local ? row->key.lport : row->key.rport;

	if (row->key.flags & TRAFFIC_ENDPOINT_UNKNOWN) {
		snprintf(endpoint, endpoint_size, "?");
		return;
	}
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

static void traffic_render_cached(struct traffic_session *session)
{
	session->snapshot.rows = session->snapshot.flows ?
		session->flow_display_rows : session->process_display_rows;
	session->snapshot.row_count = session->snapshot.flows ?
		session->flow_display_count : session->process_display_count;
	session->snapshot.history = session->snapshot.flows ?
		&session->flow_history : &session->process_history;
	traffic_display_render(&session->display, &session->snapshot);
}

static void traffic_format_timestamp(char text[20], u64 now_ns)
{
	char timestamp[64];

	ts_print_ts(timestamp, now_ns, TIME_MODE_DATE);
	if (strlen(timestamp) >= 21 && timestamp[0] == '[' && timestamp[5] == '-')
		snprintf(text, 20, "%.19s", timestamp + 1);
	else
		snprintf(text, 20, "未知");
}

static void traffic_display_counters(struct traffic_display_row *row,
		const traffic_flow_value_t *value, const traffic_flow_value_t *previous,
		u64 since_ns, u64 now_ns, bool *incomplete)
{
	u64 rx, tx;
	bool gap = false;

	traffic_sample_deltas(value, previous, since_ns, &rx, &tx, &gap);
	*incomplete |= gap;
	row->sample_valid = !gap;
	row->rx_delta = rx;
	row->tx_delta = tx;
	row->first_seen_ns = value->first_seen_ns;
	row->last_seen_ns = value->last_seen_ns;
	row->rx_bytes = value->rx_bytes;
	row->tx_bytes = value->tx_bytes;
	row->rx_rate = traffic_bytes_per_second(rx, now_ns - since_ns);
	row->tx_rate = traffic_bytes_per_second(tx, now_ns - since_ns);
	row->idle_seconds = now_ns > value->last_seen_ns ?
		(now_ns - value->last_seen_ns) / 1000000000.0 : 0;
	traffic_format_timestamp(row->last_seen, value->last_seen_ns);
}

static void traffic_sample_warning(struct traffic_session *session,
				   bool read_error, bool sample_gap)
{
	static const char *labels[TRAFFIC_STAT_MAX] = {
		[TRAFFIC_STAT_INFLIGHT_DROP] = "inflight lost (total incomplete)",
		[TRAFFIC_STAT_FLOW_DROP] = "flow detail lost",
		[TRAFFIC_STAT_UDP_ENDPOINT_MISS] = "UDP endpoints unknown",
		[TRAFFIC_STAT_PROCESS_DROP] = "process samples lost",
		[TRAFFIC_STAT_PROCESS_ID_MISS] = "process identity missing",
	};
	u32 index;
	size_t used = 0;

	session->warning[0] = '\0';
	for (index = 0; index < TRAFFIC_STAT_MAX; index++) {
		u64 count;

		if (bpf_map_lookup_elem(bpf_map__fd(session->skel->maps.traffic_stats),
					&index, &count)) {
			read_error = true;
			continue;
		}
		if (count && used < sizeof(session->warning))
			used += snprintf(session->warning + used,
				sizeof(session->warning) - used, "%s%llu %s",
				used ? "; " : "", count, labels[index]);
	}
	if (read_error && used < sizeof(session->warning))
		used += snprintf(session->warning + used, sizeof(session->warning) - used,
			"%smap read incomplete", used ? "; " : "");
	if (sample_gap && used < sizeof(session->warning))
		snprintf(session->warning + used, sizeof(session->warning) - used,
			"%ssample gap: affected rates unavailable", used ? "; " : "");
}

static void traffic_sample_display(struct traffic_session *session, u64 now_ns)
{
	traffic_flow_value_t totals;
	struct traffic_row *flow_swap;
	struct traffic_process_row *process_swap;
	bool read_error = false, sample_gap = false;
	u32 index = 0;
	int flow_count, process_count, i;

	/* Sample the header before map walks so its elapsed interval stays accurate. */
	traffic_format_timestamp(session->snapshot.timestamp, now_ns);
	traffic_history_begin(&session->flow_history, session->snapshot.timestamp,
			      now_ns, now_ns - session->last_report_ns);
	traffic_history_begin(&session->process_history, session->snapshot.timestamp,
			      now_ns, now_ns - session->last_report_ns);
	session->snapshot.rx_rate = session->snapshot.tx_rate = 0;
	if (bpf_map_lookup_elem(bpf_map__fd(session->skel->maps.traffic_totals),
				&index, &totals)) {
		read_error = true;
	} else {
		session->snapshot.rx_bytes = totals.rx_bytes;
		session->snapshot.tx_bytes = totals.tx_bytes;
		if (totals.rx_bytes < session->previous_totals.rx_bytes ||
		    totals.tx_bytes < session->previous_totals.tx_bytes) {
			sample_gap = true;
		} else {
			session->snapshot.rx_rate = traffic_bytes_per_second(
				totals.rx_bytes - session->previous_totals.rx_bytes,
				now_ns - session->totals_sample_ns);
			session->snapshot.tx_rate = traffic_bytes_per_second(
				totals.tx_bytes - session->previous_totals.tx_bytes,
				now_ns - session->totals_sample_ns);
		}
		session->previous_totals = totals;
		session->totals_sample_ns = now_ns;
	}
	flow_count = traffic_collect_flow_sample(
		bpf_map__fd(session->skel->maps.traffic_flows), session->rows, &read_error);
	process_count = traffic_collect_process_sample(
		bpf_map__fd(session->skel->maps.traffic_processes), session->process_rows,
		&read_error);
	memset(session->process_flow_counts, 0,
		TRAFFIC_MAX_PROCESSES * sizeof(*session->process_flow_counts));
	session->flow_display_count = session->process_display_count = 0;
	for (i = 0; i < flow_count; i++) {
		struct traffic_row *current = &session->rows[i], *previous;
		struct traffic_process_row process_key = {
			.key = {.tgid = current->key.tgid,
				.start_time_ns = current->key.process_start_ns},
		}, *process;
		struct traffic_display_row *row;

		if (!current->value.last_seen_ns)
			continue;
		process = bsearch(&process_key, session->process_rows, process_count,
			sizeof(*process), traffic_process_key_compare);
		if (process)
			session->process_flow_counts[process - session->process_rows]++;
		previous = bsearch(current, session->previous_rows, session->previous_row_count,
			sizeof(*previous), traffic_flow_key_compare);
		row = &session->flow_display_rows[session->flow_display_count++];
		memset(row, 0, sizeof(*row));
		row->pid = current->key.tgid;
		row->tid = current->key.tid;
		snprintf(row->comm, sizeof(row->comm), "%.16s", current->key.comm);
		snprintf(row->protocol, sizeof(row->protocol), "%s",
			traffic_protocol_name(current->key.protocol));
		traffic_format_endpoint(current, true, row->local, sizeof(row->local));
		traffic_format_endpoint(current, false, row->remote, sizeof(row->remote));
		traffic_display_counters(row, &current->value,
			previous ? &previous->value : NULL, session->last_report_ns,
			now_ns, &sample_gap);
		traffic_history_update(&session->flow_history, &current->key, row);
	}
	for (i = 0; i < process_count; i++) {
		struct traffic_process_row *current = &session->process_rows[i], *previous;
		traffic_flow_value_t *value = &current->value.counters;
		struct traffic_display_row *row;

		if (!value->last_seen_ns)
			continue;
		previous = bsearch(current, session->previous_process_rows,
			session->previous_process_count, sizeof(*previous), traffic_process_key_compare);
		row = &session->process_display_rows[session->process_display_count++];
		memset(row, 0, sizeof(*row));
		row->pid = current->key.tgid;
		row->flow_count = session->process_flow_counts[i];
		snprintf(row->comm, sizeof(row->comm), "%.16s", current->value.comm);
		traffic_display_counters(row, value,
			previous ? &previous->value.counters : NULL,
			session->last_report_ns, now_ns, &sample_gap);
		traffic_history_update(&session->process_history, &current->key, row);
	}
	/* Keep sampled identities even after the kernel LRU no longer has them. */
	session->flow_display_count = session->flow_history.count;
	for (size_t j = 0; j < session->flow_display_count; j++)
		session->flow_display_rows[j] = session->flow_history.records[j].row;
	session->process_display_count = session->process_history.count;
	for (size_t j = 0; j < session->process_display_count; j++)
		session->process_display_rows[j] = session->process_history.records[j].row;
	qsort(session->flow_display_rows, session->flow_display_count,
		sizeof(*session->flow_display_rows), traffic_display_row_compare);
	qsort(session->process_display_rows, session->process_display_count,
		sizeof(*session->process_display_rows), traffic_display_row_compare);
	session->snapshot.elapsed_seconds = (now_ns - session->start_ns) / 1000000000.0;
	traffic_sample_warning(session, read_error, sample_gap);
	if (session->flow_history.full || session->process_history.full) {
		size_t used = strlen(session->warning);

		snprintf(session->warning + used, sizeof(session->warning) - used,
			 "%sretained record limit reached; new records not retained",
			 used ? "; " : "");
	}
	/* Retain every observed entry as a baseline, including idle rows. */
	flow_swap = session->previous_rows;
	session->previous_rows = session->rows;
	session->rows = flow_swap;
	session->previous_row_count = flow_count;
	process_swap = session->previous_process_rows;
	session->previous_process_rows = session->process_rows;
	session->process_rows = process_swap;
	session->previous_process_count = process_count;
	traffic_render_cached(session);
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
		if (index == TRAFFIC_STAT_UDP_ENDPOINT_MISS)
			pr_warn("traffic: %llu UDP samples have unknown endpoints (?)"
				"; payload counters are retained\n",
				current - previous[index]);
		else if (index == TRAFFIC_STAT_PROCESS_DROP ||
			 index == TRAFFIC_STAT_PROCESS_ID_MISS)
			pr_warn("traffic: %llu samples missing process attribution (%s)\n",
				current - previous[index],
				index == TRAFFIC_STAT_PROCESS_DROP ? "process map" : "identity");
		else
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

	if (*link_count > TRAFFIC_MAX_LINKS - 2)
		return -ENOSPC;

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

static void traffic_attach_endpoint(struct bpf_program *program,
				    const char *target, struct bpf_link **links,
				    int *link_count)
{
	struct bpf_link *link = NULL;
	long err = -ENOSPC;

	if (*link_count < TRAFFIC_MAX_LINKS) {
		link = bpf_program__attach_kprobe(program, false, target);
		err = libbpf_get_error(link);
	}
	if (err) {
		pr_warn("traffic: UDP endpoint probe %s unavailable: %s; "
			"some UDP endpoints will be unknown\n", target, strerror(-err));
		return;
	}
	links[(*link_count)++] = link;
}

static int traffic_attach_probes(struct traffic *skel, u8 protocol,
				 struct bpf_link **links, int *link_count)
{
	int tcp_tx = 0, tcp_rx = 0, udp_tx = 0, udp_rx = 0;
	int udp6_tx = 0;

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
		udp6_tx = traffic_attach_pair(skel->progs.traffic_udp6_send_entry,
			skel->progs.traffic_udp6_send_exit, "udpv6_sendmsg",
			links, link_count) == 0;
		udp_tx += udp6_tx;
		udp_rx += traffic_attach_pair(skel->progs.traffic_udp6_recv_entry,
			skel->progs.traffic_udp6_recv_exit, "udpv6_recvmsg",
			links, link_count) == 0;
		if (!udp_tx || !udp_rx) {
			pr_err("traffic: UDP send/receive probes are incomplete\n");
			return -1;
		}
		traffic_attach_endpoint(skel->progs.traffic_udp4_endpoints,
			"udp_send_skb", links, link_count);
		if (udp6_tx)
			traffic_attach_endpoint(skel->progs.traffic_udp6_endpoints,
				"udp_v6_send_skb", links, link_count);
		traffic_attach_endpoint(skel->progs.traffic_udp_receive_endpoints,
			"skb_consume_udp", links, link_count);
	}

	return 0;
}

static int traffic_select_programs(struct traffic *skel, u8 protocol)
{
	struct bpf_program *program;
	const char *unused_prefix;

	if (!protocol)
		return 0;
	unused_prefix = protocol == IPPROTO_TCP ? "traffic_udp" : "traffic_tcp_";
	bpf_object__for_each_program(program, skel->obj) {
		const char *name = bpf_program__name(program);

		if (!strncmp(name, unused_prefix, strlen(unused_prefix)) &&
		    bpf_program__set_autoload(program, false))
			return -EINVAL;
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
	traffic_display_close(&session->display, &session->snapshot);
	free(session->rows);
	free(session->previous_rows);
	free(session->process_rows);
	free(session->previous_process_rows);
	free(session->flow_display_rows);
	free(session->process_display_rows);
	free(session->process_flow_counts);
	traffic_history_close(&session->flow_history);
	traffic_history_close(&session->process_history);
	memset(session, 0, sizeof(*session));
}

static bool traffic_tick(bool force)
{
	struct traffic_session *session = &traffic_session;
	u64 now_ns;

	if (!session->active || session->limit_reached)
		return session->limit_reached;
	now_ns = traffic_monotonic_ns();
	if (!now_ns || now_ns < session->last_report_ns)
		return false;
	if (!force && now_ns < session->next_report_ns)
		return false;

	if (session->display.active) {
		traffic_sample_display(session, now_ns);
	} else {
		traffic_print_snapshot(session->skel, session->args, session->rows,
				       session->last_report_ns, now_ns);
		traffic_report_drops(session->skel, session->previous_drops);
	}
	session->last_report_ns = now_ns;
	session->next_report_ns = now_ns +
		(u64)session->args->traffic_interval * 1000000000ULL;
	if (!force)
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
	if (args->traffic_ui && isatty(STDOUT_FILENO)) {
		session->previous_rows = calloc(TRAFFIC_MAX_FLOWS, sizeof(*session->previous_rows));
		session->process_rows = calloc(TRAFFIC_MAX_PROCESSES, sizeof(*session->process_rows));
		session->previous_process_rows = calloc(TRAFFIC_MAX_PROCESSES,
			sizeof(*session->previous_process_rows));
		session->flow_display_rows = calloc(TRAFFIC_MAX_FLOWS,
			sizeof(*session->flow_display_rows));
		session->process_display_rows = calloc(TRAFFIC_MAX_PROCESSES,
			sizeof(*session->process_display_rows));
		session->process_flow_counts = calloc(TRAFFIC_MAX_PROCESSES,
			sizeof(*session->process_flow_counts));
		if (!session->previous_rows || !session->process_rows ||
		    !session->previous_process_rows || !session->flow_display_rows ||
		    !session->process_display_rows || !session->process_flow_counts) {
			pr_err("traffic: failed to allocate interactive snapshots\n");
			goto out;
		}
		if (!traffic_history_open(&session->flow_history, TRAFFIC_MAX_FLOWS,
					 sizeof(traffic_flow_key_t)) ||
		    !traffic_history_open(&session->process_history, TRAFFIC_MAX_PROCESSES,
					 sizeof(traffic_process_key_t))) {
			pr_err("traffic: failed to allocate retained traffic history\n");
			goto out;
		}
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

	if (traffic_select_programs(session->skel, bpf_args->pkt.l4_proto) ||
	    traffic__load(session->skel)) {
		pr_err("traffic: failed to load BPF programs\n");
		goto out;
	}
	/* Loaded maps are empty. Include all bytes collected while attaching. */
	session->start_ns = session->last_report_ns = traffic_monotonic_ns();
	if (!session->start_ns) {
		pr_err("traffic: cannot read the monotonic clock\n");
		goto out;
	}
	session->totals_sample_ns = session->start_ns;
	if (traffic_attach_probes(session->skel, bpf_args->pkt.l4_proto,
				  session->links, &session->link_count))
		goto out;

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
	session->snapshot.protocol = bpf_args->pkt.l4_proto ?
		traffic_protocol_name(bpf_args->pkt.l4_proto) : "TCP/UDP";
	if (bpf_args->pid && bpf_args->uid_enabled)
		snprintf(session->filter, sizeof(session->filter), "TID %u / UID %u",
			bpf_args->pid, bpf_args->uid);
	else if (bpf_args->pid)
		snprintf(session->filter, sizeof(session->filter), "TID %u", bpf_args->pid);
	else if (bpf_args->uid_enabled)
		snprintf(session->filter, sizeof(session->filter), "UID %u", bpf_args->uid);
	else
		snprintf(session->filter, sizeof(session->filter), "all processes");
	session->snapshot.filter = session->filter;
	session->snapshot.warning = session->warning;
	session->snapshot.interval_seconds = args->traffic_interval;
	traffic_format_timestamp(session->snapshot.timestamp, traffic_monotonic_ns());
	session->snapshot.flows = true;
	if (args->traffic_ui && traffic_display_open(&session->display))
		traffic_render_cached(session);
	return 0;

out:
	traffic_release();
	return -1;
}

bool traffic_poll(void)
{
	struct traffic_session *session = &traffic_session;
	int key = traffic_display_read_key(&session->display);

	if (key == 'q')
		return true;
	if (traffic_display_key(&session->display, &session->snapshot, key))
		traffic_render_cached(session);
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
	traffic_exiting = 0;
	signal(SIGTERM, traffic_signal_handler);
	signal(SIGINT, traffic_signal_handler);
	if (traffic_start(args, bpf_args))
		return -1;
	while (!traffic_exiting) {
		struct timespec delay = {
			.tv_nsec = 100000000,
		};

		while (nanosleep(&delay, &delay) && errno == EINTR &&
		       !traffic_exiting)
			;
		if (traffic_exiting || traffic_poll())
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
