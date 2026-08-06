// SPDX-License-Identifier: MulanPSL-2.0

#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <bpf/libbpf.h>

#include <arg_parse.h>

#include "anettrace.h"
#include "trace.h"
#include "traffic.h"
#include "perfetto_export.h"
#include "trace_capture.h"

arg_config_t config = {
	.name = "anettrace",
	.summary = "a tool to trace skb in kernel and diagnose network problem",
	.desc = "",
};

static int print_all_levels(enum libbpf_print_level level, const char *format,
			    va_list args)
{
	(void)level;
	return vfprintf(stdout, format, args);
}

static void do_parse_args(int argc, char *argv[])
{
	bool show_log = false, debug = false, version = false;
	bool libbpf_debug = false;
	bool timestamp = false, date = false;
	trace_args_t *trace_args = &trace_ctx.args;
	bpf_args_t *bpf_args = &trace_ctx.bpf_args;
	pkt_args_t *pkt_args = &bpf_args->pkt;
	u8 addr_buf[16], saddr_buf[16], daddr_buf[16];
	u16 addr_pf = 0, saddr_pf = 0, daddr_pf = 0;
	int proto_l = 0;
	u16 proto;

	option_item_t opts[] = {
		{
			.lname = "saddr",
			.sname = 's',
			.dest = saddr_buf,
			.type = OPTION_IPV4ORIPV6,
			.set = &saddr_pf,
			.desc = "filter source ip/ipv6 address",
		},
		{
			.lname = "daddr",
			.sname = 'd',
			.dest = daddr_buf,
			.type = OPTION_IPV4ORIPV6,
			.set = &daddr_pf,
			.desc = "filter dest ip/ipv6 address",
		},
		{
			.lname = "addr",
			.dest = addr_buf,
			.type = OPTION_IPV4ORIPV6,
			.set = &addr_pf,
			.desc = "filter source or dest ip/ipv6 address",
		},
		{
			.lname = "sport",
			.sname = 'S',
			.dest = &pkt_args->sport,
			.type = OPTION_U16BE,
			.desc = "filter source TCP/UDP port",
		},
		{
			.lname = "dport",
			.sname = 'D',
			.dest = &pkt_args->dport,
			.type = OPTION_U16BE,
			.desc = "filter dest TCP/UDP port",
		},
		{
			.lname = "port",
			.sname = 'P',
			.dest = &pkt_args->port,
			.type = OPTION_U16BE,
			.desc = "filter source or dest TCP/UDP port",
		},
		{
			.lname = "proto",
			.sname = 'p',
			.dest = &proto,
			.type = OPTION_PROTO,
			.set = &proto_l,
			.desc = "filter L3/L4 protocol, such as 'tcp', 'arp'",
		},
		{
			.lname = "netns",
			.dest = &bpf_args->netns,
			.type = OPTION_U32,
			.desc = "filter by net namespace inode",
		},
		{
			.lname = "netns-current",
			.dest = &trace_args->netns_current,
			.type = OPTION_BOOL,
			.desc = "filter by current net namespace",
		},
		{
			.lname = "pid", .type = OPTION_U32,
			.dest = &bpf_args->pid,
			.desc = "filter by current thread id (legacy --pid semantics)",
		},
		{
			.lname = "uid", .type = OPTION_U32,
			.dest = &bpf_args->uid,
			.set = &bpf_args->uid_enabled,
			.desc = "filter by current user id(uid), including uid 0",
		},
		{
			.lname = "min-latency", .dest = &trace_args->min_latency,
			.type = OPTION_U32,
			.desc = "filter by the minimal time to live of the skb in us",
		},
		{
			.lname = "pkt-len", .dest = &trace_args->pkt_len,
			.type = OPTION_STRING,
			.desc = "filter by the IP packet length (include header) in byte",
		},
		{
			.lname = "tcp-flags", .dest = &trace_args->tcp_flags,
			.type = OPTION_STRING,
			.desc = "filter by TCP flags, such as: SAPR",
		},
		{ .type = OPTION_BLANK },
		{
			.lname = "traffic", .dest = &trace_args->traffic,
			.type = OPTION_BOOL,
			.desc = "show per-thread TCP/UDP traffic totals instead of socket lifecycle",
		},
		{
			.lname = "interval", .dest = &trace_args->traffic_interval,
			.type = OPTION_U32,
			.desc = "traffic refresh interval in seconds (default 1)",
		},
		{
			.lname = "basic", .dest = &trace_args->basic,
			.type = OPTION_BOOL,
			.desc = "use 'basic' trace mode, don't trace skb's life",
		},
		{
			.lname = "diag", .dest = &trace_args->intel,
			.type = OPTION_BOOL,
			.desc = "enable 'diagnose' mode",
		},
		{
			.lname = "diag-quiet", .dest = &trace_args->intel_quiet,
			.type = OPTION_BOOL,
			.desc = "only print abnormal packet",
		},
		{
			.lname = "diag-keep", .dest = &trace_args->intel_keep,
			.type = OPTION_BOOL,
			.desc = "don't quit when abnormal packet found",
		},
		{
			.lname = "drop", .dest = &trace_args->drop,
			.type = OPTION_BOOL,
			.desc = "skb drop monitor mode, for replace of 'droptrace'",
		},
#ifdef __F_STACK_TRACE
		{
			.lname = "drop-stack", .dest = &trace_args->drop_stack,
			.type = OPTION_BOOL,
			.desc = "print the kernel function call stack of kfree_skb",
		},
#endif
		{
			.lname = "sock", .dest = &trace_args->sock,
			.type = OPTION_BOOL,
			.desc = "enable 'sock' mode",
		},
		{
			.lname = "monitor", .dest = &trace_args->monitor,
			.type = OPTION_BOOL,
			.desc = "enable 'monitor' mode",
		},
		{
			.lname = "rtt", .dest = &trace_args->rtt,
			.type = OPTION_BOOL,
			.desc = "enable 'rtt' in statistics mode",
		},
		{
			.lname = "rtt-detail", .dest = &trace_args->rtt_detail,
			.type = OPTION_BOOL,
			.desc = "enable 'rtt' in detail mode",
		},
		{
			.lname = "filter-srtt", .dest = &bpf_args->first_rtt,
			.type = OPTION_U32,
			.desc = "filter by the minial first-acked rtt in ms",
		},
		{
			.lname = "filter-minrtt", .dest = &bpf_args->last_rtt,
			.type = OPTION_U32,
			.desc = "filter by the minial last-acked rtt in ms",
		},
		{
			.lname = "latency-show", .dest = &trace_args->latency_show,
			.type = OPTION_BOOL,
			.desc = "show latency between kernel functions",
		},
		{
			.lname = "latency-free", .dest = &bpf_args->latency_free,
			.type = OPTION_BOOL,
			.desc = "account the latency of skb free",
		},
		{
			.lname = "latency", .dest = &trace_args->latency,
			.type = OPTION_BOOL,
			.desc = "enable 'latency' mode",
		},
		{
			.lname = "latency-summary", .dest = &bpf_args->latency_summary,
			.type = OPTION_BOOL,
			.desc = "show latency by statistics",
		},
		{ .type = OPTION_BLANK },
		{
			.lname = "trace", .sname = 't',
			.dest = &trace_args->traces,
			.desc = "enable trace group or trace. Some traces are "
				"disabled by default, use \"all\" to enable all",
		},
		{
			.lname = "force", .dest = &trace_args->force,
			.type = OPTION_BOOL,
			.desc = "skip some check and force load anettrace",
		},
		{
			.lname = "ret", .dest = &trace_args->ret,
			.type = OPTION_BOOL,
			.desc = "show function return value",
		},
		{
			.lname = "detail", .dest = &bpf_args->detail,
			.type = OPTION_BOOL,
			.desc = "show extern packet info, such as pid, ifname, etc",
		},
		{
			.lname = "perfetto-events", .dest = &trace_args->perfetto_events,
			.type = OPTION_STRING,
			.desc = "write socket and packet timeline metadata as JSONL for Perfetto",
		},
		{
			.lname = "capture-trace", .dest = &trace_args->capture_trace,
			.type = OPTION_BOOL,
			.desc = "capture system trace plus Anettrace events into one Perfetto trace",
		},
		{
			.lname = "trace-profile", .dest = &trace_args->trace_profile,
			.type = OPTION_STRING,
			.desc = "system trace profile: full (default) or sched",
		},
		{
			.lname = "duration", .dest = &trace_args->duration,
			.type = OPTION_U32,
			.desc = "capture duration in seconds (default 10 with --capture-trace)",
		},
		{
			.lname = "output", .dest = &trace_args->output,
			.type = OPTION_STRING,
			.desc = "combined .pftrace file or existing output directory",
		},
		{
			.lname = "date", .dest = &date,
			.type = OPTION_BOOL,
			.desc = "print local date and time",
		},
		{
			.lname = "timestamp", .dest = &timestamp,
			.type = OPTION_BOOL,
			.desc = "print the raw monotonic timestamp",
		},
		{
			.lname = "id", .dest = &trace_args->show_id,
			.type = OPTION_BOOL,
			.desc = "show IPv4 id in hexadecimal",
		},
		{
			.lname = "mark", .dest = &trace_args->show_mark,
			.type = OPTION_BOOL,
			.desc = "show skb mark in hexadecimal",
		},
		{
			.lname = "count", .sname = 'c', .dest = &trace_args->count,
			.type = OPTION_U32,
			.desc = "exit after count packets, or count reports in traffic mode",
		},
		{
			.lname = "hooks", .dest = &bpf_args->hooks,
			.type = OPTION_BOOL,
			.desc = "print netfilter hooks if dropping by netfilter",
		},
		{
			.lname = "tiny-show", .dest = &bpf_args->tiny_output,
			.type = OPTION_BOOL,
			.desc = "set this option to show less infomation",
		},
		{
			.lname = "trace-stack", .dest = &trace_args->traces_stack,
			.type = OPTION_STRING,
			.desc = "print call stack for traces or group",
		},
		{
			.lname = "trace-matcher", .dest = &trace_args->trace_matcher,
			.type = OPTION_STRING,
			.desc = "traces that can match packet(default all)",
		},
		{
			.lname = "trace-exclude", .dest = &trace_args->trace_exclude,
			.type = OPTION_STRING,
			.desc = "traces that should be disabled",
		},
		{
			.lname = "trace-noclone", .dest = &trace_args->traces_noclone,
			.type = OPTION_BOOL,
			.desc = "don't trace skb clone",
		},
		{
			.lname = "trace-free", .dest = &trace_args->trace_free,
			.type = OPTION_STRING,
			.desc = "custom the free functions",
		},
		{
			.lname = "func-stats", .dest = &bpf_args->func_stats,
			.type = OPTION_BOOL,
			.desc = "only do the statistics for function call",
		},
		{
			.lname = "rate-limit", .dest = &bpf_args->rate_limit,
			.type = OPTION_U32,
			.desc = "limit the output to N/s, not valid in diag/default mode",
		},
		{
			.lname = "btf-path", .dest = &trace_args->btf_path,
			.type = OPTION_STRING,
			.desc = "custom the path of BTF info of vmlinux",
		},
		{ .type = OPTION_BLANK },
		{
			.sname = 'v', .dest = &show_log,
			.type = OPTION_BOOL,
			.desc = "show log information",
		},
		{
			.lname = "debug", .dest = &debug,
			.type = OPTION_BOOL,
			.desc = "show debug information",
		},
		{
			.lname = "libbpf-debug", .dest = &libbpf_debug,
			.type = OPTION_BOOL,
			.desc = "show libbpf debug information",
		},
		{
			.lname = "bpf-debug", .dest = &libbpf_debug,
			.type = OPTION_BOOL,
			.desc = "compatibility alias for --libbpf-debug",
		},
#ifdef BPF_DEBUG
		{
			.lname = "bpf-program-debug", .dest = &bpf_args->pkt.bpf_debug,
			.type = OPTION_BOOL,
			.desc = "show in-kernel BPF debug information",
		},
#endif
		{
			.lname = "help",
			.sname = 'h',
			.type = OPTION_HELP,
			.desc = "show help information",
		},
		{
			.lname = "version", .dest = &version,
			.sname = 'V',
			.type = OPTION_BOOL,
			.desc = "show anettrace version",
		},
	};

	if (parse_args(argc, argv, &config, opts, ARRAY_SIZE(opts)))
		goto err;
	if (date && timestamp) {
		pr_err("--date and --timestamp cannot be used together\n");
		goto err;
	}

	if (show_log)
		set_log_level(1);

	if (!debug && !libbpf_debug)
		libbpf_set_print(NULL);
	if (libbpf_debug)
		libbpf_set_print(print_all_levels);
	if (debug)
		set_log_level(2);

	if (version) {
		pr_version();
		exit(0);
	}
	if (trace_args->capture_trace && trace_args->traffic) {
		pr_err("--capture-trace cannot be used with --traffic\n");
		goto err;
	}
	if (trace_args->capture_trace && trace_args->perfetto_events) {
		pr_err("--capture-trace and --perfetto-events are separate output modes\n");
		goto err;
	}
	if (trace_args->output && !trace_args->capture_trace) {
		pr_err("--output requires --capture-trace\n");
		goto err;
	}
	if (trace_args->duration && !trace_args->capture_trace) {
		pr_err("--duration requires --capture-trace\n");
		goto err;
	}
	if (trace_args->trace_profile && !trace_args->capture_trace) {
		pr_err("--trace-profile requires --capture-trace\n");
		goto err;
	}
	if (trace_args->capture_trace && trace_args->trace_profile &&
	    strcmp(trace_args->trace_profile, "full") &&
	    strcmp(trace_args->trace_profile, "sched")) {
		pr_err("--trace-profile must be full or sched\n");
		goto err;
	}
	if (trace_args->capture_trace && !trace_args->duration)
		trace_args->duration = 10;
	if (trace_args->capture_trace && !trace_args->trace_profile)
		trace_args->trace_profile = "full";

/* convert the args to the eBPF pkt_arg struct */
#define FILL_ADDR_PROTO(name, subfix, args, pf) if (name##_pf == pf) {	\
	memcpy(&(args)->name##subfix, name##_buf,			\
	       sizeof((args)->name##subfix));				\
	if ((args)->l3_proto && (args)->l3_proto != pf) { 		\
		pr_err("ip" #subfix " protocol is excepted!\n");	\
		goto err;						\
	}								\
	(args)->l3_proto = pf;						\
}
#define FILL_ADDR(name, args)						\
	FILL_ADDR_PROTO(name, _v6, args, ETH_P_IPV6)			\
	FILL_ADDR_PROTO(name, , args, ETH_P_IP)

	switch (proto_l) {
	case 3:
		pkt_args->l3_proto = proto;
		break;
	case 4:
		pkt_args->l4_proto = proto;
		break;
	default:
		break;
	}

	/* set L3 protocol if addr is offered */
	FILL_ADDR(saddr, pkt_args)
	FILL_ADDR(daddr, pkt_args)
	FILL_ADDR(addr, pkt_args)

	pkt_args->saddr_v6_enable = !!saddr_pf;
	pkt_args->daddr_v6_enable = !!daddr_pf;
	pkt_args->addr_v6_enable = !!addr_pf;

	if (date)
		trace_args->time_mode = TIME_MODE_DATE;
	else if (timestamp)
		trace_args->time_mode = TIME_MODE_MONOTONIC;
	else
		trace_args->time_mode = TIME_MODE_LOCAL;

	if (bpf_args->detail) {
		trace_args->show_id = true;
		trace_args->show_mark = true;
	}

	return;
err:
	exit(-EINVAL);
}

static void do_exit(int code)
{
	static bool is_exited = false;
	bpf_args_t *bpf_args;
	u64 event_count;

	if (is_exited)
		return;

	is_exited = true;
	bpf_args = get_bpf_args();
	event_count = bpf_args->event_count;

	pr_info("end trace...\n");
	pr_debug("begin destory BPF skel...\n");
	trace_ctx.ops->trace_close();
	pr_debug("BPF skel is destroied\n");
	trace_ctx.stop = true;
	perfetto_export_close(event_count);

	pr_info("total event: %llu, %d context skipped\n",
		event_count, ctx_count);
}

int main(int argc, char *argv[])
{
	int capture_err = 0;

	output_time_init();
	init_trace_group();
	do_parse_args(argc, argv);
	if (trace_ctx.args.traffic)
		return traffic_run(&trace_ctx.args, &trace_ctx.bpf_args);

	if (trace_prepare())
		goto err;
	if (perfetto_export_open(trace_ctx.args.perfetto_events))
		goto err;

	if (trace_bpf_load_and_attach()) {
		pr_err("failed to load bpf\n");
		goto err;
	}
	if (trace_ctx.args.capture_trace) {
		if (trace_capture_start(trace_ctx.args.output,
					trace_ctx.args.duration,
					trace_ctx.args.trace_profile))
			goto err;
		if (perfetto_export_native_open(trace_capture_network_path()))
			goto err;
	}

	signal(SIGTERM, do_exit);
	signal(SIGINT, do_exit);

	pr_info("begin trace...\n");
	trace_poll();
	do_exit(0);
	if (trace_ctx.args.capture_trace) {
		if (perfetto_export_failed()) {
			pr_err("failed to encode Anettrace Perfetto packets\n");
			trace_capture_abort();
			return -1;
		}
		capture_err = trace_capture_finish();
		if (capture_err)
			return -1;
	}
	return 0;
err:
	perfetto_export_close(0);
	trace_capture_abort();
	return -1;
}
