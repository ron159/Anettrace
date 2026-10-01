"""Receive profile and callback filtering regressions from production helpers."""
import re
import unittest
from tests import test_flow_identity as flow_test

ROOT = flow_test.ROOT
function = flow_test.function


class RxCaptureTests(unittest.TestCase):
    run_source = flow_test.FlowIdentityTests.run_source

    def test_syscall_boundaries_retire_missing_protocol_returns(self):
        source = (ROOT / "src/progs/core.c").read_text()
        helpers = r'''
typedef struct { u64 start_ts, syscall_start_ts, socket_key;
    u32 socket_generation, depth; u16 func; u8 tx; } perfetto_io_t;
typedef struct { u64 start_ts; } network_syscall_event_t;
static int m_perfetto_io, m_network_syscalls;
static perfetto_io_t active;
static network_syscall_event_t syscall;
static bool io_present, syscall_present;
#define BPF_ANY 0
#define FUNC_STATUS_TX 128
static u64 bpf_get_current_pid_tgid(void) { return 42; }
static u32 perfetto_socket_generation(void *sk, bool created) {
    (void)sk; (void)created; return 1;
}
static void *bpf_map_lookup_elem(void *map, const void *key) {
    (void)key;
    if (map == &m_perfetto_io) return io_present ? &active : NULL;
    return syscall_present ? &syscall : NULL;
}
static void bpf_map_delete_elem(void *map, const void *key) {
    (void)key;
    if (map == &m_perfetto_io) io_present = false;
}
static void bpf_map_update_elem(void *map, const void *key, const void *value, int flags) {
    (void)map; (void)key; (void)flags;
    active = *(const perfetto_io_t *)value;
    io_present = true;
}
''' + function(source, "perfetto_io_syscall_boundary") + function(source, "perfetto_io_enter")
        result = self.run_source(helpers, r'''
syscall_present = true; syscall.start_ts = 100;
perfetto_io_enter(9, 110, 1, FUNC_STATUS_TX);
perfetto_io_enter(9, 120, 1, FUNC_STATUS_TX);
printf("%llu %u ", active.start_ts, active.depth);
/* Missing the return/cleanup of the prior call cannot reuse its ID. */
syscall.start_ts = 200;
perfetto_io_enter(9, 210, 1, FUNC_STATUS_TX);
printf("%llu %llu %u ", active.start_ts, active.syscall_start_ts, active.depth);
/* sys_exit retires even if no network syscall record is available. */
syscall_present = false;
perfetto_io_syscall_boundary(42);
printf("%d ", io_present);
/* sys_enter also bounds a call left behind when the prior exit was missed. */
io_present = true;
perfetto_io_syscall_boundary(42);
syscall_present = true; syscall.start_ts = 300;
perfetto_io_enter(9, 310, 1, FUNC_STATUS_TX);
printf("%llu %u", active.start_ts, active.depth);
''')
        self.assertEqual(result, ["110", "2", "210", "200", "1", "0", "310", "1"])

    def test_syscall_cleanup_precedes_decode_and_missing_exit_record(self):
        source = (ROOT / "src/progs/core.c").read_text()
        enter = source.split("int TRACE_NAME(network_sys_enter)", 1)[1].split(
            'SEC("tp/raw_syscalls/sys_exit")', 1)[0]
        exit_source = source.split("int TRACE_NAME(network_sys_exit)", 1)[1].split(
            'SEC("tp/raw_syscalls/sys_enter")', 1)[0]
        self.assertLess(enter.index("perfetto_io_syscall_boundary(pid_tgid)"),
                        enter.index("kind = network_call_kind"))
        self.assertLess(enter.index("bpf_map_delete_elem(&m_network_syscalls"),
                        enter.index("kind = network_call_kind"))
        self.assertLess(exit_source.index("perfetto_io_syscall_boundary(pid_tgid)"),
                        exit_source.index("bpf_map_lookup_elem(&m_network_syscalls"))

    def test_packet_generation_discards_saved_provenance_on_head_or_allocation_reuse(self):
        source = (ROOT / "src/progs/core.c").read_text()
        packet_type = re.search(
            r"typedef struct \{[^{}]*\} perfetto_packet_instance_t;", source).group()
        helpers = packet_type + r'''
struct sk_buff { u64 head; struct { struct { int counter; } refs; } users; };
#define _C(ptr, field) ((ptr)->field)
#define BPF_ANY 0
static int m_perfetto_packets, m_perfetto_packet_counter;
static u32 counter;
static u64 stored_key;
static bool present;
static perfetto_packet_instance_t stored;
static void *bpf_map_lookup_elem(void *map, const void *key) {
    if (map == &m_perfetto_packet_counter) return &counter;
    return present && stored_key == *(const u64 *)key ? &stored : NULL;
}
static void bpf_map_update_elem(void *map, const void *key, const void *value, int flags) {
    (void)map; (void)flags;
    stored_key = *(const u64 *)key;
    stored = *(const perfetto_packet_instance_t *)value;
    present = true;
}
''' + function(source, "perfetto_packet_generation")
        result = self.run_source(helpers, r'''
struct sk_buff skb = {.head = 10, .users.refs.counter = 2};
u64 key = (u64)&skb;
u32 first = perfetto_packet_generation(key, false, false);
stored.io_start_ts = 123; stored.io_multiple = 1;
printf("%d %llu ", perfetto_packet_generation(key, false, false) == first, stored.io_start_ts);
skb.head = 20;
u32 changed = perfetto_packet_generation(key, false, false);
printf("%d %llu %u ", changed != first, stored.io_start_ts, stored.io_multiple);
stored.io_start_ts = 456;
perfetto_packet_generation(key, true, false);
printf("%d ", perfetto_packet_generation(key, false, false) != changed);
printf("%llu ", stored.io_start_ts);
/* A peek/shared UDP buffer keeps identity; last-reference consume retires it. */
u32 shared = perfetto_packet_generation(key, false, true);
printf("%d ", perfetto_packet_generation(key, false, false) == shared);
skb.users.refs.counter = 1;
perfetto_packet_generation(key, false, true);
printf("%d", perfetto_packet_generation(key, false, false) != shared);
''')
        self.assertEqual(result, ["1", "123", "1", "0", "0", "1", "0", "1", "1"])

    def test_packet_provenance_does_not_guess_after_reuse_or_multiple_calls(self):
        source = (ROOT / "src/progs/core.c").read_text()
        helpers = r'''
typedef struct { u64 io_start_ts, syscall_start_ts, io_task, io_socket_key;
    u32 io_socket_generation; u8 io_multiple; } perfetto_packet_instance_t;
typedef struct { u64 start_ts, syscall_start_ts, socket_key; u32 socket_generation; } perfetto_io_t;
typedef struct { u64 io_start_ts, syscall_start_ts; u32 io_tid, io_tgid;
    u8 io_role, io_multiple; } detail_event_t;
''' + function(source, "perfetto_packet_remember_submission") + function(source, "perfetto_packet_apply_submission")
        result = self.run_source(helpers, r'''
perfetto_packet_instance_t packet = {0};
perfetto_io_t io = {.start_ts=123, .syscall_start_ts=120, .socket_key=999};
detail_event_t detail = {0};
perfetto_packet_remember_submission(&packet, &io, ((u64)8 << 32) | 42);
perfetto_packet_apply_submission(&packet, &detail);
printf("%llu %u %u %u ", detail.io_start_ts, detail.io_tid, detail.io_tgid, detail.io_role);
/* A fresh allocation/head generation has no inherited previous call. */
packet = (perfetto_packet_instance_t){0};
detail = (detail_event_t){0};
perfetto_packet_apply_submission(&packet, &detail);
printf("%llu ", detail.io_start_ts);
perfetto_packet_remember_submission(&packet, &io, 42);
perfetto_packet_remember_submission(&packet, &io, 42);
printf("%u ", packet.io_multiple);
io.start_ts = 456;
perfetto_packet_remember_submission(&packet, &io, 43);
detail = (detail_event_t){.io_start_ts=456, .io_tid=43, .io_role=1};
perfetto_packet_apply_submission(&packet, &detail);
printf("%u %llu %u", detail.io_multiple, detail.io_start_ts, detail.io_role);
''')
        self.assertEqual(result, ["123", "42", "8", "4", "0", "0", "1", "0", "0"])

    def test_receive_handoff_key_stages_are_visible_in_compact_mode(self):
        source = (ROOT / "src/trace.c").read_text()
        helpers = r'''
typedef struct { const char *name; } trace_t;
typedef struct { packet_t pkt; } event_t;
static struct { struct { bool perfetto; } bpf_args;
    struct { bool trace_detail, connect_diagnostics; } args; } trace_ctx = {
    .bpf_args.perfetto = true};
''' + function(source, "trace_name_matches") + function(source, "trace_event_visible")
        result = self.run_source(helpers, r'''
event_t event = {.pkt.proto_l4 = IPPROTO_TCP};
const char *names[] = {"tcp_queue_rcv", "udp_queue_rcv_skb",
    "__udp_enqueue_schedule_skb", "sock_def_readable", "ip_rcv"};
for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
    trace_t trace = {.name = names[i]};
    printf("%d ", trace_event_visible(&trace, &event));
}
trace_ctx.args.trace_detail = true;
trace_t ip = {.name = "ip_rcv"};
printf("%d", trace_event_visible(&ip, &event));
''')
        self.assertEqual(result, ["1", "1", "1", "1", "0", "1"])

    def test_explicit_protocol_selection_keeps_rx_identity_dependencies(self):
        source = function((ROOT / "src/trace.c").read_text(), "trace_enable_perfetto_output")
        names = sorted(set(re.findall(r"&trace_([A-Za-z0-9_]+)", source)))
        helpers = r'''
typedef struct { bool enabled; } trace_t;
static bool trace_is_enable(trace_t *trace) { return trace->enabled; }
static void trace_set_enable(trace_t *trace) { trace->enabled = true; }
static struct { struct { bool perfetto; } bpf_args;
    struct { bool connect_diagnostics; } args; } trace_ctx = {.bpf_args.perfetto=true};
''' + "\n".join("static trace_t trace_" + name + ";" for name in names) + "\n" + source
        self.assertIn("tcp_rcv_established", names)
        self.assertIn("sock_def_readable", names)
        result = self.run_source(helpers, r'''
trace_tcp_v4_rcv.enabled = true;
trace_enable_perfetto_output();
printf("%d %d %d %d %d %d %d %d", trace_tcp_rcv_established.enabled,
    trace_tcp_queue_rcv.enabled, trace_sock_def_readable.enabled,
    trace_skb_copy_datagram_iter.enabled, trace_sk_alloc.enabled,
    trace_inet_sock_set_state.enabled, trace_network_sys_enter.enabled,
    trace_network_sys_exit.enabled);
''')
        self.assertEqual(result, ["1"] * 8)
