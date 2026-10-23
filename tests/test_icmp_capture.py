"""Run the real capture helpers with ICMP packets and controlled kernel state."""
import re
import unittest

from tests import test_flow_identity as helpers

ROOT = helpers.ROOT
function = helpers.function


class IcmpCaptureTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def test_icmp_selection_enables_output_and_default_preset_has_receivers(self):
        source = (ROOT / "src/trace.c").read_text()
        preset = re.search(r'perfetto_compact_traces\[\] =([^;]+);', source).group(1)
        for receiver in ("icmp_rcv", "icmpv6_rcv"):
            self.assertIn(receiver, preset)
        selection = function(source, "trace_enable_perfetto_output")
        names = set(re.findall(r"&trace_([A-Za-z0-9_]+)", selection))
        names.update(("icmp_rcv", "icmpv6_rcv", "ip_output", "ip6_output"))
        code = r'''
typedef struct { bool enabled; } trace_t;
static bool trace_is_enable(trace_t *trace) { return trace->enabled; }
static void trace_set_enable(trace_t *trace) { trace->enabled=true; }
static void trace_set_invalid_reason(trace_t *trace, const char *reason) {
    (void)reason; trace->enabled=false;
}
static struct { struct { bool perfetto, wakeup_chain; } bpf_args;
    struct { bool connect_diagnostics; } args; } trace_ctx = {.bpf_args.perfetto=true};
''' + "\n".join("static trace_t trace_" + name + ";" for name in sorted(names))
        result = self.run_source(code + "\n" + selection, r'''
trace_icmp_rcv.enabled=true;
trace_enable_perfetto_output();
printf("%d %d ", trace_ip_output.enabled, trace_ip6_output.enabled);
trace_icmp_rcv.enabled=false; trace_ip_output.enabled=false;
trace_icmpv6_rcv.enabled=true;
trace_enable_perfetto_output();
printf("%d %d", trace_ip_output.enabled, trace_ip6_output.enabled);
''')
        self.assertEqual(result, ["1", "0", "0", "1"])

    def test_icmp_packets_pass_without_entering_transport_flow_maps(self):
        source = (ROOT / "src/progs/core.c").read_text()
        code = "".join(function(source, name) for name in (
            "perfetto_packet_supported", "perfetto_transport_packet_supported"))
        code += r'''
typedef struct { u64 socket_key; u32 socket_generation; } perfetto_owner_t;
typedef struct { u32 saddr[4], daddr[4]; u16 sport, dport; } perfetto_flow_key_t;
typedef struct { perfetto_owner_t owner; u8 direction; } perfetto_flow_owner_t;
#define PACKET_DIRECTION_TX 1
#define PACKET_DIRECTION_RX 2
#define BPF_ANY 0
static int m_perfetto_flow_owner, m_perfetto_socket_owner;
static unsigned lookups, stores, keys;
static void *bpf_map_lookup_elem(void *map, const void *key) {
    lookups++; return NULL;
}
static void bpf_map_update_elem(void *map, const void *key, const void *value, int mode) {
    stores++;
}
static void perfetto_flow_key(packet_t *pkt, perfetto_flow_key_t *key, u32 netns) {
    keys++;
}
''' + function(source, "perfetto_lookup_flow")
        # The native harness also runs with GCC; this Clang-only BPF unroll
        # hint does not affect the helper's behavior under test.
        code += function(source, "perfetto_store_flow").replace(
            "#pragma clang loop unroll(full)\n", "")
        result = self.run_source(code, r'''
perfetto_owner_t owner = {.socket_key=1};
perfetto_flow_key_t key = {0};
perfetto_flow_owner_t value = {0};
unsigned protocols[] = {IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, 255};
for (unsigned i=0; i<sizeof(protocols)/sizeof(protocols[0]); i++) {
    packet_t pkt = {.proto_l4=protocols[i]};
    lookups=stores=keys=0;
    perfetto_lookup_flow(&pkt, &key, 1);
    perfetto_store_flow(&pkt, &owner, PACKET_DIRECTION_TX, &key, &value, 1);
    printf("%d %d %u %u %u ", perfetto_packet_supported(&pkt),
        perfetto_transport_packet_supported(&pkt), lookups, stores, keys);
}
''')
        self.assertEqual(result, [
            "1", "0", "0", "0", "0",  # ICMP
            "1", "0", "0", "0", "0",  # ICMPv6
            "1", "1", "1", "2", "2",  # TCP
            "1", "1", "1", "2", "2",  # UDP
            "0", "0", "0", "0", "0",  # unsupported protocol
        ])

    def test_compact_icmp_send_receive_and_detailed_kernel_names(self):
        source = (ROOT / "src/trace.c").read_text()
        code = r'''
typedef struct { const char *name; } trace_t;
typedef struct { union { packet_t pkt; sock_t ske; }; } event_t;
static struct { struct { bool perfetto; } bpf_args;
    struct { bool trace_detail, connect_diagnostics; } args;
} trace_ctx = {.bpf_args.perfetto=true};
''' + "".join(function(source, name) for name in (
            "trace_name_matches", "trace_event_visible", "trace_event_name"))
        result = self.run_source(code, r'''
const char *names[] = {"ip_output", "icmp_rcv", "ip6_output", "icmpv6_rcv.constprop.0"};
for (unsigned i=0; i<4; i++) {
    event_t event = {.pkt.proto_l4=i<2 ? IPPROTO_ICMP : IPPROTO_ICMPV6};
    trace_t trace = {.name=names[i]};
    printf("%d %s\n", trace_event_visible(&trace, &event), trace_event_name(&trace, &event));
    trace_ctx.args.trace_detail=true;
    printf("%d %s\n", trace_event_visible(&trace, &event), trace_event_name(&trace, &event));
    trace_ctx.args.trace_detail=false;
}
trace_t intermediate = {.name="ip_local_deliver"};
event_t event = {.pkt.proto_l4=IPPROTO_ICMP};
printf("%d ", trace_event_visible(&intermediate, &event));
trace_ctx.args.trace_detail=true;
printf("%d ", trace_event_visible(&intermediate, &event));
trace_ctx.bpf_args.perfetto=false;
trace_ctx.args.trace_detail=false;
printf("%s", trace_event_name(&intermediate, &event));
''')
        self.assertEqual(result, """
1 ICMP packet send 1 ip_output
1 ICMP packet receive 1 icmp_rcv
1 ICMPv6 packet send 1 ip6_output
1 ICMPv6 packet receive 1 icmpv6_rcv.constprop.0
0 1 ip_local_deliver
""".split())

    def test_icmp_owner_requires_socket_evidence_even_when_current_task_matches(self):
        source = (ROOT / "src/progs/core.c").read_text()
        code = r'''
typedef struct { u32 pid, uid; bool uid_enabled, rx_context; } bpf_args_t;
typedef struct { union { packet_t pkt; sock_t ske; }; } event_t;
typedef struct { u32 netns, owner_tid, owner_tgid, owner_uid, owner_socket_generation;
    u64 owner_socket_key; u8 direction, owner_valid, owner_pending, owner_evidence; } detail_event_t;
typedef struct { u64 socket_key; u32 tid, tgid, uid, socket_generation; u8 dns; } perfetto_owner_t;
typedef struct { perfetto_owner_t owner; u8 direction; } perfetto_flow_owner_t;
typedef struct { perfetto_owner_t owner; int flow_key, flow_value; } perfetto_scratch_t;
typedef struct { u64 socket_key; bool tx; } perfetto_io_t;
struct sock { u32 tid, uid; };
struct sk_buff { struct sock *sk; };
typedef struct { bpf_args_t *args; event_t *e; struct sk_buff *skb;
    u16 func; u8 func_status; } context_info_t;
#define PACKET_DIRECTION_TX 1
#define PACKET_DIRECTION_RX 2
#define FUNC_STATUS_TX 1
#define FUNC_STATUS_RX 2
#define FUNC_STATUS_RET 4
#define PACKET_DIRECTION_UNKNOWN 0
#define _C(object, field) ((object)->field)
static int m_perfetto_scratch, m_perfetto_io;
static bool trusted_current;
static perfetto_scratch_t scratch;
static u64 bpf_get_current_pid_tgid(void) { return ((u64)7 << 32) | 7; }
static u64 bpf_get_current_uid_gid(void) { return 1000; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
    return map == &m_perfetto_scratch ? &scratch : NULL;
}
static bool perfetto_rx_copy(u16 func) { return false; }
static bool perfetto_socket_io(u16 func) { return false; }
static u32 perfetto_socket_generation(struct sock *sk, bool created) { return 1; }
static void perfetto_store_socket_owner(struct sock *sk, perfetto_owner_t *owner) {}
static bool perfetto_resolve_socket_owner(struct sock *sk, bool trust_current,
    perfetto_owner_t *owner, u32 tid, u32 tgid, u32 uid) {
    trusted_current=trust_current;
    if (!sk) return false;
    owner->socket_key=1; owner->uid=sk->uid;
    owner->tid=sk->tid; owner->tgid=sk->tid;
    if (trust_current && !owner->tid) owner->tid=tid;
    return true;
}
static perfetto_flow_owner_t *perfetto_lookup_flow(packet_t *pkt, int *key, u32 netns) {
    return NULL;
}
static void perfetto_store_flow(packet_t *pkt, perfetto_owner_t *owner,
    u8 direction, int *key, int *value, u32 netns) {}
''' + "".join(function(source, name) for name in (
            "perfetto_status_direction", "perfetto_current_matches", "perfetto_owner_matches",
            "perfetto_packet_supported", "perfetto_packet_is_dns", "perfetto_socket_supported",
            "perfetto_handle_owner"))
        result = self.run_source(code, r'''
bpf_args_t args = {0};
event_t event = {.pkt.proto_l4=IPPROTO_ICMP};
struct sk_buff skb = {0};
struct sock sk = {.uid=1000};
context_info_t info = {.args=&args, .e=&event, .skb=&skb, .func_status=FUNC_STATUS_TX};
detail_event_t detail = {0};
int result=perfetto_handle_owner(&info, NULL, &detail, true);
printf("%d %u %u %d ", result, detail.owner_valid, detail.owner_tid, trusted_current);
args.uid_enabled=true; args.uid=1000;
printf("%d ", perfetto_handle_owner(&info, NULL, &detail, true));
skb.sk=&sk;
printf("%d ", perfetto_handle_owner(&info, NULL, &detail, true));
printf("%u %u %d ", detail.owner_valid, detail.owner_tid, trusted_current);
args.pid=7;
printf("%d ", perfetto_handle_owner(&info, NULL, &detail, true));
sk.tid=7;
printf("%d ", perfetto_handle_owner(&info, NULL, &detail, true));
sk.uid=2000;
printf("%d ", perfetto_handle_owner(&info, NULL, &detail, true));
/* ICMPv6 on an arbitrary receive task must also retain unknown ownership. */
args=(bpf_args_t){0}; skb.sk=NULL; detail=(detail_event_t){0};
event.pkt.proto_l4=IPPROTO_ICMPV6; info.func_status=FUNC_STATUS_RX;
result=perfetto_handle_owner(&info, NULL, &detail, true);
printf("%d %u %u %d ", result, detail.owner_valid, detail.direction, trusted_current);
/* Existing transport fallback behavior remains available. */
event.pkt.proto_l4=IPPROTO_TCP;
result=perfetto_handle_owner(&info, NULL, &detail, true);
printf("%d %u %u ", result, detail.owner_valid, detail.owner_tid);
/* Opt-in RX must not accept current-task identity as socket evidence. */
args=(bpf_args_t){.uid_enabled=true,.uid=1000,.rx_context=true};
skb.sk=NULL; detail=(detail_event_t){0};
result=perfetto_handle_owner(&info, NULL, &detail, true);
printf("%d %u %u %u ", result, detail.owner_valid, detail.owner_pending, detail.direction);
/* A known foreign socket is rejected even when current task matches. */
skb.sk=&sk; sk.uid=2000; detail=(detail_event_t){0};
printf("%d ", perfetto_handle_owner(&info, NULL, &detail, true));
sk.uid=1000; detail=(detail_event_t){0};
result=perfetto_handle_owner(&info, NULL, &detail, true);
printf("%d %u %u", result, detail.owner_pending, detail.owner_evidence);
''')
        self.assertEqual(result, "0 0 0 0 -1 0 1 0 0 -1 0 -1 0 0 2 0 0 1 7 0 0 1 2 -1 0 0 1".split())

    def test_icmp_packet_identity_does_not_inherit_active_transport_io(self):
        source = (ROOT / "src/progs/core.c").read_text()
        code = r'''
typedef struct { packet_t pkt; u64 io_start_ts, syscall_start_ts, owner_socket_key;
    u32 io_tid, io_tgid, key_generation, owner_socket_generation; u8 io_role, direction;
} detail_event_t;
typedef struct { u64 start_ts, syscall_start_ts, socket_key; bool tx; } perfetto_io_t;
typedef struct { u32 generation, io_socket_generation; u64 io_socket_key; } perfetto_packet_instance_t;
static int m_perfetto_io, m_perfetto_packets;
#define PACKET_DIRECTION_TX 1
#define INDEX_skb_consume_udp 5
static perfetto_io_t active = {.start_ts=10, .syscall_start_ts=9, .tx=true};
static perfetto_packet_instance_t packet = {.generation=42};
static u64 bpf_get_current_pid_tgid(void) { return ((u64)7 << 32) | 7; }
static bool perfetto_socket_io(u16 func) { return false; }
static bool perfetto_rx_copy(u16 func) { return true; }
static bool func_is_free(u8 status) { return false; }
static void perfetto_io_enter(u64 sk, u64 ts, u16 func, u8 status) {}
static void perfetto_io_exit(u16 func) {}
static u32 perfetto_packet_generation(u64 key, bool release, bool consume) { return 42; }
static void *bpf_map_lookup_elem(void *map, const void *key) {
    return map == &m_perfetto_io ? (void *)&active : (void *)&packet;
}
static void perfetto_packet_apply_submission(perfetto_packet_instance_t *packet,
    detail_event_t *detail) { detail->io_start_ts=99; }
'''
        if "perfetto_transport_packet_supported" in source:
            code += function(source, "perfetto_transport_packet_supported")
        code += function(source, "perfetto_record_identity")
        result = self.run_source(code, r'''
unsigned protocols[] = {IPPROTO_ICMP, IPPROTO_ICMPV6, IPPROTO_TCP};
for (unsigned i=0; i<3; i++) {
    detail_event_t detail = {.pkt.proto_l4=protocols[i], .direction=PACKET_DIRECTION_TX};
    perfetto_record_identity(&detail, 1, 2, 0);
    printf("%u %llu %llu %u ", detail.key_generation, detail.io_start_ts,
        detail.syscall_start_ts, detail.io_role);
}
''')
        self.assertEqual(result, "42 0 0 0 42 0 0 0 42 99 9 2".split())


if __name__ == "__main__":
    unittest.main()
