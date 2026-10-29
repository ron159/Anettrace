"""Nonzero fexit return values must not masquerade as matched packet contexts."""
import unittest

from tests import test_flow_identity as helpers

ROOT = helpers.ROOT
function = helpers.function


class MonitorFilterTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def capture_helpers(self):
        source = (ROOT / "src/progs/core.c").read_text()
        # Keep the production retval/matched union and filter argument layout.
        shared = (ROOT / "src/progs/shared.h").read_text()
        shared = shared.replace('#include "skb_shared.h"', "")
        shared = shared.replace('#include "kprobe_trace.h"', "")
        context = (ROOT / "src/progs/core.h").read_text()
        context = context.split("/* init the skb by the index of func args */")[0]
        context += "\n#endif\n"
        code = r'''
typedef int32_t s32;
typedef long long s64;
#define TRACE_MAX 256
''' + shared + context + r'''
#define __PROG_TYPE_TRACING 1
#define auto_inline
#define pr_debug_skb(...) ((void)0)
#define pr_bpf_debug(...) ((void)0)
#define _C(ptr, field) ((ptr)->field)
#define _(value) (value)
enum {
    INDEX_skb_copy_datagram_iter=1, INDEX_tcp_close,
    INDEX_tcp_v4_destroy_sock, INDEX_udp_destroy_sock, INDEX_udpv6_destroy_sock
};
struct net_device { char name[16]; u32 ifindex; };
struct sk_buff { struct net_device *dev; u32 skb_iif, len; };
struct sock { int unused; };
typedef struct { bool tx; u64 socket_key; } perfetto_io_t;
typedef struct { bool released; } perfetto_packet_instance_t;
static int m_perfetto_io, m_perfetto_socket_owner, m_perfetto_packets;
static unsigned parser_filters;
static u64 bpf_get_current_pid_tgid(void) { return ((u64)7 << 32) | 71; }
static u64 bpf_get_current_uid_gid(void) { return 1000; }
static u64 bpf_ktime_get_ns(void) { return 123; }
static void *bpf_map_lookup_elem(void *map, const void *key) { return NULL; }
static void bpf_map_delete_elem(void *map, const void *key) {}
static bool perfetto_rx_copy(u16 func) { return false; }
static u8 perfetto_status_direction(u8 status) { return PACKET_DIRECTION_UNKNOWN; }
static void bpf_get_current_comm(char *out, unsigned size) { memset(out, 0, size); }
static void bpf_core_read_str(char *out, unsigned size, const void *in) {
    memcpy(out, in, size);
}
/* Model the parser boundary: a wrong packet address is rejected only if
 * handle_entry passes its configured packet filter to the parser. */
static int probe_parse_sk(struct sock *sk, sock_t *out, pkt_args_t *args) {
    if (args) parser_filters++;
    return args && args->daddr && args->daddr != 2 ? -1 : 0;
}
static int probe_parse_skb(struct sk_buff *skb, struct sock *sk,
                           packet_t *out, pkt_args_t *args) {
    if (args) parser_filters++;
    return args && args->daddr && args->daddr != 2 ? -1 : 0;
}
static bool filter_by_netns(context_info_t *info) { return false; }
static int perfetto_handle_owner(context_info_t *info, struct sock *sk,
                                 detail_event_t *event, bool filter) { return 0; }
static void network_syscall_bind(context_info_t *info) {}
static void try_trace_stack(context_info_t *info) {}
static void perfetto_record_identity(detail_event_t *event, u64 sk, u64 skb, u32 status) {}
static u32 perfetto_socket_generation(struct sock *sk, bool create) { return 1; }
static void get_ret(context_info_t *info) {}
static void perfetto_io_exit(u16 func) {}
''' + "".join(function(source, name) for name in (
            "mode_has_context", "trace_mode_latency", "func_is_free",
            "try_set_latency", "handle_entry"))
        return code

    def assert_filter_rejected(self, setup):
        result = self.run_source(self.capture_helpers(), r'''
const unsigned modes[] = {TRACE_MODE_MONITOR, TRACE_MODE_SOCK, TRACE_MODE_BASIC};
const u64 returns[] = {0, 1, (u64)-22};
for (unsigned m=0; m<3; m++) {
    for (unsigned r=0; r<3; r++) {
        struct sk_buff skb = {0};
        detail_event_t event = {0};
        bpf_args_t args = {.trace_mode=1U << modes[m]};
        context_info_t info = {.args=&args, .e=(void *)&event, .skb=&skb,
                              .retval=returns[r], .is_return=1};
''' + setup + r'''
        printf("%d ", handle_entry(&info));
    }
}
''')
        self.assertEqual(result, ["-1"] * 9)

    def test_fexit_return_does_not_bypass_packet_address_filter(self):
        self.assert_filter_rejected("args.pkt.daddr=99;")

    def test_fexit_return_does_not_bypass_uid_filter(self):
        self.assert_filter_rejected("args.uid_enabled=true; args.uid=1001;")

    def test_fexit_return_does_not_bypass_tid_filter(self):
        self.assert_filter_rejected("args.pid=72;")

    def test_matching_filters_preserve_fexit_return_and_event_identity(self):
        result = self.run_source(self.capture_helpers(), r'''
struct sk_buff skb = {0};
for (unsigned r=0; r<3; r++) {
    const u64 returns[] = {0, 1, (u64)-22};
    detail_event_t event = {0};
    bpf_args_t args = {.trace_mode=TRACE_MODE_MONITOR_MASK, .pid=71,
                      .uid_enabled=true, .uid=1000, .pkt.daddr=2};
    context_info_t info = {.args=&args, .e=(void *)&event, .skb=&skb,
                          .retval=returns[r], .is_return=1};
    printf("%d ", handle_entry(&info));
    printf("%d %u %u %u ", event.retval == returns[r],
           event.tid, event.tgid, event.uid);
}
''')
        self.assertEqual(result, ["0", "1", "71", "7", "1000"] * 3)

    def test_real_matched_context_preserves_packet_lifecycle_across_tasks(self):
        result = self.run_source(self.capture_helpers(), r'''
const unsigned modes[] = {TRACE_MODE_TIMELINE, TRACE_MODE_DIAG, TRACE_MODE_LATENCY};
for (unsigned m=0; m<3; m++) {
    struct sk_buff skb = {0};
    detail_event_t event = {0};
    bpf_args_t args = {.trace_mode=1U << modes[m], .pid=72,
                      .uid_enabled=true, .uid=1001, .pkt.daddr=99};
    context_info_t info = {.args=&args, .e=(void *)&event, .skb=&skb,
                          .match_val.func1=1};
    parser_filters=0;
    printf("%d ", handle_entry(&info));
    printf("%u ", parser_filters);
    info.match_val=(match_val_t){0};
    printf("%d ", handle_entry(&info));
}
''')
        self.assertEqual(result, ["0", "0", "-1"] * 3)


if __name__ == "__main__":
    unittest.main()
