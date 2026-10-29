"""Exercise the independent XFRM slow-path probe and ordinary capture filters."""
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml

from tests import test_flow_identity as helpers
from tests import test_monitor_filters as monitor_helpers

ROOT = helpers.ROOT


def policy_probe(source):
    match = re.search(
        r"^DEFINE_KPROBE_SKB\(__xfrm_policy_check,\s*\d+,\s*\d+\)\n\{", source, re.M)
    if not match:
        raise AssertionError("Missing independent __xfrm_policy_check probe")
    return source[match.start():source.index("\n}", match.end()) + 2] + "\n"


class XfrmPolicyCaptureTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def capture_helpers(self):
        # Reuse the actual handle_entry()/shared argument layouts. Only the
        # kernel packet parser and BPF helpers remain controlled boundaries.
        code = monitor_helpers.MonitorFilterTests().capture_helpers()
        self.assertEqual(code.count("u32 skb_iif, len;"), 1)
        code = code.replace("u32 skb_iif, len;", "u32 skb_iif, len; u16 protocol;")
        source = (ROOT / "src/progs/core.c").read_text()
        code += r'''
#define bpf_ntohs ntohs
#undef AF_INET
#define AF_INET 2
#undef AF_INET6
#define AF_INET6 10
static detail_event_t event_storage;
static unsigned emitted;
static detail_event_t *trace_event_buffer(void) { return &event_storage; }
static void do_event_output(context_info_t *info, unsigned size) { emitted++; }
''' + helpers.function(source, "default_handle_entry") + r'''
#define info_get_arg(info, index) ((void *)((u64 *)(info)->ctx)[index])
static int fake_policy(context_info_t *info);
#define DEFINE_KPROBE_SKB(name, skb_index, arg_count) \
static const unsigned captured_arg_count = arg_count; \
static int capture_policy(u64 *ctx, bpf_args_t *args) { \
    context_info_t info = {.ctx=ctx, .args=args, .skb=(void *)ctx[skb_index]}; \
    return fake_policy(&info); \
} \
static int fake_policy(context_info_t *info)
''' + policy_probe(source)
        return code

    def test_family_is_fourth_argument_and_must_match_packet_protocol(self):
        result = self.run_source(self.capture_helpers(), r'''
const unsigned families[] = {AF_INET, AF_INET6, 0, 123};
const unsigned protocols[] = {ETH_P_IP, ETH_P_IPV6};
for (unsigned f=0; f<4; f++) {
    for (unsigned p=0; p<2; p++) {
        struct sk_buff skb = {.protocol=htons(protocols[p])};
        bpf_args_t args = {.trace_mode=TRACE_MODE_BASIC_MASK};
        u64 ctx[4] = {0xdeadbeef, AF_INET6, (u64)&skb, families[f]};
        emitted=0;
        printf("%d ", capture_policy(ctx, &args));
        printf("%u ", emitted);
    }
}
bpf_args_t args = {0};
u64 missing_skb[4] = {1, 2, 0, AF_INET};
printf("%d %u", capture_policy(missing_skb, &args), captured_arg_count);
''')
        self.assertEqual(result, [
            "0", "1", "-1", "0",  # AF_INET accepts only an IPv4 skb.
            "-1", "0", "0", "1",  # AF_INET6 accepts only an IPv6 skb.
            "-1", "0", "-1", "0",  # Unknown family is not inferred from skb.
            "-1", "0", "-1", "0",
            "-1", "4",  # The third argument is required; ABI has four arguments.
        ])

    def test_policy_probe_keeps_address_uid_and_tid_filters(self):
        result = self.run_source(self.capture_helpers(), r'''
const unsigned families[] = {AF_INET, AF_INET6};
const unsigned protocols[] = {ETH_P_IP, ETH_P_IPV6};
for (unsigned p=0; p<2; p++) {
    struct sk_buff skb = {.protocol=htons(protocols[p])};
    u64 ctx[4] = {0, 0, (u64)&skb, families[p]};
    for (unsigned filter=0; filter<4; filter++) {
        bpf_args_t args = {.trace_mode=TRACE_MODE_BASIC_MASK, .pid=71,
                          .uid_enabled=true, .uid=1000, .pkt.daddr=2};
        if (filter==1) args.pkt.daddr=99;
        if (filter==2) args.uid=1001;
        if (filter==3) args.pid=72;
        emitted=0;
        printf("%d ", capture_policy(ctx, &args));
        printf("%u ", emitted);
    }
}
''')
        self.assertEqual(result, ["0", "1", "-1", "0", "-1", "0", "-1", "0"] * 2)

    def test_tuple_owner_cache_cannot_assign_a_direction_to_the_shared_policy_path(self):
        source = (ROOT / "src/progs/core.c").read_text()
        code = monitor_helpers.MonitorFilterTests().capture_helpers()
        code = code.replace("u32 skb_iif, len;", "u32 skb_iif, len; struct sock *sk;")
        lookup = "static void *bpf_map_lookup_elem(void *map, const void *key) { return NULL; }"
        self.assertEqual(code.count(lookup), 1)
        code = code.replace(lookup, r'''
#define INDEX___xfrm_policy_check 100
typedef struct { u64 socket_key; u32 tid, tgid, uid, socket_generation; u8 dns; } perfetto_owner_t;
typedef struct { perfetto_owner_t owner; u8 direction; } perfetto_flow_owner_t;
typedef struct { perfetto_owner_t owner; int flow_key, flow_value; } perfetto_scratch_t;
static int m_perfetto_scratch;
static perfetto_scratch_t scratch;
static perfetto_flow_owner_t cached = {
    .owner={.socket_key=44,.tid=55,.tgid=55,.uid=2000,.socket_generation=1}};
static void *bpf_map_lookup_elem(void *map, const void *key) {
    return map==&m_perfetto_scratch ? &scratch : NULL;
}
''')
        code = code.replace(
            "static u8 perfetto_status_direction(u8 status) { return PACKET_DIRECTION_UNKNOWN; }",
            helpers.function(source, "perfetto_status_direction"))
        boundary = r'''
static bool perfetto_socket_io(u16 func) { return false; }
static u32 perfetto_socket_generation(struct sock *sk, bool create);
static bool perfetto_resolve_socket_owner(struct sock *sk, bool trust_current,
    perfetto_owner_t *owner, u32 tid, u32 tgid, u32 uid) { return false; }
static void perfetto_store_socket_owner(struct sock *sk, perfetto_owner_t *owner) {}
static perfetto_flow_owner_t *perfetto_lookup_flow(packet_t *pkt, int *key, u32 netns) {
    return &cached;
}
static void perfetto_store_flow(packet_t *pkt, perfetto_owner_t *owner,
    u8 direction, int *key, int *value, u32 netns) {}
''' + "".join(helpers.function(source, name) for name in (
            "perfetto_current_matches", "perfetto_owner_matches", "perfetto_packet_supported",
            "perfetto_packet_is_dns", "perfetto_socket_supported", "perfetto_handle_owner"))
        owner_stub = re.search(
            r"static int perfetto_handle_owner\([^{}]+\{ return 0; \}", code)
        self.assertIsNotNone(owner_stub)
        code = code.replace(owner_stub.group(), boundary)
        result = self.run_source(code, r'''
struct sk_buff skb={0};
detail_event_t event={0}, detail={0};
event.pkt.proto_l4=IPPROTO_UDP;
bpf_args_t args={.pid=55,.uid_enabled=true,.uid=2000};
context_info_t info={.args=&args,.e=(void *)&event,.skb=&skb};
for (unsigned direction=PACKET_DIRECTION_TX;direction<=PACKET_DIRECTION_RX;direction++) {
    cached.direction=direction;
    info.func=INDEX___xfrm_policy_check;
    detail=(detail_event_t){0};
    printf("%d ",perfetto_handle_owner(&info,NULL,&detail,true));
    printf("%u %u ",detail.direction,detail.owner_tid);
    /* Other existing stages keep their direction association semantics. */
    info.func=INDEX_tcp_close;
    detail=(detail_event_t){0};
    printf("%d ",perfetto_handle_owner(&info,NULL,&detail,true));
    printf("%u ",detail.direction);
}
/* Keeping unknown direction must not discard the owner filter boundary. */
info.func=INDEX___xfrm_policy_check;
args.uid=2001;
printf("%d ",perfetto_handle_owner(&info,NULL,&detail,true));
args.uid=2000;args.pid=56;
printf("%d",perfetto_handle_owner(&info,NULL,&detail,true));
''')
        self.assertEqual(result, ["0", "0", "55", "0", "1",
                                  "0", "0", "55", "0", "2", "-1", "-1"])

    def test_catalog_generates_an_independent_slow_path_stage(self):
        catalog = yaml.safe_load((ROOT / "src/trace.yaml").read_text())

        def groups(node):
            yield node
            for child in node.get("children", []):
                if isinstance(child, dict) and "children" in child:
                    yield from groups(child)

        xfrm = next(group for group in groups(catalog) if group["name"] == "xfrm")
        self.assertIn("xfrm4_policy_check:2", xfrm["children"])
        probe = next((child for child in xfrm["children"]
                      if isinstance(child, dict) and
                      child.get("name") == "__xfrm_policy_check:2"), None)
        self.assertIsNotNone(probe, "Missing independent slow-path catalog item")
        self.assertTrue(probe.get("custom"))
        self.assertNotIn("backup", probe)
        self.assertIn("slow-path only", probe["desc"])
        self.assertIn("fast", probe["desc"])
        self.assertIn("bypass", probe["desc"])

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copyfile(ROOT / "src/trace.yaml", root / "trace.yaml")
            (root / "btf.raw").write_text("")
            outputs = []
            for args in (("probe",), ()):
                result = subprocess.run(
                    [sys.executable, str(ROOT / "src/gen_trace.py"), *args],
                    cwd=root, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                outputs.append(result.stdout)
        self.assertIn("FNC(__xfrm_policy_check)", outputs[0])
        self.assertIn("FN(xfrm4_policy_check, 2,", outputs[0])
        self.assertIn('.name = "__xfrm_policy_check"', outputs[1])
        self.assertIn("trace___xfrm_policy_check.backup = NULL;", outputs[1])


if __name__ == "__main__":
    unittest.main()
