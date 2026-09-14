"""Behavioral regressions compiled from the real BPF and exporter helpers."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
EXPORT = ROOT / "src/perfetto_export.c"


def function(source, name):
    match = re.search(r"^(?:static )?[^\n]*\b" + name + r"\([^;]*?\n\{", source, re.M)
    if not match:
        raise AssertionError("Missing source function: " + name)
    start = match.start()
    brace = source.index("{", match.start())
    depth = 1
    end = brace + 1
    while depth:
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    return source[start:end] + "\n"


PRELUDE = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint64_t __u64;
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define bpf_htons htons
#ifndef __always_inline
#define __always_inline inline
#endif
#include "src/progs/skb_shared.h"
static u64 export_salt = 123;
'''


class FlowIdentityTests(unittest.TestCase):
    def run_source(self, source, body):
        with tempfile.TemporaryDirectory() as tmp:
            cfile, binary = Path(tmp) / "regression.c", Path(tmp) / "regression"
            cfile.write_text(PRELUDE + source + "\nint main(void) {\n" + body + "\n}\n")
            compile_result = subprocess.run(
                ["cc", "-std=gnu11", "-Wall", "-Werror", "-Wno-unused-function",
                 "-Wno-unused-variable", "-I", str(ROOT), str(cfile), "-o", str(binary)],
                capture_output=True, text=True)
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            return result.stdout.split()

    def test_game_udp_passes_bpf_packet_and_socket_filters(self):
        source = (ROOT / "src/progs/core.c").read_text()
        helpers = "".join(function(source, name) for name in (
            "perfetto_packet_supported", "perfetto_socket_supported"))
        result = self.run_source(helpers, r'''
packet_t pkt = {.proto_l4 = IPPROTO_UDP};
sock_t sock = {.proto_l4 = IPPROTO_UDP};
pkt.l4.min.sport = sock.l4.min.sport = htons(40000);
pkt.l4.min.dport = sock.l4.min.dport = htons(27015);
printf("%d %d", perfetto_packet_supported(&pkt), perfetto_socket_supported(&sock));
''')
        self.assertEqual(result, ["1", "1"])

    def test_game_udp_connected_socket_is_exportable(self):
        result = self.run_source(function(EXPORT.read_text(), "flow_socket_supported"), r'''
sock_t sock = {.proto_l3=ETH_P_IP, .proto_l4=IPPROTO_UDP};
sock.l4.min.sport = htons(40000); sock.l4.min.dport = htons(27015);
printf("%d", flow_socket_supported(&sock));
''')
        self.assertEqual(result, ["1"])

    def test_plain_udp_labels_do_not_claim_dns(self):
        source = (ROOT / "src/trace.c").read_text()
        helpers = r'''
typedef struct { const char *name; } trace_t;
typedef struct { union { packet_t pkt; sock_t ske; }; } event_t;
static struct { struct { bool perfetto; } bpf_args;
    struct { bool trace_detail; } args; } trace_ctx = {.bpf_args.perfetto = true};
static bool trace_name_matches(const trace_t *trace, const char *name) {
    return !strcmp(trace->name, name);
}
''' + function(source, "trace_event_name")
        result = self.run_source(helpers, r'''
event_t event = {.pkt.proto_l4 = IPPROTO_UDP};
event.pkt.l4.min.sport = htons(40000);
event.pkt.l4.min.dport = htons(27015);
const char *names[] = {"udp_sendmsg", "udp_recvmsg", "udpv6_sendmsg",
    "udpv6_recvmsg", "ip_output", "ip6_output", "udp_rcv", "udpv6_rcv"};
for (unsigned i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    trace_t trace = {.name = names[i]};
    puts(trace_event_name(&trace, &event));
}
trace_t tx_queue = {.name="dev_queue_xmit"};
puts(trace_event_name(&tx_queue, &event));
''')
        self.assertNotIn("DNS", result)
        self.assertIn("UDP", result)
        self.assertIn("dev_queue_xmit", result)

    def test_ipv6_datagrams_have_distinct_ids_stable_across_stages(self):
        source = EXPORT.read_text()
        helpers = "".join(function(source, name) for name in (
            "hash_bytes", "object_id", "ipv6_is_v4_mapped", "packet_flow_hash",
            "packet_flow_id", "packet_id"))
        result = self.run_source(helpers, r'''
packet_t pkt = {.proto_l3 = ETH_P_IPV6, .proto_l4 = IPPROTO_UDP, .ts = 100};
pkt.l3.ipv6.saddr[15] = 1; pkt.l3.ipv6.daddr[15] = 2;
pkt.l4.min.sport = htons(40000); pkt.l4.min.dport = htons(27015);
u64 first = packet_id(&pkt, 0x100, 1);
u64 second = packet_id(&pkt, 0x200, 2);
pkt.ts = 200;
u64 later_stage = packet_id(&pkt, 0x100, 1);
u64 reused = packet_id(&pkt, 0x100, 3);
printf("%d %d %d", first != second, first == later_stage, first != reused);
''')
        self.assertEqual(result, ["1", "1", "1"])

    def test_io_begin_is_visible_without_a_flow(self):
        source = EXPORT.read_text()
        structs = ""
        for name in ("pending_io", "flow_state"):
            start = source.index("struct " + name + " {")
            end = source.index("\n};", start) + 3
            structs += source[start:end] + "\n"
        helpers = structs + r'''
#define PERFETTO_SCHEMA "anettrace.perfetto.v1"
typedef struct { const char *name; } trace_t;
struct proto_buffer { int unused; };
static FILE *export_file, *native_file;
static unsigned begins;
static u64 begin_ts;
static const char *trace_event_name(trace_t *t, const void *e) { return "UDP write"; }
static const char *flow_protocol_name(struct flow_state *f) { return "udp"; }
static void json_escape(const char *s, char *d, size_t n) { snprintf(d,n,"%s",s); }
static void native_event_start(struct proto_buffer *e, unsigned type, u64 track,
    const char *stage, const char *category) { if (type == 1) begins++; }
static void native_annotation_id(struct proto_buffer *e, const char *k, u64 v) {}
static void native_annotation_uint(struct proto_buffer *e, const char *k, u64 v) {}
static void native_annotation_string(struct proto_buffer *e, const char *k, const char *v) {}
static u64 native_uuid(const char *kind, u64 a, u64 b) { return a ^ b; }
static void native_event_flow(struct proto_buffer *e, u64 id, bool terminating) {}
static void native_event_write(u64 ts, struct proto_buffer *e) { begin_ts = ts; }
static void proto_free(struct proto_buffer *e) {}
''' + function(source, "pending_io_emit_start")
        result = self.run_source(helpers, r'''
struct pending_io pending = {.active=true, .tx=true, .start_ts=100,
    .socket_id=90, .native_track_uuid=99};
trace_t trace = {.name="udp_sendmsg"};
native_file = stdout; export_file = tmpfile();
if (!export_file) return 2;
pending_io_emit_start(&pending, &trace, NULL);
rewind(export_file);
char json[2048] = {0};
fread(json, 1, sizeof(json) - 1, export_file);
fclose(export_file);
printf("%d %u %llu %d", pending.visible, begins, begin_ts,
    strstr(json, "\"flow_id\":\"0000000000000000\"") != NULL);
''')
        self.assertEqual(result, ["1", "1", "100", "1"])

    def test_socket_with_multiple_peers_is_not_associated_to_latest_flow(self):
        source = EXPORT.read_text()
        start = source.index("struct flow_state {")
        end = source.index("\n};", start) + 3
        helpers = source[start:end] + r'''
static struct flow_state flows[2];
static size_t flow_count;
''' + function(source, "flow_find_by_socket")
        result = self.run_source(helpers, r'''
flows[0] = (struct flow_state){.id=123, .socket_id=90, .protocol=IPPROTO_UDP,
    .active=true, .first_ts=100, .last_ts=200};
flow_count = 1;
printf("%d ", flow_find_by_socket(90, IPPROTO_UDP) == &flows[0]);
flows[1] = (struct flow_state){.id=124, .socket_id=90, .protocol=IPPROTO_UDP,
    .active=true, .first_ts=150, .last_ts=300};
flow_count = 2;
printf("%d", flow_find_by_socket(90, IPPROTO_UDP) == NULL);
''')
        self.assertEqual(result, ["1", "1"])

    def flow_lifecycle_helpers(self):
        source = EXPORT.read_text()
        start = source.index("struct flow_state {")
        end = source.index("\n};", start) + 3
        return source[start:end] + r'''
static struct flow_state *flows;
static size_t flow_count, flow_capacity;
static u64 flow_serial;
static bool flow_lookup_ambiguous;
''' + "".join(function(source, name) for name in (
            "hash_bytes", "socket_instance_id", "flow_add", "flow_lookup", "flow_create"))

    def test_closed_flow_tuple_can_be_observed_again(self):
        result = self.run_source(self.flow_lifecycle_helpers(), r'''
struct flow_state *first = flow_create(123, 90, 5, 100);
u64 old_id = first->id;
first->last_ts = 150; first->end_ts = 180;
first->active = false; first->closed = true;
printf("%d ", flow_lookup(123, 90, 5, 200) == NULL);
struct flow_state *second = flow_create(123, 90, 5, 200);
printf("%d %d ", second != NULL && second->active, second->id != old_id);
printf("%d %d", flow_lookup(123, 90, 5, 170)->id == old_id,
    flow_lookup(123, 90, 5, 210)->id == second->id);
free(flows);
''')
        self.assertEqual(result, ["1", "1", "1", "1", "1"])

    def test_socket_generations_and_network_namespaces_isolate_flows(self):
        result = self.run_source(self.flow_lifecycle_helpers(), r'''
u64 old_socket = socket_instance_id(0x100, 1);
u64 new_socket = socket_instance_id(0x100, 2);
u64 first = flow_create(123, old_socket, 5, 100)->id;
u64 reused = flow_create(123, new_socket, 5, 101)->id;
u64 other_namespace = flow_create(123, old_socket, 6, 102)->id;
printf("%d %d %d ", old_socket != new_socket,
    first != reused, first != other_namespace);
printf("%d %d %d", flow_lookup(123, old_socket, 5, 120)->id == first,
    flow_lookup(123, new_socket, 5, 120)->id == reused,
    flow_lookup(123, old_socket, 6, 120)->id == other_namespace);
free(flows);
''')
        self.assertEqual(result, ["1"] * 6)

    def test_ownerless_packet_with_multiple_socket_candidates_is_unassociated(self):
        result = self.run_source(self.flow_lifecycle_helpers(), r'''
u64 first = flow_create(123, 90, 5, 100)->id;
printf("%d ", flow_lookup(123, 0, 5, 110)->id == first);
flow_create(123, 91, 5, 101);
struct flow_state *ambiguous = flow_lookup(123, 0, 5, 110);
printf("%d %d ", ambiguous == NULL, flow_lookup_ambiguous);
struct flow_state *missing = flow_lookup(123, 99, 5, 110);
printf("%d %d", missing == NULL, !flow_lookup_ambiguous);
free(flows);
''')
        self.assertEqual(result, ["1"] * 5)

    def test_late_event_does_not_attach_to_a_future_flow_instance(self):
        result = self.run_source(self.flow_lifecycle_helpers(), r'''
flow_create(123, 90, 5, 200);
printf("%d", flow_lookup(123, 90, 5, 100) == NULL);
free(flows);
''')
        self.assertEqual(result, ["1"])

    def test_exact_socket_match_wins_over_earlier_ambiguous_ownerless_candidates(self):
        result = self.run_source(self.flow_lifecycle_helpers(), r'''
flow_create(123, 0, 5, 100);
flow_create(123, 0, 5, 101);
u64 exact = flow_create(123, 90, 5, 102)->id;
struct flow_state *found = flow_lookup(123, 90, 5, 110);
printf("%d %d", found != NULL && found->id == exact, !flow_lookup_ambiguous);
free(flows);
''')
        self.assertEqual(result, ["1", "1"])


if __name__ == "__main__":
    unittest.main()
