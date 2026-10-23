"""Exercise the real bounded native overview and import its output in Perfetto."""
from pathlib import Path
import json
import subprocess
import tempfile
import unittest

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace
from perfetto.trace_processor import TraceProcessor
from tests.test_perfetto_graph import declaration, function

ROOT = Path(__file__).resolve().parents[1]


class NativeSocketOverviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "src/perfetto_export.c").read_text()
        cls.tmp = tempfile.TemporaryDirectory(prefix="anettrace-socket-overview-")
        cls.base = Path(cls.tmp.name)
        prelude = r'''
#include <arpa/inet.h>
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef long long s64;
typedef uint32_t u32;
typedef int32_t s32;
typedef uint16_t u16;
typedef uint8_t u8;
typedef uint64_t __u64;
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define TRACE_CFREE 1
#define TRACE_HAS_ANALYZER(t,a) 0
#define NATIVE_PACKET_SEQUENCE_ID 0xa11e7001U
#define NATIVE_RING_MAX_BYTES (64ULL * 1024 * 1024)
/* Small bounds force pressure/collision behavior through the production logic. */
#define NATIVE_OVERVIEW_WINDOW_NS 1000000000ULL
#define NATIVE_OVERVIEW_MAX_EVENTS 4
#define NATIVE_OVERVIEW_MAX_BYTES 32768
#define NATIVE_OVERVIEW_PACKET_SLOTS 1024
#include "src/progs/shared.h"
typedef struct { const char *name; unsigned status; } trace_t;
static FILE *native_file;
static u64 export_salt=123;
static bool native_failed, native_sequence_started;
static struct { struct { bool trace_detail, connect_diagnostics; } args; } trace_ctx;
'''
        structures = "".join(declaration(source, name) for name in (
            "enum native_track_kind", "struct native_track", "struct proto_buffer",
            "struct native_packet", "struct native_packet_queue", "struct flow_state",
            "struct native_packet_overview", "struct native_packet_owner"))
        state = source[source.index("static struct native_packet_overview *native_overview_head"):
                       source.index("static struct native_track *native_tracks")]
        state += r'''
static struct native_track *native_tracks;
static size_t native_track_count, native_track_capacity;
static struct native_packet_queue native_persistent_packets, native_ring_packets;
static u64 native_ring_window_ns, native_ring_latest_ns;
static bool native_ring_capacity_truncated;
static struct flow_state test_flow;
static u64 selected_flow;
static struct flow_state *flow_find_any(u64 id) {
    return id && id==test_flow.id ? &test_flow : NULL;
}
static u64 detail_flow_id(const detail_event_t *detail, bool socket) { return selected_flow; }
static const char *trace_event_name(const trace_t *trace, const void *event) { return trace->name; }
'''
        protos = source[source.index("static void proto_free("):
                        source.index("static void native_packet_queue_free(")]
        names = (
            "hash_bytes", "object_id", "native_uuid", "socket_instance_id", "packet_id",
            "native_packet_queue_free", "native_packet_queue_append", "native_packet_queue_write",
            "native_ring_evict", "native_ring_prune_all", "native_write_packet_at",
            "native_write_packet", "native_sequence_packet", "native_find_track", "native_add_track",
            "native_descriptor", "native_process_track", "native_thread_track", "native_socket_track",
            "native_clock_snapshot",
            "ipv6_is_v4_mapped", "packet_addresses", "native_event_start", "native_event_flow",
            "native_event_correlation", "native_annotation_string", "native_annotation_uint",
            "native_annotation_bool", "native_annotation_id", "native_event_write", "direction_name",
            "packet_is_icmp", "packet_is_icmp_echo", "flow_label_prefix", "format_flow_label",
            "format_packet_flow_label", "packet_submission_ids", "flow_packet_anchor",
            "packet_trace_terminal", "native_socket_packet_track", "native_packet_overview_flush_one",
            "native_packet_overview_flush", "native_packet_overview_slot_pending",
            "native_packet_overview_observe", "native_packet_overview_queue",
            "native_packet_overview_reset", "native_export_packet_event", "flow_set_owner")
        helpers = "".join(function(source, name) for name in names)
        body = r'''
static detail_event_t sample(u64 key, u64 ts, u8 direction, u64 socket) {
    detail_event_t d={.key=key,.key_generation=1,.tgid=777,.tid=778,.direction=direction,
        .owner_socket_key=socket,.owner_socket_generation=1,.owner_tgid=42,.owner_tid=43,
        .owner_valid=socket != 0};
    d.pkt.ts=ts; d.pkt.proto_l3=ETH_P_IP; d.pkt.proto_l4=IPPROTO_TCP;
    d.pkt.l3.ipv4.saddr=inet_addr("127.0.0.1");
    d.pkt.l3.ipv4.daddr=inet_addr("127.0.0.1");
    d.pkt.l4.min.sport=htons(9000); d.pkt.l4.min.dport=htons(9001);
    strcpy(d.task,"softirq");
    return d;
}
static void emit(detail_event_t d, const char *stage) {
    trace_t trace={.name=stage};
    native_export_packet_event(&d,&trace,2,sizeof(d));
}
static void evidence(detail_event_t d,u64 socket) {
    d.owner_socket_key=socket; d.owner_valid=true;
    native_packet_overview_observe(&d);
}
int main(int argc,char **argv) {
    assert(argc==3);
    native_file=fopen(argv[1],"wb"); assert(native_file);
    const u64 base=10000000000ULL;
    native_clock_snapshot(base,base,base);
    if (!strcmp(argv[2],"late")) {
        /* Same skb crosses two local sockets: direction-specific evidence. */
        detail_event_t rx=sample(1,base,PACKET_DIRECTION_RX,0);
        emit(rx,"ip_rcv");
        emit(sample(1,base+10,PACKET_DIRECTION_TX,90),"ip_output");
        rx.pkt.ts=base+20; evidence(rx,91);
        emit(sample(1,base+30,PACKET_DIRECTION_RX,0),"icmp_rcv");
        emit(sample(2,base+40,PACKET_DIRECTION_UNKNOWN,92),"unknown_stage");
        /* Emit a newer non-packet event before deferred packet originals. */
        struct proto_buffer marker={};
        struct native_track *t=native_thread_track(42,43,"app");
        native_event_start(&marker,3,t->uuid,"later marker","test");
        native_event_write(base+100000000,&marker); proto_free(&marker);
    } else if (!strcmp(argv[2],"flow")) {
        test_flow=(struct flow_state){.id=1,.socket_id=socket_instance_id(90,1),
            .owner_tgid=777,.local_port=9000};
        strcpy(test_flow.local_addr,"127.0.0.1"); selected_flow=1;
        emit(sample(1,base,PACKET_DIRECTION_RX,0),"loopback_rx_unassociated");
        emit(sample(2,base+1,PACKET_DIRECTION_TX,0),"flow_tx");
        emit(sample(3,base+2,PACKET_DIRECTION_UNKNOWN,0),"flow_unknown");
        /* Real ownership supersedes the first execution-context task name. */
        strcpy(test_flow.task,"softirq");
        detail_event_t owner=sample(4,base+3,PACKET_DIRECTION_TX,90);
        flow_set_owner(&test_flow,&owner,(const event_t *)&owner,test_flow.socket_id);
        assert(test_flow.owner_tgid==42 && !test_flow.task[0]);
    } else if (!strcmp(argv[2],"ambiguous")) {
        detail_event_t p=sample(1,base,PACKET_DIRECTION_RX,0);
        emit(p,"ambiguous_packet");
        p.pkt.ts++; evidence(p,90); p.pkt.ts++; evidence(p,91);
        /* Find a genuine cache collision, then try to erase the conflict. */
        u64 id=packet_id(&p.pkt,p.key,p.key_generation);
        u64 slot=native_uuid("packet-owner",id,p.direction)%NATIVE_OVERVIEW_PACKET_SLOTS;
        detail_event_t q=sample(2,base+3,PACKET_DIRECTION_RX,0);
        while (native_uuid("packet-owner",packet_id(&q.pkt,q.key,q.key_generation),q.direction)
                %NATIVE_OVERVIEW_PACKET_SLOTS!=slot) q.key++;
        emit(q,"collision_packet"); evidence(q,90); evidence(q,91);
        p.pkt.ts+=3; evidence(p,90);
        /* Direct packet evidence still wins over all inferred conflicts. */
        p.owner_socket_key=90; p.owner_valid=true; emit(p,"direct_wins");
        /* Out-of-order observations cannot move a live slot backwards. */
        u64 timestamp=native_packet_owners[slot].timestamp_ns;
        p.pkt.ts=base; evidence(p,90);
        assert(native_packet_owners[slot].timestamp_ns==timestamp);
        native_packet_overview_flush(base+2000000000ULL,true);
        q.pkt.ts=base+3000000000ULL; evidence(q,90);
        assert(native_packet_owners[slot].packet_id==packet_id(&q.pkt,q.key,1));
        assert(!native_packet_owners[slot].collided);
    } else if (!strcmp(argv[2],"pressure")) {
        for (unsigned i=0;i<NATIVE_OVERVIEW_MAX_EVENTS+2;i++)
            emit(sample(i+1,base+i,PACKET_DIRECTION_TX,90),"pressure");
        assert(native_overview_count==NATIVE_OVERVIEW_MAX_EVENTS);
        assert(native_overview_bytes<=NATIVE_OVERVIEW_MAX_BYTES);
    } else if (!strcmp(argv[2],"expired_slot")) {
        detail_event_t p=sample(1,base,PACKET_DIRECTION_TX,0);
        evidence(p,90);
        u64 id=packet_id(&p.pkt,p.key,1);
        u64 slot=native_uuid("packet-owner",id,p.direction)%NATIVE_OVERVIEW_PACKET_SLOTS;
        detail_event_t q=sample(2,base+3000000000ULL,PACKET_DIRECTION_TX,0);
        while (native_uuid("packet-owner",packet_id(&q.pkt,q.key,1),q.direction)
                %NATIVE_OVERVIEW_PACKET_SLOTS!=slot) q.key++;
        test_flow=(struct flow_state){.id=1,.socket_id=socket_instance_id(90,1),
            .owner_tgid=42,.owner_valid=true,.local_port=9000};
        strcpy(test_flow.local_addr,"127.0.0.1"); selected_flow=1;
        emit(q,"expired_slot_flow");
    } else if (!strcmp(argv[2],"timeout")) {
        detail_event_t p=sample(1,base,PACKET_DIRECTION_RX,0);
        emit(p,"expired_original");
        native_packet_overview_flush(base+NATIVE_OVERVIEW_WINDOW_NS,false);
        p.pkt.ts=base+NATIVE_OVERVIEW_WINDOW_NS+1; evidence(p,91);
        emit(p,"later_known");
    } else if (!strcmp(argv[2],"ring")) {
        native_ring_window_ns=NATIVE_OVERVIEW_WINDOW_NS;
        emit(sample(1,base,PACKET_DIRECTION_TX,90),"expired_ring");
        emit(sample(2,base+2000000000ULL,PACKET_DIRECTION_TX,90),"retained_ring");
    } else return 2;
    native_packet_overview_flush(0,true);
    assert(!native_overview_count && !native_overview_bytes);
    printf("{\"mirrored\":%llu,\"unresolved\":%llu,\"ambiguous\":%llu,\"capacity\":%llu}",
        native_overview_emitted,native_overview_unresolved,native_overview_ambiguous,
        native_overview_capacity_flushes);
    if (native_ring_window_ns) {
        native_ring_prune_all();
        assert(native_packet_queue_write(&native_persistent_packets));
        assert(native_packet_queue_write(&native_ring_packets));
    }
    assert(!native_failed); fclose(native_file);
    native_packet_overview_reset();
    return 0;
}
'''
        cfile = cls.base / "overview.c"
        cfile.write_text(prelude + structures + state + protos + helpers + body)
        cls.binary = cls.base / "overview"
        result = subprocess.run([
            "cc", "-std=gnu11", "-Wall", "-Werror", "-Wno-unused-function",
            "-Wno-unused-variable", "-I", str(ROOT), str(cfile), "-o", str(cls.binary),
        ], capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, scenario):
        path = self.base / (scenario + ".pftrace")
        result = subprocess.run([str(self.binary), str(path), scenario], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        trace = Trace.FromString(path.read_bytes())
        events = [(p.timestamp, p.track_event) for p in trace.packet if p.HasField("track_event")]
        return path, trace, events, json.loads(result.stdout)

    @staticmethod
    def args(event):
        return {arg.name: arg.string_value for arg in event.debug_annotations}

    def test_deferred_rx_direct_tx_unknown_and_navigation_import(self):
        path, trace, events, counts = self.run_case("late")
        raw = [(ts, e) for ts, e in events if list(e.categories) == ["anettrace.packet"]]
        mirrors = [(ts, e) for ts, e in events if list(e.categories) == ["anettrace.socket.packet"]]
        self.assertEqual(len(raw), 4)
        self.assertEqual(counts["mirrored"], 4)
        self.assertEqual(len(mirrors), 4)
        self.assertEqual([self.args(e)["stage"] for _, e in raw],
                         ["ip_rcv", "ip_output", "icmp_rcv", "unknown_stage"])
        descriptors = {p.track_descriptor.uuid: p.track_descriptor for p in trace.packet
                       if p.HasField("track_descriptor")}
        nav_ids = []
        for (raw_ts, original), (mirror_ts, mirror) in zip(raw, mirrors):
            attrs = self.args(mirror)
            navigation = int(attrs["navigation_id"], 16)
            nav_ids.append(navigation)
            self.assertEqual(raw_ts, mirror_ts)
            self.assertIn(navigation, original.flow_ids)
            self.assertEqual(list(mirror.terminating_flow_ids), [navigation])
            self.assertNotEqual(navigation, int(attrs["packet_id"], 16))
            self.assertEqual(attrs["source_tid"], "778")
            self.assertEqual(attrs["source_tgid"], "777")
            self.assertEqual(int(attrs["source_track_uuid"], 16), original.track_uuid)
            self.assertEqual(attrs["source_ts_ns"], str(raw_ts))
            self.assertEqual(sum(a.name == "socket_id" for a in mirror.debug_annotations), 1)
            lane = descriptors[mirror.track_uuid]
            socket = descriptors[lane.parent_uuid]
            parent = descriptors[socket.parent_uuid]
            self.assertEqual(parent.process.pid, 42)
            self.assertNotEqual(parent.process.process_name, "softirq")
        self.assertEqual(len(set(nav_ids)), 4)
        self.assertEqual([descriptors[e.track_uuid].name for _, e in mirrors],
                         ["RX packets", "TX packets", "RX packets", "Unknown direction packets"])
        with TraceProcessor(trace=str(path)) as processor:
            rows = list(processor.query("""
                SELECT source.ts source_ts, target.ts target_ts,
                       EXTRACT_ARG(target.arg_set_id, 'debug.source_tid') source_tid,
                       EXTRACT_ARG(target.arg_set_id, 'debug.socket_id') socket_id
                FROM flow JOIN slice source ON source.id=flow.slice_out
                JOIN slice target ON target.id=flow.slice_in
                WHERE target.category='anettrace.socket.packet'
            """))
            self.assertEqual(len(rows), 4)
            for row in rows:
                self.assertEqual(row.source_ts, row.target_ts)
                self.assertEqual(str(row.source_tid), "778")
                self.assertNotEqual(row.socket_id, "0000000000000000")
            errors = list(processor.query("SELECT name,value FROM stats WHERE severity='error' AND value>0"))
            self.assertFalse(errors, errors)

    def test_flow_endpoint_guard_and_owner_name(self):
        _, trace, events, counts = self.run_case("flow")
        mirrors = [e for _, e in events if "anettrace.socket.packet" in e.categories]
        self.assertEqual(counts["mirrored"], 1)
        self.assertEqual(self.args(mirrors[0])["stage"], "flow_tx")
        descriptors = {p.track_descriptor.uuid: p.track_descriptor for p in trace.packet
                       if p.HasField("track_descriptor")}
        lane = descriptors[mirrors[0].track_uuid]
        socket = descriptors[lane.parent_uuid]
        self.assertEqual(descriptors[socket.parent_uuid].process.pid, 42)
        self.assertNotEqual(descriptors[socket.parent_uuid].process.process_name, "softirq")

    def test_conflicts_and_hash_collisions_do_not_guess_socket(self):
        _, _, events, counts = self.run_case("ambiguous")
        mirrors = [e for _, e in events if "anettrace.socket.packet" in e.categories]
        self.assertEqual([self.args(e)["stage"] for e in mirrors], ["direct_wins"])
        self.assertEqual(counts["ambiguous"], 1)
        self.assertEqual(counts["unresolved"], 1)

    def test_capacity_flush_keeps_every_original_in_order(self):
        _, _, events, counts = self.run_case("pressure")
        raw = [ts for ts, e in events if "anettrace.packet" in e.categories]
        self.assertEqual(len(raw), 6)
        self.assertEqual(raw, sorted(raw))
        self.assertEqual(counts["capacity"], 2)
        self.assertEqual(counts["mirrored"], 6)

    def test_expired_other_packet_slot_does_not_block_unique_flow(self):
        _, _, events, counts = self.run_case("expired_slot")
        mirrors = [e for _, e in events if "anettrace.socket.packet" in e.categories]
        self.assertEqual(counts["mirrored"], 1)
        self.assertEqual(self.args(mirrors[0])["stage"], "expired_slot_flow")

    def test_timeout_preserves_original_without_late_guess(self):
        _, _, events, counts = self.run_case("timeout")
        raw = [e for _, e in events if "anettrace.packet" in e.categories]
        mirrors = [e for _, e in events if "anettrace.socket.packet" in e.categories]
        self.assertEqual(len(raw), 2)
        self.assertEqual([self.args(e)["stage"] for e in mirrors], ["later_known"])
        self.assertEqual(counts["unresolved"], 1)

    def test_ring_keeps_original_and_mirror_together(self):
        _, _, events, _ = self.run_case("ring")
        self.assertEqual([self.args(e)["stage"] for _, e in events],
                         ["retained_ring", "retained_ring"])


if __name__ == "__main__":
    unittest.main()
