"""Decode unavailable-probe evidence from real JSONL, native and ring exports."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace
from tests.test_perfetto_graph import declaration, function
from tests import test_perfetto_converter as converter_tests

ROOT = Path(__file__).resolve().parents[1]
FIELDS = ("probe", "status", "reason", "coverage")
END_TS = 20_000_000_000


class ProbeStatusExportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = (ROOT / "src/perfetto_export.c").read_text()
        cls.tmp = tempfile.TemporaryDirectory(prefix="anettrace-probe-status-")
        cls.base = Path(cls.tmp.name)
        prelude = r'''
#include <assert.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
typedef unsigned long long u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define PERFETTO_SCHEMA "anettrace.perfetto.v1"
#define NATIVE_PACKET_SEQUENCE_ID 0xa11e7001U
#define NATIVE_RING_MAX_BYTES (64ULL*1024*1024)
#define NATIVE_OVERVIEW_WINDOW_NS 1000000000ULL
#define NATIVE_OVERVIEW_MAX_EVENTS 4096
#define TRACE_ENABLE (1 << 1)
#define TRACE_INVALID (1 << 2)
#define TRACE_SYMBOL_AMBIGUOUS (1 << 9)
#define pr_warn(...) ((void)0)
typedef struct { char name[64]; unsigned status; } trace_t;
static trace_t selected[] = {
    {.name="xfrm4_policy_check", .status=TRACE_ENABLE|TRACE_INVALID|TRACE_SYMBOL_AMBIGUOUS},
    {.name="excluded", .status=TRACE_INVALID|TRACE_SYMBOL_AMBIGUOUS},
    {.name="healthy", .status=TRACE_ENABLE},
    {.name="__xfrm_policy_check", .status=TRACE_ENABLE},
    {.name="escaped\\\"probe", .status=TRACE_ENABLE|TRACE_INVALID|TRACE_SYMBOL_AMBIGUOUS},
};
#define trace_for_each(trace) for (trace=selected; trace<selected+ARRAY_SIZE(selected); trace++)
#define trace_for_each_cond(trace, cond) trace_for_each(trace) if (cond)
static bool trace_is_enable(trace_t *trace) { return trace->status & TRACE_ENABLE; }
static FILE *native_file, *export_file;
static bool native_failed, native_sequence_started;
static pthread_mutex_t export_lock=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rx_context_lock=PTHREAD_MUTEX_INITIALIZER;
static struct { u64 replayed, expired, capacity_dropped, unresolved; } rx_context;
static struct { struct { bool trace_tags; } args;
    struct { bool rx_context; } bpf_args; } trace_ctx;
static u64 exported_events, lost_events, queue_lost_events;
static int fixed_clock_gettime(clockid_t clock, struct timespec *value) {
    (void)clock; value->tv_sec=20; value->tv_nsec=0; return 0;
}
#define clock_gettime fixed_clock_gettime
'''
        structures = "".join(declaration(source, name) for name in (
            "enum native_track_kind", "struct native_track", "struct proto_buffer",
            "struct native_packet", "struct native_packet_queue", "struct pending_io",
            "struct flow_state"))
        state = r'''
static struct native_track *native_tracks;
static size_t native_track_count, native_track_capacity;
static struct native_packet_queue native_persistent_packets, native_ring_packets;
static u64 native_ring_window_ns, native_ring_latest_ns;
static bool native_ring_capacity_truncated;
static u64 native_overview_emitted, native_overview_unresolved, native_overview_ambiguous;
static u64 native_overview_capacity_flushes;
static struct pending_io *pending_ios;
static size_t pending_io_count, pending_io_capacity;
static struct { struct { u64 ts; } event; u64 flow_id; bool active; } pending_syscalls[1];
static size_t pending_syscall_count;
static struct flow_state *flows;
static size_t flow_count, flow_capacity;
static u64 flow_serial, tcp_flow_count, udp_flow_count, dns_flow_count;
static void rx_context_finish(void *context) {}
static void native_packet_overview_flush(u64 timestamp, bool finish) {}
static void native_packet_overview_reset(void) {}
static void pending_io_finish(struct pending_io *io, u64 timestamp, int result, bool incomplete) {}
static void export_network_syscall(void *event, u64 flow_id, bool incomplete) {}
static void flow_finish(struct flow_state *flow, u64 timestamp, const char *reason, bool inferred) {}
static void native_close_socket(struct native_track *track, u64 timestamp) {}
static void native_slice(u64 timestamp, u64 uuid, u32 type, const char *name,
                         const char *category, u64 flow, bool terminating) {}
'''
        protos = source[source.index("static void proto_free("):
                        source.index("static void native_packet_queue_free(")]
        queue = "".join(function(source, name) for name in (
            "native_packet_queue_free", "native_packet_queue_append", "native_packet_queue_write",
            "native_ring_evict", "native_ring_prune_all", "native_write_packet_at",
            "native_write_packet", "native_sequence_packet", "native_descriptor"))
        global_track = r'''
static struct native_track *native_global_track(void) {
    static struct native_track global={.uuid=7, .kind=NATIVE_TRACK_GLOBAL};
    native_descriptor(global.uuid,"Anettrace metadata",0,NATIVE_TRACK_GLOBAL,0,0);
    return &global;
}
'''
        event_helpers = "".join(function(source, name) for name in (
            "timespec_to_ns", "json_escape", "native_event_start",
            "native_annotation_string", "native_annotation_uint", "native_event_write",
            "native_export_meta", "native_clock_snapshot"))
        # Before the fix the real close function emits no probe status at all.
        status = (function(source, "export_probe_status")
                  if "static void export_probe_status(" in source else "")
        clock_stub = r'''
static void write_clock_snapshot(void) {
    if (export_file) fputs("{\"schema\":\"anettrace.perfetto.v1\","
        "\"type\":\"clock_snapshot\",\"monotonic_ns\":1000000000,"
        "\"boottime_ns\":1000000000,\"realtime_ns\":1000000000}\n",export_file);
    native_clock_snapshot(1000000000ULL,1000000000ULL,1000000000ULL);
}
static void write_clock_snapshot_if_due(void) {}
'''
        body = r'''
int main(int argc, char **argv) {
    assert(argc==4);
    native_file=fopen(argv[1],"wb"); export_file=fopen(argv[2],"w");
    assert(native_file && export_file);
    trace_ctx.args.trace_tags=strstr(argv[3],"tags") != NULL;
    if (!strcmp(argv[3],"healthy"))
        for (unsigned i=0; i<ARRAY_SIZE(selected); i++)
            selected[i].status &= ~TRACE_SYMBOL_AMBIGUOUS;
    if (strstr(argv[3],"ring")) {
        struct proto_buffer event={};
        native_ring_window_ns=1000000000ULL;
        native_event_start(&event,3,7,"early_marker","test");
        native_event_write(1000000000ULL,&event);
        proto_free(&event);
    }
    if (!strcmp(argv[3],"loss")) {
        perfetto_export_lost(3,5);
        perfetto_export_queue_lost(7);
    }
    perfetto_export_close(0);
    assert(!native_failed);
    return 0;
}
'''
        cfile = cls.base / "probe_status.c"
        cls.binary = cls.base / "probe_status"
        cfile.write_text(prelude + structures + state + protos + queue + global_track +
                         event_helpers + status + clock_stub +
                         function(source, "perfetto_export_lost") +
                         function(source, "perfetto_export_queue_lost") +
                         function(source, "perfetto_export_close") + body)
        result = subprocess.run(
            ["cc", "-std=gnu11", "-Wall", "-Werror", "-Wno-unused-function",
             "-Wno-unused-variable", "-pthread", str(cfile), "-o", str(cls.binary)],
            text=True, capture_output=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_case(self, scenario):
        native = self.base / f"{scenario}.pftrace"
        jsonl = self.base / f"{scenario}.jsonl"
        result = subprocess.run([str(self.binary), str(native), str(jsonl), scenario],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        records = [json.loads(line) for line in jsonl.read_text().splitlines()]
        trace = Trace.FromString(native.read_bytes())
        return records, trace

    @staticmethod
    def statuses(trace):
        return [(packet.timestamp, packet.track_event,
                 {arg.name: arg.string_value for arg in packet.track_event.debug_annotations})
                for packet in trace.packet if packet.HasField("track_event")
                and packet.track_event.name == "probe_status"]

    def test_close_exports_only_selected_ambiguous_probes_in_jsonl_and_native(self):
        records, trace = self.run_case("normal")
        statuses = [record for record in records if record["type"] == "probe_status"]
        self.assertEqual({record["probe"] for record in statuses},
                         {"xfrm4_policy_check", 'escaped\\"probe'})
        native = self.statuses(trace)
        self.assertEqual(len(native), len(statuses))
        by_probe = {record["probe"]: record for record in statuses}
        for timestamp, event, args in native:
            self.assertEqual(list(event.categories), ["anettrace.metadata"])
            self.assertEqual(timestamp, END_TS)
            record = by_probe[args["probe"]]
            self.assertEqual(record["ts_ns"], END_TS)
            self.assertEqual(tuple(args[field] for field in FIELDS),
                             tuple(record[field] for field in FIELDS))
            self.assertEqual((args["status"], args["reason"], args["coverage"]),
                             ("unavailable", "ambiguous_symbol", "degraded"))

    def test_kernel_and_queue_loss_are_counted_once_and_queue_is_identified(self):
        records, trace = self.run_case("loss")
        end = next(record for record in records if record["type"] == "trace_end")
        self.assertEqual(end["lost_events"], 12)
        self.assertEqual(end["queue_lost_events"], 7)
        fields = {}
        for packet in trace.packet:
            if packet.track_event.name in ("trace_end", "capture_queue"):
                fields[packet.track_event.name] = {
                    arg.name: arg.string_value for arg in packet.track_event.debug_annotations}
        self.assertEqual(fields["trace_end"]["lost_events"], "12")
        self.assertEqual(fields["capture_queue"]["lost_events"], "7")

    def test_end_status_survives_the_ring_window_and_trace_tags(self):
        for scenario in ("tags", "ring", "ring-tags"):
            with self.subTest(scenario=scenario):
                records, trace = self.run_case(scenario)
                self.assertEqual(len(self.statuses(trace)), 2)
                self.assertTrue(all(timestamp == END_TS
                                    for timestamp, _, _ in self.statuses(trace)))
                if "ring" in scenario:
                    names = [packet.track_event.name for packet in trace.packet
                             if packet.HasField("track_event")]
                    self.assertNotIn("early_marker", names)
                self.assertEqual(len([record for record in records
                                      if record["type"] == "probe_status"]), 2)

    def test_healthy_trace_does_not_claim_full_coverage(self):
        records, trace = self.run_case("healthy")
        self.assertFalse(self.statuses(trace))
        self.assertFalse(any("coverage" in record for record in records))

    def test_jsonl_converter_preserves_status_in_normal_and_trace_tags_modes(self):
        records, _ = self.run_case("normal")
        expected = {record["probe"]: record for record in records
                    if record["type"] == "probe_status"}
        self.assertEqual(len(expected), 2)
        for tags in (False, True):
            with self.subTest(trace_tags=tags):
                encoded = converter_tests.MODULE.PerfettoExporter(
                    records, trace_tags=tags).serialize()
                statuses = self.statuses(Trace.FromString(encoded))
                self.assertEqual(len(statuses), 2)
                for timestamp, event, args in statuses:
                    self.assertEqual(timestamp, END_TS)
                    self.assertEqual(list(event.categories), ["anettrace.metadata"])
                    self.assertEqual(tuple(args[field] for field in FIELDS),
                                     tuple(expected[args["probe"]][field] for field in FIELDS))


if __name__ == "__main__":
    unittest.main()
