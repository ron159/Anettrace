#!/usr/bin/env python3
"""Contract test for Anettrace JSONL to Perfetto conversion."""

from __future__ import annotations

import copy
import importlib.util
import sys
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace, TrackEvent
from perfetto.trace_processor import TraceProcessor

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "anettrace_to_perfetto.py"
SPEC = importlib.util.spec_from_file_location("anettrace_to_perfetto", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PerfettoConverterTest(unittest.TestCase):
    def test_network_syscall_duration_error_and_thread_track(self) -> None:
        records = MODULE.read_records(ROOT / "tests/fixtures/perfetto-events.jsonl")
        clock = records[0]
        start = int(clock["monotonic_ns"]) + 100000
        calls = [dict(schema=MODULE.SCHEMA, type="network_syscall",
                      start_ts_ns=start, ts_ns=start + 2000,
                      syscall="recvfrom", tid=70, tgid=60, uid=10000,
                      fd=9, flags=0, result=-11, error=11, bytes=0,
                      requested_bytes=4096, requested_valid=True,
                      call_id="abc", socket_id="def", flow_id="123",
                      flow_tag="tcp-1", incomplete=False)]
        trace = Trace()
        trace.ParseFromString(MODULE.PerfettoExporter([clock] + calls).serialize())
        begins = [p for p in trace.packet if p.track_event.type == TrackEvent.TYPE_SLICE_BEGIN]
        ends = [p for p in trace.packet if p.track_event.type == TrackEvent.TYPE_SLICE_END]
        self.assertEqual(len(begins), 1)
        self.assertEqual(len(ends), 1)
        self.assertIn("recvfrom", begins[0].track_event.name)
        self.assertIn("tcp-1", begins[0].track_event.name)
        self.assertEqual(ends[0].timestamp - begins[0].timestamp, 2000)
        args = {a.name: a.string_value for a in begins[0].track_event.debug_annotations}
        self.assertEqual(args["error"], "11")
        self.assertEqual(args["result"], "-11")
        descriptors = {p.track_descriptor.uuid: p.track_descriptor for p in trace.packet
                       if p.HasField("track_descriptor")}
        track = descriptors[begins[0].track_event.track_uuid]
        self.assertEqual(track.name, "Network syscalls")
        self.assertEqual(descriptors[track.parent_uuid].thread.tid, 70)
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "syscall.pftrace"
            path.write_bytes(trace.SerializeToString())
            with TraceProcessor(trace=str(path)) as processor:
                slices = list(processor.query(
                    "SELECT dur FROM slice WHERE category = 'anettrace.syscall'"))
                self.assertEqual([row.dur for row in slices], [2000])

    def test_incomplete_syscall_does_not_claim_success(self) -> None:
        clock = MODULE.read_records(ROOT / "tests/fixtures/perfetto-events.jsonl")[0]
        start = int(clock["monotonic_ns"]) + 100000
        call = dict(schema=MODULE.SCHEMA, type="network_syscall", syscall="recvmsg",
                    start_ts_ns=start, ts_ns=start + 1000, tid=1, tgid=1, fd=3,
                    requested_valid=False, requested_bytes=0, result=0, bytes=0,
                    error=0, incomplete=True)
        trace = Trace()
        trace.ParseFromString(MODULE.PerfettoExporter([clock, call]).serialize())
        event = next(p.track_event for p in trace.packet
                     if p.track_event.type == TrackEvent.TYPE_SLICE_BEGIN)
        args = {a.name: a.string_value for a in event.debug_annotations}
        self.assertEqual(args["incomplete"], "true")
        self.assertNotIn("result", args)
        self.assertNotIn("requested_bytes", args)

    def test_all_arguments_are_searchable_without_duplicates(self) -> None:
        exporter = MODULE.PerfettoExporter(MODULE.read_records(
            ROOT / "tests" / "fixtures" / "perfetto-events.jsonl"
        ))
        trace = Trace()
        trace.ParseFromString(exporter.serialize())
        for packet in trace.packet:
            args = {a.name: a for a in packet.track_event.debug_annotations}
            self.assertEqual(len(args), len(packet.track_event.debug_annotations))
            for key, arg in args.items():
                self.assertFalse(key.startswith("search."))
                self.assertEqual(arg.WhichOneof("value"), "string_value")

    def test_native_and_python_search_encoding_and_ui_query(self) -> None:
        # Compile the actual native protobuf/annotation helpers without BPF or
        # Android dependencies, then decode and query their output with Perfetto.
        source = (ROOT / "src" / "perfetto_export.c").read_text()
        helpers = source[source.index("static void proto_free("):
                         source.index("static void native_packet_queue_free(")]
        annotations = source[source.index("static void native_annotation_string("):
                             source.index("static void native_event_write(")]
        harness = """
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef unsigned long long u64;
typedef long long s64;
typedef uint32_t u32;
typedef uint8_t u8;
struct proto_buffer { unsigned char *data; size_t size, capacity; bool failed; };
""" + helpers + annotations + """
int main(void) {
    struct proto_buffer event = {};
    native_annotation_uint(&event, "dport", 443);
    native_annotation_uint(&event, "maximum", ~0ULL);
    native_annotation_int(&event, "error", (-9223372036854775807LL - 1));
    native_annotation_bool(&event, "terminal", false);
    native_annotation_bool(&event, "dropped", true);
    native_annotation_string(&event, "daddr", "2001:db8::1");
    native_annotation_string(&event, "empty", NULL);
    native_annotation_id(&event, "socket_id", 0x1234);
    char long_value[8193];
    memset(long_value, 'x', sizeof(long_value) - 1);
    long_value[sizeof(long_value) - 1] = 0;
    native_annotation_string(&event, "long", long_value);
    if (event.failed) return 1;
    size_t written = fwrite(event.data, 1, event.size, stdout);
    int result = written != event.size;
    proto_free(&event);
    return result;
}
"""
        record = dict(dport=443, maximum=2**64 - 1, error=-(2**63),
                      terminal=False, dropped=True, daddr="2001:db8::1",
                      empty="", socket_id="0000000000001234", long="x" * 8192)
        exporter = MODULE.PerfettoExporter(MODULE.read_records(
            ROOT / "tests" / "fixtures" / "perfetto-events.jsonl"
        ))
        python_event = TrackEvent()
        exporter.add_annotations(python_event, record, record.keys())
        with TemporaryDirectory(prefix="anettrace-search-") as directory:
            base = Path(directory)
            (base / "test.c").write_text(harness)
            subprocess.run(["cc", "-std=gnu11", "-Wall", "-Werror",
                            "-Wno-unused-function", str(base / "test.c"),
                            "-o", str(base / "test")], check=True)
            native_event = TrackEvent()
            native_event.ParseFromString(subprocess.check_output([str(base / "test")]))
            self.assertEqual(native_event, python_event)
            for event in (native_event, python_event):
                trace = Trace()
                trace.ParseFromString(exporter.serialize())
                descriptor = trace.packet.add()
                descriptor.trusted_packet_sequence_id = 777
                descriptor.sequence_flags = 1
                descriptor.track_descriptor.uuid = 987654
                descriptor.track_descriptor.name = "search test track"
                packet = trace.packet.add()
                packet.trusted_packet_sequence_id = 777
                packet.timestamp = 100000000000
                packet.track_event.CopyFrom(event)
                packet.track_event.type = TrackEvent.TYPE_INSTANT
                packet.track_event.track_uuid = 987654
                packet.track_event.name = "search test"
                path = base / "search.pftrace"
                path.write_bytes(trace.SerializeToString())
                with TraceProcessor(trace=str(path)) as processor:
                    for term in ("443", "false", "true", "-9223372036854775808",
                                 "2001:db8::1", "18446744073709551615", "dport"):
                        rows = list(processor.query(f"""
                            SELECT DISTINCT slice.id FROM slice JOIN args USING(arg_set_id)
                            WHERE slice.name = 'search test'
                            AND (args.string_value GLOB '*{term}*'
                                 OR args.key GLOB '*{term}*')
                        """))
                        self.assertEqual(len(rows), 1, term)

    def test_socket_packet_and_terminal_events(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "perfetto-events.jsonl"
        encoded = MODULE.PerfettoExporter(MODULE.read_records(fixture)).serialize()
        trace = Trace()
        trace.ParseFromString(encoded)

        names = [
            packet.track_event.name
            for packet in trace.packet
            if packet.HasField("track_event")
        ]
        self.assertIn("socket allocation", names)
        self.assertIn("socket lifetime", names)
        self.assertIn("tcp-1", names)
        self.assertIn("tcp_sendmsg", names)
        self.assertIn("tcp_sendmsg_locked", names)
        self.assertIn("tcp_recvmsg", names)
        self.assertIn("tcp_close", names)
        self.assertIn("ESTABLISHED → CLOSE", names)

        packet_events = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and any(
                category.startswith("anettrace.packet")
                for category in packet.track_event.categories
            )
        ]
        self.assertEqual(len(packet_events), 3)
        self.assertEqual({event.name for event in packet_events}, {"tcp-1"})
        self.assertEqual({event.correlation_id for event in packet_events}, {0x2001})
        packet_annotations = [
            {annotation.name: annotation for annotation in event.debug_annotations}
            for event in packet_events
        ]
        self.assertEqual(
            {annotations["stage"].string_value for annotations in packet_annotations},
            {"__tcp_transmit_skb", "consume_skb", "tcp_v4_rcv"},
        )
        self.assertTrue(
            all(
                annotations["flow_tag"].string_value == "tcp-1"
                for annotations in packet_annotations
            )
        )
        packets = [
            event
            for event, annotations in zip(packet_events, packet_annotations)
            if annotations["stage"].string_value == "consume_skb"
        ]
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].type, TrackEvent.TYPE_INSTANT)
        self.assertEqual(list(packets[0].terminating_flow_ids), [0x3001])

        tx_packets = [
            event
            for event, annotations in zip(packet_events, packet_annotations)
            if annotations["stage"].string_value == "__tcp_transmit_skb"
        ]
        self.assertEqual(len(tx_packets), 1)
        self.assertEqual(list(tx_packets[0].flow_ids), [0x3001, 0x2001])

        rx_packets = [
            event
            for event, annotations in zip(packet_events, packet_annotations)
            if annotations["stage"].string_value == "tcp_v4_rcv"
        ]
        self.assertEqual(len(rx_packets), 1)
        self.assertEqual(list(rx_packets[0].flow_ids), [0x3002, 0x2001])
        rx_annotations = {
            annotation.name: annotation
            for annotation in rx_packets[0].debug_annotations
        }
        self.assertEqual(rx_annotations["direction"].string_value, "rx")
        self.assertEqual(rx_annotations["owner_uid"].string_value, str(10000))

        recv_begins = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.name == "tcp_recvmsg"
        ]
        self.assertEqual(len(recv_begins), 1)
        recv_track = recv_begins[0].track_uuid
        recv_ends = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.track_uuid == recv_track
            and packet.timestamp == 1_053_000_000
            and packet.track_event.type == TrackEvent.TYPE_SLICE_END
        ]
        self.assertEqual(len(recv_ends), 1)
        recv_annotations = {
            annotation.name: annotation for annotation in recv_ends[0].debug_annotations
        }
        self.assertEqual(recv_annotations["bytes"].string_value, str(512))

        flow_begins = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.name == "tcp-1"
            and "anettrace.flow" in packet.track_event.categories
        ]
        self.assertEqual(len(flow_begins), 1)
        self.assertEqual(list(flow_begins[0].flow_ids), [0x2001])
        flow_track = flow_begins[0].track_uuid
        flow_ends = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.track_uuid == flow_track
            and packet.track_event.type == TrackEvent.TYPE_SLICE_END
        ]
        self.assertEqual(len(flow_ends), 1)
        self.assertEqual(list(flow_ends[0].terminating_flow_ids), [0x2001])
        flow_annotations = {
            annotation.name: annotation for annotation in flow_ends[0].debug_annotations
        }
        self.assertEqual(flow_annotations["tx_bytes"].string_value, str(128))
        self.assertEqual(flow_annotations["rx_bytes"].string_value, str(512))
        self.assertEqual(flow_annotations["tx_packets"].string_value, str(1))
        self.assertEqual(flow_annotations["rx_packets"].string_value, str(1))
        self.assertEqual(
            flow_annotations["byte_scope"].string_value, "application_payload"
        )
        self.assertEqual(flow_annotations["end_reason"].string_value, "tcp_close")
        self.assertEqual(flow_annotations["incomplete"].string_value, "false")

        descriptors = {
            packet.track_descriptor.uuid: packet.track_descriptor
            for packet in trace.packet
            if packet.HasField("track_descriptor")
        }
        socket_parent = descriptors[flow_track].parent_uuid
        self.assertEqual(descriptors[socket_parent].name, "socket 00001001")
        self.assertNotEqual(descriptors[socket_parent].parent_uuid, 0)

        lifetime_begins = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.name == "socket lifetime"
        ]
        self.assertEqual(len(lifetime_begins), 1)
        lifetime_track = lifetime_begins[0].track_uuid
        lifetime_ends = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.track_uuid == lifetime_track
            and packet.track_event.type == TrackEvent.TYPE_SLICE_END
        ]
        self.assertEqual(len(lifetime_ends), 1)

        thread_descriptors = [
            packet.track_descriptor
            for packet in trace.packet
            if packet.HasField("track_descriptor")
            and packet.track_descriptor.HasField("thread")
        ]
        self.assertTrue(
            any(descriptor.thread.tid == 101 for descriptor in thread_descriptors)
        )

        snapshots = [
            packet.clock_snapshot
            for packet in trace.packet
            if packet.HasField("clock_snapshot")
        ]
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0].primary_trace_clock, MODULE.CLOCK_BOOTTIME)

        event_packets = [
            packet for packet in trace.packet if packet.HasField("track_event")
        ]
        self.assertTrue(event_packets)
        self.assertTrue(
            all(
                packet.timestamp_clock_id == MODULE.CLOCK_MONOTONIC
                for packet in event_packets
            )
        )

    def test_dns_transaction_id_is_exported_as_packet_metadata(self) -> None:
        records = [
            {
                "schema": MODULE.SCHEMA,
                "type": "clock_snapshot",
                "monotonic_ns": 1_000_000_000,
                "boottime_ns": 1_100_000_000,
                "realtime_ns": 1_800_000_000_000_000_000,
            },
            {
                "schema": MODULE.SCHEMA,
                "type": "packet_event",
                "ts_ns": 1_010_000_000,
                "packet_id": "0000000000005001",
                "skb_id": "0000000000006001",
                "flow_id": "0000000000007001",
                "stage": "ip_output",
                "terminal": False,
                "dropped": False,
                "flow_anchor": True,
                "cpu": 2,
                "tid": 101,
                "tgid": 100,
                "uid": 10000,
                "task": "dns-worker",
                "ifname": "wlan0",
                "direction": "tx",
                "ifindex": 3,
                "netns": 42,
                "proto_l3": 2048,
                "proto_l4": 17,
                "saddr": "10.0.0.2",
                "sport": 40000,
                "daddr": "1.1.1.1",
                "dport": 53,
                "mark": 0,
                "ip_id": 0x2345,
                "ip_id_hex": "0x2345",
                "dns_transaction_id": 0x1201,
                "dns_transaction_id_hex": "0x1201",
            },
        ]
        trace = Trace()
        trace.ParseFromString(MODULE.PerfettoExporter(records).serialize())
        packet = next(
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and "anettrace.packet" in packet.track_event.categories
        )
        annotations = {
            annotation.name: annotation for annotation in packet.debug_annotations
        }
        self.assertEqual(annotations["ip_id"].string_value, str(0x2345))
        self.assertEqual(annotations["ip_id_hex"].string_value, "0x2345")
        self.assertEqual(annotations["dns_transaction_id"].string_value, str(0x1201))
        self.assertEqual(
            annotations["dns_transaction_id_hex"].string_value, "0x1201"
        )

    def test_flow_labels_are_sequential_per_protocol(self) -> None:
        exporter = MODULE.PerfettoExporter([])
        self.assertEqual(exporter.flow_label("1", {"protocol": "tcp"}), "tcp-1")
        self.assertEqual(exporter.flow_label("2", {"proto_l4": 17}), "udp-1")
        self.assertEqual(
            exporter.flow_label("3", {"proto_l4": 17, "dport": 53}), "dns-1"
        )
        self.assertEqual(exporter.flow_label("4", {"protocol": "tcp"}), "tcp-2")
        self.assertEqual(exporter.flow_label("5", {"protocol": "udp"}), "udp-2")
        self.assertEqual(
            exporter.flow_label("6", {"protocol": "udp-dns"}), "dns-2"
        )
        self.assertEqual(
            exporter.flow_label("1", {"protocol": "udp"}),
            "tcp-1",
            "an existing flow_id must keep its first label",
        )

    def test_tcp_tx_anchor_inference_accepts_compact_and_detailed_stages(self) -> None:
        base = {"proto_l4": 6, "direction": "tx"}
        self.assertTrue(MODULE.packet_flow_anchor({**base, "stage": "ip_output"}))
        self.assertTrue(
            MODULE.packet_flow_anchor({**base, "stage": "__tcp_transmit_skb"})
        )

    def test_interleaved_thread_flows_keep_visuals_and_stats_distinct(self) -> None:
        owner = {
            "owner_tid": 101,
            "owner_tgid": 100,
            "owner_uid": 10000,
            "task": "net-worker",
        }
        flows = (
            {
                "flow_id": "0000000000002001",
                "protocol": "tcp",
                "socket_id": "000000000000a001",
                "local_port": 40001,
                "remote_addr": "203.0.113.1",
                "remote_port": 443,
                "start_ts": 1_010_000_000,
                "last_ts": 1_030_000_000,
                "end_ts": 1_080_000_000,
                "tx_bytes": 128,
                "rx_bytes": 512,
                "tx_packets": 2,
                "rx_packets": 3,
                "end_reason": "tcp_close",
                "incomplete": False,
            },
            {
                "flow_id": "0000000000002002",
                "protocol": "tcp",
                "socket_id": "000000000000a002",
                "local_port": 40002,
                "remote_addr": "203.0.113.2",
                "remote_port": 8443,
                "start_ts": 1_011_000_000,
                "last_ts": 1_032_000_000,
                "end_ts": 6_040_000_000,
                "tx_bytes": 256,
                "rx_bytes": 1024,
                "tx_packets": 3,
                "rx_packets": 4,
                "end_reason": "trace_end",
                "incomplete": True,
            },
            {
                "flow_id": "0000000000003001",
                "protocol": "udp-dns",
                "socket_id": "000000000000b001",
                "local_port": 40003,
                "remote_addr": "192.0.2.53",
                "remote_port": 53,
                "start_ts": 1_012_000_000,
                "last_ts": 1_031_000_000,
                "end_ts": 6_031_000_000,
                "tx_bytes": 64,
                "rx_bytes": 96,
                "tx_packets": 1,
                "rx_packets": 1,
                "end_reason": "idle_timeout",
                "incomplete": False,
            },
            {
                "flow_id": "0000000000003002",
                "protocol": "udp-dns",
                "socket_id": "000000000000b002",
                "local_port": 40004,
                "remote_addr": "192.0.2.54",
                "remote_port": 53,
                "start_ts": 1_013_000_000,
                "last_ts": 1_033_000_000,
                "end_ts": 6_040_000_000,
                "tx_bytes": 80,
                "rx_bytes": 120,
                "tx_packets": 2,
                "rx_packets": 2,
                "end_reason": "trace_end",
                "incomplete": True,
            },
        )
        expected_labels = {
            MODULE.id_value("0000000000002001"): "tcp-1",
            MODULE.id_value("0000000000002002"): "tcp-2",
            MODULE.id_value("0000000000003001"): "dns-1",
            MODULE.id_value("0000000000003002"): "dns-2",
        }
        records = [
            {
                "schema": MODULE.SCHEMA,
                "type": "clock_snapshot",
                "monotonic_ns": 1_000_000_000,
                "boottime_ns": 1_100_000_000,
                "realtime_ns": 1_800_000_000_000_000_000,
            }
        ]
        for flow in flows:
            records.append(
                {
                    "schema": MODULE.SCHEMA,
                    "type": "flow_start",
                    "ts_ns": flow["start_ts"],
                    "local_addr": "10.0.0.2",
                    **owner,
                    **{
                        key: flow[key]
                        for key in (
                            "flow_id",
                            "protocol",
                            "socket_id",
                            "local_port",
                            "remote_addr",
                            "remote_port",
                        )
                    },
                }
            )

        interleaved = (
            (1_020_000_000, flows[0], "tx"),
            (1_021_000_000, flows[2], "tx"),
            (1_022_000_000, flows[1], "tx"),
            (1_023_000_000, flows[3], "tx"),
            (1_030_000_000, flows[0], "rx"),
            (1_031_000_000, flows[2], "rx"),
            (1_032_000_000, flows[1], "rx"),
            (1_033_000_000, flows[3], "rx"),
        )
        for index, (ts_ns, flow, direction) in enumerate(interleaved, 1):
            records.append(
                {
                    "schema": MODULE.SCHEMA,
                    "type": "packet_event",
                    "ts_ns": ts_ns,
                    "packet_id": f"{0x4000 + index:016x}",
                    "flow_id": flow["flow_id"],
                    "stage": "test_tx" if direction == "tx" else "test_rx",
                    "terminal": False,
                    "dropped": False,
                    "flow_anchor": True,
                    "cpu": 0,
                    "tid": owner["owner_tid"],
                    "tgid": owner["owner_tgid"],
                    "uid": owner["owner_uid"],
                    "task": owner["task"],
                    "direction": direction,
                }
            )

        for flow in sorted(flows, key=lambda item: item["end_ts"]):
            records.append(
                {
                    "schema": MODULE.SCHEMA,
                    "type": "flow_end",
                    "ts_ns": flow["end_ts"],
                    "first_ts_ns": flow["start_ts"],
                    "last_ts_ns": flow["last_ts"],
                    "duration_ns": flow["end_ts"] - flow["start_ts"],
                    "local_addr": "10.0.0.2",
                    **owner,
                    **{
                        key: flow[key]
                        for key in (
                            "flow_id",
                            "protocol",
                            "socket_id",
                            "tx_bytes",
                            "rx_bytes",
                            "tx_packets",
                            "rx_packets",
                            "local_port",
                            "remote_addr",
                            "remote_port",
                            "end_reason",
                            "incomplete",
                        )
                    },
                }
            )
        records.append(
            {
                "schema": MODULE.SCHEMA,
                "type": "trace_end",
                "ts_ns": 6_040_000_000,
                "event_count": 0,
                "exported_events": 0,
                "lost_events": 0,
            }
        )

        encoded = MODULE.PerfettoExporter(records).serialize()
        trace = Trace()
        trace.ParseFromString(encoded)
        begins = [
            packet
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.type == TrackEvent.TYPE_SLICE_BEGIN
            and "anettrace.flow" in packet.track_event.categories
        ]
        self.assertEqual(len(begins), 4)
        self.assertEqual(len({packet.track_event.track_uuid for packet in begins}), 4)

        expected_by_id = {MODULE.id_value(flow["flow_id"]): flow for flow in flows}
        begin_by_id = {packet.track_event.correlation_id: packet for packet in begins}
        self.assertEqual(set(begin_by_id), set(expected_by_id))

        packet_events = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and "anettrace.packet" in packet.track_event.categories
        ]
        expected_visual_order = [
            expected_labels[MODULE.id_value(flow["flow_id"])]
            for _, flow, _ in interleaved
        ]
        self.assertEqual([event.name for event in packet_events], expected_visual_order)
        self.assertEqual(len({event.track_uuid for event in packet_events}), 1)
        for event in packet_events:
            self.assertEqual(
                event.name,
                expected_labels[event.correlation_id],
                "one flow must keep one visual tag across interleaved packets",
            )
        self.assertEqual(len(set(expected_visual_order)), 4)

        descriptors = {
            packet.track_descriptor.uuid: packet.track_descriptor
            for packet in trace.packet
            if packet.HasField("track_descriptor")
        }
        end_by_track = {
            packet.track_event.track_uuid: packet
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.type == TrackEvent.TYPE_SLICE_END
            and "anettrace.flow" in packet.track_event.categories
        }
        self.assertEqual(len(end_by_track), 4)
        flow_parents = {
            descriptors[packet.track_event.track_uuid].parent_uuid
            for packet in begins
        }
        self.assertEqual(len(flow_parents), 4)
        self.assertTrue(
            all(descriptors[parent].name.startswith("socket ") for parent in flow_parents)
        )
        self.assertEqual(
            len({descriptors[parent].parent_uuid for parent in flow_parents}), 1
        )

        for flow_id, flow in expected_by_id.items():
            begin = begin_by_id[flow_id]
            track_uuid = begin.track_event.track_uuid
            end = end_by_track[track_uuid]
            tag = expected_labels[flow_id]
            descriptor_name = descriptors[track_uuid].name
            self.assertEqual(begin.track_event.name, tag)
            self.assertIn(tag, descriptor_name)
            self.assertIn(flow["remote_addr"], descriptor_name)
            self.assertEqual(
                end.timestamp - begin.timestamp, flow["end_ts"] - flow["start_ts"]
            )

            annotations = {
                annotation.name: annotation
                for annotation in end.track_event.debug_annotations
            }
            for key in (
                "duration_ns",
                "tx_bytes",
                "rx_bytes",
                "tx_packets",
                "rx_packets",
            ):
                expected = (
                    flow["end_ts"] - flow["start_ts"]
                    if key == "duration_ns"
                    else flow[key]
                )
                self.assertEqual(annotations[key].string_value, str(expected))
            self.assertEqual(annotations["owner_tid"].string_value, str(owner["owner_tid"]))
            self.assertEqual(annotations["owner_tgid"].string_value, str(owner["owner_tgid"]))
            self.assertEqual(annotations["owner_uid"].string_value, str(owner["owner_uid"]))
            self.assertEqual(annotations["local_addr"].string_value, "10.0.0.2")
            self.assertEqual(annotations["local_port"].string_value, str(flow["local_port"]))
            self.assertEqual(
                annotations["remote_addr"].string_value, flow["remote_addr"]
            )
            self.assertEqual(annotations["remote_port"].string_value, str(flow["remote_port"]))
            self.assertEqual(annotations["end_reason"].string_value, flow["end_reason"])
            self.assertEqual(annotations["incomplete"].string_value, str(flow["incomplete"]).lower())

        with TemporaryDirectory(prefix="anettrace-flow-") as directory:
            trace_path = Path(directory) / "interleaved-flows.pftrace"
            trace_path.write_bytes(encoded)
            with TraceProcessor(trace=str(trace_path)) as processor:
                flow_rows = list(
                    processor.query(
                        """
                        SELECT
                          name,
                          dur,
                          track_id,
                          CAST(extract_arg(arg_set_id, 'debug.tx_bytes') AS INT) AS tx_bytes,
                          CAST(extract_arg(arg_set_id, 'debug.rx_bytes') AS INT) AS rx_bytes,
                          CAST(extract_arg(arg_set_id, 'debug.tx_packets') AS INT) AS tx_packets,
                          CAST(extract_arg(arg_set_id, 'debug.rx_packets') AS INT) AS rx_packets,
                          CAST(extract_arg(arg_set_id, 'debug.owner_tid') AS INT) AS owner_tid,
                          extract_arg(arg_set_id, 'debug.local_addr') AS local_addr,
                          CAST(extract_arg(arg_set_id, 'debug.local_port') AS INT) AS local_port,
                          extract_arg(arg_set_id, 'debug.remote_addr') AS remote_addr,
                          CAST(extract_arg(arg_set_id, 'debug.remote_port') AS INT) AS remote_port,
                          extract_arg(arg_set_id, 'debug.end_reason') AS end_reason,
                          extract_arg(arg_set_id, 'debug.incomplete') = 'true' AS incomplete
                        FROM slice
                        WHERE category = 'anettrace.flow'
                        ORDER BY name
                        """
                    )
                )
                packet_rows = list(
                    processor.query(
                        """
                        SELECT name, track_id
                        FROM slice
                        WHERE category = 'anettrace.packet'
                        ORDER BY ts
                        """
                    )
                )
                flow_link_rows = list(
                    processor.query("SELECT COUNT(*) AS count FROM flow")
                )

        expected_by_tag = {
            expected_labels[MODULE.id_value(flow["flow_id"])]: flow for flow in flows
        }
        self.assertEqual(len(flow_rows), 4)
        self.assertEqual(len({row.track_id for row in flow_rows}), 4)
        for row in flow_rows:
            flow = expected_by_tag[row.name]
            self.assertEqual(row.dur, flow["end_ts"] - flow["start_ts"])
            for key in ("tx_bytes", "rx_bytes", "tx_packets", "rx_packets"):
                self.assertEqual(getattr(row, key), flow[key])
            self.assertEqual(row.owner_tid, owner["owner_tid"])
            self.assertEqual(row.local_addr, "10.0.0.2")
            self.assertEqual(row.local_port, flow["local_port"])
            self.assertEqual(row.remote_addr, flow["remote_addr"])
            self.assertEqual(row.remote_port, flow["remote_port"])
            self.assertEqual(row.end_reason, flow["end_reason"])
            self.assertEqual(bool(row.incomplete), flow["incomplete"])

        self.assertEqual([row.name for row in packet_rows], expected_visual_order)
        self.assertEqual(len({row.track_id for row in packet_rows}), 1)
        self.assertEqual(flow_link_rows[0].count, 12)

    def test_multiple_clock_snapshots_cover_suspend_offset_changes(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "perfetto-events.jsonl"
        records = MODULE.read_records(fixture)
        second_snapshot = copy.deepcopy(records[0])
        second_snapshot.update(
            monotonic_ns=1_060_000_000,
            boottime_ns=6_160_000_000,
            realtime_ns=1_800_000_005_060_000_000,
        )
        records.insert(-1, second_snapshot)

        trace = Trace()
        trace.ParseFromString(MODULE.PerfettoExporter(records).serialize())

        snapshots = [
            packet.clock_snapshot
            for packet in trace.packet
            if packet.HasField("clock_snapshot")
        ]
        self.assertEqual(len(snapshots), 2)
        trace_end = next(
            packet
            for packet in trace.packet
            if packet.HasField("track_event") and packet.track_event.name == "trace_end"
        )
        self.assertEqual(trace_end.timestamp, 1_070_000_000)
        self.assertEqual(trace_end.timestamp_clock_id, MODULE.CLOCK_MONOTONIC)

    def test_connect_diagnostic_events_are_queryable(self) -> None:
        records = MODULE.read_records(
            ROOT / "tests" / "fixtures" / "connect-diagnostics-events.jsonl"
        )
        encoded = MODULE.PerfettoExporter(records).serialize()
        with TemporaryDirectory(prefix="anettrace-connect-") as directory:
            trace_path = Path(directory) / "connect.pftrace"
            trace_path.write_bytes(encoded)
            with TraceProcessor(trace=str(trace_path)) as processor:
                rows = list(
                    processor.query(
                        (ROOT / "tools" / "perfetto_sql" / "connect_diagnostics.sql")
                        .read_text(encoding="utf-8")
                    )
                )

        attempt_ids = {row.attempt_id for row in rows if row.attempt_id}
        self.assertEqual(len(attempt_ids), 8)
        self.assertTrue(any(row.name == "TCP connect attempt" for row in rows))
        self.assertTrue(any(row.name == "connect SO_ERROR" for row in rows))
        self.assertTrue(any(row.name == "connect kernel drop" for row in rows))
        success = next(
            row for row in rows
            if row.name == "TCP connect attempt"
            and row.attempt_id == "0000000000000001"
        )
        self.assertEqual(success.dur, 6_000_000)
        self.assertEqual(success.uid, 10000)
        self.assertEqual(success.tid, 101)
        self.assertEqual(success.fd, 11)
        self.assertTrue(any(row.result == -115 for row in rows))
        self.assertEqual(
            {row.async_pending for row in rows if row.async_pending is not None},
            {0, 1},
        )

        with TemporaryDirectory(prefix="anettrace-connect-metrics-") as directory:
            trace_path = Path(directory) / "connect.pftrace"
            trace_path.write_bytes(encoded)
            with TraceProcessor(trace=str(trace_path)) as processor:
                metrics = list(
                    processor.query(
                        (
                            ROOT
                            / "tools"
                            / "perfetto_sql"
                            / "connect_diagnostics_metrics.sql"
                        ).read_text(encoding="utf-8")
                    )
                )
        self.assertEqual(len(metrics), 8)
        self.assertTrue(all(row.runnable_delay_ns == 0 for row in metrics))
        self.assertTrue(all(row.process_exit_ns == 0 for row in metrics))


if __name__ == "__main__":
    unittest.main()
