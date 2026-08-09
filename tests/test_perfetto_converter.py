#!/usr/bin/env python3
"""Contract test for Anettrace JSONL to Perfetto conversion."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace, TrackEvent


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "anettrace_to_perfetto.py"
SPEC = importlib.util.spec_from_file_location("anettrace_to_perfetto", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PerfettoConverterTest(unittest.TestCase):
    def test_socket_packet_and_terminal_events(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "perfetto-events.jsonl"
        encoded = MODULE.PerfettoExporter(MODULE.read_records(fixture)).serialize()
        trace = Trace()
        trace.ParseFromString(encoded)

        names = [packet.track_event.name for packet in trace.packet if packet.HasField("track_event")]
        self.assertIn("socket allocation", names)
        self.assertIn("socket lifetime", names)
        self.assertIn("F-00002001", names)
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
        self.assertEqual({event.name for event in packet_events}, {"F-00002001"})
        self.assertEqual(
            {event.correlation_id for event in packet_events}, {0x2001}
        )
        packet_annotations = [
            {annotation.name: annotation for annotation in event.debug_annotations}
            for event in packet_events
        ]
        self.assertEqual(
            {annotations["stage"].string_value for annotations in packet_annotations},
            {"__tcp_transmit_skb", "consume_skb", "tcp_rcv_established"},
        )
        self.assertTrue(
            all(
                annotations["flow_tag"].string_value == "F-00002001"
                for annotations in packet_annotations
            )
        )
        self.assertNotEqual(
            MODULE.flow_tag(MODULE.id_value("0000000000002001")),
            MODULE.flow_tag(MODULE.id_value("0000000000002002")),
        )

        packets = [
            event
            for event, annotations in zip(packet_events, packet_annotations)
            if annotations["stage"].string_value == "consume_skb"
        ]
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0].type, TrackEvent.TYPE_INSTANT)
        self.assertEqual(list(packets[0].terminating_flow_ids), [0x3001])

        rx_packets = [
            event
            for event, annotations in zip(packet_events, packet_annotations)
            if annotations["stage"].string_value == "tcp_rcv_established"
        ]
        self.assertEqual(len(rx_packets), 1)
        rx_annotations = {
            annotation.name: annotation
            for annotation in rx_packets[0].debug_annotations
        }
        self.assertEqual(rx_annotations["direction"].string_value, "rx")
        self.assertEqual(rx_annotations["owner_uid"].uint_value, 10000)

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
            annotation.name: annotation
            for annotation in recv_ends[0].debug_annotations
        }
        self.assertEqual(recv_annotations["bytes"].uint_value, 512)

        flow_begins = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.name == "F-00002001"
            and "anettrace.flow" in packet.track_event.categories
        ]
        self.assertEqual(len(flow_begins), 1)
        flow_track = flow_begins[0].track_uuid
        flow_ends = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.track_uuid == flow_track
            and packet.track_event.type == TrackEvent.TYPE_SLICE_END
        ]
        self.assertEqual(len(flow_ends), 1)
        flow_annotations = {
            annotation.name: annotation
            for annotation in flow_ends[0].debug_annotations
        }
        self.assertEqual(flow_annotations["tx_bytes"].uint_value, 128)
        self.assertEqual(flow_annotations["rx_bytes"].uint_value, 512)
        self.assertEqual(flow_annotations["tx_packets"].uint_value, 1)
        self.assertEqual(flow_annotations["rx_packets"].uint_value, 1)
        self.assertEqual(flow_annotations["end_reason"].string_value, "tcp_close")
        self.assertFalse(flow_annotations["incomplete"].bool_value)

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
        self.assertTrue(any(descriptor.thread.tid == 101 for descriptor in thread_descriptors))

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

    def test_interleaved_thread_flows_use_distinct_tracks(self) -> None:
        records = [
            {
                "schema": MODULE.SCHEMA,
                "type": "clock_snapshot",
                "monotonic_ns": 1_000_000_000,
                "boottime_ns": 1_100_000_000,
                "realtime_ns": 1_800_000_000_000_000_000,
            }
        ]
        for flow_id, protocol, remote_port, tx_bytes, reason in (
            ("0000000000002001", "tcp", 443, 128, "tcp_close"),
            ("0000000000002002", "udp-dns", 53, 64, "idle_timeout"),
        ):
            tag = MODULE.flow_tag(MODULE.id_value(flow_id))
            records.extend(
                [
                    {
                        "schema": MODULE.SCHEMA,
                        "type": "flow_start",
                        "ts_ns": 1_010_000_000,
                        "flow_id": flow_id,
                        "flow_tag": tag,
                        "protocol": protocol,
                        "socket_id": f"000000000000{remote_port:04x}",
                        "owner_tid": 101,
                        "owner_tgid": 100,
                        "owner_uid": 10000,
                        "task": "net-worker",
                        "local_addr": "10.0.0.2",
                        "local_port": 40000,
                        "remote_addr": "10.0.0.1",
                        "remote_port": remote_port,
                    },
                    {
                        "schema": MODULE.SCHEMA,
                        "type": "flow_end",
                        "ts_ns": 1_020_000_000,
                        "first_ts_ns": 1_010_000_000,
                        "last_ts_ns": 1_015_000_000,
                        "duration_ns": 10_000_000,
                        "flow_id": flow_id,
                        "flow_tag": tag,
                        "protocol": protocol,
                        "socket_id": f"000000000000{remote_port:04x}",
                        "tx_bytes": tx_bytes,
                        "rx_bytes": tx_bytes * 2,
                        "tx_packets": 1,
                        "rx_packets": 1,
                        "owner_tid": 101,
                        "owner_tgid": 100,
                        "owner_uid": 10000,
                        "task": "net-worker",
                        "local_addr": "10.0.0.2",
                        "local_port": 40000,
                        "remote_addr": "10.0.0.1",
                        "remote_port": remote_port,
                        "end_reason": reason,
                        "incomplete": False,
                    },
                ]
            )
        records.append(
            {
                "schema": MODULE.SCHEMA,
                "type": "trace_end",
                "ts_ns": 1_030_000_000,
                "event_count": 0,
                "exported_events": 0,
                "lost_events": 0,
            }
        )

        trace = Trace()
        trace.ParseFromString(MODULE.PerfettoExporter(records).serialize())
        begins = [
            packet.track_event
            for packet in trace.packet
            if packet.HasField("track_event")
            and packet.track_event.type == TrackEvent.TYPE_SLICE_BEGIN
            and "anettrace.flow" in packet.track_event.categories
        ]
        self.assertEqual(len(begins), 2)
        self.assertEqual(len({event.track_uuid for event in begins}), 2)
        self.assertEqual({event.name for event in begins}, {"F-00002001", "F-00002002"})

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


if __name__ == "__main__":
    unittest.main()
