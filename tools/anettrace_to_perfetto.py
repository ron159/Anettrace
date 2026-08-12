#!/usr/bin/env python3
"""Convert Anettrace JSONL metadata into Perfetto TracePacket protobufs."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import TrackEvent
    from perfetto.trace_builder.proto_builder import TraceProtoBuilder
except ImportError as error:  # pragma: no cover - exercised by CLI users
    raise SystemExit(
        "missing Python dependency; run: "
        "uv run --with perfetto==0.57.2 tools/anettrace_to_perfetto.py ..."
    ) from error


SCHEMA = "anettrace.perfetto.v1"
CLOCK_REALTIME = 1
CLOCK_MONOTONIC = 3
CLOCK_BOOTTIME = 6


def stable_uuid(*parts: object) -> int:
    digest = hashlib.blake2b(
        "\0".join(str(part) for part in parts).encode(), digest_size=8
    ).digest()
    return int.from_bytes(digest, "little") or 1


def id_value(value: str) -> int:
    return int(value, 16) or 1


def flow_prefix(record: dict[str, Any]) -> str:
    protocol = str(record.get("protocol", "")).lower()
    proto_l4 = int(record.get("proto_l4", 0) or 0)
    ports = {
        int(record.get(key, 0) or 0)
        for key in ("sport", "dport", "local_port", "remote_port")
    }
    if protocol in ("dns", "udp-dns"):
        return "dns"
    if protocol == "tcp" or proto_l4 == 6:
        return "tcp"
    if protocol == "udp" or proto_l4 == 17:
        return "dns" if 53 in ports else "udp"
    return "flow"


def packet_flow_anchor(record: dict[str, Any]) -> bool:
    if "flow_anchor" in record:
        return bool(record["flow_anchor"])
    stage = str(record.get("stage", ""))
    protocol = int(record.get("proto_l4", 0) or 0)
    direction = str(record.get("direction", ""))
    if direction == "tx":
        if protocol == 6:
            return stage == "__tcp_transmit_skb"
        return stage in ("ip_output", "ip6_output")
    if direction == "rx":
        if protocol == 6:
            return stage in ("tcp_v4_rcv", "tcp_v6_rcv")
        return stage in ("udp_rcv", "udpv6_rcv")
    return False


def read_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
            if record.get("schema") != SCHEMA:
                raise ValueError(
                    f"{path}:{line_number}: unsupported schema {record.get('schema')!r}"
                )
            records.append(record)
    return records


class PerfettoExporter:
    def __init__(self, records: Iterable[dict[str, Any]]) -> None:
        self.records = list(records)
        self.builder = TraceProtoBuilder()
        self.descriptors: set[int] = set()
        self.process_tracks: dict[int, int] = {}
        self.thread_tracks: dict[tuple[int, int], int] = {}
        self.socket_tracks: dict[str, int] = {}
        self.socket_lifetimes: set[str] = set()
        self.closed_sockets: set[str] = set()
        self.flow_tracks: dict[str, int] = {}
        self.flow_labels: dict[str, str] = {}
        self.flow_label_counts = {"tcp": 0, "udp": 0, "dns": 0, "flow": 0}
        self.active_flows: set[str] = set()
        self.pending_io: dict[tuple[str, str, int], int] = {}
        self.connect_tracks: dict[str, int] = {}
        self.connect_sockets: dict[str, str] = {}
        self.active_connects: set[str] = set()
        self.global_track = stable_uuid("anettrace", "global")
        self.capture_start_monotonic_ns = 0
        self.clock_monotonic_ns: list[int] = []
        self.sequence_started = False

    def sequence_packet(self):
        packet = self.builder.add_packet()
        packet.trusted_packet_sequence_id = 1
        if not self.sequence_started:
            packet.sequence_flags = packet.SEQ_INCREMENTAL_STATE_CLEARED
            self.sequence_started = True
        return packet

    def add_clock_snapshot(self, record: dict[str, Any]) -> None:
        packet = self.builder.add_packet()
        snapshot = packet.clock_snapshot
        for clock_id, key in (
            (CLOCK_REALTIME, "realtime_ns"),
            (CLOCK_MONOTONIC, "monotonic_ns"),
            (CLOCK_BOOTTIME, "boottime_ns"),
        ):
            clock = snapshot.clocks.add()
            clock.clock_id = clock_id
            clock.timestamp = int(record[key])
        snapshot.primary_trace_clock = CLOCK_BOOTTIME
        monotonic_ns = int(record["monotonic_ns"])
        if not self.clock_monotonic_ns:
            self.capture_start_monotonic_ns = monotonic_ns
        self.clock_monotonic_ns.append(monotonic_ns)

    def descriptor(self, uuid: int, name: str, parent_uuid: int = 0):
        if uuid in self.descriptors:
            return None
        packet = self.sequence_packet()
        descriptor = packet.track_descriptor
        descriptor.uuid = uuid
        descriptor.name = name
        if parent_uuid:
            descriptor.parent_uuid = parent_uuid
        self.descriptors.add(uuid)
        return descriptor

    def process_track(self, tgid: int, task: str) -> int:
        uuid = self.process_tracks.get(tgid)
        if uuid is not None:
            return uuid
        uuid = stable_uuid("process", tgid)
        descriptor = self.descriptor(uuid, task or f"pid {tgid}")
        assert descriptor is not None
        descriptor.process.pid = tgid
        descriptor.process.process_name = task or f"pid {tgid}"
        self.process_tracks[tgid] = uuid
        return uuid

    def thread_track(self, record: dict[str, Any]) -> int:
        tgid = int(record.get("tgid", 0))
        tid = int(record.get("tid", 0))
        task = str(record.get("task", ""))
        key = (tgid, tid)
        uuid = self.thread_tracks.get(key)
        if uuid is not None:
            return uuid
        process_uuid = self.process_track(tgid, task)
        uuid = stable_uuid("thread", tgid, tid)
        descriptor = self.descriptor(uuid, task or f"tid {tid}", process_uuid)
        assert descriptor is not None
        descriptor.thread.pid = tgid
        descriptor.thread.tid = tid
        descriptor.thread.thread_name = task or f"tid {tid}"
        self.thread_tracks[key] = uuid
        return uuid

    def socket_track(self, socket_id: str, record: dict[str, Any]) -> int:
        uuid = self.socket_tracks.get(socket_id)
        if uuid is not None:
            return uuid
        tgid = int(record.get("tgid", record.get("owner_tgid", 0)))
        parent_uuid = self.process_track(tgid, str(record.get("task", "")))
        uuid = stable_uuid("socket", socket_id)
        self.descriptor(uuid, f"socket {socket_id[-8:]}", parent_uuid)
        self.socket_tracks[socket_id] = uuid
        return uuid

    def flow_track(self, flow_id: str, record: dict[str, Any]) -> int:
        uuid = self.flow_tracks.get(flow_id)
        if uuid is not None:
            return uuid
        owner_tgid = int(record.get("owner_tgid", record.get("tgid", 0)))
        task = str(record.get("task", ""))
        socket_id = str(record.get("socket_id", ""))
        parent_uuid = (
            self.socket_track(socket_id, record)
            if socket_id and int(socket_id, 16)
            else self.process_track(owner_tgid, task)
        )
        uuid = stable_uuid("flow", flow_id)
        name = (
            f"{self.flow_label(flow_id, record)} "
            f"{record.get('protocol', 'tcp')} "
            f"{record.get('local_addr', '')}:{record.get('local_port', 0)} -> "
            f"{record.get('remote_addr', '')}:{record.get('remote_port', 0)}"
        )
        self.descriptor(uuid, name, parent_uuid)
        self.flow_tracks[flow_id] = uuid
        return uuid

    def flow_label(self, flow_id: str, record: dict[str, Any]) -> str:
        label = self.flow_labels.get(flow_id)
        if label is not None:
            return label
        prefix = flow_prefix(record)
        self.flow_label_counts[prefix] += 1
        label = f"{prefix}-{self.flow_label_counts[prefix]}"
        self.flow_labels[flow_id] = label
        return label

    def connect_track(self, attempt_id: str, record: dict[str, Any]) -> int:
        uuid = self.connect_tracks.get(attempt_id)
        if uuid is not None:
            return uuid
        parent_uuid = self.thread_track(record)
        uuid = stable_uuid("connect", attempt_id)
        self.descriptor(uuid, f"connect {attempt_id[-8:]}", parent_uuid)
        self.connect_tracks[attempt_id] = uuid
        return uuid

    def connect_attempt_id(self, record: dict[str, Any]) -> str:
        attempt_id = str(record.get("attempt_id", ""))
        if attempt_id:
            return attempt_id
        socket_id = str(
            record.get("socket_instance_id")
            or record.get("socket_id")
            or record.get("owner_socket_id")
            or ""
        )
        return self.connect_sockets.get(socket_id, "")

    def timestamp(self, monotonic_ns: int) -> int:
        if not self.clock_monotonic_ns:
            raise ValueError("cannot emit an event without a clock snapshot")
        if monotonic_ns < self.clock_monotonic_ns[0]:
            raise ValueError("event timestamp precedes the first clock snapshot")
        return monotonic_ns

    def add_annotations(self, event, record: dict[str, Any], keys: Iterable[str]) -> None:
        for key in keys:
            if key not in record:
                continue
            value = record[key]
            annotation = event.debug_annotations.add()
            annotation.name = key
            if isinstance(value, bool):
                annotation.bool_value = value
            elif isinstance(value, int):
                if value >= 0:
                    annotation.uint_value = value
                else:
                    annotation.int_value = value
            else:
                annotation.string_value = str(value)

    def event(
        self,
        ts_ns: int,
        track_uuid: int,
        event_type: int,
        name: str = "",
        category: str = "anettrace",
        flow_id: int | None = None,
        terminating_flow: bool = False,
        linked_flow_ids: Iterable[int] = (),
        correlation_id: int | None = None,
        annotations: tuple[dict[str, Any], Iterable[str]] | None = None,
    ) -> None:
        packet = self.sequence_packet()
        packet.timestamp = self.timestamp(ts_ns)
        packet.timestamp_clock_id = CLOCK_MONOTONIC
        track_event = packet.track_event
        track_event.type = event_type
        track_event.track_uuid = track_uuid
        if name:
            track_event.name = name
        track_event.categories.append(category)
        if flow_id is not None:
            if terminating_flow:
                track_event.terminating_flow_ids.append(flow_id)
            else:
                track_event.flow_ids.append(flow_id)
        for linked_flow_id in linked_flow_ids:
            track_event.flow_ids.append(linked_flow_id)
        if correlation_id is not None:
            track_event.correlation_id = correlation_id
        if annotations:
            self.add_annotations(track_event, annotations[0], annotations[1])

    def export_socket_create(self, record: dict[str, Any]) -> None:
        thread_track = self.thread_track(record)
        socket_id = str(record["socket_id"])
        flow_id = id_value(socket_id)
        self.event(
            int(record["start_ts_ns"]),
            thread_track,
            TrackEvent.TYPE_SLICE_BEGIN,
            "socket allocation",
            "anettrace.socket",
            flow_id,
            annotations=(record, ("socket_id", "cpu", "uid")),
        )
        self.event(
            int(record["ts_ns"]),
            thread_track,
            TrackEvent.TYPE_SLICE_END,
            category="anettrace.socket",
            flow_id=flow_id,
        )
        socket_track = self.socket_track(socket_id, record)
        if socket_id in self.socket_lifetimes:
            self.event(
                int(record["start_ts_ns"]),
                socket_track,
                TrackEvent.TYPE_SLICE_END,
                category="anettrace.socket",
                flow_id=flow_id,
                terminating_flow=True,
            )
        self.event(
            int(record["ts_ns"]),
            socket_track,
            TrackEvent.TYPE_SLICE_BEGIN,
            "socket lifetime",
            "anettrace.socket",
            flow_id,
        )
        self.socket_lifetimes.add(socket_id)
        self.closed_sockets.discard(socket_id)

    def export_socket_state(self, record: dict[str, Any]) -> None:
        socket_id = str(record["socket_id"])
        socket_track = self.socket_track(socket_id, record)
        if (
            socket_id not in self.socket_lifetimes
            and socket_id not in self.closed_sockets
            and not record.get("terminal")
        ):
            self.event(
                int(record["ts_ns"]),
                socket_track,
                TrackEvent.TYPE_SLICE_BEGIN,
                "socket lifetime",
                "anettrace.socket",
                id_value(socket_id),
            )
            self.socket_lifetimes.add(socket_id)
        self.event(
            int(record["ts_ns"]),
            socket_track,
            TrackEvent.TYPE_INSTANT,
            f"{record['old_state_name']} → {record['new_state_name']}",
            "anettrace.socket.state",
            id_value(socket_id),
            annotations=(
                record,
                (
                    "socket_id",
                    "flow_id",
                    "old_state",
                    "new_state",
                    "saddr",
                    "sport",
                    "daddr",
                    "dport",
                    "cpu",
                    "tid",
                    "uid",
                ),
            ),
        )
        if record.get("terminal"):
            if socket_id in self.socket_lifetimes:
                self.event(
                    int(record["ts_ns"]),
                    socket_track,
                    TrackEvent.TYPE_SLICE_END,
                    category="anettrace.socket",
                    flow_id=id_value(socket_id),
                    terminating_flow=True,
                )
                self.socket_lifetimes.remove(socket_id)
            self.closed_sockets.add(socket_id)

    def export_socket_event(self, record: dict[str, Any]) -> None:
        socket_id = str(record["socket_id"])
        socket_track = self.socket_track(socket_id, record)
        if (
            socket_id not in self.socket_lifetimes
            and socket_id not in self.closed_sockets
            and not record.get("terminal")
        ):
            self.event(
                int(record["ts_ns"]),
                socket_track,
                TrackEvent.TYPE_SLICE_BEGIN,
                "socket lifetime",
                "anettrace.socket",
                id_value(socket_id),
            )
            self.socket_lifetimes.add(socket_id)
        self.event(
            int(record["ts_ns"]),
            self.thread_track(record),
            TrackEvent.TYPE_INSTANT,
            str(record["stage"]),
            "anettrace.socket",
            id_value(socket_id),
            bool(record.get("terminal")),
            annotations=(
                record,
                (
                    "socket_id",
                    "flow_id",
                    "saddr",
                    "sport",
                    "daddr",
                    "dport",
                    "cpu",
                    "uid",
                    "direction",
                    "owner_valid",
                    "owner_tid",
                    "owner_tgid",
                    "owner_uid",
                    "owner_socket_id",
                ),
            ),
        )
        if record.get("terminal"):
            if socket_id in self.socket_lifetimes:
                self.event(
                    int(record["ts_ns"]),
                    socket_track,
                    TrackEvent.TYPE_SLICE_END,
                    category="anettrace.socket",
                    flow_id=id_value(socket_id),
                    terminating_flow=True,
                )
                self.socket_lifetimes.remove(socket_id)
            self.closed_sockets.add(socket_id)

    def export_packet_event(self, record: dict[str, Any]) -> None:
        packet_id = str(record["packet_id"])
        flow_id = str(record["flow_id"])
        packet_record = dict(record)
        packet_record["flow_tag"] = self.flow_label(flow_id, record)
        self.event(
            int(record["ts_ns"]),
            self.thread_track(record),
            TrackEvent.TYPE_INSTANT,
            packet_record["flow_tag"],
            "anettrace.packet.drop"
            if record.get("dropped")
            else "anettrace.packet",
            id_value(packet_id),
            bool(record.get("terminal")),
            linked_flow_ids=(id_value(flow_id),)
            if packet_flow_anchor(record)
            else (),
            correlation_id=id_value(flow_id),
            annotations=(
                packet_record,
                (
                    "stage",
                    "packet_id",
                    "skb_id",
                    "flow_id",
                    "flow_tag",
                    "terminal",
                    "dropped",
                    "flow_anchor",
                    "cpu",
                    "uid",
                    "direction",
                    "owner_valid",
                    "owner_tid",
                    "owner_tgid",
                    "owner_uid",
                    "owner_socket_id",
                    "ifname",
                    "ifindex",
                    "netns",
                    "proto_l3",
                    "proto_l4",
                    "saddr",
                    "sport",
                    "daddr",
                    "dport",
                    "mark",
                    "tcp_seq",
                    "tcp_ack",
                    "tcp_flags",
                    "drop_reason",
                    "drop_location_id",
                ),
            ),
        )

    def export_connect_event(self, record: dict[str, Any]) -> None:
        record_type = str(record["type"])
        attempt_id = self.connect_attempt_id(record)
        if not attempt_id:
            return
        track = self.connect_track(attempt_id, record)
        event_record = dict(record)
        event_record["attempt_id"] = attempt_id
        annotation_keys = tuple(
            key
            for key in event_record
            if key not in ("schema", "type", "task", "ts_ns")
        )
        ts_ns = int(record["ts_ns"])
        flow_id = id_value(attempt_id)

        if record_type == "connect_attempt_start":
            self.event(
                ts_ns,
                track,
                TrackEvent.TYPE_SLICE_BEGIN,
                "TCP connect attempt",
                "anettrace.connect",
                flow_id=flow_id,
                correlation_id=flow_id,
                annotations=(event_record, annotation_keys),
            )
            self.active_connects.add(attempt_id)
            return

        if record_type == "connect_socket":
            socket_id = str(record["socket_instance_id"])
            self.connect_sockets[socket_id] = attempt_id

        should_close = (
            (
                record_type == "connect_so_error"
                and int(record.get("error", 0)) not in (114, 115)
            )
            or record_type == "connect_cancel"
            or (
                record_type == "connect_attempt_end"
                and not bool(record.get("async_pending", False))
            )
        )
        name = {
            "connect_socket": "connect socket associated",
            "connect_attempt_end": "connect syscall returned",
            "connect_so_error": "connect SO_ERROR",
            "connect_reset": "connect reset",
            "connect_drop": "connect kernel drop",
            "connect_retransmit": "connect retransmit",
            "connect_rtt": "connect RTT",
            "connect_sched_delay": "connect scheduler delay",
            "connect_cancel": "connect cancelled",
        }.get(record_type, record_type)
        self.event(
            ts_ns,
            track,
            TrackEvent.TYPE_INSTANT,
            name,
            "anettrace.connect",
            flow_id=flow_id,
            correlation_id=flow_id,
            annotations=(event_record, annotation_keys),
        )
        if should_close and attempt_id in self.active_connects:
            self.event(
                ts_ns,
                track,
                TrackEvent.TYPE_SLICE_END,
                category="anettrace.connect",
                flow_id=flow_id,
                terminating_flow=True,
            )
            self.active_connects.remove(attempt_id)

    def export_connect_socket_state(self, record: dict[str, Any]) -> None:
        attempt_id = self.connect_attempt_id(record)
        if not attempt_id:
            return
        event_record = dict(record)
        event_record["attempt_id"] = attempt_id
        self.event(
            int(record["ts_ns"]),
            self.connect_track(attempt_id, event_record),
            TrackEvent.TYPE_INSTANT,
            f"connect state {record.get('new_state_name', 'UNKNOWN')}",
            "anettrace.connect",
            flow_id=id_value(attempt_id),
            correlation_id=id_value(attempt_id),
            annotations=(
                event_record,
                (
                    "attempt_id",
                    "socket_id",
                    "old_state",
                    "old_state_name",
                    "new_state",
                    "new_state_name",
                ),
            ),
        )

    def export_flow_start(self, record: dict[str, Any]) -> None:
        flow_id = str(record["flow_id"])
        flow_record = dict(record)
        flow_record["flow_tag"] = self.flow_label(flow_id, record)
        self.event(
            int(record["ts_ns"]),
            self.flow_track(flow_id, flow_record),
            TrackEvent.TYPE_SLICE_BEGIN,
            flow_record["flow_tag"],
            "anettrace.flow",
            flow_id=id_value(flow_id),
            correlation_id=id_value(flow_id),
            annotations=(
                flow_record,
                (
                    "flow_id",
                    "flow_tag",
                    "protocol",
                    "socket_id",
                    "owner_tid",
                    "owner_tgid",
                    "owner_uid",
                    "local_addr",
                    "local_port",
                    "remote_addr",
                    "remote_port",
                ),
            ),
        )
        self.active_flows.add(flow_id)

    def export_flow_end(self, record: dict[str, Any]) -> None:
        flow_id = str(record["flow_id"])
        flow_record = dict(record)
        flow_record["flow_tag"] = self.flow_label(flow_id, record)
        track = self.flow_tracks.get(flow_id)
        if track is None:
            track = self.flow_track(flow_id, flow_record)
            self.event(
                int(record.get("first_ts_ns", record["ts_ns"])),
                track,
                TrackEvent.TYPE_SLICE_BEGIN,
                flow_record["flow_tag"],
                "anettrace.flow",
                flow_id=id_value(flow_id),
                correlation_id=id_value(flow_id),
            )
        self.event(
            int(record["ts_ns"]),
            track,
            TrackEvent.TYPE_SLICE_END,
            category="anettrace.flow",
            flow_id=id_value(flow_id),
            terminating_flow=True,
            correlation_id=id_value(flow_id),
            annotations=(
                flow_record,
                (
                    "flow_id",
                    "byte_scope",
                    "duration_ns",
                    "tx_bytes",
                    "rx_bytes",
                    "tx_packets",
                    "rx_packets",
                    "owner_tid",
                    "owner_tgid",
                    "owner_uid",
                    "local_addr",
                    "local_port",
                    "remote_addr",
                    "remote_port",
                    "end_reason",
                    "incomplete",
                ),
            ),
        )
        self.active_flows.discard(flow_id)

    def export_io_start(self, record: dict[str, Any], direction: str) -> None:
        key = (direction, str(record["stage"]), int(record["tid"]))
        track = self.thread_track(record)
        category = f"anettrace.{direction}.{'write' if direction == 'tx' else 'read'}"
        if key in self.pending_io:
            self.event(
                int(record["ts_ns"]),
                self.pending_io[key],
                TrackEvent.TYPE_SLICE_END,
                category=category,
            )
        self.event(
            int(record["ts_ns"]),
            track,
            TrackEvent.TYPE_SLICE_BEGIN,
            str(record["stage"]),
            category,
            annotations=(
                record,
                (
                    "socket_id",
                    "flow_id",
                    "protocol",
                    "cpu",
                    "uid",
                    "owner_tid",
                    "owner_tgid",
                    "owner_uid",
                ),
            ),
        )
        self.pending_io[key] = track

    def export_io_end(self, record: dict[str, Any], direction: str) -> None:
        key = (direction, str(record["stage"]), int(record["tid"]))
        track = self.pending_io.pop(key, None)
        if track is None:
            return
        category = f"anettrace.{direction}.{'write' if direction == 'tx' else 'read'}"
        self.event(
            int(record["ts_ns"]),
            track,
            TrackEvent.TYPE_SLICE_END,
            category=category,
            annotations=(
                record,
                (
                    "socket_id",
                    "flow_id",
                    "result",
                    "bytes",
                    "error",
                    "incomplete",
                ),
            ),
        )

    def export_meta_event(self, record: dict[str, Any]) -> None:
        self.descriptor(self.global_track, "Anettrace metadata")
        self.event(
            int(record.get("ts_ns", self.capture_start_monotonic_ns)),
            self.global_track,
            TrackEvent.TYPE_INSTANT,
            str(record["type"]),
            "anettrace.metadata",
            annotations=(record, tuple(key for key in record if key != "schema")),
        )

    def serialize(self) -> bytes:
        clocks = [record for record in self.records if record.get("type") == "clock_snapshot"]
        if not clocks:
            raise ValueError("input has no clock_snapshot record")
        previous_monotonic = -1
        for record in clocks:
            monotonic_ns = int(record["monotonic_ns"])
            if monotonic_ns <= previous_monotonic:
                raise ValueError("clock snapshots must be strictly monotonic")
            self.add_clock_snapshot(record)
            previous_monotonic = monotonic_ns
        for record in self.records:
            record_type = record.get("type")
            if record_type == "clock_snapshot":
                continue
            if record_type == "socket_create":
                self.export_socket_create(record)
            elif record_type == "socket_state":
                self.export_socket_state(record)
                self.export_connect_socket_state(record)
            elif record_type == "socket_event":
                self.export_socket_event(record)
            elif record_type == "packet_event":
                self.export_packet_event(record)
            elif record_type == "flow_start":
                self.export_flow_start(record)
            elif record_type == "flow_end":
                self.export_flow_end(record)
            elif record_type == "rx_read_start":
                self.export_io_start(record, "rx")
            elif record_type == "rx_read_end":
                self.export_io_end(record, "rx")
            elif record_type == "tx_write_start":
                self.export_io_start(record, "tx")
            elif record_type == "tx_write_end":
                self.export_io_end(record, "tx")
            elif record_type.startswith("connect_"):
                self.export_connect_event(record)
            elif record_type in ("lost_events", "trace_end"):
                if record_type == "trace_end" and record.get("ts_ns"):
                    for socket_id in tuple(self.socket_lifetimes):
                        self.event(
                            int(record["ts_ns"]),
                            self.socket_tracks[socket_id],
                            TrackEvent.TYPE_SLICE_END,
                            category="anettrace.socket",
                            flow_id=id_value(socket_id),
                            terminating_flow=True,
                        )
                        self.socket_lifetimes.remove(socket_id)
                    for track in tuple(self.pending_io.values()):
                        self.event(
                            int(record["ts_ns"]),
                            track,
                            TrackEvent.TYPE_SLICE_END,
                            category="anettrace.io",
                        )
                    self.pending_io.clear()
                    for attempt_id in tuple(self.active_connects):
                        self.event(
                            int(record["ts_ns"]),
                            self.connect_tracks[attempt_id],
                            TrackEvent.TYPE_SLICE_END,
                            category="anettrace.connect",
                            flow_id=id_value(attempt_id),
                            terminating_flow=True,
                        )
                        self.active_connects.remove(attempt_id)
                self.export_meta_event(record)
        return self.builder.serialize()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Anettrace JSONL event file")
    parser.add_argument("output", type=Path, help="output Perfetto .pftrace file")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        records = read_records(args.input)
        encoded = PerfettoExporter(records).serialize()
        args.output.write_bytes(encoded)
    except (OSError, ValueError, KeyError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {args.output} ({len(encoded)} bytes, {len(records)} records)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
