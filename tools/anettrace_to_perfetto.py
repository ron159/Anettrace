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


def flow_tag(flow_id: int) -> str:
    return f"F-{flow_id & 0xFFFFFFFF:08X}"


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
        self.pending_reads: dict[tuple[str, int], int] = {}
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
        parent_uuid = self.process_track(
            int(record.get("tgid", 0)), str(record.get("task", ""))
        )
        uuid = stable_uuid("socket", socket_id)
        self.descriptor(uuid, f"socket {socket_id[-8:]}", parent_uuid)
        self.socket_tracks[socket_id] = uuid
        return uuid

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
        packet_record = dict(record)
        packet_record["flow_tag"] = flow_tag(id_value(str(record["flow_id"])))
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
            correlation_id=id_value(str(record["flow_id"])),
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
                ),
            ),
        )

    def export_rx_read_start(self, record: dict[str, Any]) -> None:
        key = (str(record["stage"]), int(record["tid"]))
        track = self.thread_track(record)
        if key in self.pending_reads:
            self.event(
                int(record["ts_ns"]),
                self.pending_reads[key],
                TrackEvent.TYPE_SLICE_END,
                category="anettrace.rx.read",
            )
        self.event(
            int(record["ts_ns"]),
            track,
            TrackEvent.TYPE_SLICE_BEGIN,
            str(record["stage"]),
            "anettrace.rx.read",
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
        self.pending_reads[key] = track

    def export_rx_read_end(self, record: dict[str, Any]) -> None:
        key = (str(record["stage"]), int(record["tid"]))
        track = self.pending_reads.pop(key, None)
        if track is None:
            return
        self.event(
            int(record["ts_ns"]),
            track,
            TrackEvent.TYPE_SLICE_END,
            category="anettrace.rx.read",
            annotations=(record, ("result", "bytes", "error", "incomplete")),
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
            elif record_type == "socket_event":
                self.export_socket_event(record)
            elif record_type == "packet_event":
                self.export_packet_event(record)
            elif record_type == "rx_read_start":
                self.export_rx_read_start(record)
            elif record_type == "rx_read_end":
                self.export_rx_read_end(record)
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
                    for track in tuple(self.pending_reads.values()):
                        self.event(
                            int(record["ts_ns"]),
                            track,
                            TrackEvent.TYPE_SLICE_END,
                            category="anettrace.rx.read",
                        )
                    self.pending_reads.clear()
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
