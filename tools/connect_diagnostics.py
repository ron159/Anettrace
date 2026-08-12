#!/usr/bin/env python3
"""Classify bounded Anettrace TCP connect event streams."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


EVENT_SCHEMA = "anettrace.perfetto.v1"
REPORT_SCHEMA = "anettrace.connect-diagnostics.v1"

OUTCOMES = (
    "success",
    "local_rejection",
    "network_unreachable",
    "peer_refused",
    "timeout_no_response",
    "kernel_drop",
    "interrupted_or_cancelled",
    "incomplete_or_unknown",
)

# Event errno values come from Linux/Android. Do not use the host Python errno
# module here: Darwin and Linux assign different numbers to many socket errors.
LINUX_ERRNO_NAMES = {
    1: "EPERM",
    4: "EINTR",
    9: "EBADF",
    12: "ENOMEM",
    13: "EACCES",
    22: "EINVAL",
    23: "ENFILE",
    24: "EMFILE",
    88: "ENOTSOCK",
    91: "EPROTOTYPE",
    97: "EAFNOSUPPORT",
    98: "EADDRINUSE",
    99: "EADDRNOTAVAIL",
    100: "ENETDOWN",
    101: "ENETUNREACH",
    104: "ECONNRESET",
    105: "ENOBUFS",
    110: "ETIMEDOUT",
    111: "ECONNREFUSED",
    112: "EHOSTDOWN",
    113: "EHOSTUNREACH",
    114: "EALREADY",
    115: "EINPROGRESS",
    125: "ECANCELED",
}

LINUX_EINTR = 4
LINUX_ECONNRESET = 104
LINUX_ETIMEDOUT = 110
LINUX_ECONNREFUSED = 111
LINUX_EALREADY = 114
LINUX_EINPROGRESS = 115
LINUX_ECANCELED = 125

LOCAL_REJECTION_ERRNOS = frozenset((1, 9, 12, 13, 22, 23, 24, 88, 91, 97, 98, 99, 105))
NETWORK_UNREACHABLE_ERRNOS = frozenset((100, 101, 112, 113))
INTERRUPTED_ERRNOS = frozenset((LINUX_EINTR, LINUX_ECANCELED))


class ConnectDiagnosticsError(ValueError):
    """Raised when the event contract is malformed."""


def read_event_records(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise ConnectDiagnosticsError(
                    f"{path}:{line_number}: invalid JSON: {error}"
                ) from error
            if record.get("schema") != EVENT_SCHEMA:
                raise ConnectDiagnosticsError(
                    f"{path}:{line_number}: unsupported schema "
                    f"{record.get('schema')!r}"
                )
            records.append(record)
    return records


def anonymous_application_id(report_id: str, uid: int) -> str:
    return hashlib.blake2b(
        f"{report_id}\0application\0{uid}".encode(), digest_size=8
    ).hexdigest()


def errno_record(number: int | None) -> dict[str, Any] | None:
    if number is None:
        return None
    return {"number": number, "name": LINUX_ERRNO_NAMES.get(number, "UNKNOWN")}


@dataclass
class Attempt:
    attempt_id: str
    uid: int
    tid: int
    tgid: int
    fd: int
    started_ns: int
    task: str = ""
    socket_instance_id: str | None = None
    ended_ns: int | None = None
    result: int | None = None
    error: int | None = None
    async_pending: bool = False
    so_error: int | None = None
    established: bool = False
    state: str = ""
    reset_while_connecting: bool = False
    exact_drop: bool = False
    cancelled: bool = False
    endpoint: dict[str, Any] = field(
        default_factory=lambda: {
            "local_addr": "",
            "local_port": 0,
            "remote_addr": "",
            "remote_port": 0,
        }
    )
    evidence: list[dict[str, Any]] = field(default_factory=list)
    retransmissions: int = 0
    rtt_samples: list[int] = field(default_factory=list)
    sched_delays: list[int] = field(default_factory=list)

    def add_evidence(self, record: dict[str, Any], evidence_type: str) -> None:
        evidence = {
            key: value
            for key, value in record.items()
            if key not in ("schema", "type", "task")
        }
        evidence["type"] = evidence_type
        evidence.setdefault("ts_ns", self.started_ns)
        self.evidence.append(evidence)

    def effective_error(self) -> int | None:
        if self.so_error not in (None, 0):
            return self.so_error
        if self.error not in (None, 0, LINUX_EINPROGRESS, LINUX_EALREADY):
            return self.error
        return None

    def classify(self, report_status: str, trace_end_ns: int) -> tuple[str, str]:
        if report_status == "invalid":
            return "incomplete_or_unknown", "insufficient"

        if self.exact_drop:
            return "kernel_drop", "direct"

        effective_error = self.effective_error()
        if effective_error in LOCAL_REJECTION_ERRNOS:
            return "local_rejection", "direct"
        if effective_error in NETWORK_UNREACHABLE_ERRNOS:
            return "network_unreachable", "direct"
        if effective_error in (LINUX_ECONNRESET, LINUX_ECONNREFUSED):
            return "peer_refused", "direct"
        if effective_error == LINUX_ETIMEDOUT:
            return "timeout_no_response", "direct"
        if effective_error in INTERRUPTED_ERRNOS:
            return "interrupted_or_cancelled", "direct"
        if effective_error is not None:
            return "incomplete_or_unknown", "insufficient"

        if self.reset_while_connecting:
            return "peer_refused", "correlated"
        if self.cancelled:
            return "interrupted_or_cancelled", "correlated"
        if self.result == 0:
            return "success", "direct"
        if self.async_pending and self.so_error == 0 and self.established:
            return "success", "correlated"

        if self.ended_ns is None:
            self.ended_ns = trace_end_ns
        return "incomplete_or_unknown", "insufficient"

    def report(self, report_status: str, trace_end_ns: int) -> dict[str, Any]:
        outcome, strength = self.classify(report_status, trace_end_ns)
        end_ns = self.ended_ns if self.ended_ns is not None else trace_end_ns
        effective_error = self.effective_error()
        factors: list[str] = []
        if self.retransmissions:
            factors.append("tcp_retransmission")
        if self.rtt_samples:
            factors.append("rtt_observed")
        if self.sched_delays:
            factors.append("scheduler_delay_observed")
        return {
            "attempt_id": self.attempt_id,
            "socket_instance_id": self.socket_instance_id,
            "uid": self.uid,
            "tid": self.tid,
            "tgid": self.tgid,
            "fd": self.fd,
            "started_ns": self.started_ns,
            "ended_ns": end_ns,
            "duration_ns": max(0, end_ns - self.started_ns),
            "outcome": outcome,
            "evidence_strength": strength,
            "errno": errno_record(effective_error),
            "endpoint": dict(self.endpoint),
            "evidence": list(self.evidence),
            "contributing_factors": factors,
        }


def _record_attempt(
    record: dict[str, Any],
    attempts: dict[str, Attempt],
    sockets: dict[str, Attempt],
) -> Attempt | None:
    attempt_id = str(record.get("attempt_id", ""))
    if attempt_id:
        return attempts.get(attempt_id)
    socket_id = str(
        record.get("socket_instance_id")
        or record.get("owner_socket_id")
        or record.get("socket_id")
        or ""
    )
    return sockets.get(socket_id) if socket_id else None


def _update_endpoint(attempt: Attempt, record: dict[str, Any]) -> None:
    aliases = {
        "local_addr": ("local_addr", "saddr"),
        "local_port": ("local_port", "sport"),
        "remote_addr": ("remote_addr", "daddr"),
        "remote_port": ("remote_port", "dport"),
    }
    for target, names in aliases.items():
        for name in names:
            value = record.get(name)
            if value not in (None, "", 0):
                attempt.endpoint[target] = value
                break


def build_attempts(records: Sequence[dict[str, Any]]) -> tuple[list[Attempt], int, int]:
    attempts: dict[str, Attempt] = {}
    sockets: dict[str, Attempt] = {}
    capture_start_ns = 0
    capture_end_ns = 0

    for record in records:
        record_type = record.get("type")
        if record_type == "clock_snapshot" and not capture_start_ns:
            capture_start_ns = int(record.get("monotonic_ns", 0))
        if record_type == "connect_attempt_start":
            attempt_id = str(record["attempt_id"])
            if attempt_id in attempts:
                raise ConnectDiagnosticsError(f"duplicate attempt_id: {attempt_id}")
            attempt = Attempt(
                attempt_id=attempt_id,
                uid=int(record["uid"]),
                tid=int(record["tid"]),
                tgid=int(record["tgid"]),
                fd=int(record["fd"]),
                started_ns=int(record["ts_ns"]),
                task=str(record.get("task", "")),
            )
            _update_endpoint(attempt, record)
            attempt.add_evidence(record, "connect_attempt_start")
            attempts[attempt_id] = attempt
            continue

        attempt = _record_attempt(record, attempts, sockets)
        if attempt is None:
            if record_type == "trace_end":
                capture_end_ns = int(record.get("ts_ns", 0))
            continue

        if record_type == "connect_socket":
            socket_id = str(record["socket_instance_id"])
            previous = sockets.get(socket_id)
            if previous is not None and previous is not attempt:
                raise ConnectDiagnosticsError(
                    f"socket instance {socket_id} belongs to multiple attempts"
                )
            attempt.socket_instance_id = socket_id
            sockets[socket_id] = attempt
            _update_endpoint(attempt, record)
            attempt.add_evidence(record, "connect_socket")
        elif record_type == "connect_attempt_end":
            attempt.ended_ns = int(record["ts_ns"])
            attempt.result = int(record["result"])
            attempt.error = int(record.get("error", 0))
            attempt.async_pending = bool(record.get("async_pending", False))
            attempt.add_evidence(record, "connect_attempt_end")
        elif record_type == "connect_so_error":
            attempt.so_error = int(record["error"])
            attempt.add_evidence(record, "connect_so_error")
        elif record_type == "socket_state":
            state_before = attempt.state
            attempt.state = str(record.get("new_state_name", ""))
            attempt.established = attempt.established or attempt.state == "ESTABLISHED"
            attempt.add_evidence(record, "socket_state")
            if record.get("tcp_rst") and state_before == "SYN_SENT":
                attempt.reset_while_connecting = True
        elif record_type == "connect_reset":
            attempt.reset_while_connecting = bool(
                record.get("exact", False)
                and str(record.get("state", attempt.state)) == "SYN_SENT"
            )
            attempt.add_evidence(record, "connect_reset")
        elif record_type == "connect_drop":
            attempt.exact_drop = bool(record.get("exact", False))
            attempt.add_evidence(record, "connect_drop")
        elif record_type == "connect_retransmit":
            attempt.retransmissions += max(1, int(record.get("count", 1)))
            attempt.add_evidence(record, "connect_retransmit")
        elif record_type == "connect_rtt":
            attempt.rtt_samples.append(int(record["rtt_us"]))
            attempt.add_evidence(record, "connect_rtt")
        elif record_type == "connect_sched_delay":
            attempt.sched_delays.append(int(record["delay_ns"]))
            attempt.add_evidence(record, "connect_sched_delay")
        elif record_type == "connect_cancel":
            attempt.cancelled = bool(record.get("exact", False))
            attempt.add_evidence(record, "connect_cancel")
        elif record_type == "socket_event":
            stage = str(record.get("stage", ""))
            if stage in (
                "tcp_v4_send_reset",
                "tcp_v6_send_reset",
                "tcp_send_active_reset",
            ):
                attempt.reset_while_connecting = bool(
                    record.get("state_name", attempt.state) == "SYN_SENT"
                    or attempt.state == "SYN_SENT"
                )
                attempt.add_evidence(record, "connect_reset")
            elif stage in ("tcp_retransmit_skb", "__tcp_retransmit_skb"):
                attempt.retransmissions += 1
                attempt.add_evidence(record, "connect_retransmit")
            elif stage == "tcp_ack_update_rtt" and "first_rtt_us" in record:
                attempt.rtt_samples.append(int(record["first_rtt_us"]))
                attempt.add_evidence(record, "connect_rtt")
            elif stage in ("tcp_close", "tcp_v4_destroy_sock"):
                if attempt.async_pending and not attempt.established:
                    attempt.cancelled = True
                    attempt.add_evidence(record, "connect_cancel")
        elif record_type == "packet_event":
            tcp_flags = int(record.get("tcp_flags", 0))
            is_connect_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
            if (
                record.get("dropped")
                and str(record.get("stage", "")) == "kfree_skb"
                and is_connect_syn
            ):
                attempt.exact_drop = True
                attempt.add_evidence(record, "connect_drop")

    if not capture_start_ns and attempts:
        capture_start_ns = min(attempt.started_ns for attempt in attempts.values())
    if not capture_end_ns:
        ended = [attempt.ended_ns for attempt in attempts.values() if attempt.ended_ns]
        capture_end_ns = max(ended, default=capture_start_ns)
    return sorted(attempts.values(), key=lambda item: item.started_ns), capture_start_ns, capture_end_ns


def analyze_records(
    records: Sequence[dict[str, Any]],
    *,
    report_id: str,
    uid: int,
    profile: str = "sched",
    package: str | None = None,
    shared_uid_candidates: Sequence[str] = (),
    requested_status: str = "valid",
    generated_at_utc: str | None = None,
) -> dict[str, Any]:
    if requested_status not in ("valid", "degraded", "invalid"):
        raise ConnectDiagnosticsError(f"invalid report status: {requested_status}")
    if profile not in ("sched", "full"):
        raise ConnectDiagnosticsError(f"invalid profile: {profile}")

    attempts, capture_start_ns, capture_end_ns = build_attempts(records)
    trace_end = next(
        (record for record in reversed(records) if record.get("type") == "trace_end"),
        None,
    )
    warnings: list[str] = []
    errors: list[str] = []
    status = requested_status
    lost_events = int(trace_end.get("lost_events", 0)) if trace_end else 0
    truncated = bool(trace_end.get("truncated", False)) if trace_end else False
    if trace_end is None:
        status = "invalid"
        errors.append("event stream has no trace_end record")
    elif status != "invalid" and (lost_events or truncated):
        status = "degraded"
        if lost_events:
            warnings.append(f"event stream lost {lost_events} events")
        if truncated:
            warnings.append("capture reached a configured resource limit")

    attempt_reports = [attempt.report(status, capture_end_ns) for attempt in attempts]
    outcome_counts = Counter(item["outcome"] for item in attempt_reports)
    candidates = sorted(set(shared_uid_candidates))
    if len(candidates) > 1:
        warnings.append("target UID is shared by multiple packages")

    target: dict[str, Any] = {
        "uid": uid,
        "application_id": anonymous_application_id(report_id, uid),
        "package_included": package is not None,
        "shared_uid_ambiguous": len(candidates) > 1,
    }
    if package is not None:
        target["package"] = package
        target["shared_uid_candidates"] = candidates

    return {
        "schema_version": REPORT_SCHEMA,
        "report_id": report_id,
        "generated_at_utc": generated_at_utc
        or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "status": status,
        "summary": {
            "attempt_count": len(attempt_reports),
            "outcome_counts": dict(sorted(outcome_counts.items())),
        },
        "target": target,
        "capture": {
            "profile": profile,
            "started_ns": capture_start_ns,
            "ended_ns": capture_end_ns,
            "lost_events": lost_events,
            "truncated": truncated,
        },
        "attempts": attempt_reports,
        "warnings": warnings,
        "errors": errors,
    }


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Anettrace TCP connect diagnostics",
        "",
        f"- Report ID: `{report['report_id']}`",
        f"- Status: `{report['status']}`",
        f"- Attempts: {report['summary']['attempt_count']}",
        "",
        "## Attempts",
        "",
    ]
    if not report["attempts"]:
        lines.append("No TCP connect attempts were observed.")
    for attempt in report["attempts"]:
        endpoint = attempt["endpoint"]
        error = attempt["errno"]
        lines.extend(
            [
                f"### `{attempt['attempt_id']}`",
                "",
                f"- Outcome: `{attempt['outcome']}`",
                f"- Evidence: `{attempt['evidence_strength']}`",
                f"- Duration: {attempt['duration_ns']} ns",
                f"- Endpoint: `{endpoint['remote_addr']}:{endpoint['remote_port']}`",
                f"- Errno: `{error['name']} ({error['number']})`" if error else "- Errno: none",
                "",
            ]
        )
    if report["warnings"]:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {warning}" for warning in report["warnings"])
        lines.append("")
    if report["errors"]:
        lines.extend(["## Errors", ""])
        lines.extend(f"- {error}" for error in report["errors"])
        lines.append("")
    lines.extend(
        [
            "## Perfetto",
            "",
            "Open `trace.pftrace` and filter for the attempt or socket ID above.",
            "",
            "This report contains sensitive network metadata. Review it before sharing.",
            "",
        ]
    )
    return "\n".join(lines)


def write_report(report: dict[str, Any], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    output_dir.chmod(0o700)
    report_json = output_dir / "report.json"
    report_markdown = output_dir / "report.md"
    report_json.write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    report_markdown.write_text(render_markdown(report), encoding="utf-8")
    report_json.chmod(0o600)
    report_markdown.chmod(0o600)
