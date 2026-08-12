#!/usr/bin/env python3
"""Run one bounded Android TCP connect diagnostic session."""

from __future__ import annotations

import argparse
import base64
import csv
import importlib.util
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
VERSION = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
MANIFEST_SCHEMA = "anettrace.connect-diagnostics.manifest.v1"
DEFAULT_DURATION_S = 120
DEFAULT_MAX_REPORT_MIB = 512
CONNECT_METRICS_SQL = ROOT / "tools" / "perfetto_sql" / "connect_diagnostics_metrics.sql"


def load_tool(name: str):
    path = TOOLS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if not spec or not spec.loader:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


CAPTURE = load_tool("capture_android_trace")
ANALYZER = load_tool("connect_diagnostics")


class DiagnosticError(RuntimeError):
    """A user-facing diagnostic orchestration failure."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def private_write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def prepare_output_dir(path: Path) -> Path:
    path = path.resolve()
    if path.exists() and any(path.iterdir()):
        raise DiagnosticError(f"output directory is not empty: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.chmod(0o700)
    return path


def run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command), check=check, text=True, capture_output=True
        )
    except FileNotFoundError as error:
        raise DiagnosticError(f"command not found: {command[0]}") from error
    except subprocess.CalledProcessError as error:
        detail = (error.stderr or error.stdout or "").strip()
        raise DiagnosticError(
            f"command failed ({error.returncode}): {' '.join(command)}"
            + (f": {detail}" if detail else "")
        ) from error


def repository_commit() -> str | None:
    identity = ROOT / "SOURCE_COMMIT"
    if identity.is_file():
        try:
            value = identity.read_text(encoding="utf-8").strip()
        except OSError as error:
            raise DiagnosticError(f"cannot read SOURCE_COMMIT: {error}") from error
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise DiagnosticError("SOURCE_COMMIT is not a full Git object ID")
        return value
    result = run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"], check=False
    )
    value = result.stdout.strip() if result.returncode == 0 else ""
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        return None
    status = run(
        [
            "git",
            "-C",
            str(ROOT),
            "status",
            "--porcelain",
            "--untracked-files=no",
        ],
        check=False,
    )
    if status.returncode != 0:
        return None
    if status.stdout.strip():
        raise DiagnosticError(
            "host tools checkout has tracked changes; commit and rebuild first"
        )
    return value


def resolve_trace_processor(explicit: Path | None) -> Path:
    candidate = explicit
    if candidate is None:
        found = shutil.which("trace_processor") or shutil.which("trace_processor_shell")
        candidate = Path(found) if found else None
    if candidate is None or not candidate.is_file():
        raise DiagnosticError(
            "Trace Processor is required; use --trace-processor or add it to PATH"
        )
    return candidate.resolve()


def tool_record(path: Path, *, version_args: Sequence[str]) -> dict[str, Any]:
    result = run([str(path), *version_args], check=False)
    if result.returncode != 0:
        raise DiagnosticError(f"cannot execute {path} for version validation")
    version = (result.stdout or result.stderr).strip().splitlines()
    return {
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": CAPTURE.sha256_file(path),
        "version": version[0] if version else "unknown",
    }


def validate_local_inputs(binary: Path, trace_processor: Path) -> dict[str, Any]:
    if not binary.is_file():
        raise DiagnosticError(f"Anettrace binary does not exist: {binary}")
    file_result = run(["file", str(binary)], check=False)
    if file_result.returncode != 0 or not re.search(
        r"(ARM aarch64|AArch64)", file_result.stdout, re.IGNORECASE
    ):
        raise DiagnosticError("Anettrace binary is not an AArch64 executable")
    if importlib.util.find_spec("perfetto") is None:
        raise DiagnosticError(
            "Python package perfetto==0.57.2 is required; runtime download is disabled"
        )
    return {
        "binary": {
            "name": binary.name,
            "size": binary.stat().st_size,
            "sha256": CAPTURE.sha256_file(binary),
            "file": file_result.stdout.strip(),
        },
        "trace_processor": tool_record(trace_processor, version_args=("--version",)),
    }


def device_value(adb: Any, script: str) -> str:
    result = adb.shell(script, check=False)
    return result.stdout.strip().replace("\r", "") if result.returncode == 0 else ""


def capability(adb: Any, script: str) -> bool:
    return adb.shell(script, check=False).returncode == 0


def _protobuf_varint(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(data):
            raise DiagnosticError("truncated Perfetto service-state protobuf")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise DiagnosticError("invalid Perfetto service-state protobuf varint")


def parse_perfetto_service_state(data: bytes) -> dict[str, Any]:
    values: dict[int, int] = {}
    offset = 0
    while offset < len(data):
        key, offset = _protobuf_varint(data, offset)
        field = key >> 3
        wire_type = key & 7
        if not field:
            raise DiagnosticError("invalid Perfetto service-state protobuf field")
        if wire_type == 0:
            value, offset = _protobuf_varint(data, offset)
            if field in (3, 4, 7):
                values[field] = value
        elif wire_type == 1:
            offset += 8
        elif wire_type == 2:
            size, offset = _protobuf_varint(data, offset)
            offset += size
        elif wire_type == 5:
            offset += 4
        else:
            raise DiagnosticError(
                f"unsupported Perfetto service-state wire type: {wire_type}"
            )
        if offset > len(data):
            raise DiagnosticError("truncated Perfetto service-state protobuf field")
    if values.get(7) != 1 or 3 not in values or 4 not in values:
        raise DiagnosticError("Perfetto cannot report active tracing sessions")
    return {
        "supports_tracing_sessions": True,
        "session_count": values[3],
        "started_session_count": values[4],
    }


def query_perfetto_service_state(adb: Any) -> dict[str, Any]:
    result = adb.shell("perfetto --query-raw | base64", check=False)
    if result.returncode != 0:
        raise DiagnosticError("Perfetto service-state query failed")
    encoded = "".join(result.stdout.split())
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise DiagnosticError("Perfetto service-state query was not valid base64") from error
    if not raw:
        raise DiagnosticError("Perfetto service-state query returned no data")
    return parse_perfetto_service_state(raw)


def resolve_package(adb: Any, package: str, include_package: bool) -> tuple[int, list[str], int]:
    if not re.fullmatch(r"[A-Za-z0-9._:]+", package):
        raise DiagnosticError("invalid Android package name")
    output = device_value(
        adb, f"cmd package list packages -U {shlex.quote(package)}"
    )
    matches = re.findall(r"package:([^\s]+)\s+uid:([0-9]+)", output)
    exact = [(name, int(uid)) for name, uid in matches if name == package]
    if len(exact) != 1:
        raise DiagnosticError(f"package is not installed or is ambiguous: {package}")
    uid = exact[0][1]
    candidate_output = device_value(
        adb, f"cmd package list packages -U --uid {uid}"
    )
    candidate_matches = re.findall(
        rf"package:([^\s]+)\s+uid:{uid}(?:\s|$)", candidate_output
    )
    candidates = sorted(set(candidate_matches))
    candidate_count = len(candidates)
    if package not in candidates or candidate_count < 1:
        raise DiagnosticError("cannot determine shared UID ambiguity")
    if not include_package:
        candidates = []
    return uid, candidates, candidate_count


def device_preflight(
    adb: Any,
    binary: Path,
    package: str,
    include_package: bool,
    profile: str,
    source_commit: str | None = None,
) -> tuple[dict[str, Any], int, list[str], int, list[str]]:
    if adb.run("get-state").stdout.strip() != "device":
        raise DiagnosticError("Android device is not ready")
    if device_value(adb, "id -u") != "0":
        raise DiagnosticError(
            "device shell must run as root; use an explicit --root-command if needed"
        )

    current_tracer = device_value(adb, "cat /sys/kernel/tracing/current_tracer")
    checks = {
        "root_adb_shell": True,
        "btf_vmlinux": capability(adb, "test -r /sys/kernel/btf/vmlinux"),
        "tracefs": capability(adb, "test -d /sys/kernel/tracing/events"),
        "current_tracer_nop": current_tracer == "nop",
        "global_trace_events_idle": capability(
            adb,
            "test \"$(cat /sys/kernel/tracing/tracing_on)\" != 1 || "
            "test -z \"$(cat /sys/kernel/tracing/set_event)\"",
        ),
        "trace_instances_idle": capability(
            adb,
            "for trace_instance in /sys/kernel/tracing/instances/*; do "
            "test -d \"$trace_instance\" || continue; "
            "test \"$(cat \"$trace_instance/tracing_on\")\" != 1 || "
            "{ test \"$(cat \"$trace_instance/current_tracer\")\" = nop && "
            "test -z \"$(cat \"$trace_instance/set_event\")\"; } || exit 1; "
            "done",
        ),
        "perfetto": capability(adb, "test -x /system/bin/perfetto"),
        "base64": capability(adb, "test -x /system/bin/base64"),
        "raw_syscalls_enter": capability(
            adb, "test -r /sys/kernel/tracing/events/raw_syscalls/sys_enter/format"
        ),
        "raw_syscalls_exit": capability(
            adb, "test -r /sys/kernel/tracing/events/raw_syscalls/sys_exit/format"
        ),
        "socket_state": capability(
            adb, "test -r /sys/kernel/tracing/events/sock/inet_sock_set_state/format"
        ),
        "tcp_retransmit": capability(
            adb, "test -r /sys/kernel/tracing/events/tcp/tcp_retransmit_skb/format"
        ),
        "skb_drop": capability(
            adb, "test -r /sys/kernel/tracing/events/skb/kfree_skb/format"
        ),
        "sched_switch": capability(
            adb, "test -r /sys/kernel/tracing/events/sched/sched_switch/format"
        ),
        "inet_stream_connect_symbol": capability(
            adb, "grep -q -w inet_stream_connect /proc/kallsyms"
        ),
        "sk_alloc_symbol": capability(adb, "grep -q -w sk_alloc /proc/kallsyms"),
        "inet_stream_connect_kprobe_allowed": capability(
            adb,
            "test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w inet_stream_connect /sys/kernel/debug/kprobes/blacklist",
        ),
        "sk_alloc_kprobe_allowed": capability(
            adb,
            "test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w sk_alloc /sys/kernel/debug/kprobes/blacklist",
        ),
        "kprobe_events_writable": capability(
            adb, "test -w /sys/kernel/tracing/kprobe_events"
        ),
        "toybox_timeout": capability(adb, "toybox timeout --help >/dev/null 2>&1"),
        "file_ulimit": capability(adb, "sh -c 'ulimit -f' >/dev/null 2>&1"),
        "tcp_close_symbol": capability(adb, "grep -q -w tcp_close /proc/kallsyms"),
        "tcp_close_kprobe_allowed": capability(
            adb,
            "test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w tcp_close /sys/kernel/debug/kprobes/blacklist",
        ),
        "tcp_ack_update_rtt_symbol": capability(
            adb, "grep -q -w tcp_ack_update_rtt /proc/kallsyms"
        ),
        "tcp_ack_update_rtt_kprobe_allowed": capability(
            adb,
            "grep -q -w tcp_ack_update_rtt /proc/kallsyms && "
            "(test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w tcp_ack_update_rtt /sys/kernel/debug/kprobes/blacklist)",
        ),
        "tcp_tx_kprobe_allowed": capability(
            adb,
            "grep -q -w __tcp_transmit_skb /proc/kallsyms && "
            "(test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w __tcp_transmit_skb /sys/kernel/debug/kprobes/blacklist)",
        ),
        "tcp_v4_rx_kprobe_allowed": capability(
            adb,
            "grep -q -w tcp_v4_rcv /proc/kallsyms && "
            "(test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w tcp_v4_rcv /sys/kernel/debug/kprobes/blacklist)",
        ),
        "tcp_v6_rx_kprobe_allowed": capability(
            adb,
            "grep -q -w tcp_v6_rcv /proc/kallsyms && "
            "(test ! -r /sys/kernel/debug/kprobes/blacklist || "
            "! grep -q -w tcp_v6_rcv /sys/kernel/debug/kprobes/blacklist)",
        ),
    }
    perfetto_service_state: dict[str, Any] = {}
    if checks["perfetto"] and checks["base64"]:
        perfetto_service_state = query_perfetto_service_state(adb)
    checks["perfetto_session_query"] = bool(perfetto_service_state)
    checks["perfetto_no_active_sessions"] = (
        perfetto_service_state.get("started_session_count") == 0
    )
    required = (
        "root_adb_shell",
        "btf_vmlinux",
        "tracefs",
        "current_tracer_nop",
        "global_trace_events_idle",
        "trace_instances_idle",
        "perfetto",
        "base64",
        "perfetto_session_query",
        "perfetto_no_active_sessions",
        "raw_syscalls_enter",
        "raw_syscalls_exit",
        "socket_state",
        "inet_stream_connect_symbol",
        "inet_stream_connect_kprobe_allowed",
        "sk_alloc_symbol",
        "sk_alloc_kprobe_allowed",
        "tcp_close_symbol",
        "tcp_close_kprobe_allowed",
        "kprobe_events_writable",
        "toybox_timeout",
        "file_ulimit",
    )
    if profile in ("sched", "full"):
        required += ("sched_switch",)
    missing_required = [name for name in required if not checks[name]]
    if missing_required:
        conflict_detail = ""
        if not checks["perfetto_no_active_sessions"] and perfetto_service_state:
            conflict_detail = (
                "; started Perfetto sessions: "
                + str(perfetto_service_state["started_session_count"])
                + "; existing tracing is not modified"
            )
        raise DiagnosticError(
            "missing core device capabilities: "
            + ", ".join(missing_required)
            + conflict_detail
        )
    optional = tuple(name for name in checks if name not in required)
    missing_optional = [name for name in optional if not checks[name]]

    uid, candidates, candidate_count = resolve_package(adb, package, include_package)
    session = uuid.uuid4().hex[:12]
    remote_dir = f"/data/local/tmp/anettrace-preflight-{session}"
    remote_binary = f"{remote_dir}/anettrace"
    try:
        adb.shell(
            f"mkdir -p {shlex.quote(remote_dir)} && chmod 0700 {shlex.quote(remote_dir)}"
        )
        adb.push(binary, remote_binary)
        adb.shell(f"chmod 0700 {shlex.quote(remote_binary)}")
        version_result = adb.shell(f"{shlex.quote(remote_binary)} --version", check=False)
        version_text = (version_result.stdout or version_result.stderr).strip()
        if version_result.returncode != 0 or f"Anettrace {VERSION}" not in version_text:
            raise DiagnosticError(
                f"device binary version does not match VERSION {VERSION}"
            )
        commit = source_commit or repository_commit()
        if not commit:
            raise DiagnosticError("host tools have no verifiable source commit identity")
        if f"commit {commit}" not in version_text:
            raise DiagnosticError("device binary Git commit does not match this checkout")
    finally:
        adb.shell(f"rm -rf {shlex.quote(remote_dir)}", check=False)

    device = {
        "product": device_value(adb, "getprop ro.product.device"),
        "android_release": device_value(adb, "getprop ro.build.version.release"),
        "sdk": device_value(adb, "getprop ro.build.version.sdk"),
        "architecture": device_value(adb, "uname -m"),
        "kernel_release": device_value(adb, "uname -r"),
        "selinux": device_value(adb, "getenforce"),
        "capabilities": checks,
        "missing_optional_capabilities": missing_optional,
        "existing_tracing": {
            "tracing_on": device_value(adb, "cat /sys/kernel/tracing/tracing_on"),
            "current_tracer": current_tracer,
            "perfetto": perfetto_service_state,
        },
    }
    return device, uid, candidates, candidate_count, missing_optional


def capture_args(
    args: argparse.Namespace,
    uid: int,
    capture_dir: Path,
    trace_processor: Path,
) -> argparse.Namespace:
    values = [
        "--uid",
        str(uid),
        "--connect-diagnostics",
        "--profile",
        args.profile,
        "--duration",
        str(args.duration),
        "--out",
        str(capture_dir),
        "--anettrace",
        str(args.binary.resolve()),
        "--adb",
        args.adb,
        "--trace-processor",
        str(trace_processor),
        "--max-device-file-mib",
        str(max(1, args.max_report_mib // 2)),
        "--redact-device-metadata",
    ]
    if args.device:
        values.extend(("--device", args.device))
    if args.root_command:
        values.extend(("--root-command", args.root_command))
    if args.keep_device_artifacts:
        values.append("--keep-remote")
    if args.resource_sample_interval:
        values.extend(
            ("--resource-sample-interval", str(args.resource_sample_interval))
        )
    if args.external_command:
        values.append("--external-command")
        values.extend(args.external_command)
    return CAPTURE.parse_args(values)


def redacted_session_log(capture_dir: Path, secrets: Sequence[str]) -> str:
    chunks: list[str] = []
    for name in ("anettrace.log", "perfetto.log", "external-command.log"):
        path = capture_dir / name
        if path.is_file():
            chunks.append(f"[{name}]\n{path.read_text(encoding='utf-8', errors='replace')}")
    text = "\n".join(chunks) or "No device log was available.\n"
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def query_connect_metrics(
    trace_processor: Path, trace: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    result = run(
        [
            str(trace_processor),
            "--query-file",
            str(CONNECT_METRICS_SQL),
            str(trace),
        ]
    )
    records: list[dict[str, Any]] = []
    rows = list(csv.DictReader(result.stdout.splitlines()))
    for row in rows:
        attempt_id = str(row.get("attempt_id", ""))
        if not re.fullmatch(r"[0-9a-f]{16,64}", attempt_id):
            raise DiagnosticError("Trace Processor returned an invalid attempt ID")
        runnable_delay_ns = int(row.get("runnable_delay_ns") or 0)
        if runnable_delay_ns > 0:
            records.append(
                {
                    "schema": ANALYZER.EVENT_SCHEMA,
                    "type": "connect_sched_delay",
                    "ts_ns": int(row["started_ns"]),
                    "attempt_id": attempt_id,
                    "delay_ns": runnable_delay_ns,
                    "running_ns": int(row.get("running_ns") or 0),
                }
            )
        process_exit_ns = int(row.get("process_exit_ns") or 0)
        if process_exit_ns > 0:
            records.append(
                {
                    "schema": ANALYZER.EVENT_SCHEMA,
                    "type": "connect_cancel",
                    "ts_ns": process_exit_ns,
                    "attempt_id": attempt_id,
                    "exact": True,
                    "reason": "process_exit",
                }
            )
    return records, {
        "query": str(CONNECT_METRICS_SQL.relative_to(ROOT)),
        "attempt_rows": len(rows),
        "derived_events": len(records),
    }


def redact_failure(error: object, args: argparse.Namespace) -> str:
    text = str(error)
    secrets = [args.device]
    if not args.include_package:
        secrets.append(args.package)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def redacted_messages(values: Sequence[object], args: argparse.Namespace) -> list[str]:
    return [redact_failure(value, args) for value in values]


def recovery_paths(session_id: str) -> tuple[str, ...]:
    if not re.fullmatch(r"[0-9a-f]{12}", session_id):
        raise DiagnosticError("recovery session ID must be 12 lowercase hex characters")
    remote_dir = f"/data/local/tmp/anettrace-capture-{session_id}"
    return (
        remote_dir,
        f"/data/misc/perfetto-configs/anettrace-capture-{session_id}.pbtxt",
        f"/data/misc/perfetto-traces/anettrace-capture-{session_id}.pftrace",
    )


def recover_session(args: argparse.Namespace) -> str:
    remote_dir, remote_config, remote_trace = recovery_paths(args.recover_session)
    adb = CAPTURE.Adb(args.adb, args.device, args.root_command)
    if adb.run("get-state").stdout.strip() != "device":
        raise DiagnosticError("Android device is not ready")
    if device_value(adb, "id -u") != "0":
        raise DiagnosticError(
            "device shell must run as root; use an explicit --root-command if needed"
        )

    if args.recover_action == "cleanup":
        adb.shell(f"rm -rf {shlex.quote(remote_dir)}")
        adb.shell(
            f"rm -f {shlex.quote(remote_config)} {shlex.quote(remote_trace)}"
        )
        return f"cleaned recovery session {args.recover_session}"

    remote_files = (
        f"{remote_dir}/anettrace-events.jsonl",
        f"{remote_dir}/anettrace.log",
        f"{remote_dir}/perfetto.log",
        remote_config,
        remote_trace,
    )
    existing = [
        path for path in remote_files if capability(adb, f"test -e {shlex.quote(path)}")
    ]
    if args.recover_action == "inspect":
        rows = []
        for path in existing:
            size = device_value(adb, f"stat -c %s {shlex.quote(path)}") or "unknown"
            rows.append(f"{Path(path).name}\t{size}")
        return "\n".join(rows) if rows else "no recovery artifacts found"

    if args.out is None:
        raise DiagnosticError("--out is required for recovery pull")
    output = prepare_output_dir(args.out)
    for path in existing:
        destination = output / Path(path).name
        adb.pull(path, destination)
        destination.chmod(0o600)
    private_write(
        output / "RECOVERY_SESSION",
        f"session_id={args.recover_session}\nfiles={len(existing)}\n",
    )
    return str(output)


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    private_write(
        path,
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


def write_checksums(output_dir: Path) -> None:
    names = ("report.md", "report.json", "manifest.json", "trace.pftrace", "session.log")
    lines = [
        f"{CAPTURE.sha256_file(output_dir / name)}  {name}"
        for name in names
        if (output_dir / name).is_file()
    ]
    private_write(output_dir / "SHA256SUMS", "\n".join(lines) + "\n")


def invalid_report(report_id: str, uid: int, profile: str, error: str) -> dict[str, Any]:
    report = ANALYZER.analyze_records(
        [],
        report_id=report_id,
        uid=uid,
        profile=profile,
        requested_status="invalid",
    )
    report["errors"] = [error]
    return report


def diagnose(args: argparse.Namespace) -> Path:
    output_dir = prepare_output_dir(args.out)
    report_id = uuid.uuid4().hex[:16]
    started = utc_now()
    trace_processor: Path | None = None
    inputs: dict[str, Any] = {}
    device: dict[str, Any] = {}
    uid = 0
    candidates: list[str] = []
    candidate_count = 0
    report: dict[str, Any] | None = None
    failure: str | None = None
    capture_manifest: dict[str, Any] = {}
    connect_metrics: dict[str, Any] = {}
    analysis_warnings: list[str] = []
    source_commit: str | None = None

    try:
        source_commit = repository_commit()
        if not source_commit:
            raise DiagnosticError("host tools have no verifiable source commit identity")
        trace_processor = resolve_trace_processor(args.trace_processor)
        inputs = validate_local_inputs(args.binary.resolve(), trace_processor)
        adb = CAPTURE.Adb(args.adb, args.device, args.root_command)
        device, uid, candidates, candidate_count, missing_optional = device_preflight(
            adb,
            args.binary.resolve(),
            args.package,
            args.include_package,
            args.profile,
            source_commit,
        )
        requested_status = (
            "degraded" if candidate_count > 1 or missing_optional else "valid"
        )
        if missing_optional:
            analysis_warnings.append(
                "optional device evidence unavailable: " + ", ".join(missing_optional)
            )
        with tempfile.TemporaryDirectory(prefix="anettrace-connect-") as directory:
            capture_dir = Path(directory) / "capture"
            try:
                manifest_path = CAPTURE.capture(
                    capture_args(args, uid, capture_dir, trace_processor)
                )
            except CAPTURE.CaptureError:
                failed_manifest = capture_dir / "session-manifest.json"
                if failed_manifest.is_file():
                    capture_manifest = json.loads(
                        failed_manifest.read_text(encoding="utf-8")
                    )
                    private_write(
                        output_dir / "session.log",
                        redacted_session_log(
                            capture_dir,
                            () if args.include_package else (args.package,),
                        ),
                    )
                raise
            capture_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            events = ANALYZER.read_event_records(
                capture_dir / "anettrace-events.jsonl"
            )
            source_trace = capture_dir / "anettrace-combined.pftrace"
            if not source_trace.is_file():
                raise DiagnosticError("capture did not produce the combined Perfetto trace")
            try:
                derived, connect_metrics = query_connect_metrics(
                    trace_processor, source_trace
                )
                events.extend(derived)
            except DiagnosticError as error:
                requested_status = "degraded"
                analysis_warnings.append(
                    "scheduler/process-exit metrics unavailable: " + str(error)
                )
            report = ANALYZER.analyze_records(
                events,
                report_id=report_id,
                uid=uid,
                profile=args.profile,
                package=args.package if args.include_package else None,
                shared_uid_candidates=candidates,
                shared_uid_ambiguous=candidate_count > 1,
                requested_status=requested_status,
            )
            report["warnings"].extend(analysis_warnings)
            report_size = sum(
                path.stat().st_size for path in capture_dir.iterdir() if path.is_file()
            )
            if report_size > args.max_report_mib * 1024 * 1024:
                raise DiagnosticError("capture exceeded the report size limit")
            shutil.copyfile(source_trace, output_dir / "trace.pftrace")
            (output_dir / "trace.pftrace").chmod(0o600)
            private_write(
                output_dir / "session.log",
                redacted_session_log(
                    capture_dir,
                    () if args.include_package else (args.package,),
                ),
            )
    except (DiagnosticError, CAPTURE.CaptureError, ANALYZER.ConnectDiagnosticsError) as error:
        failure = redact_failure(error, args)
        report = invalid_report(report_id, uid, args.profile, failure)
        failure_line = f"diagnostic failed: {failure}\n"
        session_log = output_dir / "session.log"
        existing_log = (
            session_log.read_text(encoding="utf-8", errors="replace")
            if session_log.is_file()
            else ""
        )
        private_write(session_log, existing_log + failure_line)
        (output_dir / "trace.pftrace").write_bytes(b"")
        (output_dir / "trace.pftrace").chmod(0o600)

    assert report is not None
    ANALYZER.write_report(report, output_dir)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "report_id": report_id,
        "product_version": VERSION,
        "source_commit": source_commit,
        "started_at_utc": started,
        "ended_at_utc": utc_now(),
        "status": report["status"],
        "profile": args.profile,
        "limits": {
            "duration_s": args.duration,
            "max_report_mib": args.max_report_mib,
        },
        "privacy": {
            "package_included": args.include_package,
            "payload_collected": False,
            "device_identifiers_persisted": False,
        },
        "target": {
            "uid": uid,
            "shared_uid_ambiguous": candidate_count > 1,
            **({"package": args.package, "shared_uid_candidates": candidates}
               if args.include_package else {}),
        },
        "inputs": inputs,
        "device": device,
        "capture": {
            "session_id": capture_manifest.get("session_id"),
            "status": capture_manifest.get("status"),
            "cleanup": capture_manifest.get("cleanup"),
            "anettrace": capture_manifest.get("anettrace"),
            "merge": capture_manifest.get("merge"),
            "resource_sampling": capture_manifest.get("resource_sampling"),
            "connect_metrics": connect_metrics,
            "warnings": redacted_messages(
                capture_manifest.get("warnings", []), args
            ),
            "errors": redacted_messages(capture_manifest.get("errors", []), args),
        },
        "failure": failure,
    }
    write_manifest(output_dir / "manifest.json", manifest)
    write_checksums(output_dir)
    if failure:
        raise DiagnosticError(failure)
    return output_dir


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", help="target Android package")
    parser.add_argument("--binary", type=Path, help="matching Android arm64 Anettrace")
    parser.add_argument("--trace-processor", type=Path, help="compatible Trace Processor CLI")
    parser.add_argument("--out", type=Path, help="new or empty report directory")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION_S)
    parser.add_argument("--max-report-mib", type=int, default=DEFAULT_MAX_REPORT_MIB)
    parser.add_argument("--resource-sample-interval", type=int)
    parser.add_argument("--profile", choices=("sched", "full"), default="sched")
    parser.add_argument("--include-package", action="store_true")
    parser.add_argument("--keep-device-artifacts", action="store_true")
    parser.add_argument("--device", help="adb device selector; never persisted")
    parser.add_argument("--adb", default="adb")
    parser.add_argument(
        "--root-command",
        help="explicit trusted device-shell prefix, for example 'su -c'",
    )
    parser.add_argument(
        "--recover-session",
        help="inspect, pull, or clean a 12-hex interrupted capture session",
    )
    parser.add_argument(
        "--recover-action",
        choices=("inspect", "pull", "cleanup"),
        default="inspect",
    )
    parser.add_argument(
        "--external-command",
        nargs=argparse.REMAINDER,
        help="host workload command started with capture; this option must be last",
    )
    args = parser.parse_args(argv)
    if args.duration <= 0:
        parser.error("duration must be positive")
    if args.max_report_mib <= 0:
        parser.error("max report size must be positive")
    if args.resource_sample_interval is not None and args.resource_sample_interval <= 0:
        parser.error("resource sample interval must be positive")
    if args.root_command is not None and (
        not args.root_command.strip()
        or any(character in args.root_command for character in "\r\n\0")
    ):
        parser.error("root command must be one non-empty shell prefix")
    if args.recover_session:
        if args.recover_action == "pull" and args.out is None:
            parser.error("--out is required with --recover-action pull")
        return args
    if args.external_command == []:
        parser.error("--external-command needs a command")
    if not args.package or args.binary is None or args.out is None:
        parser.error("--package, --binary, and --out are required for a new diagnosis")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.recover_session:
            print(recover_session(args))
            return 0
        output = diagnose(args)
    except DiagnosticError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"diagnostic report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
