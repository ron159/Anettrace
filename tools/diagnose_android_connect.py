#!/usr/bin/env python3
"""Run one bounded Android TCP connect diagnostic session."""

from __future__ import annotations

import argparse
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
    result = run(
        ["git", "-C", str(ROOT), "rev-parse", "--verify", "HEAD"], check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


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
    count_output = device_value(
        adb,
        "cmd package list packages -U | "
        f"awk '$2 == \"uid:{uid}\" {{count++}} END {{print count+0}}'",
    )
    try:
        candidate_count = int(count_output)
    except ValueError as error:
        raise DiagnosticError("cannot determine shared UID ambiguity") from error
    candidates: list[str] = []
    if include_package:
        candidate_output = device_value(
            adb,
            "cmd package list packages -U | "
            f"awk '$2 == \"uid:{uid}\" {{sub(/^package:/, \"\", $1); print $1}}'",
        )
        candidates = sorted(line for line in candidate_output.splitlines() if line)
    return uid, candidates, candidate_count


def device_preflight(
    adb: Any,
    binary: Path,
    package: str,
    include_package: bool,
) -> tuple[dict[str, Any], int, list[str], int]:
    if adb.run("get-state").stdout.strip() != "device":
        raise DiagnosticError("Android device is not ready")
    if device_value(adb, "id -u") != "0":
        raise DiagnosticError(
            "adb shell must already be root; automatic privilege escalation is disabled"
        )

    checks = {
        "root_adb_shell": True,
        "btf_vmlinux": capability(adb, "test -r /sys/kernel/btf/vmlinux"),
        "tracefs": capability(adb, "test -d /sys/kernel/tracing/events"),
        "perfetto": capability(adb, "test -x /system/bin/perfetto"),
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
        "toybox_timeout": capability(adb, "toybox timeout --help >/dev/null 2>&1"),
        "file_ulimit": capability(adb, "sh -c 'ulimit -f' >/dev/null 2>&1"),
    }
    missing = [name for name, supported in checks.items() if not supported]
    if missing:
        raise DiagnosticError("missing core device capabilities: " + ", ".join(missing))

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
        commit = repository_commit()
        if commit and f"commit {commit}" not in version_text:
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
        "existing_tracing": {
            "tracing_on": device_value(adb, "cat /sys/kernel/tracing/tracing_on"),
            "current_tracer": device_value(
                adb, "cat /sys/kernel/tracing/current_tracer"
            ),
        },
    }
    return device, uid, candidates, candidate_count


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
    if args.keep_device_artifacts:
        values.append("--keep-remote")
    return CAPTURE.parse_args(values)


def redacted_session_log(capture_dir: Path, secrets: Sequence[str]) -> str:
    chunks: list[str] = []
    for name in ("anettrace.log", "perfetto.log"):
        path = capture_dir / name
        if path.is_file():
            chunks.append(f"[{name}]\n{path.read_text(encoding='utf-8', errors='replace')}")
    text = "\n".join(chunks) or "No device log was available.\n"
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


def redact_failure(error: object, args: argparse.Namespace) -> str:
    text = str(error)
    secrets = [args.device]
    if not args.include_package:
        secrets.append(args.package)
    for secret in secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    return text


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

    try:
        trace_processor = resolve_trace_processor(args.trace_processor)
        inputs = validate_local_inputs(args.binary.resolve(), trace_processor)
        adb = CAPTURE.Adb(args.adb, args.device)
        device, uid, candidates, candidate_count = device_preflight(
            adb, args.binary.resolve(), args.package, args.include_package
        )
        requested_status = "degraded" if candidate_count > 1 else "valid"
        with tempfile.TemporaryDirectory(prefix="anettrace-connect-") as directory:
            capture_dir = Path(directory) / "capture"
            manifest_path = CAPTURE.capture(
                capture_args(args, uid, capture_dir, trace_processor)
            )
            capture_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            events = ANALYZER.read_event_records(
                capture_dir / "anettrace-events.jsonl"
            )
            report = ANALYZER.analyze_records(
                events,
                report_id=report_id,
                uid=uid,
                profile=args.profile,
                package=args.package if args.include_package else None,
                shared_uid_candidates=candidates,
                requested_status=requested_status,
            )
            source_trace = capture_dir / "anettrace-combined.pftrace"
            if not source_trace.is_file():
                raise DiagnosticError("capture did not produce the combined Perfetto trace")
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
        private_write(output_dir / "session.log", f"diagnostic failed: {failure}\n")
        (output_dir / "trace.pftrace").write_bytes(b"")
        (output_dir / "trace.pftrace").chmod(0o600)

    assert report is not None
    ANALYZER.write_report(report, output_dir)
    manifest = {
        "schema_version": MANIFEST_SCHEMA,
        "report_id": report_id,
        "product_version": VERSION,
        "source_commit": repository_commit(),
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
            "status": capture_manifest.get("status"),
            "anettrace": capture_manifest.get("anettrace"),
            "merge": capture_manifest.get("merge"),
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
    parser.add_argument("--package", required=True, help="target Android package")
    parser.add_argument("--binary", type=Path, required=True, help="matching Android arm64 Anettrace")
    parser.add_argument("--trace-processor", type=Path, help="compatible Trace Processor CLI")
    parser.add_argument("--out", type=Path, required=True, help="new or empty report directory")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION_S)
    parser.add_argument("--max-report-mib", type=int, default=DEFAULT_MAX_REPORT_MIB)
    parser.add_argument("--profile", choices=("sched", "full"), default="sched")
    parser.add_argument("--include-package", action="store_true")
    parser.add_argument("--keep-device-artifacts", action="store_true")
    parser.add_argument("--device", help="adb device selector; never persisted")
    parser.add_argument("--adb", default="adb")
    args = parser.parse_args(argv)
    if args.duration <= 0:
        parser.error("duration must be positive")
    if args.max_report_mib <= 0:
        parser.error("max report size must be positive")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        output = diagnose(args)
    except DiagnosticError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"diagnostic report: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
