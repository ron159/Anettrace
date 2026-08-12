#!/usr/bin/env python3
"""Run the repeatable PKC130 TCP connect acceptance scenarios."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import sys
import time
import uuid
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]
DIAGNOSE_PATH = ROOT / "tools" / "diagnose_android_connect.py"
SPEC = importlib.util.spec_from_file_location("diagnose_android_connect_acceptance", DIAGNOSE_PATH)
assert SPEC and SPEC.loader
DIAGNOSE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DIAGNOSE
SPEC.loader.exec_module(DIAGNOSE)

SCHEMA = "anettrace.connect-diagnostics.acceptance.v1"
SCENARIOS = {
    "success": "success",
    "refused": "peer_refused",
    "timeout": "timeout_no_response",
}


class AcceptanceError(RuntimeError):
    """A device acceptance gate failed."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_workload(path: Path) -> None:
    if not path.is_file():
        raise AcceptanceError(f"workload does not exist: {path}")
    result = DIAGNOSE.run(["file", str(path)], check=False)
    if result.returncode or not re.search(
        r"(ARM aarch64|AArch64)", result.stdout, re.IGNORECASE
    ):
        raise AcceptanceError("connect workload is not an AArch64 executable")


def external_workload_command(
    args: argparse.Namespace,
    remote_workload: str,
    remote_pid_file: str,
    uid: int,
    scenario: str,
) -> list[str]:
    command = [args.adb]
    if args.device:
        command.extend(("-s", args.device))
    device_command = [
        remote_workload,
        "--uid",
        str(uid),
        "--scenario",
        scenario,
        "--repeat",
        str(args.repeat),
        "--hold-seconds",
        str(args.duration + 2),
    ]
    if scenario == "timeout":
        device_command.extend(("--timeout-address", args.timeout_address))
    device_script = (
        f"echo $$ > {shlex.quote(remote_pid_file)}; exec "
        + " ".join(shlex.quote(part) for part in device_command)
    )
    command.extend(
        (
            "shell",
            DIAGNOSE.CAPTURE.wrap_device_shell(
                device_script, args.root_command
            ),
        )
    )
    return command


def remote_workload_matches(adb: Any, pid: int, remote_workload: str) -> bool:
    script = (
        f"test -r /proc/{pid}/cmdline && "
        f"tr '\\000' ' ' < /proc/{pid}/cmdline | "
        f"grep -Fq -- {shlex.quote(remote_workload)}"
    )
    return adb.shell(script, check=False).returncode == 0


def stop_remote_workload(
    adb: Any,
    remote_pid_file: str,
    remote_workload: str,
    *,
    require_pid: bool,
) -> bool:
    pid_text = DIAGNOSE.device_value(adb, f"cat {shlex.quote(remote_pid_file)}")
    if not re.fullmatch(r"[1-9][0-9]*", pid_text):
        if require_pid:
            raise AcceptanceError("workload PID record is missing or invalid")
        return True
    pid = int(pid_text)
    if not remote_workload_matches(adb, pid, remote_workload):
        return True
    adb.shell(f"kill -TERM {pid}", check=False)
    for _ in range(50):
        if not remote_workload_matches(adb, pid, remote_workload):
            return True
        time.sleep(0.1)
    if remote_workload_matches(adb, pid, remote_workload):
        adb.shell(f"kill -KILL {pid}", check=False)
    for _ in range(20):
        if not remote_workload_matches(adb, pid, remote_workload):
            return True
        time.sleep(0.1)
    raise AcceptanceError("workload process cleanup could not be verified")


def validate_scenario_report(
    report: dict[str, Any], *, scenario: str, expected: str, repeat: int
) -> dict[str, Any]:
    status = str(report.get("status", ""))
    summary = report.get("summary") or {}
    attempt_count = int(summary.get("attempt_count", 0))
    counts = {
        str(name): int(count)
        for name, count in (summary.get("outcome_counts") or {}).items()
        if int(count)
    }
    if status == "invalid":
        raise AcceptanceError(f"{scenario}: report is invalid")
    if attempt_count != repeat or counts != {expected: repeat}:
        raise AcceptanceError(
            f"{scenario}: expected exactly {repeat} {expected} outcomes, "
            f"got {attempt_count} attempts with {counts}"
        )
    return {
        "scenario": scenario,
        "expected_outcome": expected,
        "observed_count": repeat,
        "report_status": status,
    }


def run_acceptance(args: argparse.Namespace) -> Path:
    output = args.out.resolve()
    if output.exists() and any(output.iterdir()):
        raise AcceptanceError(f"output directory is not empty: {output}")
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    output.chmod(0o700)
    validate_workload(args.workload.resolve())
    adb = DIAGNOSE.CAPTURE.Adb(args.adb, args.device, args.root_command)
    if adb.run("get-state").stdout.strip() != "device":
        raise AcceptanceError("Android device is not ready")
    if DIAGNOSE.device_value(adb, "id -u") != "0":
        raise AcceptanceError(
            "device shell must run as root; use an explicit --root-command if needed"
        )
    uid, _, _ = DIAGNOSE.resolve_package(adb, args.package, False)
    if uid == 0:
        raise AcceptanceError("acceptance workload requires a non-root package UID")

    session = uuid.uuid4().hex[:12]
    remote_dir = f"/data/local/tmp/anettrace-connect-accept-{session}"
    remote_workload = f"{remote_dir}/connect-workload"
    remote_pid_files: list[str] = []
    results: list[dict[str, Any]] = []
    workload_process_cleanup_verified = False
    try:
        adb.shell(
            f"mkdir -p {shlex.quote(remote_dir)} && chmod 0700 {shlex.quote(remote_dir)}"
        )
        adb.push(args.workload.resolve(), remote_workload)
        adb.shell(f"chmod 0700 {shlex.quote(remote_workload)}")
        for scenario, expected in SCENARIOS.items():
            scenario_output = output / scenario
            remote_pid_file = f"{remote_dir}/{scenario}.pid"
            remote_pid_files.append(remote_pid_file)
            diagnose_argv = [
                "--package",
                args.package,
                "--binary",
                str(args.binary.resolve()),
                "--trace-processor",
                str(args.trace_processor.resolve()),
                "--out",
                str(scenario_output),
                "--duration",
                str(args.duration),
                "--max-report-mib",
                str(args.max_report_mib),
                "--profile",
                args.profile,
            ]
            if args.device:
                diagnose_argv.extend(("--device", args.device))
            if args.root_command:
                diagnose_argv.extend(("--root-command", args.root_command))
            if args.include_package:
                diagnose_argv.append("--include-package")
            diagnose_argv.append("--external-command")
            diagnose_argv.extend(
                external_workload_command(
                    args, remote_workload, remote_pid_file, uid, scenario
                )
            )
            try:
                DIAGNOSE.diagnose(DIAGNOSE.parse_args(diagnose_argv))
            except DIAGNOSE.DiagnosticError as error:
                raise AcceptanceError(f"{scenario} diagnosis failed: {error}") from error
            report = json.loads(
                (scenario_output / "report.json").read_text(encoding="utf-8")
            )
            result = validate_scenario_report(
                report, scenario=scenario, expected=expected, repeat=args.repeat
            )
            result["report_sha256"] = sha256(scenario_output / "report.json")
            results.append(result)
            stop_remote_workload(
                adb,
                remote_pid_file,
                remote_workload,
                require_pid=True,
            )
    finally:
        try:
            workload_process_cleanup_verified = all(
                stop_remote_workload(
                    adb,
                    remote_pid_file,
                    remote_workload,
                    require_pid=False,
                )
                for remote_pid_file in remote_pid_files
            )
        finally:
            adb.shell(f"rm -rf {shlex.quote(remote_dir)}", check=False)

    cleanup_verified = (
        workload_process_cleanup_verified
        and adb.run("get-state", check=False).stdout.strip() == "device"
        and adb.shell(f"test -e {shlex.quote(remote_dir)}", check=False).returncode
        != 0
    )
    if not cleanup_verified:
        raise AcceptanceError("acceptance workload cleanup was not verified")

    summary = {
        "schema_version": SCHEMA,
        "uid": uid,
        "repeat": args.repeat,
        "workload_sha256": sha256(args.workload.resolve()),
        "binary_sha256": sha256(args.binary.resolve()),
        "package_included": args.include_package,
        **({"package": args.package} if args.include_package else {}),
        "workload_cleanup_verified": cleanup_verified,
        "results": results,
    }
    summary_path = output / "acceptance-summary.json"
    summary_path.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_path.chmod(0o600)
    return summary_path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--workload", type=Path, required=True)
    parser.add_argument("--trace-processor", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--device")
    parser.add_argument("--adb", default="adb")
    parser.add_argument(
        "--root-command",
        help="explicit trusted device-shell prefix, for example 'su -c'",
    )
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--duration", type=int, default=20)
    parser.add_argument("--max-report-mib", type=int, default=512)
    parser.add_argument("--profile", choices=("sched", "full"), default="sched")
    parser.add_argument("--timeout-address", default="192.0.2.1")
    parser.add_argument("--include-package", action="store_true")
    args = parser.parse_args(argv)
    if args.repeat <= 0 or args.duration <= 0 or args.max_report_mib <= 0:
        parser.error("repeat, duration, and max report size must be positive")
    if not re.fullmatch(r"[0-9A-Fa-f:.]+", args.timeout_address):
        parser.error("timeout address must be a numeric IP address")
    if args.root_command is not None and (
        not args.root_command.strip()
        or any(character in args.root_command for character in "\r\n\0")
    ):
        parser.error("root command must be one non-empty shell prefix")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = run_acceptance(args)
    except (AcceptanceError, DIAGNOSE.DiagnosticError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"acceptance summary: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
