#!/usr/bin/env python3
"""Run the release-gated 30-minute Android TCP connect soak."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import re
import shlex
import sys
import uuid
from pathlib import Path
from typing import Any, Sequence


ROOT = Path(__file__).resolve().parents[1]


def load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"anettrace_soak_{name}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


DIAGNOSE = load_tool("diagnose_android_connect")
ACCEPTANCE = load_tool("validate_android_connect")
SCHEMA = "anettrace.connect-diagnostics.soak.v1"


class SoakError(RuntimeError):
    """The release soak gate failed."""


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def workload_script(
    remote_workload: str,
    uid: int,
    *,
    run_seconds: int,
    interval_ms: int,
    progress_every: int = 0,
) -> str:
    command = [
        remote_workload,
        "--uid",
        str(uid),
        "--scenario",
        "success",
        "--run-seconds",
        str(run_seconds),
        "--interval-ms",
        str(interval_ms),
        "--quiet",
    ]
    if progress_every:
        command.extend(("--progress-every", str(progress_every)))
    return " ".join(shlex.quote(value) for value in command)


def baseline_result(output: str) -> tuple[int, int]:
    matches = re.findall(
        r"completed=([0-9]+) elapsed_ms=([0-9]+) complete=true", output
    )
    if len(matches) != 1:
        raise SoakError("baseline workload did not produce one completion summary")
    completed, elapsed_ms = (int(value) for value in matches[0])
    if completed <= 0 or elapsed_ms <= 0:
        raise SoakError("baseline workload produced no measurable throughput")
    return completed, elapsed_ms


def external_command(args: argparse.Namespace, script: str) -> list[str]:
    command = [args.adb]
    if args.device:
        command.extend(("-s", args.device))
    command.extend(
        (
            "shell",
            DIAGNOSE.CAPTURE.wrap_device_shell(script, args.root_command),
        )
    )
    return command


def validate_soak_report(
    report: dict[str, Any], manifest: dict[str, Any], duration_s: int
) -> dict[str, Any]:
    if report.get("status") != "valid":
        raise SoakError(f"soak report is not valid: {report.get('status')}")
    capture = report["capture"]
    if int(capture["lost_events"]) != 0 or bool(capture["truncated"]):
        raise SoakError("soak capture lost events or reached a resource limit")
    elapsed_s = max(0.0, (int(capture["ended_ns"]) - int(capture["started_ns"])) / 1e9)
    if elapsed_s < duration_s * 0.95:
        raise SoakError("soak event window is shorter than the requested duration")
    counts = report["summary"]["outcome_counts"]
    attempt_count = int(report["summary"]["attempt_count"])
    success_count = int(counts.get("success", 0))
    unknown_count = int(counts.get("incomplete_or_unknown", 0))
    unexpected = {
        name: int(count)
        for name, count in counts.items()
        if name not in ("success", "incomplete_or_unknown") and int(count)
    }
    if unexpected:
        raise SoakError(f"soak produced unexpected outcomes: {unexpected}")
    if success_count <= 0 or success_count + unknown_count != attempt_count:
        raise SoakError(f"soak produced unexpected outcomes: {unexpected or counts}")
    if unknown_count > 1:
        raise SoakError("soak produced more than one boundary-incomplete attempt")

    capture_manifest = manifest.get("capture", {})
    cleanup = capture_manifest.get("cleanup") or {}
    if not cleanup.get("verified"):
        raise SoakError("device capture cleanup was not verified")
    resources = capture_manifest.get("resource_sampling") or {}
    if int(resources.get("samples", 0)) < 2:
        raise SoakError("collector resource sampling is incomplete")
    return {
        "duration_s": round(elapsed_s, 3),
        "attempt_count": attempt_count,
        "success_count": success_count,
        "boundary_incomplete_count": unknown_count,
        "attempts_per_second": round(attempt_count / elapsed_s, 6),
        "lost_events": int(capture["lost_events"]),
        "truncated": bool(capture["truncated"]),
        "collector_resources": resources,
        "cleanup": cleanup,
    }


def run_soak(args: argparse.Namespace) -> Path:
    output = DIAGNOSE.prepare_output_dir(args.out)
    ACCEPTANCE.validate_workload(args.workload.resolve())
    adb = DIAGNOSE.CAPTURE.Adb(args.adb, args.device, args.root_command)
    if adb.run("get-state").stdout.strip() != "device":
        raise SoakError("Android device is not ready")
    if DIAGNOSE.device_value(adb, "id -u") != "0":
        raise SoakError(
            "device shell must run as root; use an explicit --root-command if needed"
        )
    uid, _, _ = DIAGNOSE.resolve_package(adb, args.package, False)
    if uid == 0:
        raise SoakError("soak workload requires a non-root package UID")

    session = uuid.uuid4().hex[:12]
    remote_dir = f"/data/local/tmp/anettrace-connect-soak-{session}"
    remote_workload = f"{remote_dir}/connect-workload"
    remote_pid_file = f"{remote_dir}/traced.pid"
    try:
        adb.shell(
            f"mkdir -p {shlex.quote(remote_dir)} && chmod 0700 {shlex.quote(remote_dir)}"
        )
        adb.push(args.workload.resolve(), remote_workload)
        adb.shell(f"chmod 0700 {shlex.quote(remote_workload)}")

        baseline = adb.shell(
            workload_script(
                remote_workload,
                uid,
                run_seconds=args.baseline_seconds,
                interval_ms=args.interval_ms,
            ),
            check=False,
        )
        if baseline.returncode != 0:
            raise SoakError("baseline workload failed")
        baseline_completed, baseline_elapsed_ms = baseline_result(baseline.stdout)

        traced_workload = workload_script(
            remote_workload,
            uid,
            run_seconds=args.duration + 5,
            interval_ms=args.interval_ms,
            progress_every=20,
        )
        bounded_workload = (
            f"{traced_workload} & workload_pid=$!; "
            f"echo $workload_pid > {shlex.quote(remote_pid_file)}; "
            "wait $workload_pid"
        )
        traced_script = (
            f"exec toybox timeout -s TERM {args.duration + 15} sh -c "
            + shlex.quote(bounded_workload)
        )
        diagnose_argv = [
            "--package",
            args.package,
            "--binary",
            str(args.binary.resolve()),
            "--trace-processor",
            str(args.trace_processor.resolve()),
            "--out",
            str(output / "diagnosis"),
            "--duration",
            str(args.duration),
            "--max-report-mib",
            str(args.max_report_mib),
            "--profile",
            args.profile,
            "--resource-sample-interval",
            str(args.resource_sample_interval),
        ]
        if args.device:
            diagnose_argv.extend(("--device", args.device))
        if args.root_command:
            diagnose_argv.extend(("--root-command", args.root_command))
        if args.include_package:
            diagnose_argv.append("--include-package")
        diagnose_argv.append("--external-command")
        diagnose_argv.extend(external_command(args, traced_script))
        try:
            diagnosis = DIAGNOSE.diagnose(DIAGNOSE.parse_args(diagnose_argv))
        except DIAGNOSE.DiagnosticError as error:
            raise SoakError(f"soak diagnosis failed: {error}") from error

        report = json.loads((diagnosis / "report.json").read_text(encoding="utf-8"))
        manifest = json.loads(
            (diagnosis / "manifest.json").read_text(encoding="utf-8")
        )
        traced = validate_soak_report(report, manifest, args.duration)
        process_cleanup_verified = ACCEPTANCE.stop_remote_workload(
            adb,
            remote_pid_file,
            remote_workload,
            require_pid=True,
        )
        adb.shell(f"rm -rf {shlex.quote(remote_dir)}", check=False)
        cleanup_state = adb.run("get-state", check=False)
        workload_cleanup_verified = (
            process_cleanup_verified
            and cleanup_state.returncode == 0
            and cleanup_state.stdout.strip() == "device"
            and adb.shell(
                f"test -e {shlex.quote(remote_dir)}", check=False
            ).returncode
            != 0
        )
        if not workload_cleanup_verified:
            raise SoakError("soak workload artifact cleanup was not verified")
        baseline_rate = baseline_completed / (baseline_elapsed_ms / 1000)
        traced_rate = float(traced["attempts_per_second"])
        summary = {
            "schema_version": SCHEMA,
            "uid": uid,
            "package_included": args.include_package,
            **({"package": args.package} if args.include_package else {}),
            "binary_sha256": sha256(args.binary.resolve()),
            "workload_sha256": sha256(args.workload.resolve()),
            "baseline": {
                "duration_s": round(baseline_elapsed_ms / 1000, 3),
                "completed": baseline_completed,
                "attempts_per_second": round(baseline_rate, 6),
            },
            "traced": traced,
            "business_throughput_change_percent": round(
                (traced_rate / baseline_rate - 1) * 100, 3
            ),
            "workload_cleanup_verified": workload_cleanup_verified,
            "diagnosis_report_sha256": sha256(diagnosis / "report.json"),
            "diagnosis_manifest_sha256": sha256(diagnosis / "manifest.json"),
        }
        summary_path = output / "soak-summary.json"
        DIAGNOSE.private_write(
            summary_path,
            json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        )
        return summary_path
    finally:
        try:
            ACCEPTANCE.stop_remote_workload(
                adb,
                remote_pid_file,
                remote_workload,
                require_pid=False,
            )
        finally:
            adb.shell(f"rm -rf {shlex.quote(remote_dir)}", check=False)


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
    parser.add_argument("--duration", type=int, default=1800)
    parser.add_argument("--baseline-seconds", type=int, default=30)
    parser.add_argument("--interval-ms", type=int, default=250)
    parser.add_argument("--resource-sample-interval", type=int, default=5)
    parser.add_argument("--max-report-mib", type=int, default=512)
    parser.add_argument("--profile", choices=("sched", "full"), default="sched")
    parser.add_argument("--include-package", action="store_true")
    args = parser.parse_args(argv)
    if args.duration < 1800:
        parser.error("release soak duration must be at least 1800 seconds")
    if args.baseline_seconds < 10:
        parser.error("baseline duration must be at least 10 seconds")
    if args.interval_ms < 1 or args.resource_sample_interval < 1:
        parser.error("workload and resource sample intervals must be positive")
    if args.max_report_mib <= 0:
        parser.error("max report size must be positive")
    if args.root_command is not None and (
        not args.root_command.strip()
        or any(character in args.root_command for character in "\r\n\0")
    ):
        parser.error("root command must be one non-empty shell prefix")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        summary = run_soak(args)
    except (
        SoakError,
        ACCEPTANCE.AcceptanceError,
        DIAGNOSE.DiagnosticError,
        OSError,
    ) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"soak summary: {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
