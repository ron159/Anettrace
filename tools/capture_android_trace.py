#!/usr/bin/env python3
# SPDX-License-Identifier: MulanPSL-2.0
"""Capture Anettrace with Android Perfetto, simpleperf, or another host tool.

This is the maintained, cross-platform replacement for the original shell-only
capture helper.  The built-in Perfetto profiles preserve the useful capture
profiles from PerfAllInOne without importing its Python 2 runtime or bundled
executables.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence


ROOT = Path(__file__).resolve().parents[1]
EVENT_SCHEMA = "anettrace.perfetto.v1"
MANIFEST_SCHEMA = "anettrace.capture.v1"
DEFAULT_DURATIONS = {"sched": 10, "light": 10, "full": 20, "long": 600, "none": 10}
REMOTE_ROOT = "/data/local/tmp"
PERFETTO_CONFIG_ROOT = "/data/misc/perfetto-configs"
PERFETTO_TRACE_ROOT = "/data/misc/perfetto-traces"

ATRACE_CATEGORIES = (
    "aidl",
    "am",
    "audio",
    "binder_driver",
    "binder_lock",
    "camera",
    "dalvik",
    "disk",
    "freq",
    "gfx",
    "hal",
    "idle",
    "input",
    "memreclaim",
    "network",
    "nnapi",
    "pdx",
    "pm",
    "power",
    "res",
    "rro",
    "rs",
    "sched",
    "sm",
    "ss",
    "sync",
    "thermal",
    "vibrator",
    "video",
    "view",
    "webview",
    "wm",
)

SCHED_EVENTS = (
    "sched/sched_switch",
    "sched/sched_wakeup",
    "sched/sched_wakeup_new",
    "sched/sched_waking",
    "sched/sched_process_exec",
    "sched/sched_process_exit",
    "sched/sched_process_free",
    "task/task_newtask",
    "task/task_rename",
    "power/suspend_resume",
)

FULL_EVENTS = SCHED_EVENTS + (
    "power/cpu_frequency",
    "power/cpu_frequency_limits",
    "power/cpu_idle",
    "power/gpu_frequency",
)


class CaptureError(RuntimeError):
    """A user-facing capture failure."""


@dataclass
class RemoteProcess:
    name: str
    pid: int
    log_path: str


def _field_lines(name: str, values: Iterable[str], indent: int) -> str:
    prefix = " " * indent
    return "\n".join(f'{prefix}{name}: "{value}"' for value in values)


def render_perfetto_config(profile: str, duration_s: int) -> str:
    """Build a textproto config for one supported system-trace profile."""
    if profile not in {"sched", "light", "full", "long"}:
        raise ValueError(f"profile has no Perfetto config: {profile}")

    if profile == "sched":
        return f"""buffers: {{
  size_kb: 32768
  fill_policy: RING_BUFFER
}}
data_sources: {{
  config {{
    name: "linux.ftrace"
    target_buffer: 0
    ftrace_config {{
{_field_lines("ftrace_events", SCHED_EVENTS, 6)}
      compact_sched {{ enabled: true }}
    }}
  }}
}}
data_sources: {{
  config {{
    name: "linux.process_stats"
    target_buffer: 0
    process_stats_config {{
      scan_all_processes_on_start: true
      proc_stats_poll_ms: 1000
    }}
  }}
}}
duration_ms: {duration_s * 1000}
"""

    buffer_kb = 512000 if profile == "light" else 200600 if profile == "full" else 153600
    categories = ATRACE_CATEGORIES
    events = FULL_EVENTS if profile in {"full", "long"} else SCHED_EVENTS
    extra_sources = ""
    if profile in {"full", "long"}:
        extra_sources = """
data_sources: {
  config {
    name: "android.gpu.memory"
    target_buffer: 1
  }
}
data_sources: {
  config {
    name: "linux.sys_stats"
    target_buffer: 1
    sys_stats_config {
      meminfo_period_ms: 1000
      meminfo_counters: MEMINFO_MEM_TOTAL
      meminfo_counters: MEMINFO_MEM_FREE
      meminfo_counters: MEMINFO_MEM_AVAILABLE
      meminfo_counters: MEMINFO_CACHED
      meminfo_counters: MEMINFO_SWAP_TOTAL
      meminfo_counters: MEMINFO_SWAP_FREE
      meminfo_counters: MEMINFO_DIRTY
      meminfo_counters: MEMINFO_ANON_PAGES
      meminfo_counters: MEMINFO_MAPPED
      meminfo_counters: MEMINFO_SHMEM
      stat_period_ms: 1000
      stat_counters: STAT_CPU_TIMES
      stat_counters: STAT_FORK_COUNT
    }
  }
}
data_sources: {
  config { name: "linux.system_info" }
}
"""
        if profile == "full":
            extra_sources += """data_sources: {
  config {
    name: "android.surfaceflinger.frametimeline"
    target_buffer: 2
  }
}
"""

    streaming = ""
    if profile == "long":
        streaming = "write_into_file: true\nfile_write_period_ms: 2500\n"

    return f"""buffers: {{
  size_kb: {buffer_kb}
  fill_policy: RING_BUFFER
}}
buffers: {{ size_kb: 2048 fill_policy: RING_BUFFER }}
buffers: {{ size_kb: 10240 fill_policy: RING_BUFFER }}
data_sources: {{
  config {{
    name: "linux.ftrace"
    target_buffer: 0
    ftrace_config {{
      symbolize_ksyms: true
{_field_lines("atrace_categories", categories, 6)}
      atrace_apps: "*"
{_field_lines("ftrace_events", events, 6)}
      buffer_size_kb: 24576
      drain_period_ms: 1000
    }}
  }}
}}
data_sources: {{
  config {{
    name: "linux.process_stats"
    target_buffer: 1
    process_stats_config {{
      scan_all_processes_on_start: true
      proc_stats_poll_ms: 1000
    }}
  }}
}}
{extra_sources}duration_ms: {duration_s * 1000}
{streaming}flush_period_ms: 30000
incremental_state_config {{ clear_period_ms: 5000 }}
"""


def run_command(
    command: Sequence[str],
    *,
    check: bool = True,
    cwd: Path | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(command),
            check=check,
            cwd=cwd,
            text=True,
            capture_output=capture_output,
        )
    except FileNotFoundError as exc:
        raise CaptureError(f"command not found: {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or exc.stdout or "").strip()
        suffix = f": {detail}" if detail else ""
        raise CaptureError(f"command failed ({exc.returncode}): {' '.join(command)}{suffix}") from exc


class Adb:
    def __init__(self, executable: str, serial: str | None):
        self.base = [executable]
        if serial:
            self.base.extend(["-s", serial])

    def run(self, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return run_command([*self.base, *args], check=check)

    def shell(self, script: str, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        # Pass one command argument to adb.  adb invokes the device shell itself;
        # adding a second `sh -c` loses quoting on some Windows adb builds.
        return self.run("shell", script, check=check)

    def push(self, source: Path, destination: str) -> None:
        self.run("push", str(source), destination)

    def pull(self, source: str, destination: Path) -> None:
        self.run("pull", source, str(destination))


def start_remote(adb: Adb, name: str, command: str, remote_dir: str) -> RemoteProcess:
    log_path = f"{remote_dir}/{name}.log"
    script = f"{command} >{shlex.quote(log_path)} 2>&1 & echo $!"
    output = adb.shell(script).stdout.strip().replace("\r", "")
    if not re.fullmatch(r"[1-9][0-9]*", output):
        raise CaptureError(f"failed to start {name}: {output or 'no pid returned'}")
    return RemoteProcess(name=name, pid=int(output), log_path=log_path)


def remote_alive(adb: Adb, process: RemoteProcess) -> bool:
    return adb.shell(f"kill -0 {process.pid}", check=False).returncode == 0


def signal_remote(adb: Adb, process: RemoteProcess, signal_name: str) -> None:
    adb.shell(f"kill -{signal_name} {process.pid}", check=False)


def wait_remote(adb: Adb, process: RemoteProcess, timeout_s: float) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if not remote_alive(adb, process):
            return True
        time.sleep(0.1)
    return not remote_alive(adb, process)


def remote_file_exists(adb: Adb, path: str) -> bool:
    return adb.shell(f"test -s {shlex.quote(path)}", check=False).returncode == 0


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path, output_dir: Path) -> dict[str, Any]:
    return {
        "path": str(path.relative_to(output_dir)).replace(os.sep, "/"),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def input_record(path: Path) -> dict[str, Any]:
    return {"path": str(path), "size": path.stat().st_size, "sha256": sha256_file(path)}


def repository_record() -> dict[str, Any]:
    try:
        commit_result = run_command(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], check=False
        )
        status_result = run_command(
            ["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"],
            check=False,
        )
        if commit_result.returncode != 0 or status_result.returncode != 0:
            return {"commit": None, "dirty": None}
        return {
            "commit": commit_result.stdout.strip() or None,
            "dirty": bool(status_result.stdout.strip()),
        }
    except CaptureError:
        return {"commit": None, "dirty": None}


def validate_event_stream(path: Path) -> dict[str, Any]:
    counts: dict[str, int] = {}
    trace_end: dict[str, Any] | None = None
    with path.open("r", encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise CaptureError(f"invalid JSONL at line {line_number}: {exc}") from exc
            if record.get("schema") != EVENT_SCHEMA:
                raise CaptureError(f"unexpected event schema at line {line_number}")
            event_type = record.get("type")
            if not isinstance(event_type, str):
                raise CaptureError(f"missing event type at line {line_number}")
            counts[event_type] = counts.get(event_type, 0) + 1
            if event_type == "trace_end":
                trace_end = record

    if counts.get("clock_snapshot", 0) < 1:
        raise CaptureError("Anettrace JSONL has no clock_snapshot")
    if counts.get("trace_end", 0) != 1 or trace_end is None:
        raise CaptureError("Anettrace JSONL must contain exactly one trace_end")
    return {
        "records": sum(counts.values()),
        "event_types": counts,
        "event_count": trace_end.get("event_count"),
        "exported_events": trace_end.get("exported_events"),
        "lost_events": trace_end.get("lost_events"),
    }


def convert_events(events: Path, output: Path) -> list[str]:
    converter = ROOT / "tools" / "anettrace_to_perfetto.py"
    command = perfetto_python_command(converter, str(events), str(output))
    run_command(command)
    if not output.is_file() or output.stat().st_size == 0:
        raise CaptureError("converter did not produce a non-empty Perfetto trace")
    return command


def perfetto_python_command(script: Path, *arguments: str) -> list[str]:
    if importlib.util.find_spec("perfetto") is not None:
        return [sys.executable, str(script), *arguments]
    if shutil.which("uv"):
        return [
            "uv",
            "run",
            "--with",
            "perfetto==0.57.2",
            "python",
            str(script),
            *arguments,
        ]
    raise CaptureError("install perfetto==0.57.2 or uv to process the Perfetto trace")


def merge_and_validate(
    system_trace: Path,
    anettrace_trace: Path,
    output: Path,
    report: Path,
    trace_processor: Path | None,
) -> tuple[list[str], dict[str, Any]]:
    merger = ROOT / "tools" / "merge_trace_with_anettrace.py"
    arguments = [
        str(system_trace),
        str(anettrace_trace),
        str(output),
        "--report",
        str(report),
    ]
    if trace_processor:
        arguments.extend(["--trace-processor", str(trace_processor)])
    command = perfetto_python_command(merger, *arguments)
    run_command(command)
    try:
        merge_report = json.loads(report.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CaptureError(f"cannot read merge integrity report: {error}") from error
    if merge_report.get("status") != "success":
        raise CaptureError("merged trace did not pass integrity checks")
    return command, merge_report


def concatenate_traces(inputs: Sequence[Path], output: Path) -> None:
    temporary = output.with_suffix(output.suffix + ".tmp")
    try:
        with temporary.open("wb") as destination:
            for path in inputs:
                if not path.is_file() or path.stat().st_size == 0:
                    raise CaptureError(f"cannot merge empty trace: {path}")
                with path.open("rb") as source:
                    shutil.copyfileobj(source, destination)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)


def start_external(command: Sequence[str], output_dir: Path) -> subprocess.Popen[Any]:
    kwargs: dict[str, Any] = {"cwd": output_dir}
    if os.name == "nt":
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs["start_new_session"] = True
    try:
        return subprocess.Popen(list(command), **kwargs)
    except OSError as exc:
        raise CaptureError(f"failed to start external command: {exc}") from exc


def stop_external(process: subprocess.Popen[Any], timeout_s: float = 5.0) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "nt" and hasattr(signal, "CTRL_BREAK_EVENT"):
            process.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=timeout_s)
    except (OSError, subprocess.TimeoutExpired):
        process.terminate()
        try:
            process.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2.0)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def prepare_output_dir(path: Path) -> Path:
    path = path.resolve()
    if path.exists() and any(path.iterdir()):
        raise CaptureError(f"output directory is not empty: {path}")
    path.mkdir(parents=True, exist_ok=True)
    return path


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Capture Anettrace with PerfAllInOne-style Android trace profiles."
    )
    target = parser.add_argument_group("Anettrace filter")
    target.add_argument("--uid", type=int, help="Android UID to trace")
    target.add_argument("--pid", type=int, help="exact Android thread ID to trace")
    target.add_argument(
        "--trace-detail",
        action="store_true",
        help="keep detailed kernel network stages instead of compact stages",
    )

    parser.add_argument(
        "--profile",
        choices=("sched", "light", "full", "long", "none"),
        default="sched",
        help="system Perfetto profile (default: sched)",
    )
    parser.add_argument("--duration", type=int, help="capture seconds; profile default when omitted")
    parser.add_argument("--out", type=Path, help="new or empty output directory")
    parser.add_argument("--anettrace", type=Path, default=ROOT / "src" / "anettrace")
    parser.add_argument("--device", help="adb device serial")
    parser.add_argument("--adb", default="adb", help="adb executable")
    parser.add_argument("--perfetto-config", type=Path, help="custom Perfetto textproto config")
    parser.add_argument(
        "--trace-processor",
        type=Path,
        help="Trace Processor CLI used for strict merge validation",
    )
    parser.add_argument("--simpleperf-app", help="also record this Android package")
    parser.add_argument("--simpleperf-pid", type=int, help="also record this process ID")
    parser.add_argument("--simpleperf-frequency", type=int, default=1000)
    parser.add_argument("--skip-convert", action="store_true", help="leave Anettrace as JSONL")
    parser.add_argument("--keep-remote", action="store_true", help="keep device-side temporary files")
    parser.add_argument(
        "--external-command",
        nargs=argparse.REMAINDER,
        help="host command to run during capture; this option must be last",
    )
    args = parser.parse_args(argv)

    if args.uid is None and args.pid is None:
        parser.error("specify --uid or --pid to bound the capture")
    if args.uid is not None and args.uid < 0:
        parser.error("UID cannot be negative")
    if args.pid is not None and args.pid <= 0:
        parser.error("TID must be greater than zero")
    if args.uid == 0 and args.pid is None:
        parser.error("--uid 0 alone is too broad; add --pid")
    if args.duration is not None and args.duration <= 0:
        parser.error("duration must be a positive integer")
    if args.perfetto_config and args.profile == "none":
        parser.error("--perfetto-config cannot be used with --profile none")
    if args.simpleperf_app and args.simpleperf_pid:
        parser.error("choose only one of --simpleperf-app and --simpleperf-pid")
    if args.simpleperf_pid is not None and args.simpleperf_pid <= 0:
        parser.error("simpleperf PID must be greater than zero")
    if args.simpleperf_frequency <= 0:
        parser.error("simpleperf frequency must be greater than zero")
    if args.simpleperf_app and not re.fullmatch(r"[A-Za-z0-9._:]+", args.simpleperf_app):
        parser.error("invalid Android package name")
    if args.external_command == []:
        parser.error("--external-command needs a command")

    args.duration = args.duration or DEFAULT_DURATIONS[args.profile]
    if args.out is None:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        args.out = ROOT / "output" / f"trace-capture-{stamp}"
    return args


def device_value(adb: Adb, script: str) -> str:
    result = adb.shell(script, check=False)
    return result.stdout.strip().replace("\r", "") if result.returncode == 0 else ""


def capture(args: argparse.Namespace) -> Path:
    output_dir = prepare_output_dir(args.out)
    session_id = uuid.uuid4().hex[:12]
    remote_dir = f"{REMOTE_ROOT}/anettrace-capture-{session_id}"
    remote_binary = f"{remote_dir}/anettrace"
    remote_events = f"{remote_dir}/anettrace-events.jsonl"
    remote_system_trace = f"{PERFETTO_TRACE_ROOT}/anettrace-capture-{session_id}.pftrace"
    remote_config = f"{PERFETTO_CONFIG_ROOT}/anettrace-capture-{session_id}.pbtxt"
    remote_perf_data = f"{remote_dir}/perf.data"
    manifest_path = output_dir / "session-manifest.json"
    started_at = utc_now()
    started_monotonic = time.monotonic()
    stop_requested = threading.Event()
    errors: list[str] = []
    warnings: list[str] = []
    commands: dict[str, Any] = {}
    remote_processes: list[RemoteProcess] = []
    external_process: subprocess.Popen[Any] | None = None
    status = "failed"
    previous_handlers: dict[int, Any] = {}

    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "session_id": session_id,
        "status": status,
        "started_at_utc": started_at,
        "duration_s": args.duration,
        "profile": args.profile,
        "filter": {"uid": args.uid, "tid": args.pid},
        "commands": commands,
        "repository": repository_record(),
        "device": {},
        "outputs": [],
        "errors": errors,
        "warnings": warnings,
    }

    def request_stop(_signum: int, _frame: Any) -> None:
        stop_requested.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.getsignal(signum)
        signal.signal(signum, request_stop)

    adb = Adb(args.adb, args.device)
    anettrace_process: RemoteProcess | None = None
    companion_processes: list[RemoteProcess] = []
    interrupted = False

    try:
        if not args.anettrace.is_file():
            raise CaptureError(f"Anettrace binary does not exist: {args.anettrace}")
        if args.perfetto_config and not args.perfetto_config.is_file():
            raise CaptureError(f"Perfetto config does not exist: {args.perfetto_config}")
        if args.trace_processor and not args.trace_processor.is_file():
            raise CaptureError(f"Trace Processor does not exist: {args.trace_processor}")

        manifest["inputs"] = {"anettrace": input_record(args.anettrace.resolve())}
        if args.perfetto_config:
            manifest["inputs"]["perfetto_config"] = input_record(
                args.perfetto_config.resolve()
            )

        if adb.run("get-state").stdout.strip() != "device":
            raise CaptureError("Android device is not ready")
        if device_value(adb, "id -u") != "0":
            raise CaptureError("adb shell must be root")

        manifest["device"] = {
            "serial": args.device or device_value(adb, "getprop ro.serialno"),
            "product": device_value(adb, "getprop ro.product.device"),
            "fingerprint": device_value(adb, "getprop ro.build.fingerprint"),
            "kernel": device_value(adb, "uname -a"),
            "boot_id": device_value(adb, "cat /proc/sys/kernel/random/boot_id"),
        }

        adb.shell(f"mkdir -p {shlex.quote(remote_dir)}")
        adb.push(args.anettrace.resolve(), remote_binary)
        adb.shell(f"chmod 0755 {shlex.quote(remote_binary)}")

        local_config: Path | None = None
        if args.profile != "none":
            if device_value(adb, "command -v perfetto") == "":
                raise CaptureError("device has no perfetto command")
            if args.perfetto_config:
                local_config = args.perfetto_config.resolve()
            else:
                local_config = output_dir / "perfetto-config.pbtxt"
                local_config.write_text(
                    render_perfetto_config(args.profile, args.duration), encoding="utf-8"
                )
            adb.push(local_config, remote_config)

        filter_args: list[str] = []
        if args.uid is not None:
            filter_args.extend(["--uid", str(args.uid)])
        if args.pid is not None:
            filter_args.extend(["--pid", str(args.pid)])
        trace_mode_args = ["--trace-detail"] if args.trace_detail else []
        anettrace_parts = [
            remote_binary,
            "--perfetto-events",
            remote_events,
            *trace_mode_args,
            *filter_args,
            "-v",
        ]
        anettrace_command = " ".join(
            shlex.quote(part) for part in anettrace_parts
        )
        commands["anettrace"] = anettrace_parts
        anettrace_process = start_remote(adb, "anettrace", anettrace_command, remote_dir)
        remote_processes.append(anettrace_process)
        time.sleep(0.2)
        if not remote_alive(adb, anettrace_process):
            raise CaptureError("Anettrace exited during startup")

        if args.profile != "none":
            perfetto_command = " ".join(
                shlex.quote(part)
                for part in ["perfetto", "--txt", "-c", remote_config, "-o", remote_system_trace]
            )
            commands["perfetto"] = [
                "perfetto",
                "--txt",
                "-c",
                remote_config,
                "-o",
                remote_system_trace,
            ]
            perfetto_process = start_remote(adb, "perfetto", perfetto_command, remote_dir)
            remote_processes.append(perfetto_process)
            companion_processes.append(perfetto_process)

        if args.simpleperf_app or args.simpleperf_pid:
            if device_value(adb, "command -v simpleperf") == "":
                raise CaptureError("device has no simpleperf command")
            target = (
                ["--app", args.simpleperf_app]
                if args.simpleperf_app
                else ["-p", str(args.simpleperf_pid)]
            )
            simpleperf_parts = [
                "simpleperf",
                "record",
                *target,
                "--duration",
                str(args.duration),
                "-f",
                str(args.simpleperf_frequency),
                "--call-graph",
                "dwarf",
                "-o",
                remote_perf_data,
            ]
            commands["simpleperf"] = simpleperf_parts
            simpleperf_process = start_remote(
                adb,
                "simpleperf",
                " ".join(shlex.quote(part) for part in simpleperf_parts),
                remote_dir,
            )
            remote_processes.append(simpleperf_process)
            companion_processes.append(simpleperf_process)

        if args.external_command:
            commands["external"] = list(args.external_command)
            external_process = start_external(args.external_command, output_dir)

        deadline = time.monotonic() + args.duration
        while time.monotonic() < deadline:
            if stop_requested.wait(timeout=min(0.25, max(0.0, deadline - time.monotonic()))):
                interrupted = True
                break
            if anettrace_process and not remote_alive(adb, anettrace_process):
                raise CaptureError("Anettrace exited before capture completed")
            for process in companion_processes:
                if not remote_alive(adb, process) and deadline - time.monotonic() > 0.5:
                    raise CaptureError(f"{process.name} exited before capture completed")
            if (
                external_process
                and external_process.poll() is not None
                and deadline - time.monotonic() > 0.5
            ):
                raise CaptureError(
                    f"external command exited early with status {external_process.returncode}"
                )

        if external_process and external_process.poll() not in (None, 0):
            raise CaptureError(
                f"external command failed with status {external_process.returncode}"
            )

        if anettrace_process and remote_alive(adb, anettrace_process):
            signal_remote(adb, anettrace_process, "INT")
            if not wait_remote(adb, anettrace_process, 5.0):
                signal_remote(adb, anettrace_process, "TERM")
                if not wait_remote(adb, anettrace_process, 2.0):
                    raise CaptureError("Anettrace did not stop after SIGINT/SIGTERM")

        for process in companion_processes:
            if remote_alive(adb, process):
                signal_remote(adb, process, "TERM")
                if not wait_remote(adb, process, 5.0):
                    raise CaptureError(f"{process.name} did not stop")

        if external_process:
            stop_external(external_process)

        pull_specs = [
            (remote_events, output_dir / "anettrace-events.jsonl", True),
            (f"{remote_dir}/anettrace.log", output_dir / "anettrace.log", False),
        ]
        if args.profile != "none":
            pull_specs.extend(
                [
                    (remote_system_trace, output_dir / "system.pftrace", True),
                    (f"{remote_dir}/perfetto.log", output_dir / "perfetto.log", False),
                ]
            )
        if args.simpleperf_app or args.simpleperf_pid:
            pull_specs.extend(
                [
                    (remote_perf_data, output_dir / "perf.data", True),
                    (f"{remote_dir}/simpleperf.log", output_dir / "simpleperf.log", False),
                ]
            )

        for remote, local, required in pull_specs:
            if remote_file_exists(adb, remote):
                adb.pull(remote, local)
            elif required:
                raise CaptureError(f"missing device output: {remote}")

        events_path = output_dir / "anettrace-events.jsonl"
        event_summary = validate_event_stream(events_path)
        manifest["anettrace"] = event_summary

        anettrace_trace = output_dir / "anettrace.pftrace"
        if not args.skip_convert:
            commands["converter"] = convert_events(events_path, anettrace_trace)
            if args.profile != "none":
                merge_command, merge_report = merge_and_validate(
                    output_dir / "system.pftrace",
                    anettrace_trace,
                    output_dir / "anettrace-combined.pftrace",
                    output_dir / "merge-integrity.json",
                    args.trace_processor,
                )
                commands["merge"] = merge_command
                manifest["merge"] = {
                    "method": merge_report["method"],
                    "inputs": ["system.pftrace", "anettrace.pftrace"],
                    "output": "anettrace-combined.pftrace",
                    "integrity_report": "merge-integrity.json",
                    "integrity": merge_report["integrity"],
                }

        if interrupted:
            status = "interrupted"
            raise CaptureError("capture interrupted by signal")
        status = "success"
        return manifest_path
    except CaptureError as exc:
        errors.append(str(exc))
        raise
    except (OSError, ValueError) as exc:
        errors.append(str(exc))
        raise CaptureError(str(exc)) from exc
    finally:
        try:
            if anettrace_process and remote_alive(adb, anettrace_process):
                signal_remote(adb, anettrace_process, "INT")
                wait_remote(adb, anettrace_process, 2.0)
            for process in companion_processes:
                if remote_alive(adb, process):
                    signal_remote(adb, process, "TERM")
        except CaptureError as exc:
            warnings.append(f"remote process cleanup failed: {exc}")
        if external_process:
            stop_external(external_process)

        for process in remote_processes:
            local_log = output_dir / f"{process.name}.log"
            try:
                if not local_log.exists() and remote_file_exists(adb, process.log_path):
                    adb.pull(process.log_path, local_log)
            except CaptureError as exc:
                warnings.append(f"log collection failed: {exc}")

        if remote_processes:
            fallback_outputs = [
                (remote_events, output_dir / "anettrace-events.jsonl"),
                (remote_system_trace, output_dir / "system.pftrace"),
                (remote_perf_data, output_dir / "perf.data"),
            ]
            for remote, local in fallback_outputs:
                try:
                    if not local.exists() and remote_file_exists(adb, remote):
                        adb.pull(remote, local)
                except CaptureError as exc:
                    warnings.append(f"partial output collection failed: {exc}")

        if not args.keep_remote:
            try:
                adb.shell(f"rm -rf {shlex.quote(remote_dir)}", check=False)
                adb.shell(f"rm -f {shlex.quote(remote_config)}", check=False)
                adb.shell(f"rm -f {shlex.quote(remote_system_trace)}", check=False)
            except CaptureError as exc:
                warnings.append(f"remote directory cleanup failed: {exc}")

        manifest["status"] = status
        manifest["ended_at_utc"] = utc_now()
        manifest["elapsed_s"] = round(time.monotonic() - started_monotonic, 3)
        manifest["outputs"] = [
            file_record(path, output_dir)
            for path in sorted(output_dir.iterdir())
            if path.is_file() and path != manifest_path and not path.name.endswith(".tmp")
        ]
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        for signum, previous in previous_handlers.items():
            signal.signal(signum, previous)


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = parse_args(argv)
        manifest = capture(args)
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"capture complete: {manifest.parent}")
    print(f"manifest: {manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
