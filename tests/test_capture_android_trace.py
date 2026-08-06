#!/usr/bin/env python3
"""Unit tests for the cross-platform Android trace orchestrator."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "capture_android_trace.py"
SPEC = importlib.util.spec_from_file_location("capture_android_trace", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class PerfettoProfileTest(unittest.TestCase):
    def test_sched_profile_is_small_and_has_suspend_events(self) -> None:
        config = MODULE.render_perfetto_config("sched", 7)
        self.assertIn("size_kb: 32768", config)
        self.assertIn('ftrace_events: "sched/sched_switch"', config)
        self.assertIn('ftrace_events: "power/suspend_resume"', config)
        self.assertNotIn('ftrace_events: "ftrace/print"', config)
        self.assertIn("duration_ms: 7000", config)

    def test_full_profile_keeps_perfallinone_system_sources(self) -> None:
        config = MODULE.render_perfetto_config("full", 20)
        self.assertIn('atrace_categories: "network"', config)
        self.assertIn('name: "android.gpu.memory"', config)
        self.assertIn('name: "linux.sys_stats"', config)
        self.assertIn('name: "android.surfaceflinger.frametimeline"', config)
        self.assertNotIn("write_into_file: true", config)

    def test_long_profile_streams_and_uses_requested_duration(self) -> None:
        config = MODULE.render_perfetto_config("long", 123)
        self.assertIn("size_kb: 153600", config)
        self.assertIn("duration_ms: 123000", config)
        self.assertIn("write_into_file: true", config)
        self.assertIn("file_write_period_ms: 2500", config)


class CliContractTest(unittest.TestCase):
    def test_profile_duration_defaults(self) -> None:
        full = MODULE.parse_args(["--uid", "10000", "--profile", "full"])
        long_capture = MODULE.parse_args(["--uid", "10000", "--profile", "long"])
        self.assertEqual(full.duration, 20)
        self.assertEqual(long_capture.duration, 600)

    def test_uid_zero_needs_exact_tid(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--uid", "0"])
        args = MODULE.parse_args(["--uid", "0", "--pid", "42"])
        self.assertEqual(args.pid, 42)

    def test_external_command_must_be_last_and_is_not_shell_parsed(self) -> None:
        args = MODULE.parse_args(
            ["--uid", "10000", "--external-command", "python", "capture.py", "--fast"]
        )
        self.assertEqual(args.external_command, ["python", "capture.py", "--fast"])


class OutputValidationTest(unittest.TestCase):
    def test_fixture_has_required_clock_and_trace_end(self) -> None:
        summary = MODULE.validate_event_stream(ROOT / "tests" / "fixtures" / "perfetto-events.jsonl")
        self.assertEqual(summary["records"], 9)
        self.assertEqual(summary["lost_events"], 0)
        self.assertEqual(summary["event_types"]["packet_event"], 2)

    def test_missing_trace_end_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(
                '{"schema":"anettrace.perfetto.v1","type":"clock_snapshot"}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(MODULE.CaptureError, "exactly one trace_end"):
                MODULE.validate_event_stream(path)

    def test_raw_trace_concat_is_atomic_and_ordered(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first.pftrace"
            second = root / "second.pftrace"
            output = root / "combined.pftrace"
            first.write_bytes(b"one")
            second.write_bytes(b"two")
            MODULE.concatenate_traces([first, second], output)
            self.assertEqual(output.read_bytes(), b"onetwo")
            self.assertFalse((root / "combined.pftrace.tmp").exists())


class FailureManifestTest(unittest.TestCase):
    def test_preflight_failure_still_writes_manifest(self) -> None:
        class FakeAdb:
            def __init__(self, _executable: str, _serial: str | None):
                pass

            def shell(self, _script: str, *, check: bool = True):
                return MODULE.subprocess.CompletedProcess([], 0, "", "")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture"
            missing_binary = Path(directory) / "missing-anettrace"
            args = MODULE.parse_args(
                [
                    "--uid",
                    "10000",
                    "--profile",
                    "none",
                    "--skip-convert",
                    "--anettrace",
                    str(missing_binary),
                    "--out",
                    str(output),
                ]
            )
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                with self.assertRaisesRegex(MODULE.CaptureError, "does not exist"):
                    MODULE.capture(args)

            manifest = MODULE.json.loads(
                (output / "session-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["status"], "failed")
            self.assertIn("does not exist", manifest["errors"][0])


class SuccessfulCaptureTest(unittest.TestCase):
    def test_mock_device_capture_records_outputs_and_metadata(self) -> None:
        class FakeAdb:
            next_pid = 200

            def __init__(self, _executable: str, _serial: str | None):
                self.alive: dict[int, bool] = {}

            @staticmethod
            def result(returncode: int = 0, stdout: str = ""):
                return MODULE.subprocess.CompletedProcess([], returncode, stdout, "")

            def run(self, *args: str, check: bool = True):
                if args == ("get-state",):
                    return self.result(stdout="device\n")
                return self.result()

            def shell(self, script: str, *, check: bool = True):
                values = {
                    "id -u": "0\n",
                    "command -v perfetto": "/system/bin/perfetto\n",
                    "getprop ro.serialno": "SERIAL1\n",
                    "getprop ro.product.device": "test-device\n",
                    "getprop ro.build.fingerprint": "test/fingerprint\n",
                    "uname -a": "Linux test 6.6 aarch64\n",
                    "cat /proc/sys/kernel/random/boot_id": "boot-123\n",
                }
                if script in values:
                    return self.result(stdout=values[script])
                if script.endswith("& echo $!"):
                    pid = self.next_pid
                    FakeAdb.next_pid += 1
                    self.alive[pid] = True
                    return self.result(stdout=f"{pid}\n")
                match = MODULE.re.fullmatch(r"kill -0 ([0-9]+)", script)
                if match:
                    return self.result(0 if self.alive.get(int(match.group(1)), False) else 1)
                match = MODULE.re.fullmatch(r"kill -(?:INT|TERM) ([0-9]+)", script)
                if match:
                    self.alive[int(match.group(1))] = False
                    return self.result()
                if script.startswith("test -s "):
                    return self.result()
                return self.result()

            def push(self, _source: Path, _destination: str) -> None:
                pass

            def pull(self, source: str, destination: Path) -> None:
                if source.endswith("anettrace-events.jsonl"):
                    destination.write_bytes(
                        (ROOT / "tests" / "fixtures" / "perfetto-events.jsonl").read_bytes()
                    )
                elif source.endswith(".pftrace"):
                    destination.write_bytes(b"system-trace")
                else:
                    destination.write_text("mock log\n", encoding="utf-8")

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "anettrace"
            binary.write_bytes(b"mock-binary")
            output = root / "capture"
            args = MODULE.parse_args(
                [
                    "--uid",
                    "10000",
                    "--duration",
                    "1",
                    "--skip-convert",
                    "--anettrace",
                    str(binary),
                    "--out",
                    str(output),
                ]
            )
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                manifest_path = MODULE.capture(args)

            manifest = MODULE.json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["status"], "success")
            self.assertEqual(manifest["device"]["boot_id"], "boot-123")
            self.assertEqual(manifest["anettrace"]["lost_events"], 0)
            output_names = {record["path"] for record in manifest["outputs"]}
            self.assertIn("anettrace-events.jsonl", output_names)
            self.assertIn("system.pftrace", output_names)


if __name__ == "__main__":
    unittest.main()
