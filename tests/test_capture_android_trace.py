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
    def test_custom_config_replaces_only_top_level_duration(self) -> None:
        source = '''# duration_ms: 1
duration_ms /* note */ : 0x20;
data_sources { config { name: "duration_ms: 7" duration_ms: 42 } }
duration_ms: 90000
'''
        bounded = MODULE.bound_perfetto_config(source, 66)
        self.assertIn("# duration_ms: 1", bounded)
        self.assertIn('name: "duration_ms: 7" duration_ms: 42', bounded)
        self.assertNotIn("0x20", bounded)
        self.assertNotIn("90000", bounded)
        self.assertTrue(bounded.endswith("duration_ms: 66000\n"))
        for invalid in ("", "duration_ms: nope", "duration_ms: 1.5"):
            with self.subTest(invalid=invalid), self.assertRaises(MODULE.CaptureError):
                MODULE.bound_perfetto_config(invalid, 66)

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
    def test_explicit_root_command_wraps_device_shell_only(self) -> None:
        adb = MODULE.Adb("adb", "device", "su -c")
        with mock.patch.object(MODULE, "run_command") as run_command:
            run_command.return_value = MODULE.subprocess.CompletedProcess(
                [], 0, "", ""
            )
            adb.shell("id -u")
        command = run_command.call_args.args[0]
        self.assertEqual(command[:4], ["adb", "-s", "device", "shell"])
        self.assertEqual(command[4], "su -c 'id -u'")

    def test_explicit_root_command_stages_push_and_pull(self) -> None:
        adb = MODULE.Adb("adb", None, "su -c")
        with mock.patch.object(MODULE, "run_command") as run_command:
            run_command.return_value = MODULE.subprocess.CompletedProcess(
                [], 0, "", ""
            )
            adb.push(Path("/tmp/source"), "/data/root/destination")
            adb.pull("/data/root/source", Path("/tmp/destination"))
        commands = [call.args[0] for call in run_command.call_args_list]
        self.assertEqual(commands[0][:2], ["adb", "push"])
        self.assertIn("su -c", commands[1][-1])
        self.assertEqual(commands[3][0:2], ["adb", "shell"])
        self.assertIn("chown 2000:2000", commands[3][-1])
        self.assertEqual(commands[4][0:2], ["adb", "pull"])

    def test_profile_duration_defaults(self) -> None:
        full = MODULE.parse_args(["--uid", "10000", "--profile", "full"])
        long_capture = MODULE.parse_args(["--uid", "10000", "--profile", "long"])
        self.assertEqual(full.duration, 20)
        self.assertEqual(long_capture.duration, 600)

    def test_package_target_is_private_by_default(self) -> None:
        args = MODULE.parse_args(["--package", "com.example.app"])
        self.assertEqual(args.package, "com.example.app")
        self.assertIsNone(args.uid)
        self.assertTrue(args.redact_device_metadata)

    def test_package_and_uid_are_mutually_exclusive(self) -> None:
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--package", "com.example.app", "--uid", "10000"])

    def test_invalid_package_is_rejected_before_device_access(self) -> None:
        for package in ("", "com.example.app;id", "com.example.app\n", "app name"):
            with self.subTest(package=package):
                with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                    MODULE.parse_args(["--package", package])

    def test_tid_alias_preserves_exact_thread_filter(self) -> None:
        current = MODULE.parse_args(["--uid", "10000", "--tid", "42"])
        legacy = MODULE.parse_args(["--uid", "10000", "--pid", "42"])
        self.assertEqual((current.uid, current.pid), (legacy.uid, legacy.pid))
        self.assertEqual(MODULE.parse_args(["--tid", "42"]).pid, 42)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--tid", "42", "--pid", "43"])

    def test_trace_detail_is_forwarded_explicitly(self) -> None:
        args = MODULE.parse_args(["--uid", "10000", "--trace-detail"])
        self.assertTrue(args.trace_detail)

    def test_wakeup_chain_is_opt_in(self) -> None:
        self.assertFalse(MODULE.parse_args(["--uid", "10000"]).wakeup_chain)
        self.assertTrue(MODULE.parse_args(["--uid", "10000", "--wakeup-chain"]).wakeup_chain)

    def test_rx_context_is_opt_in_and_requires_a_target(self) -> None:
        self.assertFalse(MODULE.parse_args(["--uid", "10000"]).rx_context)
        self.assertTrue(MODULE.parse_args(["--package", "com.example.app", "--rx-context"]).rx_context)
        with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
            MODULE.parse_args(["--rx-context"])

    def test_connect_diagnostics_hard_limit_contract(self) -> None:
        args = MODULE.parse_args(
            [
                "--uid",
                "10000",
                "--connect-diagnostics",
                "--max-device-file-mib",
                "256",
                "--redact-device-metadata",
            ]
        )
        self.assertTrue(args.connect_diagnostics)
        self.assertEqual(args.max_device_file_mib, 256)
        self.assertTrue(args.redact_device_metadata)

    def test_resource_sampling_is_explicit_and_summarized(self) -> None:
        args = MODULE.parse_args(
            ["--uid", "10000", "--resource-sample-interval", "5"]
        )
        self.assertEqual(args.resource_sample_interval, 5)
        summary = MODULE.summarize_resource_samples(
            [
                {"elapsed_s": 1.0, "rss_kib": 100, "cpu_ticks": 10, "event_file_bytes": 4},
                {"elapsed_s": 6.0, "rss_kib": 140, "cpu_ticks": 60, "event_file_bytes": 20},
            ],
            100,
        )
        self.assertEqual(summary["peak_rss_kib"], 140)
        self.assertEqual(summary["cpu_seconds"], 0.5)
        self.assertEqual(summary["average_cpu_percent"], 10.0)
        self.assertEqual(summary["max_event_file_bytes"], 20)

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
        self.assertEqual(summary["records"], 16)
        self.assertEqual(summary["lost_events"], 0)
        self.assertEqual(summary["event_types"]["packet_event"], 3)

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


class PackageResolutionTest(unittest.TestCase):
    def test_exact_package_match_does_not_select_prefix_match(self) -> None:
        adb = mock.Mock()
        adb.shell.side_effect = [
            MODULE.subprocess.CompletedProcess(
                [], 0, "package:com.example.app.extra uid:10124\n"
                "package:com.example.app uid:10123\n", ""
            ),
            MODULE.subprocess.CompletedProcess(
                [], 0, "package:com.example.app uid:10123\n"
                "package:com.example.shared uid:10123\n", ""
            ),
        ]
        self.assertEqual(
            MODULE.resolve_package(adb, "com.example.app", False), (10123, [], 2)
        )
        self.assertEqual(
            adb.shell.call_args_list[1],
            mock.call("cmd package list packages -U --uid 10123", check=False),
        )

    def test_missing_or_ambiguous_package_fails_without_disclosing_name(self) -> None:
        for output in ("", "package:com.example.app.extra uid:10123\n",
                       "package:com.example.app uid:10123\n"
                       "package:com.example.app uid:110123\n"):
            with self.subTest(output=output):
                adb = mock.Mock()
                adb.shell.return_value = MODULE.subprocess.CompletedProcess([], 0, output, "")
                with self.assertRaises(MODULE.CaptureError) as raised:
                    MODULE.resolve_package(adb, "com.example.app", False)
                self.assertNotIn("com.example.app", str(raised.exception))

    def test_unverified_shared_uid_query_fails_closed(self) -> None:
        adb = mock.Mock()
        adb.shell.side_effect = [
            MODULE.subprocess.CompletedProcess([], 0, "package:com.example.app uid:10123\n", ""),
            MODULE.subprocess.CompletedProcess([], 1, "", "query failed"),
        ]
        with self.assertRaisesRegex(MODULE.CaptureError, "shared UID"):
            MODULE.resolve_package(adb, "com.example.app", False)


class FailureManifestTest(unittest.TestCase):
    def test_package_failure_manifest_redacts_target_and_device_from_errors(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "anettrace"
            binary.write_bytes(b"mock-binary")
            output = root / "capture"
            args = MODULE.parse_args(
                ["--package", "com.example.app", "--device", "PRIVATE-SERIAL",
                 "--anettrace", str(binary), "--out", str(output)]
            )
            with mock.patch.object(MODULE, "Adb") as adb:
                adb.return_value.run.side_effect = MODULE.CaptureError(
                    "adb -s PRIVATE-SERIAL failed while checking com.example.app"
                )
                with self.assertRaises(MODULE.CaptureError):
                    MODULE.capture(args)
            manifest_text = (output / "session-manifest.json").read_text(encoding="utf-8")
            self.assertNotIn("com.example.app", manifest_text)
            self.assertNotIn("PRIVATE-SERIAL", manifest_text)
            self.assertEqual(MODULE.json.loads(manifest_text)["status"], "failed")

    def test_preflight_failure_still_writes_manifest(self) -> None:
        class FakeAdb:
            def __init__(
                self,
                _executable: str,
                _serial: str | None,
                _root_command: str | None = None,
            ):
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
    def test_perfetto_readiness_requires_binary_zero_ack(self) -> None:
        process = MODULE.RemoteProcess("perfetto", 200, "/tmp/perfetto.log", "/tmp/session")
        adb = mock.Mock()
        adb.shell.side_effect = [
            MODULE.subprocess.CompletedProcess([], 1, "", ""),
            MODULE.subprocess.CompletedProcess([], 0, "   0\n", ""),
        ]
        with mock.patch.object(MODULE, "remote_alive", return_value=True), mock.patch.object(MODULE.time, "sleep"):
            MODULE.wait_perfetto_ready(adb, process, "/tmp/ready", 1.0)
        self.assertIn("od -An -tu1 -N1", adb.shell.call_args.args[0])

    def test_perfetto_readiness_rejects_failed_ack_or_early_exit(self) -> None:
        process = MODULE.RemoteProcess("perfetto", 200, "/tmp/perfetto.log", "/tmp/session")
        for output, alive in (("1", True), ("48", True), ("", False)):
            with self.subTest(output=output):
                adb = mock.Mock()
                adb.shell.return_value = MODULE.subprocess.CompletedProcess([], 0, output, "")
                with mock.patch.object(MODULE, "remote_alive", return_value=alive):
                    with self.assertRaises(MODULE.CaptureError):
                        MODULE.wait_perfetto_ready(adb, process, "/tmp/ready", 1.0)

    def test_perfetto_readiness_timeout_is_bounded(self) -> None:
        process = MODULE.RemoteProcess("perfetto", 200, "/tmp/perfetto.log", "/tmp/session")
        with mock.patch.object(MODULE.time, "monotonic", side_effect=[0.0, 2.0]):
            with self.assertRaisesRegex(MODULE.CaptureError, "did not become ready"):
                MODULE.wait_perfetto_ready(mock.Mock(), process, "/tmp/ready", 1.0)

    def test_start_remote_tracks_explicit_command_identity(self) -> None:
        adb = mock.Mock()
        adb.shell.return_value = MODULE.subprocess.CompletedProcess(
            [], 0, "321\n", ""
        )
        process = MODULE.start_remote(
            adb,
            "perfetto",
            "perfetto --txt -c config -o /data/misc/perfetto-traces/session.pftrace",
            "/data/local/tmp/session",
            "/data/misc/perfetto-traces/session.pftrace",
        )
        self.assertEqual(process.pid, 321)
        self.assertEqual(
            process.identity,
            "/data/misc/perfetto-traces/session.pftrace",
        )

    def test_remote_signal_requires_matching_session_identity(self) -> None:
        process = MODULE.RemoteProcess(
            name="anettrace",
            pid=200,
            log_path="/data/local/tmp/session/anettrace.log",
            identity="/data/local/tmp/session",
        )
        adb = mock.Mock()
        adb.shell.return_value = MODULE.subprocess.CompletedProcess([], 1, "", "")
        MODULE.signal_remote(adb, process, "TERM")
        self.assertEqual(adb.shell.call_count, 1)
        self.assertIn("/proc/200/cmdline", adb.shell.call_args.args[0])
        self.assertIn(process.identity, adb.shell.call_args.args[0])

    def test_remote_stop_escalates_only_while_identity_matches(self) -> None:
        process = MODULE.RemoteProcess(
            name="anettrace",
            pid=200,
            log_path="/data/local/tmp/session/anettrace.log",
            identity="/data/local/tmp/session",
        )
        adb = mock.Mock()
        with mock.patch.object(
            MODULE,
            "remote_alive",
            side_effect=[True, True, True],
        ), mock.patch.object(
            MODULE, "wait_remote", side_effect=[False, True]
        ), mock.patch.object(MODULE, "signal_remote") as signal_remote:
            self.assertTrue(
                MODULE.stop_remote(adb, process, "INT", timeout_s=0.01)
            )
        self.assertEqual(
            signal_remote.call_args_list,
            [mock.call(adb, process, "INT"), mock.call(adb, process, "KILL")],
        )

    def test_remote_readiness_waits_for_anettrace_marker(self) -> None:
        process = MODULE.RemoteProcess(
            name="anettrace",
            pid=200,
            log_path="/data/local/tmp/session/anettrace.log",
            identity="/data/local/tmp/session/anettrace",
        )
        adb = mock.Mock()
        adb.shell.side_effect = [
            MODULE.subprocess.CompletedProcess([], 1, "", ""),
            MODULE.subprocess.CompletedProcess([], 0, "", ""),
        ]
        with (
            mock.patch.object(MODULE, "remote_alive", return_value=True),
            mock.patch.object(MODULE.time, "sleep"),
        ):
            MODULE.wait_remote_ready(adb, process, "begin trace...", 1.0)
        self.assertEqual(adb.shell.call_count, 2)
        self.assertIn("begin trace...", adb.shell.call_args.args[0])

    def test_remote_readiness_rejects_early_exit(self) -> None:
        process = MODULE.RemoteProcess(
            name="anettrace",
            pid=200,
            log_path="/data/local/tmp/session/anettrace.log",
            identity="/data/local/tmp/session/anettrace",
        )
        adb = mock.Mock()
        adb.shell.return_value = MODULE.subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(MODULE, "remote_alive", return_value=False):
            with self.assertRaisesRegex(MODULE.CaptureError, "exited during startup"):
                MODULE.wait_remote_ready(adb, process, "begin trace...", 1.0)

    def test_mock_device_capture_records_outputs_and_metadata(self) -> None:
        class FakeAdb:
            next_pid = 200
            package_uid = 10123
            readiness_delay = 0.0
            ready_status = 0

            def __init__(
                self,
                _executable: str,
                _serial: str | None,
                _root_command: str | None = None,
            ):
                self.alive: dict[int, bool] = {}
                self.expires: dict[int, float] = {}
                self.configs: dict[str, str] = {}

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
                    "cmd package list packages -U com.example.app":
                        f"package:com.example.app uid:{self.package_uid}\n",
                    f"cmd package list packages -U --uid {self.package_uid}":
                        f"package:com.example.app uid:{self.package_uid}\n"
                        f"package:com.example.shared uid:{self.package_uid}\n",
                }
                if script in values:
                    return self.result(stdout=values[script])
                if script.endswith("& echo $!"):
                    pid = self.next_pid
                    FakeAdb.next_pid += 1
                    self.alive[pid] = True
                    duration = MODULE.re.search(r"--duration (\d+)", script)
                    if duration:
                        self.expires[pid] = MODULE.time.monotonic() + int(duration[1])
                    elif script.startswith("perfetto "):
                        config = MODULE.re.search(r"-c (\S+)", script)[1]
                        duration_ms = MODULE.re.findall(r"duration_ms:\s*(\d+)", self.configs[config])[-1]
                        self.expires[pid] = MODULE.time.monotonic() + int(duration_ms) / 1000
                    return self.result(stdout=f"{pid}\n")
                if script.startswith("grep -Fq -- 'begin trace...' "):
                    return self.result()
                if "od -An -tu1 -N1" in script:
                    MODULE.time.sleep(self.readiness_delay)
                    return self.result(stdout=f"{self.ready_status}\n")
                match = MODULE.re.match(
                    r"test -r /proc/([0-9]+)/cmdline && ", script
                )
                if match:
                    pid = int(match.group(1))
                    if MODULE.time.monotonic() >= self.expires.get(pid, float("inf")):
                        self.alive[pid] = False
                    return self.result(0 if self.alive.get(pid, False) else 1)
                match = MODULE.re.fullmatch(r"kill -(?:INT|TERM) ([0-9]+)", script)
                if match:
                    self.alive[int(match.group(1))] = False
                    return self.result()
                if script.startswith("test -s "):
                    return self.result()
                if script.startswith("test -e "):
                    return self.result(returncode=1)
                return self.result()

            def push(self, _source: Path, _destination: str) -> None:
                if _destination.endswith(".pbtxt"):
                    self.configs[_destination] = _source.read_text(encoding="utf-8")

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
                    "--trace-detail",
                    "--wakeup-chain",
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
            self.assertIn("--trace-detail", manifest["commands"]["anettrace"])
            self.assertIn("--wakeup-chain", manifest["commands"]["anettrace"])
            self.assertTrue(manifest["wakeup_chain"]["enabled"])
            self.assertEqual(manifest["readiness"]["perfetto"], "ready")
            self.assertIn("--notify-fd", manifest["commands"]["perfetto"])
            duration_index = manifest["commands"]["anettrace"].index("--duration")
            self.assertEqual(
                manifest["commands"]["anettrace"][duration_index + 1], "66"
            )
            self.assertEqual(manifest["duration_s"], 1)
            self.assertEqual(manifest["collector_safety_duration_s"], 66)
            self.assertTrue(manifest["cleanup"]["verified"])
            self.assertTrue(manifest["cleanup"]["processes_verified"])
            self.assertEqual(manifest["cleanup"]["remaining_processes"], [])
            self.assertEqual(manifest["cleanup"]["remaining"], [])
            output_names = {record["path"] for record in manifest["outputs"]}
            self.assertIn("anettrace-events.jsonl", output_names)
            self.assertIn("system.pftrace", output_names)

            failed_output = root / "failed-cleanup"
            args.out = failed_output
            with mock.patch.object(MODULE, "Adb", FakeAdb), mock.patch.object(
                MODULE, "stop_remote", return_value=False
            ):
                with self.assertRaisesRegex(
                    MODULE.CaptureError, "cleanup could not be verified"
                ):
                    MODULE.capture(args)
            failed_manifest = MODULE.json.loads(
                (failed_output / "session-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(failed_manifest["status"], "failed")
            self.assertFalse(failed_manifest["cleanup"]["verified"])

            package_output = root / "package-capture"
            package_args = MODULE.parse_args(
                ["--package", "com.example.app", "--device", "PRIVATE-SERIAL",
                 "--duration", "1", "--profile", "none", "--skip-convert",
                 "--anettrace", str(binary), "--out", str(package_output)]
            )
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                package_manifest_path = MODULE.capture(package_args)
            package_manifest_text = package_manifest_path.read_text(encoding="utf-8")
            package_manifest = MODULE.json.loads(package_manifest_text)
            self.assertEqual(package_manifest["filter"]["uid"], 10123)
            self.assertEqual(package_manifest["target"]["uid_candidate_count"], 2)
            self.assertTrue(package_manifest["target"]["shared_uid"])
            self.assertTrue(any("shared UID" in item for item in package_manifest["warnings"]))
            self.assertNotIn("com.example", package_manifest_text)
            self.assertNotIn("PRIVATE-SERIAL", package_manifest_text)
            self.assertFalse({"serial", "fingerprint", "kernel", "boot_id"} &
                             package_manifest["device"].keys())
            command = package_manifest["commands"]["anettrace"]
            self.assertEqual(command[command.index("--uid") + 1], "10123")
            self.assertNotIn("--package", command)

            FakeAdb.package_uid = 0
            package_args.out = root / "root-package-capture"
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                with self.assertRaisesRegex(MODULE.CaptureError, "UID 0.*too broad"):
                    MODULE.capture(package_args)

            package_args.pid = 42
            package_args.out = root / "root-thread-capture"
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                root_manifest_path = MODULE.capture(package_args)
            root_manifest = MODULE.json.loads(root_manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(root_manifest["filter"], {"uid": 0, "tid": 42})
            command = root_manifest["commands"]["anettrace"]
            self.assertEqual(command[command.index("--uid") + 1], "0")
            self.assertEqual(command[command.index("--pid") + 1], "42")

            FakeAdb.readiness_delay = 0.75
            args.out = root / "delayed-readiness"
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                delayed_path = MODULE.capture(args)
            delayed = MODULE.json.loads(delayed_path.read_text(encoding="utf-8"))
            self.assertEqual(delayed["status"], "success")
            self.assertTrue(delayed["cleanup"]["verified"])

            custom = root / "custom.pbtxt"
            custom_source = "duration_ms: 1\nbuffers { size_kb: 1024 }\n"
            custom.write_text(custom_source, encoding="utf-8")
            args.perfetto_config = custom
            args.out = root / "custom-delayed-readiness"
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                custom_manifest = MODULE.capture(args)
            self.assertEqual(MODULE.json.loads(custom_manifest.read_text())["status"], "success")
            self.assertEqual(custom.read_text(encoding="utf-8"), custom_source)
            self.assertIn("duration_ms: 66000", (args.out / "perfetto-config.pbtxt").read_text())

            FakeAdb.ready_status = 1
            FakeAdb.readiness_delay = 0
            args.out = root / "failed-perfetto-readiness"
            with mock.patch.object(MODULE, "Adb", FakeAdb):
                with self.assertRaisesRegex(MODULE.CaptureError, "failed to become ready"):
                    MODULE.capture(args)
            failed_ready = MODULE.json.loads((args.out / "session-manifest.json").read_text())
            self.assertTrue(failed_ready["cleanup"]["verified"])
            self.assertNotIn("ready_at_utc", failed_ready["readiness"])


if __name__ == "__main__":
    unittest.main()
