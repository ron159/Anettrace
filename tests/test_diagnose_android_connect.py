#!/usr/bin/env python3
"""Unit tests for the Android TCP connect diagnostic orchestrator."""

from __future__ import annotations

import importlib.util
import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "diagnose_android_connect.py"
SPEC = importlib.util.spec_from_file_location("diagnose_android_connect", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class CliContractTest(unittest.TestCase):
    def test_defaults_are_bounded_and_private(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--out",
                "/tmp/report",
            ]
        )
        self.assertEqual(args.duration, 120)
        self.assertEqual(args.max_report_mib, 512)
        self.assertEqual(args.profile, "sched")
        self.assertFalse(args.include_package)

    def test_capture_arguments_enable_hard_limits_and_redaction(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--out",
                "/tmp/report",
            ]
        )
        capture = MODULE.capture_args(
            args, 10000, Path("/tmp/capture"), Path("/tmp/trace_processor")
        )
        self.assertTrue(capture.connect_diagnostics)
        self.assertTrue(capture.redact_device_metadata)
        self.assertEqual(capture.max_device_file_mib, 256)

    def test_root_command_is_explicitly_forwarded_to_capture(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--out",
                "/tmp/report",
                "--root-command",
                "su -c",
            ]
        )
        capture = MODULE.capture_args(
            args, 10000, Path("/tmp/capture"), Path("/tmp/trace_processor")
        )
        self.assertEqual(capture.root_command, "su -c")

    def test_external_workload_is_forwarded_without_shell_parsing(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--out",
                "/tmp/report",
                "--external-command",
                "adb",
                "shell",
                "workload --scenario success",
            ]
        )
        capture = MODULE.capture_args(
            args, 10000, Path("/tmp/capture"), Path("/tmp/trace_processor")
        )
        self.assertEqual(
            capture.external_command,
            ["adb", "shell", "workload --scenario success"],
        )

    def test_recovery_mode_does_not_require_package_or_binary(self) -> None:
        args = MODULE.parse_args(
            ["--recover-session", "0123456789ab", "--recover-action", "inspect"]
        )
        self.assertEqual(args.recover_session, "0123456789ab")
        self.assertIsNone(args.package)

    def test_recovery_paths_are_exact_and_reject_untrusted_ids(self) -> None:
        paths = MODULE.recovery_paths("0123456789ab")
        self.assertEqual(
            paths[0], "/data/local/tmp/anettrace-capture-0123456789ab"
        )
        with self.assertRaises(MODULE.DiagnosticError):
            MODULE.recovery_paths("../../data")


class PrivacyAndFailureTest(unittest.TestCase):
    def test_release_source_commit_identity_is_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "SOURCE_COMMIT"
            identity.write_text("not-a-commit\n", encoding="utf-8")
            with mock.patch.object(MODULE, "ROOT", Path(directory)):
                with self.assertRaisesRegex(MODULE.DiagnosticError, "full Git"):
                    MODULE.repository_commit()

    def test_source_checkout_identity_rejects_tracked_changes(self) -> None:
        completed = MODULE.subprocess.CompletedProcess
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            MODULE, "ROOT", Path(directory)
        ), mock.patch.object(
            MODULE,
            "run",
            side_effect=[
                completed([], 0, "a" * 40 + "\n", ""),
                completed([], 0, " M tools/diagnose_android_connect.py\n", ""),
            ],
        ):
            with self.assertRaisesRegex(MODULE.DiagnosticError, "tracked changes"):
                MODULE.repository_commit()

    def test_shared_uid_query_is_scoped_to_target_uid(self) -> None:
        adb = mock.Mock()
        adb.shell.side_effect = [
            MODULE.subprocess.CompletedProcess(
                [], 0, "package:com.example.app uid:10123\n", ""
            ),
            MODULE.subprocess.CompletedProcess(
                [],
                0,
                "package:com.example.app uid:10123\n"
                "package:com.example.shared uid:10123\n",
                "",
            ),
        ]
        uid, candidates, count = MODULE.resolve_package(
            adb, "com.example.app", False
        )
        self.assertEqual((uid, candidates, count), (10123, [], 2))
        self.assertEqual(
            adb.shell.call_args_list[1],
            mock.call("cmd package list packages -U --uid 10123", check=False),
        )

    def test_perfetto_raw_service_state_is_parsed_without_human_output(self) -> None:
        # num_sessions=2, num_sessions_started=1, supports_tracing_sessions=true.
        raw = bytes((0x18, 0x02, 0x20, 0x01, 0x38, 0x01))
        self.assertEqual(
            MODULE.parse_perfetto_service_state(raw),
            {
                "supports_tracing_sessions": True,
                "session_count": 2,
                "started_session_count": 1,
            },
        )
        adb = mock.Mock()
        adb.shell.return_value = MODULE.subprocess.CompletedProcess(
            [], 0, base64.b64encode(raw).decode() + "\n", ""
        )
        self.assertEqual(
            MODULE.query_perfetto_service_state(adb)["started_session_count"], 1
        )
        adb.shell.assert_called_once_with(
            "perfetto --query-raw | base64", check=False
        )

    def test_perfetto_service_state_rejects_missing_session_support(self) -> None:
        with self.assertRaisesRegex(
            MODULE.DiagnosticError, "cannot report active tracing sessions"
        ):
            MODULE.parse_perfetto_service_state(bytes((0x18, 0x00, 0x20, 0x00)))

    def test_missing_core_device_capability_stops_before_capture(self) -> None:
        adb = mock.Mock()
        adb.run.return_value = MODULE.subprocess.CompletedProcess([], 0, "device\n", "")
        with mock.patch.object(MODULE, "device_value", return_value="0"), mock.patch.object(
            MODULE, "capability", return_value=False
        ):
            with self.assertRaisesRegex(
                MODULE.DiagnosticError, "missing core device capabilities"
            ):
                MODULE.device_preflight(
                    adb,
                    Path("/tmp/anettrace"),
                    "com.example.app",
                    False,
                    "sched",
                )

    def test_active_perfetto_session_stops_before_device_mutation(self) -> None:
        adb = mock.Mock()
        adb.run.return_value = MODULE.subprocess.CompletedProcess([], 0, "device\n", "")

        def device_value(_adb: object, script: str) -> str:
            if script == "id -u":
                return "0"
            if script == "cat /sys/kernel/tracing/current_tracer":
                return "nop"
            return ""

        with mock.patch.object(MODULE, "device_value", side_effect=device_value), \
             mock.patch.object(MODULE, "capability", return_value=True), \
             mock.patch.object(
                 MODULE,
                 "query_perfetto_service_state",
                 return_value={
                     "supports_tracing_sessions": True,
                     "session_count": 2,
                     "started_session_count": 2,
                 },
             ):
            with self.assertRaisesRegex(
                MODULE.DiagnosticError, "started Perfetto sessions: 2"
            ):
                MODULE.device_preflight(
                    adb,
                    Path("/tmp/anettrace"),
                    "com.example.app",
                    False,
                    "sched",
                )
        adb.push.assert_not_called()

    def test_trace_processor_metrics_create_sched_and_exit_evidence(self) -> None:
        output = (
            "attempt_id,started_ns,duration_ns,tid,tgid,runnable_delay_ns,"
            "running_ns,process_exit_ns\n"
            "00000000000000aa,100,900,20,20,300,500,800\n"
        )
        completed = MODULE.subprocess.CompletedProcess([], 0, output, "")
        with mock.patch.object(MODULE, "run", return_value=completed) as run:
            records, summary = MODULE.query_connect_metrics(
                Path("/tmp/tp"), Path("/tmp/trace")
            )
        run.assert_called_once_with(
            [
                "/tmp/tp",
                "--query-file",
                str(MODULE.CONNECT_METRICS_SQL),
                "/tmp/trace",
            ]
        )
        self.assertEqual(summary["attempt_rows"], 1)
        self.assertEqual(
            [record["type"] for record in records],
            ["connect_sched_delay", "connect_cancel"],
        )
        self.assertEqual(records[0]["delay_ns"], 300)
        self.assertEqual(records[1]["reason"], "process_exit")

    def test_invalid_preflight_still_writes_fixed_private_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            args = MODULE.parse_args(
                [
                    "--package",
                    "com.secret.app",
                    "--binary",
                    str(Path(directory) / "missing"),
                    "--out",
                    str(output),
                ]
            )
            with mock.patch.object(
                MODULE, "resolve_trace_processor", return_value=Path("/tmp/tp")
            ):
                with self.assertRaises(MODULE.DiagnosticError):
                    MODULE.diagnose(args)

            names = {path.name for path in output.iterdir()}
            self.assertEqual(
                names,
                {
                    "report.md",
                    "report.json",
                    "manifest.json",
                    "trace.pftrace",
                    "session.log",
                    "SHA256SUMS",
                },
            )
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            manifest = json.loads(
                (output / "manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["status"], "invalid")
            self.assertNotIn("package", report["target"])
            self.assertNotIn("package", manifest["target"])
            self.assertNotIn("com.secret.app", (output / "session.log").read_text())
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_manifest_never_persists_device_selector(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--out",
                "/tmp/report",
                "--device",
                "sensitive-serial",
            ]
        )
        self.assertEqual(args.device, "sensitive-serial")
        redacted = MODULE.redact_failure(
            "adb -s sensitive-serial failed for com.example.app", args
        )
        self.assertNotIn("sensitive-serial", redacted)
        self.assertNotIn("com.example.app", redacted)
        self.assertEqual(
            MODULE.redacted_messages(
                ["sensitive-serial", "com.example.app"], args
            ),
            ["<redacted>", "<redacted>"],
        )


if __name__ == "__main__":
    unittest.main()
