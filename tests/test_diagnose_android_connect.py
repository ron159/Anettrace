#!/usr/bin/env python3
"""Unit tests for the Android TCP connect diagnostic orchestrator."""

from __future__ import annotations

import importlib.util
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


class PrivacyAndFailureTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
