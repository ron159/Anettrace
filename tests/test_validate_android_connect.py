#!/usr/bin/env python3
"""Static contracts for repeatable Android connect acceptance."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "validate_android_connect.py"
SPEC = importlib.util.spec_from_file_location("validate_android_connect", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class AndroidAcceptanceContractTest(unittest.TestCase):
    def test_default_gate_repeats_all_three_scenarios(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--workload",
                "/tmp/workload",
                "--trace-processor",
                "/tmp/tp",
                "--out",
                "/tmp/acceptance",
            ]
        )
        self.assertEqual(args.repeat, 3)
        self.assertEqual(args.duration, 20)
        self.assertEqual(
            MODULE.SCENARIOS,
            {
                "success": "success",
                "refused": "peer_refused",
                "timeout": "timeout_no_response",
            },
        )

    def test_device_selector_is_used_but_not_embedded_in_workload_shell(self) -> None:
        args = MODULE.parse_args(
            [
                "--package",
                "com.example.app",
                "--binary",
                "/tmp/anettrace",
                "--workload",
                "/tmp/workload",
                "--trace-processor",
                "/tmp/tp",
                "--out",
                "/tmp/acceptance",
                "--device",
                "sensitive-serial",
            ]
        )
        command = MODULE.external_workload_command(
            args,
            "/data/local/tmp/session/connect-workload",
            "/data/local/tmp/session/success.pid",
            10123,
            "success",
        )
        self.assertEqual(command[:3], ["adb", "-s", "sensitive-serial"])
        self.assertNotIn("sensitive-serial", command[-1])
        self.assertIn("--uid 10123", command[-1])
        self.assertIn("echo $$", command[-1])
        self.assertIn("success.pid", command[-1])

    def test_workload_cleanup_only_signals_matching_process(self) -> None:
        adb = mock.Mock()
        with mock.patch.object(MODULE.DIAGNOSE, "device_value", return_value="123"):
            with mock.patch.object(
                MODULE, "remote_workload_matches", return_value=False
            ):
                self.assertTrue(
                    MODULE.stop_remote_workload(
                        adb,
                        "/data/local/tmp/session/success.pid",
                        "/data/local/tmp/session/connect-workload",
                        require_pid=True,
                    )
                )
        adb.shell.assert_not_called()

    def test_workload_cleanup_terminates_the_matching_process(self) -> None:
        adb = mock.Mock()
        adb.shell.return_value = MODULE.DIAGNOSE.subprocess.CompletedProcess(
            [], 0, "", ""
        )
        with mock.patch.object(MODULE.DIAGNOSE, "device_value", return_value="123"), \
             mock.patch.object(
                 MODULE, "remote_workload_matches", side_effect=[True, False]
             ):
            self.assertTrue(
                MODULE.stop_remote_workload(
                    adb,
                    "/data/local/tmp/session/success.pid",
                    "/data/local/tmp/session/connect-workload",
                    require_pid=True,
                )
            )
        adb.shell.assert_called_once_with("kill -TERM 123", check=False)

    def test_scenario_gate_rejects_extra_attempts_or_outcomes(self) -> None:
        valid = {
            "status": "valid",
            "summary": {
                "attempt_count": 3,
                "outcome_counts": {"success": 3},
            },
        }
        result = MODULE.validate_scenario_report(
            valid, scenario="success", expected="success", repeat=3
        )
        self.assertEqual(result["observed_count"], 3)

        extra = {
            "status": "valid",
            "summary": {
                "attempt_count": 4,
                "outcome_counts": {"success": 3, "peer_refused": 1},
            },
        }
        with self.assertRaisesRegex(MODULE.AcceptanceError, "expected exactly"):
            MODULE.validate_scenario_report(
                extra, scenario="success", expected="success", repeat=3
            )


if __name__ == "__main__":
    unittest.main()
