#!/usr/bin/env python3
"""Unit tests for strict system/network trace merging."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))
SCRIPT = TOOLS / "merge_trace_with_anettrace.py"
SPEC = importlib.util.spec_from_file_location("merge_trace_with_anettrace", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class NativeTraceValidationTest(unittest.TestCase):
    def test_converted_fixture_is_native_perfetto(self) -> None:
        converter = sys.modules["anettrace_to_perfetto"]
        records = converter.read_records(
            ROOT / "tests" / "fixtures" / "perfetto-events.jsonl"
        )
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "anettrace.pftrace"
            trace.write_bytes(converter.PerfettoExporter(records).serialize())
            self.assertGreater(MODULE.validate_native_trace(trace), 0)

    def test_non_proto_input_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace.json"
            trace.write_text('{"traceEvents": []}', encoding="utf-8")
            with self.assertRaisesRegex(MODULE.MergeError, "not an uncompressed native"):
                MODULE.validate_native_trace(trace)


class MergeCapabilityTest(unittest.TestCase):
    def test_old_global_help_is_not_mistaken_for_util_merge(self) -> None:
        result = MODULE.subprocess.CompletedProcess([], 0, "global help", "")
        with mock.patch.object(MODULE, "run", return_value=result):
            self.assertFalse(MODULE.supports_util_merge(Path("trace_processor")))

    def test_strict_util_merge_help_is_detected(self) -> None:
        result = MODULE.subprocess.CompletedProcess(
            [], 0, "trace_processor util merge --strict", ""
        )
        with mock.patch.object(MODULE, "run", return_value=result):
            self.assertTrue(MODULE.supports_util_merge(Path("trace_processor")))


class IntegrityGateTest(unittest.TestCase):
    def test_valid_system_and_network_metrics_pass(self) -> None:
        metrics = {
            "packet_events": 5,
            "thread_states": 20,
            "packet_events_with_thread_state": 4,
            "error_stats_total": 0,
            **{name: 0 for name in MODULE.ERROR_STATS},
        }
        MODULE.check_metrics(
            metrics, allow_empty_network=False, allow_missing_thread_state=False
        )

    def test_clock_error_fails_the_merge(self) -> None:
        metrics = {
            "packet_events": 5,
            "thread_states": 20,
            "packet_events_with_thread_state": 4,
            "error_stats_total": 0,
            **{name: 0 for name in MODULE.ERROR_STATS},
        }
        metrics["clock_sync_failure_no_path"] = 1
        with self.assertRaisesRegex(MODULE.MergeError, "clock/timestamp integrity"):
            MODULE.check_metrics(
                metrics, allow_empty_network=False, allow_missing_thread_state=False
            )


class FailureHandlingTest(unittest.TestCase):
    def test_missing_input_still_writes_failure_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report_path = root / "integrity.json"
            args = MODULE.parse_args(
                [
                    str(root / "missing-system.pftrace"),
                    str(root / "missing-anettrace.jsonl"),
                    str(root / "combined.pftrace"),
                    "--report",
                    str(report_path),
                ]
            )
            with self.assertRaisesRegex(MODULE.MergeError, "system trace does not exist"):
                MODULE.execute(args)
            report = MODULE.json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "failed")
            self.assertIn("system trace does not exist", report["error"])

    def test_any_trace_processor_import_error_fails_the_merge(self) -> None:
        metrics = {
            "packet_events": 5,
            "thread_states": 20,
            "packet_events_with_thread_state": 4,
            "error_stats_total": 1,
            **{name: 0 for name in MODULE.ERROR_STATS},
        }
        with self.assertRaisesRegex(MODULE.MergeError, "input/import errors"):
            MODULE.check_metrics(
                metrics, allow_empty_network=False, allow_missing_thread_state=False
            )


if __name__ == "__main__":
    unittest.main()
