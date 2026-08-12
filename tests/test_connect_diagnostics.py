#!/usr/bin/env python3
"""Contract tests for TCP connect diagnostics v1."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "connect_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("connect_diagnostics", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ConnectDiagnosticsContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.records = MODULE.read_event_records(
            ROOT / "tests" / "fixtures" / "connect-diagnostics-events.jsonl"
        )
        self.report = MODULE.analyze_records(
            self.records,
            report_id="0123456789abcdef",
            uid=10000,
            generated_at_utc="2026-08-12T00:00:00Z",
        )

    def test_fixture_covers_all_outcomes_once(self) -> None:
        self.assertEqual(self.report["status"], "valid")
        self.assertEqual(self.report["summary"]["attempt_count"], 8)
        self.assertEqual(
            self.report["summary"]["outcome_counts"],
            {outcome: 1 for outcome in MODULE.OUTCOMES},
        )

    def test_nonblocking_connect_requires_state_and_so_error(self) -> None:
        success = self.report["attempts"][0]
        self.assertEqual(success["outcome"], "success")
        self.assertEqual(success["evidence_strength"], "correlated")
        self.assertEqual(success["duration_ns"], 6_000_000)
        without_so_error = [
            record
            for record in self.records
            if not (
                record.get("type") == "connect_so_error"
                and record.get("attempt_id") == "0000000000000001"
            )
        ]
        report = MODULE.analyze_records(
            without_so_error,
            report_id="0123456789abcdef",
            uid=10000,
            generated_at_utc="2026-08-12T00:00:00Z",
        )
        self.assertEqual(report["attempts"][0]["outcome"], "incomplete_or_unknown")
        self.assertIn("terminal_so_error", report["attempts"][0]["missing_evidence"])

    def test_precise_drop_beats_timeout(self) -> None:
        attempt = self.report["attempts"][5]
        self.assertEqual(attempt["outcome"], "kernel_drop")
        self.assertEqual(attempt["errno"]["name"], "ETIMEDOUT")

    def test_existing_socket_and_packet_events_become_connect_evidence(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000aa",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_socket",
                "ts_ns": 2_000_010_000,
                "attempt_id": "00000000000000aa",
                "socket_instance_id": "00000000000000bb",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "socket_event",
                "ts_ns": 2_000_020_000,
                "socket_id": "00000000000000bb",
                "stage": "tcp_retransmit_skb",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "packet_event",
                "ts_ns": 2_000_030_000,
                "owner_socket_id": "00000000000000bb",
                "stage": "kfree_skb",
                "dropped": True,
                "direction": "tx",
                "tcp_flags": 2,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_000_040_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        attempt = report["attempts"][0]
        self.assertEqual(attempt["outcome"], "kernel_drop")
        self.assertIn("tcp_retransmission", attempt["contributing_factors"])

    def test_drop_without_outbound_direction_is_not_exact(self) -> None:
        records = [dict(record) for record in self.records]
        drop = next(record for record in records if record.get("type") == "connect_drop")
        drop["exact"] = False
        drop["type"] = "packet_event"
        drop["owner_socket_id"] = drop.pop("socket_instance_id")
        drop.update({"stage": "kfree_skb", "dropped": True, "tcp_flags": 2})
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        self.assertEqual(report["attempts"][5]["outcome"], "timeout_no_response")

    def test_pending_so_error_does_not_finish_async_attempt(self) -> None:
        records = [dict(record) for record in self.records]
        so_error = next(
            record
            for record in records
            if record.get("type") == "connect_so_error"
        )
        so_error["error"] = MODULE.LINUX_EINPROGRESS
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        attempt = report["attempts"][0]
        self.assertEqual(attempt["outcome"], "incomplete_or_unknown")
        self.assertEqual(attempt["ended_ns"], 1_090_000_000)

    def test_direct_connection_reset_is_peer_refused(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000cc",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_end",
                "ts_ns": 2_000_030_000,
                "attempt_id": "00000000000000cc",
                "result": -104,
                "error": 104,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_000_040_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        self.assertEqual(report["attempts"][0]["outcome"], "peer_refused")

    def test_received_rst_in_syn_sent_is_correlated_peer_refusal(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000ab",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_socket",
                "ts_ns": 2_000_010_000,
                "attempt_id": "00000000000000ab",
                "socket_instance_id": "00000000000000bc",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "socket_state",
                "ts_ns": 2_000_020_000,
                "socket_id": "00000000000000bc",
                "new_state_name": "SYN_SENT",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "packet_event",
                "ts_ns": 2_000_030_000,
                "owner_socket_id": "00000000000000bc",
                "stage": "tcp_v4_rcv",
                "direction": "rx",
                "tcp_flags": 4,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_000_040_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        attempt = report["attempts"][0]
        self.assertEqual(attempt["outcome"], "peer_refused")
        self.assertEqual(attempt["evidence_strength"], "correlated")

    def test_precise_received_rst_beats_later_timeout(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000ad",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_socket",
                "ts_ns": 2_000_010_000,
                "attempt_id": "00000000000000ad",
                "socket_instance_id": "00000000000000be",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "socket_state",
                "ts_ns": 2_000_020_000,
                "socket_id": "00000000000000be",
                "new_state_name": "SYN_SENT",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "packet_event",
                "ts_ns": 2_000_030_000,
                "owner_socket_id": "00000000000000be",
                "stage": "tcp_v4_rcv",
                "direction": "rx",
                "tcp_flags": 4,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_end",
                "ts_ns": 2_000_040_000,
                "attempt_id": "00000000000000ad",
                "result": -MODULE.LINUX_ETIMEDOUT,
                "error": MODULE.LINUX_ETIMEDOUT,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_000_050_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        attempt = report["attempts"][0]
        self.assertEqual(attempt["outcome"], "peer_refused")
        self.assertEqual(attempt["evidence_strength"], "correlated")
        self.assertEqual(attempt["errno"]["name"], "ETIMEDOUT")

    def test_local_send_reset_is_not_mislabeled_as_peer_refusal(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000ac",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_socket",
                "ts_ns": 2_000_010_000,
                "attempt_id": "00000000000000ac",
                "socket_instance_id": "00000000000000bd",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "socket_event",
                "ts_ns": 2_000_020_000,
                "socket_id": "00000000000000bd",
                "stage": "tcp_send_active_reset",
                "state_name": "SYN_SENT",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_000_040_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        self.assertEqual(
            report["attempts"][0]["outcome"], "incomplete_or_unknown"
        )

    def test_pending_socket_close_is_correlated_cancellation(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000dd",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_socket",
                "ts_ns": 2_000_010_000,
                "attempt_id": "00000000000000dd",
                "socket_instance_id": "00000000000000ee",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_end",
                "ts_ns": 2_000_020_000,
                "attempt_id": "00000000000000dd",
                "result": -115,
                "error": 115,
                "async_pending": True,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "socket_event",
                "ts_ns": 2_000_030_000,
                "socket_id": "00000000000000ee",
                "stage": "tcp_close",
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_000_040_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        attempt = report["attempts"][0]
        self.assertEqual(attempt["outcome"], "interrupted_or_cancelled")
        self.assertEqual(attempt["evidence_strength"], "correlated")

    def test_unknown_errno_is_not_guessed(self) -> None:
        records = [
            self.records[0],
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_start",
                "ts_ns": 2_000_000_000,
                "attempt_id": "00000000000000ff",
                "uid": 10000,
                "tid": 200,
                "tgid": 200,
                "fd": 20,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "connect_attempt_end",
                "ts_ns": 2_001_000_000,
                "attempt_id": "00000000000000ff",
                "result": -999,
                "error": 999,
            },
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "trace_end",
                "ts_ns": 2_002_000_000,
                "lost_events": 0,
            },
        ]
        report = MODULE.analyze_records(
            records,
            report_id="0123456789abcdef",
            uid=10000,
        )
        self.assertEqual(report["attempts"][0]["outcome"], "incomplete_or_unknown")
        self.assertEqual(report["attempts"][0]["errno"]["name"], "UNKNOWN")

    def test_missing_trace_end_invalidates_report(self) -> None:
        report = MODULE.analyze_records(
            self.records[:-1],
            report_id="0123456789abcdef",
            uid=10000,
        )
        self.assertEqual(report["status"], "invalid")
        self.assertTrue(report["errors"])
        self.assertTrue(
            all(
                attempt["outcome"] == "incomplete_or_unknown"
                for attempt in report["attempts"]
            )
        )

    def test_lost_events_degrade_report(self) -> None:
        records = [dict(record) for record in self.records]
        records[-1]["lost_events"] = 3
        report = MODULE.analyze_records(
            records,
            report_id="0123456789abcdef",
            uid=10000,
        )
        self.assertEqual(report["status"], "degraded")
        self.assertEqual(report["capture"]["lost_events"], 3)

    def test_truncated_stream_degrades_report_without_guessing(self) -> None:
        records = [dict(record) for record in self.records]
        records[-1]["truncated"] = True
        report = MODULE.analyze_records(
            records,
            report_id="0123456789abcdef",
            uid=10000,
        )
        self.assertEqual(report["status"], "degraded")
        self.assertTrue(report["capture"]["truncated"])
        self.assertIn("capture reached a configured resource limit", report["warnings"])

    def test_package_persistence_is_explicit(self) -> None:
        self.assertNotIn("package", self.report["target"])
        private_ambiguous = MODULE.analyze_records(
            self.records,
            report_id="0123456789abcdef",
            uid=10000,
            shared_uid_ambiguous=True,
        )
        self.assertTrue(private_ambiguous["target"]["shared_uid_ambiguous"])
        self.assertNotIn("shared_uid_candidates", private_ambiguous["target"])
        included = MODULE.analyze_records(
            self.records,
            report_id="0123456789abcdef",
            uid=10000,
            package="com.example.app",
            shared_uid_candidates=("com.example.app", "com.example.peer"),
        )
        self.assertEqual(included["target"]["package"], "com.example.app")
        self.assertTrue(included["target"]["shared_uid_ambiguous"])

    def test_public_schema_lists_every_outcome(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "connect-diagnostics-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        outcomes = schema["$defs"]["attempt"]["properties"]["outcome"]["enum"]
        self.assertEqual(tuple(outcomes), MODULE.OUTCOMES)

    def test_packet_metadata_builds_android_network_context(self) -> None:
        records = [dict(record) for record in self.records]
        records.insert(
            -1,
            {
                "schema": MODULE.EVENT_SCHEMA,
                "type": "packet_event",
                "ts_ns": 1_017_000_000,
                "owner_socket_id": "0000000000001001",
                "stage": "__tcp_transmit_skb",
                "ifname": "wlan0",
                "netns": 42,
                "mark": 0x30064,
                "tcp_flags": 0x12,
            },
        )
        report = MODULE.analyze_records(
            records, report_id="0123456789abcdef", uid=10000
        )
        context = report["attempts"][0]["network_context"]
        self.assertEqual(context["interfaces"], ["wlan0"])
        self.assertEqual(context["network_namespace_ids"], [42])
        self.assertEqual(
            context["android_fwmarks"],
            [
                {
                    "mark": 0x30064,
                    "net_id": 100,
                    "explicitly_selected": True,
                    "protected_from_vpn": True,
                }
            ],
        )

    def test_report_files_use_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report"
            MODULE.write_report(self.report, output)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "report.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual((output / "report.md").stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
