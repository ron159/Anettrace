#!/usr/bin/env python3
"""Contracts for the release-gated Android connect soak."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "soak_android_connect.py"
SPEC = importlib.util.spec_from_file_location("soak_android_connect", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class SoakContractTest(unittest.TestCase):
    def test_defaults_enforce_release_duration_and_bounded_sampling(self) -> None:
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
                "/tmp/soak",
            ]
        )
        self.assertEqual(args.duration, 1800)
        self.assertEqual(args.baseline_seconds, 30)
        self.assertEqual(args.resource_sample_interval, 5)

    def test_baseline_summary_is_strict(self) -> None:
        self.assertEqual(
            MODULE.baseline_result(
                "scenario=success completed=120 elapsed_ms=30001 complete=true\n"
            ),
            (120, 30001),
        )
        with self.assertRaises(MODULE.SoakError):
            MODULE.baseline_result("scenario=success progress=true\n")

    def test_valid_soak_requires_no_loss_and_verified_cleanup(self) -> None:
        report = {
            "status": "valid",
            "summary": {
                "attempt_count": 7200,
                "outcome_counts": {"success": 7199, "incomplete_or_unknown": 1},
            },
            "capture": {
                "started_ns": 1_000_000_000,
                "ended_ns": 1_801_000_000_000,
                "lost_events": 0,
                "truncated": False,
            },
        }
        manifest = {
            "capture": {
                "cleanup": {"verified": True, "remaining": []},
                "resource_sampling": {"samples": 360, "peak_rss_kib": 2048},
            }
        }
        result = MODULE.validate_soak_report(report, manifest, 1800)
        self.assertEqual(result["success_count"], 7199)
        self.assertEqual(result["collector_resources"]["samples"], 360)
        report["capture"]["lost_events"] = 1
        with self.assertRaises(MODULE.SoakError):
            MODULE.validate_soak_report(report, manifest, 1800)

    def test_soak_requires_at_least_one_success(self) -> None:
        report = {
            "status": "valid",
            "summary": {
                "attempt_count": 1,
                "outcome_counts": {"incomplete_or_unknown": 1},
            },
            "capture": {
                "started_ns": 1_000_000_000,
                "ended_ns": 1_801_000_000_000,
                "lost_events": 0,
                "truncated": False,
            },
        }
        manifest = {
            "capture": {
                "cleanup": {"verified": True, "remaining": []},
                "resource_sampling": {"samples": 360},
            }
        }
        with self.assertRaisesRegex(MODULE.SoakError, "unexpected outcomes"):
            MODULE.validate_soak_report(report, manifest, 1800)


if __name__ == "__main__":
    unittest.main()
