#!/usr/bin/env python3
"""Validate generated connect reports against the published JSON Schema."""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path

import jsonschema


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "connect_diagnostics.py"
SPEC = importlib.util.spec_from_file_location("connect_diagnostics_schema_tool", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ConnectDiagnosticsSchemaTest(unittest.TestCase):
    def test_fixture_report_matches_published_schema(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "connect-diagnostics-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        validator_class = jsonschema.validators.validator_for(schema)
        validator_class.check_schema(schema)
        report = MODULE.analyze_records(
            MODULE.read_event_records(
                ROOT / "tests" / "fixtures" / "connect-diagnostics-events.jsonl"
            ),
            report_id="0123456789abcdef",
            uid=10000,
            generated_at_utc="2026-08-12T00:00:00Z",
        )
        validator_class(schema, format_checker=jsonschema.FormatChecker()).validate(report)

    def test_schema_rejects_unknown_outcome_count_key(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "connect-diagnostics-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        report = MODULE.analyze_records(
            MODULE.read_event_records(
                ROOT / "tests" / "fixtures" / "connect-diagnostics-events.jsonl"
            ),
            report_id="0123456789abcdef",
            uid=10000,
            generated_at_utc="2026-08-12T00:00:00Z",
        )
        report["summary"]["outcome_counts"]["guessed_failure"] = 1
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(report)

    def test_schema_enforces_package_opt_in_shape(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "connect-diagnostics-v1.schema.json").read_text(
                encoding="utf-8"
            )
        )
        report = MODULE.analyze_records(
            MODULE.read_event_records(
                ROOT / "tests" / "fixtures" / "connect-diagnostics-events.jsonl"
            ),
            report_id="0123456789abcdef",
            uid=10000,
            generated_at_utc="2026-08-12T00:00:00Z",
        )
        report["target"]["package"] = "com.example.leaked"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.Draft202012Validator(schema).validate(report)


if __name__ == "__main__":
    unittest.main()
