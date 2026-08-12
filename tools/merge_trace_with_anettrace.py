#!/usr/bin/env python3
# SPDX-License-Identifier: MulanPSL-2.0
"""Strictly merge a system trace with Anettrace JSONL or Perfetto data."""

from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

try:
    from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace
    from perfetto.trace_processor import TraceProcessor
except ImportError as error:  # pragma: no cover - exercised by CLI users
    raise SystemExit(
        "missing Python dependency; run: uv run --with perfetto==0.57.2 "
        "python tools/merge_trace_with_anettrace.py ..."
    ) from error

from anettrace_to_perfetto import PerfettoExporter, read_records


ROOT = Path(__file__).resolve().parents[1]
INTEGRITY_SQL = ROOT / "tools" / "perfetto_sql" / "anettrace_integrity.sql"
REPORT_SCHEMA = "anettrace.merge.v1"
ERROR_STATS = (
    "clock_sync_unrelatable_clock_domains",
    "clock_sync_failure_no_path",
    "trace_sorter_negative_timestamp_dropped",
)


class MergeError(RuntimeError):
    """A merge or integrity failure that should be shown to the user."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "size": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def run(command: Sequence[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(list(command), text=True, capture_output=True)
    except OSError as error:
        raise MergeError(f"failed to run {command[0]}: {error}") from error
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise MergeError(
            f"command failed ({result.returncode}): {' '.join(command)}"
            + (f": {detail}" if detail else "")
        )
    return result


def validate_native_trace(path: Path) -> int:
    if not path.is_file() or path.stat().st_size == 0:
        raise MergeError(f"trace is missing or empty: {path}")
    trace = Trace()
    try:
        trace.ParseFromString(path.read_bytes())
    except Exception as error:
        raise MergeError(f"not an uncompressed native Perfetto trace: {path}") from error
    if not trace.packet:
        raise MergeError(f"Perfetto trace has no TracePacket records: {path}")
    return len(trace.packet)


def summarize_events(records: list[dict[str, Any]]) -> dict[str, Any]:
    counts: dict[str, int] = {}
    trace_end: list[dict[str, Any]] = []
    for record in records:
        event_type = record.get("type")
        if not isinstance(event_type, str):
            raise MergeError("Anettrace JSONL contains a record without type")
        counts[event_type] = counts.get(event_type, 0) + 1
        if event_type == "trace_end":
            trace_end.append(record)
    if counts.get("clock_snapshot", 0) < 1:
        raise MergeError("Anettrace JSONL has no clock_snapshot")
    if len(trace_end) != 1:
        raise MergeError("Anettrace JSONL must contain exactly one trace_end")
    return {
        "records": sum(counts.values()),
        "event_types": counts,
        "lost_events": int(trace_end[0].get("lost_events", 0)),
    }


def prepare_anettrace(path: Path, directory: Path) -> tuple[Path, dict[str, Any] | None]:
    if path.suffix.lower() != ".jsonl":
        validate_native_trace(path)
        return path, None
    try:
        records = read_records(path)
        summary = summarize_events(records)
        encoded = PerfettoExporter(records).serialize()
    except (OSError, ValueError, KeyError) as error:
        raise MergeError(str(error)) from error
    converted = directory / "anettrace.pftrace"
    converted.write_bytes(encoded)
    validate_native_trace(converted)
    return converted, summary


def find_trace_processor(explicit: Path | None) -> Path | None:
    if explicit:
        path = explicit.resolve()
        if not path.is_file():
            raise MergeError(f"Trace Processor does not exist: {path}")
        return path
    for name in ("trace_processor", "trace_processor_shell"):
        found = shutil.which(name)
        if found:
            return Path(found).resolve()
    return None


def supports_util_merge(trace_processor: Path | None) -> bool:
    if trace_processor is None:
        return False
    result = run([str(trace_processor), "util", "merge", "--help"], check=False)
    help_text = f"{result.stdout}\n{result.stderr}".lower()
    return (
        result.returncode == 0
        and "util merge" in help_text
        and "--strict" in help_text
    )


def trace_processor_record(trace_processor: Path | None) -> dict[str, Any]:
    if trace_processor is None:
        try:
            package_version = importlib.metadata.version("perfetto")
        except importlib.metadata.PackageNotFoundError:
            package_version = None
        return {
            "interface": "python-api",
            "perfetto_package": package_version,
            "util_merge": False,
        }
    result = run([str(trace_processor), "--version"], check=False)
    version = (result.stdout or result.stderr).strip().splitlines()
    return {
        "interface": "cli",
        "path": str(trace_processor),
        "version": version[0] if version else None,
        "util_merge": supports_util_merge(trace_processor),
    }


def raw_concatenate(inputs: Sequence[Path], output: Path) -> None:
    with output.open("wb") as destination:
        for path in inputs:
            validate_native_trace(path)
            with path.open("rb") as source:
                shutil.copyfileobj(source, destination)


def merge_inputs(
    system_trace: Path,
    anettrace_trace: Path,
    output: Path,
    trace_processor: Path | None,
    manifest: Path | None,
) -> tuple[str, list[str]]:
    if supports_util_merge(trace_processor):
        command = [
            str(trace_processor),
            "util",
            "merge",
            "-o",
            str(output),
            "--strict",
        ]
        if manifest:
            command.extend(["--manifest", str(manifest)])
        command.extend([str(system_trace), str(anettrace_trace)])
        run(command)
        return "trace_processor_util_merge", command
    if manifest:
        raise MergeError("this Trace Processor has no util merge support for a manifest")
    raw_concatenate((system_trace, anettrace_trace), output)
    return "raw_native_tracepacket_concat", []


def normalize_metrics(row: dict[str, Any]) -> dict[str, int]:
    metrics: dict[str, int] = {}
    for key, value in row.items():
        try:
            metrics[key] = int(value)
        except (TypeError, ValueError) as error:
            raise MergeError(f"unexpected integrity value for {key}: {value!r}") from error
    return metrics


def query_integrity(trace: Path, trace_processor: Path | None) -> dict[str, int]:
    sql = INTEGRITY_SQL.read_text(encoding="utf-8")
    if trace_processor:
        result = run(
            [str(trace_processor), "--query-file", str(INTEGRITY_SQL), str(trace)]
        )
        rows = list(csv.DictReader(result.stdout.splitlines()))
    else:
        try:
            with TraceProcessor(trace=str(trace)) as processor:
                rows = list(processor.query(sql))
        except Exception as error:
            raise MergeError(f"Trace Processor could not load the merged trace: {error}") from error
    if len(rows) != 1:
        raise MergeError(f"integrity query returned {len(rows)} rows, expected one")
    return normalize_metrics(dict(rows[0]))


def check_metrics(
    metrics: dict[str, int], *, allow_empty_network: bool, allow_missing_thread_state: bool
) -> None:
    failures = [name for name in ERROR_STATS if metrics.get(name, 0) > 0]
    if failures:
        raise MergeError("clock/timestamp integrity failed: " + ", ".join(failures))
    if metrics.get("error_stats_total", 0) > 0:
        raise MergeError("Trace Processor reported input/import errors")
    if not allow_empty_network and metrics.get("packet_events", 0) == 0:
        raise MergeError("merged trace contains no Anettrace packet events")
    if not allow_missing_thread_state:
        if metrics.get("thread_states", 0) == 0:
            raise MergeError("system trace contains no thread_state data")
        if metrics.get("packet_events_with_thread_state", 0) == 0:
            raise MergeError("Anettrace packet events do not overlap a traced thread state")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("system_trace", type=Path)
    parser.add_argument("anettrace", type=Path, help="Anettrace JSONL or native .pftrace")
    parser.add_argument("output", type=Path, help="merged trace/archive; must not exist")
    parser.add_argument("--trace-processor", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--allow-empty-network", action="store_true")
    parser.add_argument("--allow-missing-thread-state", action="store_true")
    args = parser.parse_args(argv)
    args.report = args.report or args.output.with_name(args.output.name + ".integrity.json")
    return args


def execute(args: argparse.Namespace) -> dict[str, Any]:
    output = args.output.resolve()
    report_path = args.report.resolve()
    if output == report_path:
        raise MergeError("output and report paths must be different")
    if output.exists():
        raise MergeError(f"refusing to overwrite output: {output}")
    if report_path.exists():
        raise MergeError(f"refusing to overwrite report: {report_path}")
    output.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "status": "failed",
        "created_at_utc": utc_now(),
        "inputs": {
            "system_trace": {"path": str(args.system_trace.resolve())},
            "anettrace": {"path": str(args.anettrace.resolve())},
        },
    }
    temporary_output: Path | None = None
    try:
        trace_processor = find_trace_processor(args.trace_processor)
        manifest = args.manifest.resolve() if args.manifest else None
        if not args.system_trace.resolve().is_file():
            raise MergeError(f"system trace does not exist: {args.system_trace.resolve()}")
        if not args.anettrace.resolve().is_file():
            raise MergeError(f"Anettrace input does not exist: {args.anettrace.resolve()}")
        if manifest and not manifest.is_file():
            raise MergeError(f"manifest does not exist: {manifest}")
        report["inputs"] = {
            "system_trace": file_record(args.system_trace.resolve()),
            "anettrace": file_record(args.anettrace.resolve()),
        }
        if manifest:
            report["inputs"]["manifest"] = file_record(manifest)
        report["trace_processor"] = trace_processor_record(trace_processor)

        with tempfile.TemporaryDirectory(prefix="anettrace-merge-") as directory_name:
            directory = Path(directory_name)
            anettrace_trace, event_summary = prepare_anettrace(
                args.anettrace.resolve(), directory
            )
            temporary_path = output.with_name(f".{output.name}.tmp")
            if temporary_path.exists():
                raise MergeError(f"temporary output already exists: {temporary_path}")
            temporary_output = temporary_path
            method, command = merge_inputs(
                args.system_trace.resolve(),
                anettrace_trace,
                temporary_output,
                trace_processor,
                manifest,
            )
            metrics = query_integrity(temporary_output, trace_processor)
            check_metrics(
                metrics,
                allow_empty_network=args.allow_empty_network,
                allow_missing_thread_state=args.allow_missing_thread_state,
            )
            output_record = file_record(temporary_output)
            output_record["path"] = str(output)
            temporary_output.replace(output)
            temporary_output = None
            report.update(
                status="success",
                method=method,
                command=command,
                anettrace=event_summary,
                integrity=metrics,
                output=output_record,
            )
            return report
    except (MergeError, OSError) as error:
        report["error"] = str(error)
        raise
    finally:
        if temporary_output:
            temporary_output.unlink(missing_ok=True)
        report_path.write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = execute(args)
    except (MergeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"wrote {report['output']['path']}")
    print(f"integrity: {args.report.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
