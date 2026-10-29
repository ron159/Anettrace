#!/usr/bin/env python3
"""Compatibility entry; the self-contained implementation lives in the analysis skill."""
import importlib.util
from pathlib import Path
import sys

_path = Path(__file__).resolve().parents[1]/'skills/anettrace-analysis/scripts/network_report.py'
_spec = importlib.util.spec_from_file_location('anettrace_analysis_report', _path)
_implementation = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _implementation
_spec.loader.exec_module(_implementation)


def __getattr__(name):
    return getattr(_implementation, name)


if __name__ == '__main__':
    raise SystemExit(_implementation.main())
