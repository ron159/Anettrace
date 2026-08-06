#!/usr/bin/env bash
# SPDX-License-Identifier: MulanPSL-2.0

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec python3 "$ROOT/tools/capture_android_trace.py" "$@"
