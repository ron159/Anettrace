#!/usr/bin/env bash
# SPDX-License-Identifier: MulanPSL-2.0

set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 OUTPUT_DIR ANDROID_BINARY" >&2
	exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="$1"
android_binary="$2"
version="$(tr -d '[:space:]' < "$root/VERSION")"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	echo "invalid VERSION: $version" >&2
	exit 1
fi
if [[ ! -f "$android_binary" ]]; then
	echo "Android binary not found: $android_binary" >&2
	exit 1
fi

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/anettrace-release.XXXXXX")"
trap 'rm -rf -- "$staging_root"' EXIT

host_name="anettrace-${version}-host-tools"
host_root="$staging_root/$host_name"
mkdir -p "$host_root/docs" "$host_root/schemas" \
	"$host_root/tools/perfetto_sql"

cp "$root/VERSION" "$root/README.md" "$root/LICENSE" "$host_root/"
cp "$root/docs/connect-diagnostics.md" "$host_root/docs/"
cp "$root/schemas/connect-diagnostics-v1.schema.json" "$host_root/schemas/"
cp "$root/tools/anettrace_to_perfetto.py" \
	"$root/tools/capture_android_trace.py" \
	"$root/tools/connect_diagnostics.py" \
	"$root/tools/diagnose_android_connect.py" \
	"$root/tools/validate_android_connect.py" \
	"$root/tools/soak_android_connect.py" \
	"$root/tools/merge_trace_with_anettrace.py" \
	"$root/tools/requirements-perfetto.txt" "$host_root/tools/"
cp "$root/tools/perfetto_sql/anettrace_integrity.sql" \
	"$root/tools/perfetto_sql/connect_diagnostics.sql" \
	"$root/tools/perfetto_sql/connect_diagnostics_metrics.sql" \
	"$host_root/tools/perfetto_sql/"
chmod 0755 "$host_root/tools/"*.py
find "$host_root" -type f ! -path '*/tools/*.py' -exec chmod 0644 {} +

tar -C "$staging_root" -cjf "$output_dir/${host_name}.tar.bz2" "$host_name"
install -m 0755 "$android_binary" \
	"$output_dir/anettrace-${version}-android-arm64-dual"
