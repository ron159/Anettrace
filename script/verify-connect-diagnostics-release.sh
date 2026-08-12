#!/usr/bin/env bash
# SPDX-License-Identifier: MulanPSL-2.0

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "usage: $0 RELEASE_ASSET_DIR" >&2
	exit 2
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
asset_dir="$(cd "$1" && pwd)"
version="$(tr -d '[:space:]' < "$root/VERSION")"
android_binary="anettrace-${version}-android-arm64-dual"
android_archive="${android_binary}.tar.bz2"
host_archive="anettrace-${version}-host-tools.tar.bz2"
connect_workload="anettrace-${version}-connect-workload-android-arm64"
sbom="anettrace-${version}-sbom.cdx.json"
staging_root="$(mktemp -d "${TMPDIR:-/tmp}/anettrace-release-verify.XXXXXX")"
trap 'rm -rf -- "$staging_root"' EXIT

expected="$(printf '%s\n' \
	"$android_binary" "$android_archive" "$connect_workload" \
	"$host_archive" "$sbom" SHA256SUMS | sort)"
actual="$(find "$asset_dir" -mindepth 1 -maxdepth 1 -type f -exec basename {} \; | sort)"
if [[ "$actual" != "$expected" ]]; then
	echo "release asset set mismatch" >&2
	diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") || true
	exit 1
fi

(
	cd "$asset_dir"
	sha256sum --check SHA256SUMS
)
file "$asset_dir/$android_binary" | grep -Eiq 'ARM aarch64|AArch64'
readelf -h "$asset_dir/$android_binary" | grep -q 'Machine:.*AArch64'
! readelf -l "$asset_dir/$android_binary" | grep -q INTERP
! readelf -d "$asset_dir/$android_binary" | grep -q NEEDED
strings "$asset_dir/$android_binary" | grep -Fq "Anettrace ${version}"
file "$asset_dir/$connect_workload" | grep -Eiq 'ARM aarch64|AArch64'
readelf -h "$asset_dir/$connect_workload" | grep -q 'Machine:.*AArch64'
! readelf -l "$asset_dir/$connect_workload" | grep -q INTERP
! readelf -d "$asset_dir/$connect_workload" | grep -q NEEDED

android_member="anettrace-${version}-android-arm64-dual/anettrace"
android_members="$(tar -tjf "$asset_dir/$android_archive")"
grep -Fxq "$android_member" <<<"$android_members"
tar -xjf "$asset_dir/$android_archive" -C "$staging_root" "$android_member"
cmp "$asset_dir/$android_binary" "$staging_root/$android_member"

host_prefix="anettrace-${version}-host-tools"
host_members="$(tar -tjf "$asset_dir/$host_archive")"
for member in \
	VERSION README.md LICENSE docs/connect-diagnostics.md \
	schemas/connect-diagnostics-v1.schema.json \
	tools/anettrace_to_perfetto.py tools/capture_android_trace.py \
	tools/connect_diagnostics.py tools/diagnose_android_connect.py \
	tools/validate_android_connect.py tools/soak_android_connect.py \
	tools/merge_trace_with_anettrace.py tools/requirements-perfetto.txt \
	tools/perfetto_sql/anettrace_integrity.sql \
	tools/perfetto_sql/connect_diagnostics.sql \
	tools/perfetto_sql/connect_diagnostics_metrics.sql; do
	grep -Fxq "$host_prefix/$member" <<<"$host_members"
done
test "$(tar -xOf "$asset_dir/$host_archive" "$host_prefix/VERSION" | \
	tr -d '[:space:]')" = "$version"

python3 - "$asset_dir" "$version" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

asset_dir = Path(sys.argv[1])
version = sys.argv[2]
sbom = json.loads(
    (asset_dir / f"anettrace-{version}-sbom.cdx.json").read_text(encoding="utf-8")
)
assert sbom["bomFormat"] == "CycloneDX"
assert sbom["specVersion"] == "1.6"
assert sbom["metadata"]["component"]["version"] == version
components = {item["name"]: item for item in sbom["components"]}
expected = {
    f"anettrace-{version}-android-arm64-dual",
    f"anettrace-{version}-android-arm64-dual.tar.bz2",
    f"anettrace-{version}-connect-workload-android-arm64",
    f"anettrace-{version}-host-tools.tar.bz2",
}
assert set(components) == expected
for name, component in components.items():
    digest = hashlib.sha256((asset_dir / name).read_bytes()).hexdigest()
    assert component["hashes"] == [{"alg": "SHA-256", "content": digest}]
PY
