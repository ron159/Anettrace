#!/usr/bin/env python3
"""Release asset and CycloneDX contracts."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools" / "generate_release_sbom.py"
SPEC = importlib.util.spec_from_file_location("generate_release_sbom", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ReleaseAssetTest(unittest.TestCase):
    def test_sbom_is_deterministic_and_hashes_every_asset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "a.bin"
            second = root / "b.tar.bz2"
            first.write_bytes(b"anettrace")
            second.write_bytes(b"host-tools")
            args = {
                "version": "0.5.0",
                "commit": "a" * 40,
                "timestamp": "2026-08-12T00:00:00Z",
            }
            left = MODULE.build_sbom([second, first], **args)
            right = MODULE.build_sbom([first, second], **args)
            self.assertEqual(left, right)
            self.assertEqual(left["bomFormat"], "CycloneDX")
            self.assertEqual(left["specVersion"], "1.6")
            components = left["components"]
            self.assertEqual([item["name"] for item in components], ["a.bin", "b.tar.bz2"])
            expected = {
                path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                for path in (first, second)
            }
            self.assertEqual(
                {
                    item["name"]: item["hashes"][0]["content"]
                    for item in components
                },
                expected,
            )

    def test_sbom_rejects_non_release_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            asset = Path(directory) / "asset"
            asset.write_bytes(b"anettrace")
            with self.assertRaisesRegex(ValueError, "MAJOR.MINOR.PATCH"):
                MODULE.build_sbom(
                    [asset],
                    version="v0.5.0",
                    commit="a" * 40,
                    timestamp="2026-08-12T00:00:00Z",
                )
            with self.assertRaisesRegex(ValueError, "full lowercase"):
                MODULE.build_sbom(
                    [asset],
                    version="0.5.0",
                    commit="A" * 40,
                    timestamp="2026-08-12T00:00:00Z",
                )

    def test_release_packager_contains_public_contract_and_host_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            binary = root / "anettrace"
            binary.write_bytes(b"fixture")
            subprocess.run(
                [
                    "bash",
                    str(ROOT / "script" / "package-connect-diagnostics-release.sh"),
                    str(root / "assets"),
                    str(binary),
                ],
                check=True,
            )
            version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
            archive = root / "assets" / f"anettrace-{version}-host-tools.tar.bz2"
            with tarfile.open(archive, "r:bz2") as package:
                names = set(package.getnames())
            prefix = f"anettrace-{version}-host-tools"
            required = {
                f"{prefix}/VERSION",
                f"{prefix}/SOURCE_COMMIT",
                f"{prefix}/LICENSE",
                f"{prefix}/docs/connect-diagnostics.md",
                f"{prefix}/schemas/connect-diagnostics-v1.schema.json",
                f"{prefix}/tools/diagnose_android_connect.py",
                f"{prefix}/tools/validate_android_connect.py",
                f"{prefix}/tools/soak_android_connect.py",
                f"{prefix}/tools/connect_diagnostics.py",
                f"{prefix}/tools/capture_android_trace.py",
                f"{prefix}/tools/anettrace_to_perfetto.py",
                f"{prefix}/tools/merge_trace_with_anettrace.py",
                f"{prefix}/tools/requirements-perfetto.txt",
                f"{prefix}/tools/perfetto_sql/anettrace_integrity.sql",
                f"{prefix}/tools/perfetto_sql/connect_diagnostics.sql",
                f"{prefix}/tools/perfetto_sql/connect_diagnostics_metrics.sql",
            }
            self.assertTrue(required.issubset(names), required - names)
            android = root / "assets" / f"anettrace-{version}-android-arm64-dual"
            self.assertEqual(android.read_bytes(), b"fixture")
            self.assertEqual(android.stat().st_mode & 0o777, 0o755)
            with tarfile.open(archive, "r:bz2") as package:
                commit = package.extractfile(f"{prefix}/SOURCE_COMMIT")
                assert commit is not None
                expected_commit = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=ROOT,
                    check=True,
                    text=True,
                    capture_output=True,
                ).stdout.strip()
                self.assertEqual(commit.read().decode().strip(), expected_commit)

    def test_release_notes_are_chinese_and_versioned(self) -> None:
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        notes = (ROOT / "docs" / "releases" / f"v{version}.md").read_text(
            encoding="utf-8"
        )
        for text in ("TCP 主动建连", "Android 15+", "PKC130", "隐私", "已知限制"):
            self.assertIn(text, notes)


if __name__ == "__main__":
    unittest.main()
