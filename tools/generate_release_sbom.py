#!/usr/bin/env python3
"""Generate a deterministic CycloneDX SBOM for Anettrace release assets."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


SCHEMA = "http://cyclonedx.org/schema/bom-1.6.schema.json"
SPEC_VERSION = "1.6"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def utc_timestamp(value: str | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def build_sbom(
    assets: Sequence[Path],
    *,
    version: str,
    commit: str,
    timestamp: str,
) -> dict[str, object]:
    if not assets:
        raise ValueError("at least one release asset is required")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("version must use MAJOR.MINOR.PATCH")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("commit must be a full lowercase Git object ID")

    components: list[dict[str, object]] = []
    dependencies: list[str] = []
    names: set[str] = set()
    for asset in sorted((path.resolve() for path in assets), key=lambda path: path.name):
        if not asset.is_file():
            raise ValueError(f"release asset does not exist: {asset}")
        if asset.name in names:
            raise ValueError(f"duplicate release asset name: {asset.name}")
        names.add(asset.name)
        digest = sha256(asset)
        reference = f"urn:anettrace:release-file:sha256:{digest}"
        components.append(
            {
                "type": "file",
                "bom-ref": reference,
                "name": asset.name,
                "version": version,
                "hashes": [{"alg": "SHA-256", "content": digest}],
                "properties": [
                    {"name": "anettrace:release:size", "value": str(asset.stat().st_size)},
                    {"name": "anettrace:release:source-commit", "value": commit},
                ],
            }
        )
        dependencies.append(reference)

    product_ref = f"pkg:github/ron159/Anettrace@{version}"
    return {
        "$schema": SCHEMA,
        "bomFormat": "CycloneDX",
        "specVersion": SPEC_VERSION,
        "serialNumber": f"urn:uuid:{_release_uuid(version, commit)}",
        "version": 1,
        "metadata": {
            "timestamp": utc_timestamp(timestamp),
            "component": {
                "type": "application",
                "bom-ref": product_ref,
                "name": "Anettrace",
                "version": version,
                "purl": product_ref,
                "properties": [
                    {"name": "anettrace:source-commit", "value": commit}
                ],
            },
        },
        "components": components,
        "dependencies": [{"ref": product_ref, "dependsOn": dependencies}],
    }


def _release_uuid(version: str, commit: str) -> str:
    digest = hashlib.sha256(f"Anettrace\0{version}\0{commit}".encode()).hexdigest()
    return f"{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-a{digest[17:20]}-{digest[20:32]}"


def write_sbom(sbom: dict[str, object], output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(sbom, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--timestamp", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("assets", type=Path, nargs="+")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        sbom = build_sbom(
            args.assets,
            version=args.version,
            commit=args.commit,
            timestamp=args.timestamp,
        )
        write_sbom(sbom, args.output)
    except (OSError, ValueError) as error:
        raise SystemExit(f"error: {error}") from error
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
