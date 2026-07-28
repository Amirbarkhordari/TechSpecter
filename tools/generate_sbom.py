#!/usr/bin/env python3
"""Generate CycloneDX and SPDX Software Bill of Materials for TechSpecter."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def _pip_list_json() -> list[dict[str, str]]:
    """Return installed packages as JSON from pip."""
    result = subprocess.run(
        [sys.executable, "-m", "pip", "list", "--format", "json"],
        check=True,
        capture_output=True,
        text=True,
    )
    payload = json.loads(result.stdout)
    if not isinstance(payload, list):
        msg = "Unexpected pip list output"
        raise RuntimeError(msg)
    return payload


def generate_cyclonedx(output_path: Path) -> None:
    """Generate a CycloneDX SBOM using cyclonedx-bom."""
    from cyclonedx.model import Bom
    from cyclonedx.model.component import Component, ComponentType
    from cyclonedx.output import OutputFormat, make_outputter
    from cyclonedx.schema import SchemaVersion

    from techspecter import __version__

    bom = Bom()
    root = Component(
        type=ComponentType.APPLICATION,
        name="techspecter",
        version=__version__,
    )
    bom.metadata.component = root

    for item in _pip_list_json():
        name = item.get("name", "")
        version = item.get("version", "")
        if not name:
            continue
        bom.components.add(
            Component(
                type=ComponentType.LIBRARY,
                name=name,
                version=version,
            ),
        )

    outputter = make_outputter(
        bom=bom,
        output_format=OutputFormat.JSON,
        schema_version=SchemaVersion.V1_5,
    )
    output_path.write_text(outputter.output_as_string(), encoding="utf-8")


def generate_spdx(output_path: Path) -> None:
    """Generate a SPDX JSON SBOM from installed packages."""
    from techspecter import __version__

    packages = _pip_list_json()
    document = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "techspecter-sbom",
        "documentNamespace": (
            f"https://github.com/Amirbarkhordari/TechSpecter/sbom/{datetime.now(UTC).isoformat()}"
        ),
        "creationInfo": {
            "created": datetime.now(UTC).isoformat(),
            "creators": ["Tool: techspecter-sbom-generator"],
        },
        "packages": [
            {
                "name": "techspecter",
                "SPDXID": "SPDXRef-Package-techspecter",
                "versionInfo": __version__,
                "downloadLocation": "NOASSERTION",
                "licenseConcluded": "MIT",
            },
            *[
                {
                    "name": item.get("name", "unknown"),
                    "SPDXID": f"SPDXRef-Package-{index}",
                    "versionInfo": item.get("version", "UNKNOWN"),
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                }
                for index, item in enumerate(packages, start=1)
            ],
        ],
        "relationships": [
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relatedSpdxElement": "SPDXRef-Package-techspecter",
                "relationshipType": "DESCRIBES",
            },
        ],
    }
    output_path.write_text(json.dumps(document, indent=2), encoding="utf-8")


def main() -> None:
    """Generate SBOM files."""
    parser = argparse.ArgumentParser(description="Generate TechSpecter SBOM artifacts.")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("dist/sbom"),
        help="Directory for SBOM output files.",
    )
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    cyclonedx_path = args.output_dir / "techspecter.cyclonedx.json"
    spdx_path = args.output_dir / "techspecter.spdx.json"

    generate_cyclonedx(cyclonedx_path)
    generate_spdx(spdx_path)
    print(f"CycloneDX SBOM written to {cyclonedx_path}")
    print(f"SPDX SBOM written to {spdx_path}")


if __name__ == "__main__":
    main()
