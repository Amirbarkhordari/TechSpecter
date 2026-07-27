"""Generate fingerprint JSON files from the bundled catalog manifest."""

from __future__ import annotations

import json
from pathlib import Path

CATALOG_PATH = Path(__file__).with_name("fingerprint_catalog.json")
OUTPUT_DIR = Path(__file__).resolve().parents[1] / "techspecter" / "fingerprints"


def main() -> None:
    """Write fingerprint JSON files from the catalog manifest."""
    catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for entry in catalog["fingerprints"]:
        target = OUTPUT_DIR / f"{entry['id']}.json"
        target.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {len(catalog['fingerprints'])} fingerprints to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
