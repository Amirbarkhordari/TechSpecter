"""Technology signature loader."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError

from techspecter.fingerprinting.signatures.models import TechnologySignature

logger = logging.getLogger(__name__)

PACKAGE_SIGNATURES_DIR = Path(__file__).resolve().parent / "data"


class TechnologySignatureLoader:
    """Load evidence-based technology signatures from JSON files."""

    def __init__(self, signatures_dir: Path | str | None = None) -> None:
        """Initialize loader with optional custom directory."""
        self._signatures_dir = Path(signatures_dir) if signatures_dir else PACKAGE_SIGNATURES_DIR
        self._cache: list[TechnologySignature] | None = None

    @property
    def signatures_dir(self) -> Path:
        """Return active signatures directory."""
        return self._signatures_dir

    def load_all(self, *, reload: bool = False) -> list[TechnologySignature]:
        """Load all technology signatures."""
        if self._cache is not None and not reload:
            return list(self._cache)

        if not self._signatures_dir.is_dir():
            logger.warning("Technology signatures directory missing: %s", self._signatures_dir)
            self._cache = []
            return []

        loaded: dict[str, TechnologySignature] = {}
        for json_file in sorted(self._signatures_dir.glob("*.json")):
            signature = self._load_file(json_file)
            if signature is None:
                continue
            loaded[signature.id] = signature

        signatures = sorted(loaded.values(), key=lambda item: (-item.priority, item.name.lower()))
        self._cache = signatures
        logger.info(
            "Loaded %d technology signatures from %s", len(signatures), self._signatures_dir
        )
        return list(signatures)

    def _load_file(self, json_file: Path) -> TechnologySignature | None:
        """Load one signature JSON file."""
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
            return TechnologySignature.model_validate(payload)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            logger.warning("Ignoring invalid technology signature %s: %s", json_file.name, exc)
            return None


@lru_cache(maxsize=2)
def get_cached_technology_signatures(signatures_dir: str) -> tuple[TechnologySignature, ...]:
    """Return cached technology signatures."""
    loader = TechnologySignatureLoader(signatures_dir)
    return tuple(loader.load_all())
