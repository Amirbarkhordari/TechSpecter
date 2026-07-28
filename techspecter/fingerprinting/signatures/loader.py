"""Technology signature loader."""

from __future__ import annotations

import json
import logging
from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError

from techspecter.fingerprinting.signatures.catalog import build_catalog
from techspecter.fingerprinting.signatures.compiler import compile_signature
from techspecter.fingerprinting.signatures.models import TechnologySignature
from techspecter.fingerprinting.signatures.validator import SignatureValidator

logger = logging.getLogger(__name__)

PACKAGE_SIGNATURES_DIR = Path(__file__).resolve().parent / "data"


class TechnologySignatureLoader:
    """Load evidence-based technology signatures from JSON and catalog."""

    def __init__(
        self,
        signatures_dir: Path | str | None = None,
        *,
        include_catalog: bool = True,
        validate: bool = True,
    ) -> None:
        """Initialize loader with optional custom directory."""
        self._signatures_dir = Path(signatures_dir) if signatures_dir else PACKAGE_SIGNATURES_DIR
        self._include_catalog = include_catalog
        self._validate = validate
        self._validator = SignatureValidator()
        self._cache: list[TechnologySignature] | None = None

    @property
    def signatures_dir(self) -> Path:
        """Return active signatures directory."""
        return self._signatures_dir

    def load_all(self, *, reload: bool = False) -> list[TechnologySignature]:
        """Load all technology signatures."""
        if self._cache is not None and not reload:
            return list(self._cache)

        loaded: dict[str, TechnologySignature] = {}

        if self._signatures_dir.is_dir():
            for json_file in sorted(self._signatures_dir.rglob("*.json")):
                signature = self._load_file(json_file)
                if signature is None:
                    continue
                loaded[signature.id] = signature

        if self._include_catalog:
            for signature in build_catalog():
                loaded[signature.id] = signature

        compiled = [self._finalize(item) for item in loaded.values()]
        signatures = sorted(compiled, key=lambda item: (-item.priority, item.name.lower()))
        self._cache = signatures
        logger.info(
            "Loaded %d technology signatures (%d from files, catalog=%s)",
            len(signatures),
            len(list(self._signatures_dir.rglob("*.json"))) if self._signatures_dir.is_dir() else 0,
            self._include_catalog,
        )
        return list(signatures)

    def load_by_category(self, category: str) -> list[TechnologySignature]:
        """Return signatures for a category."""
        return [item for item in self.load_all() if item.category == category]

    def categories(self) -> dict[str, int]:
        """Return signature counts grouped by category."""
        counts: dict[str, int] = {}
        for signature in self.load_all():
            counts[signature.category] = counts.get(signature.category, 0) + 1
        return counts

    def _load_file(self, json_file: Path) -> TechnologySignature | None:
        """Load one signature JSON file."""
        try:
            payload = json.loads(json_file.read_text(encoding="utf-8"))
            return TechnologySignature.model_validate(payload)
        except (OSError, json.JSONDecodeError, ValidationError) as exc:
            logger.warning("Ignoring invalid technology signature %s: %s", json_file.name, exc)
            return None

    def _finalize(self, signature: TechnologySignature) -> TechnologySignature:
        """Compile and validate a signature."""
        compiled = compile_signature(signature)
        if self._validate:
            self._validator.validate_or_raise(compiled)
        return compiled


@lru_cache(maxsize=2)
def get_cached_technology_signatures(signatures_dir: str) -> tuple[TechnologySignature, ...]:
    """Return cached technology signatures."""
    loader = TechnologySignatureLoader(signatures_dir)
    return tuple(loader.load_all())
