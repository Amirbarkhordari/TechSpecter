"""Fingerprint signature loader."""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from pathlib import Path

from pydantic import ValidationError as PydanticValidationError

from techspecter.exceptions import FingerprintLoadError
from techspecter.fingerprints.models import Fingerprint

logger = logging.getLogger(__name__)

ENV_SIGNATURES_DIR = "TECHSPECTER_SIGNATURES_DIR"


def resolve_signatures_directory(custom_path: Path | str | None = None) -> Path:
    """Resolve the fingerprint signatures directory.

    Resolution order:

    1. Explicit ``custom_path`` argument
    2. ``TECHSPECTER_SIGNATURES_DIR`` environment variable
    3. ``signatures/`` directory at the project root
    4. ``signatures/`` directory bundled adjacent to the package

    Args:
        custom_path: Optional explicit signatures directory.

    Returns:
        Resolved signatures directory path.

    Raises:
        FingerprintLoadError: If no signatures directory can be resolved.
    """
    if custom_path is not None:
        path = Path(custom_path)
        if not path.is_dir():
            msg = f"Signatures directory does not exist: {path}"
            raise FingerprintLoadError(msg)
        return path

    env_path = os.environ.get(ENV_SIGNATURES_DIR)
    if env_path:
        path = Path(env_path)
        if not path.is_dir():
            msg = f"Configured signatures directory does not exist: {path}"
            raise FingerprintLoadError(msg)
        return path

    project_root = Path(__file__).resolve().parents[2]
    candidates = (
        project_root / "signatures",
        Path(__file__).resolve().parent / "signatures",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate

    msg = "Unable to locate fingerprint signatures directory."
    raise FingerprintLoadError(msg)


class SignatureLoader:
    """Load and cache technology fingerprint definitions from JSON files."""

    def __init__(self, signatures_dir: Path | str | None = None) -> None:
        """Initialize the signature loader.

        Args:
            signatures_dir: Optional explicit signatures directory path.
        """
        self._signatures_dir = resolve_signatures_directory(signatures_dir)
        self._cache: list[Fingerprint] | None = None

    @property
    def signatures_dir(self) -> Path:
        """Return the active signatures directory."""
        return self._signatures_dir

    def load_all(self, *, reload: bool = False) -> list[Fingerprint]:
        """Load all valid fingerprint definitions.

        Args:
            reload: When ``True``, bypass the in-memory cache.

        Returns:
            Sorted list of loaded fingerprints.

        Raises:
            FingerprintLoadError: If the signatures directory cannot be read.
        """
        if self._cache is not None and not reload:
            return list(self._cache)

        json_files = sorted(self._signatures_dir.glob("*.json"))
        if not json_files:
            msg = f"No fingerprint JSON files found in {self._signatures_dir}"
            raise FingerprintLoadError(msg)

        loaded: dict[str, Fingerprint] = {}
        for json_file in json_files:
            if json_file.name == "schema.json":
                continue
            fingerprint = self._load_file(json_file)
            if fingerprint is None:
                continue
            if fingerprint.id in loaded:
                logger.warning(
                    "Ignoring duplicate fingerprint ID '%s' from %s",
                    fingerprint.id,
                    json_file.name,
                )
                continue
            loaded[fingerprint.id] = fingerprint

        if not loaded:
            msg = f"No valid fingerprint definitions loaded from {self._signatures_dir}"
            raise FingerprintLoadError(msg)

        fingerprints = sorted(
            loaded.values(),
            key=lambda item: (-item.priority, item.name.lower()),
        )
        self._cache = fingerprints
        logger.info(
            "Loaded %d fingerprint signatures from %s",
            len(fingerprints),
            self._signatures_dir,
        )
        return list(fingerprints)

    def _load_file(self, json_file: Path) -> Fingerprint | None:
        """Load a single fingerprint JSON file.

        Args:
            json_file: Path to the JSON signature file.

        Returns:
            Parsed fingerprint, or ``None`` when the file is malformed.
        """
        try:
            raw = json_file.read_text(encoding="utf-8")
            payload = json.loads(raw)
            fingerprint = Fingerprint.model_validate(payload)
        except (OSError, json.JSONDecodeError, PydanticValidationError) as exc:
            logger.warning("Ignoring malformed fingerprint file %s: %s", json_file.name, exc)
            return None

        if fingerprint.id != json_file.stem and json_file.stem not in {"schema"}:
            logger.debug(
                "Fingerprint file %s ID '%s' differs from filename stem.",
                json_file.name,
                fingerprint.id,
            )
        return fingerprint


@lru_cache(maxsize=4)
def get_cached_signatures(signatures_dir: str) -> tuple[Fingerprint, ...]:
    """Return cached fingerprints for a signatures directory path.

    Args:
        signatures_dir: String path to the signatures directory.

    Returns:
        Immutable tuple of loaded fingerprints.
    """
    loader = SignatureLoader(signatures_dir)
    return tuple(loader.load_all())
