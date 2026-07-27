"""Rule loading and discovery."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from techspecter.rules.cache import RuleCache
from techspecter.rules.models import Rule

logger = logging.getLogger(__name__)

DEFAULT_RULES_DIR = Path(__file__).resolve().parent / "data"


class RuleLoader:
    """Discover and load rules from YAML and JSON files."""

    def __init__(
        self,
        *,
        rule_directories: list[str | Path] | None = None,
        cache: RuleCache | None = None,
        use_cache: bool = True,
    ) -> None:
        """Initialize the rule loader."""
        directories = [Path(item) for item in (rule_directories or [DEFAULT_RULES_DIR])]
        self._directories = directories
        self._cache = cache or RuleCache()
        self._use_cache = use_cache

    def load_all(self) -> list[Rule]:
        """Load all rules from configured directories."""
        cache_key = "|".join(str(path.resolve()) for path in self._directories)
        if self._use_cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return list(cached)

        rules: list[Rule] = []
        for directory in self._directories:
            if not directory.is_dir():
                logger.debug("Rule directory does not exist: %s", directory)
                continue
            for path in sorted(directory.glob("*")):
                if path.suffix.lower() not in {".yaml", ".yml", ".json"}:
                    continue
                rules.extend(self._load_file(path))

        if self._use_cache:
            self._cache.set(cache_key, rules)
        logger.info("Loaded %d rules from %d directories", len(rules), len(self._directories))
        return rules

    def _load_file(self, path: Path) -> list[Rule]:
        """Load rules from a single file."""
        try:
            raw = path.read_text(encoding="utf-8")
            payload = json.loads(raw) if path.suffix.lower() == ".json" else yaml.safe_load(raw)
        except (OSError, yaml.YAMLError, json.JSONDecodeError) as exc:
            logger.warning("Failed to load rule file '%s': %s", path, exc)
            return []

        return self._parse_payload(payload, source=str(path))

    def _parse_payload(self, payload: Any, *, source: str) -> list[Rule]:
        """Parse a rule payload into rule models."""
        if payload is None:
            return []
        if isinstance(payload, dict) and "rules" in payload:
            items = payload["rules"]
        elif isinstance(payload, list):
            items = payload
        elif isinstance(payload, dict):
            items = [payload]
        else:
            logger.warning("Unsupported rule payload in %s", source)
            return []

        rules: list[Rule] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                rules.append(Rule.model_validate(item))
            except Exception as exc:
                logger.warning("Invalid rule in %s: %s", source, exc)
        return rules

    def clear_cache(self) -> None:
        """Clear the rule loader cache."""
        self._cache.clear()
