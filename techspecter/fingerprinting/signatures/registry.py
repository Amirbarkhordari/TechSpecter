"""Technology signature registry."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from techspecter.fingerprinting.signatures.loader import TechnologySignatureLoader
from techspecter.fingerprinting.signatures.models import TechnologySignature

logger = logging.getLogger(__name__)


@dataclass
class SignatureRegistry:
    """Registry for technology signatures and plugin-provided rules."""

    loader: TechnologySignatureLoader = field(default_factory=TechnologySignatureLoader)
    _custom_signatures: list[TechnologySignature] = field(default_factory=list)

    def register(self, signature: TechnologySignature) -> None:
        """Register a custom technology signature."""
        if any(item.id == signature.id for item in self._custom_signatures):
            logger.warning("Replacing custom signature '%s'", signature.id)
            self._custom_signatures = [
                item for item in self._custom_signatures if item.id != signature.id
            ]
        self._custom_signatures.append(signature)

    def resolve(self) -> list[TechnologySignature]:
        """Return merged built-in and custom signatures sorted by priority."""
        loaded = {signature.id: signature for signature in self.loader.load_all()}
        for signature in self._custom_signatures:
            loaded[signature.id] = signature
        return sorted(loaded.values(), key=lambda item: (-item.priority, item.name.lower()))


signature_registry = SignatureRegistry()
