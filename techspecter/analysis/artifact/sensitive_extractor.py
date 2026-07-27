"""Passive sensitive artifact extraction from collected discovery data."""

from __future__ import annotations

import logging
import math
import re
from collections import Counter

from techspecter.analysis.artifact.classification import ClassificationEngine
from techspecter.analysis.artifact.risk import RiskEngine
from techspecter.analysis.artifact.sources import ArtifactTextSource, collect_artifact_text_sources
from techspecter.models.artifact import ArtifactReference
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)

_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws-access-key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("google-api-key", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("firebase-key", re.compile(r"firebase[_-]?api[_-]?key\s*[:=]", re.I)),
    ("stripe-secret-key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{16,}")),
    ("github-token", re.compile(r"(?:ghp_|github_pat_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{20,}")),
    ("gitlab-token", re.compile(r"glpat-[A-Za-z0-9\-_]{20,}")),
    ("slack-token", re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}")),
    ("discord-token", re.compile(r"[MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}")),
    ("twilio-key", re.compile(r"AC[a-f0-9]{32}")),
    ("sendgrid-key", re.compile(r"SG\.[A-Za-z0-9_\-]{20,}")),
    ("azure-key", re.compile(r"(?:AccountKey|SharedAccessSignature)=[A-Za-z0-9+/=]{20,}", re.I)),
    ("jwt-token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("bearer-token-ref", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{10,}", re.I)),
    ("basic-auth-token", re.compile(r"Basic\s+[A-Za-z0-9+/=]{10,}", re.I)),
    ("public-ssh-key", re.compile(r"ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{20,}")),
    ("pem-block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("private-key-header", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("certificate-block", re.compile(r"-----BEGIN CERTIFICATE-----")),
    ("webhook-token", re.compile(r"(?:whsec_|webhook[_-]?token\s*[:=])", re.I)),
)

_CONFIG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "config-file-ref",
        re.compile(r"(?:/|\b)(?:config|settings|application)\.(?:json|ya?ml|toml|ini)\b", re.I),
    ),
    ("env-reference", re.compile(r"process\.env\.[A-Z0-9_]+|import\.meta\.env\.[A-Z0-9_]+")),
    ("runtime-config", re.compile(r"runtime[_-]?config\s*[:=]|__RUNTIME_CONFIG__", re.I)),
    ("frontend-config", re.compile(r"window\.__[A-Z0-9_]*CONFIG__", re.I)),
    ("public-config", re.compile(r"public[_-]?config\s*[:=]", re.I)),
    ("app-config", re.compile(r"app[_-]?config\s*[:=]|application[_-]?config", re.I)),
    ("framework-config", re.compile(r"(?:next|nuxt|vue|angular)[_-]?config", re.I)),
    (
        "deployment-config",
        re.compile(r"deploy(?:ment)?[_-]?config|vercel\.json|netlify\.toml", re.I),
    ),
    ("dotenv-reference", re.compile(r"\.env(?:\.(?:local|production|development))?\b", re.I)),
    ("client-config", re.compile(r"window\.__(?:INITIAL_STATE|APP_CONFIG|NUXT__)__", re.I)),
)

_BUILD_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("webpack-build", re.compile(r"webpack(?:Jsonp|Chunk|Runtime)|__webpack_require__", re.I)),
    ("vite-build", re.compile(r"/@vite/|vite\.config|import\.meta\.hot", re.I)),
    ("rollup-build", re.compile(r"rollup(?:Plugin)?|Rollup", re.I)),
    ("parcel-build", re.compile(r"parcelRequire|@parcel/", re.I)),
    ("nextjs-build", re.compile(r"__NEXT_DATA__|/_next/static/|next/dist", re.I)),
    ("nuxt-build", re.compile(r"__NUXT__|/_nuxt/|nuxt\.config", re.I)),
    ("angular-build", re.compile(r"ng-version|angular\.json|@angular/", re.I)),
    (
        "react-build",
        re.compile(r"react(?:-dom)?(?:\.production|\.development)?\.min\.js|data-reactroot", re.I),
    ),
    ("vue-build", re.compile(r"vue(?:\.runtime)?(?:\.min)?\.js|__VUE__|data-v-", re.I)),
    ("svelte-build", re.compile(r"svelte(?:/internal|-hydrate)?|__svelte", re.I)),
    ("remix-build", re.compile(r"@remix-run/|remix\.config", re.I)),
    ("astro-build", re.compile(r"astro(?:\.config|/assets/)", re.I)),
    ("build-id", re.compile(r"build[_-]?id\s*[:=]\s*['\"][^'\"]+['\"]", re.I)),
    ("chunk-naming", re.compile(r"(?:chunk|vendor|main)[_.-][a-f0-9]{8,}\.(?:js|css)", re.I)),
    ("bundle-metadata", re.compile(r"bundle(?:Id|Hash|Version)\s*[:=]", re.I)),
    ("version-metadata", re.compile(r"(?:app|asset|release)[_-]?version\s*[:=]", re.I)),
    ("asset-manifest", re.compile(r"asset-manifest\.json|manifest\.json", re.I)),
)

_DEBUG_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("debug-comment", re.compile(r"<!--\s*(?:DEBUG|DEV|TODO:.*debug)", re.I)),
    ("dev-banner", re.compile(r"(?:development|debug)\s+(?:mode|build|environment)", re.I)),
    ("debug-endpoint", re.compile(r"/(?:debug|__debug|_debug|dev-tools)(?:/|\b)", re.I)),
    ("stack-trace", re.compile(r"at\s+\w+\.[a-zA-Z]+\([^)]*:\d+:\d+\)|Stack trace:", re.I)),
    ("framework-debug", re.compile(r"__REACT_DEVTOOLS|__VUE_DEVTOOLS|ng\.probe", re.I)),
    ("dev-mode", re.compile(r"__DEV__\s*=\s*true|NODE_ENV\s*=\s*['\"]development['\"]", re.I)),
    ("build-env", re.compile(r"BUILD_ENV\s*[:=]\s*['\"]development['\"]", re.I)),
)

_BACKUP_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "backup-filename",
        re.compile(r"\.(?:bak|backup|old|orig|save)(?:\.\w+)?(?:\?|\"|'|\s|$)", re.I),
    ),
    ("temp-file", re.compile(r"\.(?:tmp|temp|swp|~)(?:\.\w+)?(?:\?|\"|'|\s|$)", re.I)),
    ("archive-ref", re.compile(r"\.(?:zip|tar|gz|tgz|7z|rar)(?:\?|\"|'|\s|$)", re.I)),
    ("old-config-ref", re.compile(r"config\.(?:old|bak|backup|example)", re.I)),
    ("legacy-asset", re.compile(r"/(?:legacy|old|archive|deprecated)/", re.I)),
    ("deployment-leftover", re.compile(r"\.DS_Store|Thumbs\.db|\.git/|\.svn/", re.I)),
)

_ENV_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("env-reference", re.compile(r"(?:process\.env|import\.meta\.env|DOTENV)\b")),
    ("dotenv-reference", re.compile(r"dotenv|\.env\b")),
)

_SOURCE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("source-artifact", re.compile(r"sourceMappingURL=|//# sourceURL=", re.I)),
)

_DEV_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("dev-server", re.compile(r"localhost:\d+|127\.0\.0\.1:\d+|webpack-dev-server", re.I)),
    ("hot-reload", re.compile(r"hot-module-replacement|HMR|react-refresh", re.I)),
)

_INFRA_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("infra-metadata", re.compile(r"(?:docker|kubernetes|k8s|terraform|helm)\b", re.I)),
)

_CATEGORY_PATTERNS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "secret": _SECRET_PATTERNS,
    "configuration": _CONFIG_PATTERNS,
    "build": _BUILD_PATTERNS,
    "debug": _DEBUG_PATTERNS,
    "backup": _BACKUP_PATTERNS,
    "environment": _ENV_PATTERNS,
    "source": _SOURCE_PATTERNS,
    "client-config": _CONFIG_PATTERNS[-1:],  # client-config only
    "development": _DEV_PATTERNS,
    "infrastructure": _INFRA_PATTERNS,
}

_ENTROPY_PATTERN = re.compile(
    r"(?:token|secret|password|key)\s*[:=]\s*['\"]([A-Za-z0-9+/=_\-]{24,})['\"]",
    re.I,
)


class SensitiveArtifactExtractor:
    """Extract passive sensitive, configuration, and build artifact indicators."""

    def __init__(
        self,
        *,
        entropy_threshold: float = 3.5,
        classifier: ClassificationEngine | None = None,
        risk_engine: RiskEngine | None = None,
    ) -> None:
        """Initialize with optional classification and risk engines."""
        self._entropy_threshold = entropy_threshold
        self._classifier = classifier or ClassificationEngine()
        self._risk_engine = risk_engine or RiskEngine(self._classifier)

    def extract(self, discovery: DiscoveryResult) -> list[ArtifactReference]:
        """Scan collected data for sensitive artifact patterns."""
        sources = collect_artifact_text_sources(discovery)
        references: list[ArtifactReference] = []
        seen: set[tuple[str, str, str]] = set()

        for text_source in sources:
            references.extend(self._scan_patterns(text_source, seen))
            references.extend(self._scan_entropy(text_source, seen))

        enriched = self._enrich_with_risk(references)
        logger.debug("Extracted %d sensitive artifact references", len(enriched))
        return enriched

    def _scan_patterns(
        self,
        text_source: ArtifactTextSource,
        seen: set[tuple[str, str, str]],
    ) -> list[ArtifactReference]:
        """Scan text for categorized sensitive patterns."""
        references: list[ArtifactReference] = []
        content = text_source.content

        for category, patterns in _CATEGORY_PATTERNS.items():
            for artifact_type, pattern in patterns:
                for match in pattern.finditer(content):
                    value = self._redact_match(artifact_type, match.group(0))
                    key = (artifact_type, value, text_source.source)
                    if key in seen:
                        continue
                    seen.add(key)
                    start = max(0, match.start() - 20)
                    end = min(len(content), match.end() + 20)
                    references.append(
                        ArtifactReference(
                            artifact_type=artifact_type,
                            category=category,
                            value=value,
                            source=text_source.source,
                            location=text_source.location,
                            snippet=content[start:end],
                            metadata={"redacted": True},
                        ),
                    )
        return references

    def _scan_entropy(
        self,
        text_source: ArtifactTextSource,
        seen: set[tuple[str, str, str]],
    ) -> list[ArtifactReference]:
        """Detect high-entropy token assignments passively."""
        references: list[ArtifactReference] = []
        for match in _ENTROPY_PATTERN.finditer(text_source.content):
            token = match.group(1)
            if _shannon_entropy(token) < self._entropy_threshold:
                continue
            key = ("high-entropy-token", token[:20], text_source.source)
            if key in seen:
                continue
            seen.add(key)
            references.append(
                ArtifactReference(
                    artifact_type="high-entropy-token",
                    category="secret",
                    value="high-entropy-token [redacted]",
                    source=text_source.source,
                    location=text_source.location,
                    snippet=match.group(0)[:80] + "...",
                    metadata={"redacted": True, "entropy": round(_shannon_entropy(token), 2)},
                ),
            )
        return references

    def _enrich_with_risk(self, references: list[ArtifactReference]) -> list[ArtifactReference]:
        """Attach classification and risk metadata to references."""
        enriched: list[ArtifactReference] = []
        for reference in references:
            assessment = self._risk_engine.assess(reference)
            metadata = {
                **reference.metadata,
                "classification": assessment.classification.value,
                "risk_level": assessment.risk_level.value,
                "severity": assessment.severity.value,
                "confidence": assessment.confidence,
            }
            enriched.append(reference.model_copy(update={"metadata": metadata}))
        return enriched

    @staticmethod
    def _redact_match(artifact_type: str, value: str) -> str:
        """Redact sensitive matched values for passive reporting."""
        if artifact_type in {
            "aws-access-key",
            "google-api-key",
            "github-token",
            "gitlab-token",
            "stripe-secret-key",
            "jwt-token",
            "bearer-token-ref",
            "basic-auth-token",
        }:
            return f"{artifact_type} [redacted]"
        return value[:80] + ("..." if len(value) > 80 else "")


def _shannon_entropy(value: str) -> float:
    """Calculate Shannon entropy for passive high-entropy detection."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())
