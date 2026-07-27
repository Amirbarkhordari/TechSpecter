"""Passive artifact extraction from already-collected discovery data."""

from __future__ import annotations

import logging
import re

from techspecter.analysis.artifact.sources import ArtifactTextSource, collect_artifact_text_sources
from techspecter.models.artifact import ArtifactDiscoveryObservation, ArtifactReference
from techspecter.models.discovery import DiscoveryResult

logger = logging.getLogger(__name__)

_JWT_PATTERN = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
)
_BEARER_PATTERN = re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{10,}", re.IGNORECASE)
_API_KEY_PATTERN = re.compile(
    r"(?:api[_-]?key|x-api-key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9._-]{8,})",
    re.IGNORECASE,
)

_PATTERN_DEFINITIONS: tuple[tuple[str, str, re.Pattern[str]], ...] = (
    # API technologies
    ("openapi", "api", re.compile(r"openapi\s*[:=]?\s*['\"]?(?:3\.|2\.|1\.)", re.I)),
    ("swagger", "api", re.compile(r"swagger(?:\.json|\.yaml|ui|/v\d)?", re.I)),
    ("swagger-ui", "api", re.compile(r"swagger-ui|swaggerui", re.I)),
    ("redoc", "api", re.compile(r"redoc(?:\.min)?\.(?:js|css)|/redoc", re.I)),
    ("graphql", "api", re.compile(r"/graphql|graphql(?:\.js|endpoint|api)?", re.I)),
    ("graphql-playground", "api", re.compile(r"graphql-playground|graphiql", re.I)),
    ("graphql-voyager", "api", re.compile(r"graphql-voyager", re.I)),
    ("apollo", "api", re.compile(r"apollo(?:-client|-server|-graphql|\.io)?", re.I)),
    ("rest-api-version", "api", re.compile(r"/api/v\d+|api[_-]?version\s*[:=]", re.I)),
    ("api-documentation", "api", re.compile(r"api[_-]?docs?|/docs/api", re.I)),
    # Identity
    ("oauth", "identity", re.compile(r"oauth(?:2)?(?:/authorize|/token|\.well-known)?", re.I)),
    ("oidc", "identity", re.compile(r"openid-connect|\.well-known/openid-configuration", re.I)),
    ("openid", "identity", re.compile(r"openid(?:\.|/|\s)", re.I)),
    ("jwks", "identity", re.compile(r"\.well-known/jwks\.json|/jwks", re.I)),
    ("authorization-endpoint", "identity", re.compile(r"authorization_endpoint\s*[:=]", re.I)),
    ("token-endpoint", "identity", re.compile(r"token_endpoint\s*[:=]", re.I)),
    ("issuer", "identity", re.compile(r"issuer\s*[:=]\s*['\"]https?://", re.I)),
    # Cloud - AWS
    ("aws", "cloud", re.compile(r"amazonaws\.com|aws-sdk|AWS\.", re.I)),
    ("s3", "cloud", re.compile(r"s3[.-](?:amazonaws|dualstack)\.com|s3://", re.I)),
    ("cloudfront", "cloud", re.compile(r"cloudfront\.net|\.cloudfront\.", re.I)),
    # Cloud - Azure
    ("azure", "cloud", re.compile(r"azure(?:websites|edge)?\.net|blob\.core\.windows\.net", re.I)),
    ("blob-storage", "cloud", re.compile(r"blob\.core\.windows\.net|\.blob\.storage", re.I)),
    # Cloud - GCP / Firebase
    ("gcp", "cloud", re.compile(r"googleapis\.com|google-cloud|gstatic\.com/cloud", re.I)),
    ("firebase", "cloud", re.compile(r"firebase(?:app|io|google)?\.com|firebaseConfig", re.I)),
    # CDN / hosting
    ("cloudflare", "cloud", re.compile(r"cloudflare(?:insights|cdn)?|cf-ray|__cf_bm", re.I)),
    ("fastly", "cloud", re.compile(r"fastly\.net|fastly-insights", re.I)),
    ("akamai", "cloud", re.compile(r"akamai(?:hd)?\.net|akamai\.com", re.I)),
    ("netlify", "cloud", re.compile(r"netlify(?:app)?\.com|netlify\.dev", re.I)),
    ("vercel", "cloud", re.compile(r"vercel\.app|vercel\.com|/_next/static", re.I)),
    ("github-pages", "cloud", re.compile(r"github\.io|githubusercontent\.com/pages", re.I)),
    # Analytics
    ("google-analytics", "analytics", re.compile(r"google-analytics\.com|gtag\(|ga\(", re.I)),
    ("google-tag-manager", "analytics", re.compile(r"googletagmanager\.com|GTM-[A-Z0-9]+", re.I)),
    ("matomo", "analytics", re.compile(r"matomo(?:\.js|\.php)?|piwik", re.I)),
    # Monitoring
    ("sentry", "monitoring", re.compile(r"sentry(?:\.io|-dsn|\.js)|dsn\s*[:=].*sentry", re.I)),
    ("rollbar", "monitoring", re.compile(r"rollbar(?:\.com|\.js)|rollbar\.init", re.I)),
    ("bugsnag", "monitoring", re.compile(r"bugsnag(?:\.com|\.js)|bugsnag\.start", re.I)),
    # Third-party services
    ("hotjar", "third-party", re.compile(r"hotjar(?:\.com|\.js)", re.I)),
    ("intercom", "third-party", re.compile(r"intercom(?:cdn)?\.com|Intercom\(", re.I)),
    ("zendesk", "third-party", re.compile(r"zendesk(?:\.com|\.js)|zE\(", re.I)),
    ("stripe", "third-party", re.compile(r"stripe(?:\.com|\.js)|pk_(?:live|test)_", re.I)),
    ("paypal", "third-party", re.compile(r"paypal(?:objects)?\.com|paypal\.Buttons", re.I)),
    ("recaptcha", "third-party", re.compile(r"recaptcha(?:\.net|/api)|g-recaptcha", re.I)),
    ("hcaptcha", "third-party", re.compile(r"hcaptcha\.com|h-captcha", re.I)),
    # Technology exposure
    ("public-key", "token", re.compile(r"-----BEGIN (?:RSA |EC )?PUBLIC KEY-----", re.I)),
    ("technology-exposure", "technology", re.compile(r"webpack|vite|esbuild|rollup|parcel", re.I)),
)


class ArtifactExtractor:
    """Extract passive artifact indicators from collected discovery data."""

    def extract(self, discovery: DiscoveryResult) -> ArtifactDiscoveryObservation:
        """Scan already-collected data for passive artifact indicators."""
        sources = collect_artifact_text_sources(discovery)
        references: list[ArtifactReference] = []
        seen: set[tuple[str, str, str]] = set()

        for text_source in sources:
            references.extend(
                self._scan_text(text_source, seen),
            )

        logger.debug(
            "Extracted %d artifact references from %d sources",
            len(references),
            len(sources),
        )
        return ArtifactDiscoveryObservation(
            references=references,
            sources_scanned=[item.source for item in sources],
        )

    def _scan_text(
        self,
        text_source: ArtifactTextSource,
        seen: set[tuple[str, str, str]],
    ) -> list[ArtifactReference]:
        """Scan a text source for artifact patterns."""
        references: list[ArtifactReference] = []
        content = text_source.content

        for artifact_type, category, pattern in _PATTERN_DEFINITIONS:
            for match in pattern.finditer(content):
                value = match.group(0)
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
                    ),
                )

        for match in _JWT_PATTERN.finditer(content):
            value = match.group(0)
            key = ("jwt", value[:40], text_source.source)
            if key not in seen:
                seen.add(key)
                references.append(
                    ArtifactReference(
                        artifact_type="jwt",
                        category="token",
                        value=value[:80] + ("..." if len(value) > 80 else ""),
                        source=text_source.source,
                        location=text_source.location,
                        snippet=value[:120],
                        metadata={"redacted": True},
                    ),
                )

        for match in _BEARER_PATTERN.finditer(content):
            value = match.group(0)
            key = ("bearer-token", value[:30], text_source.source)
            if key not in seen:
                seen.add(key)
                references.append(
                    ArtifactReference(
                        artifact_type="bearer-token",
                        category="token",
                        value="Bearer [redacted]",
                        source=text_source.source,
                        location=text_source.location,
                        snippet=value[:60] + "...",
                        metadata={"redacted": True},
                    ),
                )

        for match in _API_KEY_PATTERN.finditer(content):
            value = match.group(0)
            key = ("api-key", value[:30], text_source.source)
            if key not in seen:
                seen.add(key)
                references.append(
                    ArtifactReference(
                        artifact_type="api-key",
                        category="token",
                        value="api-key [redacted]",
                        source=text_source.source,
                        location=text_source.location,
                        snippet=value[:60] + "...",
                        metadata={"redacted": True},
                    ),
                )

        return references
