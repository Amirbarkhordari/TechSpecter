"""Passive artifact extraction from already-collected discovery data."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

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


@dataclass(frozen=True, slots=True)
class _TextSource:
    """A text source scanned for passive artifact indicators."""

    content: str
    source: str
    location: str | None = None


class ArtifactExtractor:
    """Extract passive artifact indicators from collected discovery data."""

    def extract(self, discovery: DiscoveryResult) -> ArtifactDiscoveryObservation:
        """Scan already-collected data for passive artifact indicators."""
        sources = self._collect_text_sources(discovery)
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

    def _collect_text_sources(self, discovery: DiscoveryResult) -> list[_TextSource]:
        """Gather text from HTTP, HTML, metadata, scripts, and well-known resources."""
        sources: list[_TextSource] = []
        target_url = str(discovery.target.url)

        if discovery.http_response is not None:
            http = discovery.http_response
            header_text = "\n".join(f"{k}: {v}" for k, v in http.headers.items())
            if header_text:
                sources.append(
                    _TextSource(content=header_text, source="http-headers", location=target_url),
                )
            for redirect in http.redirects:
                sources.append(
                    _TextSource(
                        content=redirect.url,
                        source="http-redirect",
                        location=redirect.url,
                    ),
                )

        if discovery.metadata_observation is not None:
            metadata = discovery.metadata_observation
            if metadata.html is not None:
                html = metadata.html
                html_fields = [
                    html.title,
                    html.description,
                    html.keywords,
                    html.author,
                    html.generator,
                    *html.framework_hints,
                    *html.pwa_indicators,
                    *html.ssr_indicators,
                ]
                for key, value in html.opengraph.items():
                    html_fields.append(f"{key}={value}")
                for key, value in html.twitter_cards.items():
                    html_fields.append(f"{key}={value}")
                combined = "\n".join(item for item in html_fields if item)
                if combined:
                    sources.append(
                        _TextSource(content=combined, source="html-metadata", location=html.url),
                    )
                for link in html.links:
                    sources.append(
                        _TextSource(
                            content=f"{link.rel} {link.href}",
                            source="html-link",
                            location=html.url,
                        ),
                    )
                for comment in html.comments:
                    sources.append(
                        _TextSource(
                            content=comment.content,
                            source="html-comment",
                            location=html.url,
                        ),
                    )

            for resource in metadata.well_known_resources:
                if resource.content:
                    sources.append(
                        _TextSource(
                            content=resource.content,
                            source=f"well-known:{resource.resource_type}",
                            location=resource.url,
                        ),
                    )

        for script in discovery.inline_scripts:
            sources.append(
                _TextSource(
                    content=script.content,
                    source="inline-script",
                    location=f"inline-script:{script.index}",
                ),
            )

        for download in discovery.downloads:
            if download.content:
                sources.append(
                    _TextSource(
                        content=download.content,
                        source="external-script",
                        location=str(download.url),
                    ),
                )
            sources.append(
                _TextSource(
                    content=str(download.url),
                    source="external-script-url",
                    location=str(download.url),
                ),
            )

        for external in discovery.external_scripts:
            sources.append(
                _TextSource(
                    content=str(external.url),
                    source="external-script-url",
                    location=str(external.url),
                ),
            )

        return sources

    def _scan_text(
        self,
        text_source: _TextSource,
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
