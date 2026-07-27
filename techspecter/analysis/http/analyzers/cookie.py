"""Cookie analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.helpers import build_http_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class CookieAnalyzer(PassiveHttpAnalyzer):
    """Analyze cookies observed in passive HTTP responses."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="cookie-analyzer",
            name="Cookie Analyzer",
            version="1.0.0",
            description="Extracts cookie attributes from passive HTTP responses.",
            category=FindingCategory.COOKIES.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        findings = []
        if not observation.cookies:
            findings.append(
                build_http_finding(
                    finding_id="cookie:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.COOKIES,
                    title="No cookies observed",
                    description="The passive HTTP response did not set any cookies.",
                    url=observation.final_url,
                )
            )
            return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)

        for index, cookie in enumerate(observation.cookies, start=1):
            description = (
                f"Cookie `{cookie.name}` was observed with Secure={cookie.secure}, "
                f"HttpOnly={cookie.httponly}, SameSite={cookie.samesite or 'unset'}."
            )
            findings.append(
                build_http_finding(
                    finding_id=f"cookie:{cookie.name}:{index}",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.COOKIES,
                    title=f"Cookie observed: {cookie.name}",
                    description=description,
                    recommendation="Review cookie attributes for expected passive configuration.",
                    cookie=cookie.raw,
                    url=observation.final_url,
                    metadata={
                        "name": cookie.name,
                        "domain": cookie.domain,
                        "path": cookie.path,
                        "expires": cookie.expires,
                        "max_age": cookie.max_age,
                        "secure": cookie.secure,
                        "httponly": cookie.httponly,
                        "samesite": cookie.samesite,
                        "priority": cookie.priority,
                        "partitioned": cookie.partitioned,
                        "host_prefix": cookie.host_prefix,
                        "secure_prefix": cookie.secure_prefix,
                    },
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
