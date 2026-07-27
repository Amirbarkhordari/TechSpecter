"""Redirect analyzer implementation."""

from __future__ import annotations

from techspecter.analysis.analyzers.base import AnalyzerMetadata
from techspecter.analysis.http.analyzers.base import PassiveHttpAnalyzer
from techspecter.analysis.http.helpers import build_http_finding
from techspecter.analysis.models.finding import FindingCategory
from techspecter.analysis.results.analysis_result import AnalyzerResult
from techspecter.models.http import HttpResponseObservation


class RedirectAnalyzer(PassiveHttpAnalyzer):
    """Analyze redirect chains observed passively."""

    @property
    def metadata(self) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            id="redirect-analyzer",
            name="Redirect Analyzer",
            version="1.0.0",
            description="Analyzes redirect chains from passive HTTP responses.",
            category=FindingCategory.HTTP.value,
        )

    def analyze_http(self, observation: HttpResponseObservation) -> AnalyzerResult:
        findings = []
        if not observation.redirects:
            findings.append(
                build_http_finding(
                    finding_id="redirect:none",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.HTTP,
                    title="No redirect chain observed",
                    description="The passive request did not traverse any redirect hops.",
                    url=observation.final_url,
                    metadata={"status_code": observation.status_code},
                )
            )
        else:
            for index, hop in enumerate(observation.redirects, start=1):
                findings.append(
                    build_http_finding(
                        finding_id=f"redirect:{index}",
                        analyzer_id=self.metadata.id,
                        category=FindingCategory.HTTP,
                        title=f"Redirect hop {index}",
                        description=(
                            f"Redirect hop {index} returned status {hop.status_code} "
                            f"for `{hop.url}`."
                        ),
                        url=hop.url,
                        metadata={
                            "status_code": hop.status_code,
                            "location": hop.location,
                            "hop_index": index,
                        },
                    )
                )
        location = observation.headers.get("location")
        if location is not None:
            findings.append(
                build_http_finding(
                    finding_id="redirect:location-header",
                    analyzer_id=self.metadata.id,
                    category=FindingCategory.HTTP,
                    title="Location header observed",
                    description=f"The final response included Location `{location}`.",
                    header=f"location: {location}",
                    url=observation.final_url,
                )
            )
        return AnalyzerResult(analyzer_id=self.metadata.id, findings=findings)
