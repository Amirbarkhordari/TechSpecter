"""Passive artifact analyzers."""

from __future__ import annotations

from techspecter.analysis.artifact.analyzers.analytics_service import AnalyticsServiceAnalyzer
from techspecter.analysis.artifact.analyzers.api_key import ApiKeyAnalyzer
from techspecter.analysis.artifact.analyzers.aws_metadata import AwsMetadataAnalyzer
from techspecter.analysis.artifact.analyzers.azure_metadata import AzureMetadataAnalyzer
from techspecter.analysis.artifact.analyzers.cdn import CdnAnalyzer
from techspecter.analysis.artifact.analyzers.firebase import FirebaseAnalyzer
from techspecter.analysis.artifact.analyzers.google_cloud_metadata import (
    GoogleCloudMetadataAnalyzer,
)
from techspecter.analysis.artifact.analyzers.graphql_metadata import GraphqlMetadataAnalyzer
from techspecter.analysis.artifact.analyzers.jwt import JwtAnalyzer
from techspecter.analysis.artifact.analyzers.monitoring_service import MonitoringServiceAnalyzer
from techspecter.analysis.artifact.analyzers.oauth_metadata import OAuthMetadataAnalyzer
from techspecter.analysis.artifact.analyzers.openapi import OpenApiAnalyzer
from techspecter.analysis.artifact.analyzers.openid_connect import OpenIdConnectAnalyzer
from techspecter.analysis.artifact.analyzers.technology_exposure import TechnologyExposureAnalyzer
from techspecter.analysis.artifact.analyzers.third_party_service import ThirdPartyServiceAnalyzer

__all__ = [
    "AnalyticsServiceAnalyzer",
    "ApiKeyAnalyzer",
    "AwsMetadataAnalyzer",
    "AzureMetadataAnalyzer",
    "CdnAnalyzer",
    "FirebaseAnalyzer",
    "GoogleCloudMetadataAnalyzer",
    "GraphqlMetadataAnalyzer",
    "JwtAnalyzer",
    "MonitoringServiceAnalyzer",
    "OAuthMetadataAnalyzer",
    "OpenApiAnalyzer",
    "OpenIdConnectAnalyzer",
    "TechnologyExposureAnalyzer",
    "ThirdPartyServiceAnalyzer",
]
