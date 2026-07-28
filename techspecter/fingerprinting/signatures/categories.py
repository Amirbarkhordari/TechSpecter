"""Signature platform taxonomy."""

from __future__ import annotations

from enum import StrEnum


class TechnologyCategory(StrEnum):
    """Primary technology categories for signature organization."""

    FRONTEND_FRAMEWORKS = "frontend-frameworks"
    BACKEND_FRAMEWORKS = "backend-frameworks"
    STATIC_SITE_GENERATORS = "static-site-generators"
    CMS = "cms"
    JAVASCRIPT_LIBRARIES = "javascript-libraries"
    CSS_FRAMEWORKS = "css-frameworks"
    COMPONENT_LIBRARIES = "component-libraries"
    UI_KITS = "ui-kits"
    BUILD_TOOLS = "build-tools"
    BUNDLERS = "bundlers"
    PACKAGE_MANAGERS = "package-managers"
    RUNTIME_PLATFORMS = "runtime-platforms"
    TEMPLATE_ENGINES = "template-engines"
    PROGRAMMING_LANGUAGES = "programming-languages"
    ANALYTICS = "analytics"
    TAG_MANAGERS = "tag-managers"
    CDNS = "cdns"
    REVERSE_PROXIES = "reverse-proxies"
    CACHING = "caching"
    CLOUD_PROVIDERS = "cloud-providers"
    HOSTING_PLATFORMS = "hosting-platforms"
    WEB_SERVERS = "web-servers"
    APPLICATION_SERVERS = "application-servers"
    DATABASES = "databases"
    AUTHENTICATION = "authentication-systems"
    MONITORING = "monitoring"
    LOGGING = "logging"
    SECURITY = "security-products"
    WAF = "waf"
    LOAD_BALANCERS = "load-balancers"
    SEARCH_ENGINES = "search-engines"
    API_GATEWAYS = "api-gateways"
    CI_CD = "ci-cd"
    DEVELOPER_TOOLS = "developer-tools"
    PAYMENT = "payment-providers"
    CHAT = "chat-widgets"
    MARKETING = "marketing-platforms"
    VIDEO = "video-platforms"
    FONTS = "fonts"
    MAPS = "maps"
    COOKIE_MANAGERS = "cookie-managers"
    CONSENT = "consent-platforms"
    AB_TESTING = "ab-testing"
    META_FRAMEWORKS = "meta-frameworks"
    FRAMEWORK = "framework"
    BUILD_TOOL = "build-tool"


CATEGORY_LABELS: dict[str, str] = {
    TechnologyCategory.FRONTEND_FRAMEWORKS: "Frontend Frameworks",
    TechnologyCategory.BACKEND_FRAMEWORKS: "Backend Frameworks",
    TechnologyCategory.STATIC_SITE_GENERATORS: "Static Site Generators",
    TechnologyCategory.CMS: "CMS",
    TechnologyCategory.JAVASCRIPT_LIBRARIES: "JavaScript Libraries",
    TechnologyCategory.CSS_FRAMEWORKS: "CSS Frameworks",
    TechnologyCategory.COMPONENT_LIBRARIES: "Component Libraries",
    TechnologyCategory.BUILD_TOOLS: "Build Tools",
    TechnologyCategory.BUNDLERS: "Bundlers",
    TechnologyCategory.ANALYTICS: "Analytics",
    TechnologyCategory.TAG_MANAGERS: "Tag Managers",
    TechnologyCategory.CDNS: "CDNs",
    TechnologyCategory.HOSTING_PLATFORMS: "Hosting Platforms",
    TechnologyCategory.WEB_SERVERS: "Web Servers",
    TechnologyCategory.AUTHENTICATION: "Authentication Systems",
    TechnologyCategory.MONITORING: "Monitoring",
    TechnologyCategory.PAYMENT: "Payment Providers",
    TechnologyCategory.SEARCH_ENGINES: "Search Engines",
    TechnologyCategory.DATABASES: "Databases",
    TechnologyCategory.META_FRAMEWORKS: "Meta Frameworks",
}
