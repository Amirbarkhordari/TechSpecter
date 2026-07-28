"""Technology category summary groupings."""

from __future__ import annotations

CATEGORY_SUMMARY_GROUPS: dict[str, str] = {
    "frontend-frameworks": "Frontend",
    "javascript-frameworks": "Frontend",
    "javascript-libraries": "JavaScript Libraries",
    "web-frameworks": "Backend",
    "backend-frameworks": "Backend",
    "cms": "CMS",
    "css-frameworks": "CSS Frameworks",
    "databases": "Databases",
    "programming-languages": "Programming Languages",
    "web-servers": "Web Servers",
    "hosting": "Hosting",
    "cloud-providers": "Cloud",
    "analytics": "Analytics",
    "monitoring": "Monitoring",
    "authentication": "Authentication",
    "payment-providers": "Payment",
    "cdn": "CDN",
    "reverse-proxy": "Reverse Proxy",
    "caching": "Caching",
    "message-queue": "Queue",
    "font-scripts": "Fonts",
    "widgets": "Icons",
    "maps": "Maps",
    "video-players": "Video",
    "storage": "Storage",
    "security": "Security",
    "ssl-tls": "TLS",
    "miscellaneous": "Infrastructure",
}


def summary_group_for_category(category: str) -> str:
    """Map a technology category to a summary group label."""
    normalized = category.strip().lower().replace("_", "-").replace(" ", "-")
    if normalized in CATEGORY_SUMMARY_GROUPS:
        return CATEGORY_SUMMARY_GROUPS[normalized]
    for key, label in CATEGORY_SUMMARY_GROUPS.items():
        if key in normalized or normalized in key:
            return label
    return category.replace("-", " ").title()
