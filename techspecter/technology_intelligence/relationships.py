"""Known technology dependency relationships."""

from __future__ import annotations

from techspecter.technology_intelligence.models import RelationshipKind

# source_technology_id -> list of (target_technology_id, relationship_kind)
KNOWN_TECHNOLOGY_RELATIONSHIPS: dict[str, list[tuple[str, RelationshipKind]]] = {
    "nextjs": [("react", RelationshipKind.FRAMEWORK_DEPENDENCY)],
    "next.js": [("react", RelationshipKind.FRAMEWORK_DEPENDENCY)],
    "nuxt": [("vue", RelationshipKind.FRAMEWORK_DEPENDENCY)],
    "nuxtjs": [("vue", RelationshipKind.FRAMEWORK_DEPENDENCY)],
    "angular": [
        ("typescript", RelationshipKind.LANGUAGE_DEPENDENCY),
        ("rxjs", RelationshipKind.RUNTIME),
    ],
    "material-ui": [("react", RelationshipKind.UI_DEPENDENCY)],
    "mui": [("react", RelationshipKind.UI_DEPENDENCY)],
    "react-router": [("react", RelationshipKind.ROUTING_DEPENDENCY)],
    "react-router-dom": [("react", RelationshipKind.ROUTING_DEPENDENCY)],
    "gatsby": [("react", RelationshipKind.FRAMEWORK_DEPENDENCY)],
    "remix": [("react", RelationshipKind.FRAMEWORK_DEPENDENCY)],
    "vite": [("javascript", RelationshipKind.BUILD_TOOL)],
    "webpack": [("javascript", RelationshipKind.BUILD_TOOL)],
    "turbopack": [("javascript", RelationshipKind.BUILD_TOOL)],
    "emotion": [("react", RelationshipKind.UI_DEPENDENCY)],
    "styled-components": [("react", RelationshipKind.UI_DEPENDENCY)],
    "redux": [("react", RelationshipKind.RUNTIME)],
    "react-redux": [("react", RelationshipKind.RUNTIME), ("redux", RelationshipKind.RUNTIME)],
}
