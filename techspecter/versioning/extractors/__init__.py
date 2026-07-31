"""Built-in technology version extractors."""

from techspecter.versioning.extractors.angular import AngularVersionExtractor
from techspecter.versioning.extractors.bootstrap import BootstrapVersionExtractor
from techspecter.versioning.extractors.jquery import JQueryVersionExtractor
from techspecter.versioning.extractors.leaflet import LeafletVersionExtractor
from techspecter.versioning.extractors.materialui import MaterialUiVersionExtractor
from techspecter.versioning.extractors.nextjs import NextJsVersionExtractor
from techspecter.versioning.extractors.react import ReactVersionExtractor
from techspecter.versioning.extractors.tailwind import TailwindVersionExtractor
from techspecter.versioning.extractors.turbopack import TurbopackVersionExtractor
from techspecter.versioning.extractors.vite import ViteVersionExtractor
from techspecter.versioning.extractors.vue import VueVersionExtractor
from techspecter.versioning.extractors.webpack import WebpackVersionExtractor

__all__ = [
    "AngularVersionExtractor",
    "BootstrapVersionExtractor",
    "JQueryVersionExtractor",
    "LeafletVersionExtractor",
    "MaterialUiVersionExtractor",
    "NextJsVersionExtractor",
    "ReactVersionExtractor",
    "TailwindVersionExtractor",
    "TurbopackVersionExtractor",
    "ViteVersionExtractor",
    "VueVersionExtractor",
    "WebpackVersionExtractor",
]
