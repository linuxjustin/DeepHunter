"""DeepHunter integrations package.

Provides import adapters for external tools and data formats:
- Burp Suite (HTTP history, site map, scanner results)
- Playwright (captured requests, console logs, storage)
- OpenAPI/Swagger (API specifications)
"""

from deephunter.integrations.burp import BurpImporter, BurpStateParser, BurpHarImporter
from deephunter.integrations.playwright import PlaywrightImporter, PlaywrightCapturedData
from deephunter.integrations.openapi import OpenAPIImporter, OpenAPISpec, OpenAPIImporterFacade

__all__ = [
    "BurpImporter",
    "BurpStateParser",
    "BurpHarImporter",
    "PlaywrightImporter",
    "PlaywrightCapturedData",
    "OpenAPIImporter",
    "OpenAPISpec",
    "OpenAPIImporterFacade",
]