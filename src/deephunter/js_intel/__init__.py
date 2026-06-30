"""JavaScript Intelligence Platform — static analysis of JavaScript artifacts.

Analyzes JavaScript source content (not execution) to extract structured
reconnaissance intelligence: API endpoints, routes, modules, frameworks,
authentication patterns, and configuration values.

All output maps to existing recon models (JavaScriptFile, JavaScriptEndpoint,
Technology, Application, Endpoint) and enriches the Attack Surface Graph.

This module does NOT crawl, execute, or exploit JavaScript.
"""

from __future__ import annotations

from deephunter.js_intel.models import (
    JSAnalysisResult,
    JSAuthObs,
    JSBundle,
    JSConfigObs,
    JSCookieUsage,
    JSEndpointRef,
    JSFrameworkObs,
    JSModule,
    JSRoute,
    JSTokenStorage,
)

__all__ = [
    "JSAnalysisResult",
    "JSAuthObs",
    "JSBundle",
    "JSConfigObs",
    "JSCookieUsage",
    "JSEndpointRef",
    "JSFrameworkObs",
    "JSModule",
    "JSRoute",
    "JSTokenStorage",
]
