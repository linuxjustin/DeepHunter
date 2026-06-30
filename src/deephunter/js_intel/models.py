"""Data models for the JavaScript Intelligence Platform.

Each model captures a specific class of observation extracted from
JavaScript source code during static analysis.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.recon.models import EndpointCategory, HttpMethod


class ModuleType(str, Enum):
    ESM = "esm"
    COMMONJS = "commonjs"
    DYNAMIC = "dynamic"
    AMD = "amd"
    SYSTEMJS = "systemjs"


class JSBundle(BaseModel):
    """Metadata about a JavaScript bundle file."""

    id: str = Field(default_factory=lambda: f"jsb-{uuid4().hex[:12]}")
    url: str = ""
    size: int = 0
    content_hash: str = ""
    build_tool: str = ""
    is_minified: bool = False
    has_source_map_comment: bool = False
    has_source_map_header: bool = False
    module_count: int = 0
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class JSModule(BaseModel):
    """An imported or required module found in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jsm-{uuid4().hex[:12]}")
    name: str
    module_type: ModuleType = ModuleType.ESM
    is_relative: bool = False
    line_number: int = 0
    context: str = ""
    source_url: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class JSEndpointRef(BaseModel):
    """An API endpoint reference found in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jse-{uuid4().hex[:12]}")
    url: str
    methods: list[HttpMethod] = Field(default_factory=list)
    category: EndpointCategory = EndpointCategory.API
    source_url: str = ""
    line_number: int = 0
    context: str = ""
    params: list[str] = Field(default_factory=list)
    body_params: list[str] = Field(default_factory=list)
    is_graphql: bool = False
    graphql_operation: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class JSRoute(BaseModel):
    """A client-side route definition found in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jsr-{uuid4().hex[:12]}")
    path: str
    component: str = ""
    is_dynamic: bool = False
    is_lazy: bool = False
    is_nested: bool = False
    params: list[str] = Field(default_factory=list)
    line_number: int = 0
    context: str = ""
    source_url: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class JSAuthObs(BaseModel):
    """An authentication-related observation in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jsa-{uuid4().hex[:12]}")
    mechanism: str
    location: str = ""
    identifier: str = ""
    value_preview: str = ""
    line_number: int = 0
    context: str = ""
    source_url: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class JSTokenStorage(BaseModel):
    """An observation about token or credential storage in JavaScript."""

    id: str = Field(default_factory=lambda: f"jst-{uuid4().hex[:12]}")
    storage_type: str  # localStorage, sessionStorage, cookie, variable, etc.
    key: str = ""
    value_preview: str = ""
    line_number: int = 0
    context: str = ""
    source_url: str = ""


class JSCookieUsage(BaseModel):
    """Cookie usage observed in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jsc-{uuid4().hex[:12]}")
    name: str
    domain: str = ""
    secure: bool = False
    http_only: bool = False
    same_site: str = ""
    line_number: int = 0
    context: str = ""
    source_url: str = ""


class JSConfigObs(BaseModel):
    """A configuration value or feature flag found in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jscf-{uuid4().hex[:12]}")
    key: str
    value: str = ""
    category: str = ""  # feature_flag, api_url, environment, etc.
    line_number: int = 0
    context: str = ""
    source_url: str = ""


class JSFrameworkObs(BaseModel):
    """Evidence of a framework or library detected in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jsfw-{uuid4().hex[:12]}")
    framework: str
    evidence: str = ""
    confidence: float = 0.5
    version: str = ""
    line_number: int = 0
    context: str = ""
    source_url: str = ""


class JSSecretObs(BaseModel):
    """A potential secret or credential observed in JavaScript source."""

    id: str = Field(default_factory=lambda: f"jss-{uuid4().hex[:12]}")
    secret_type: str  # api_key, jwt, password, token, etc.
    value_preview: str = ""
    line_number: int = 0
    context: str = ""
    source_url: str = ""
    entropy: float = 0.0


class JSAnalysisResult(BaseModel):
    """Complete structured result from analyzing a JavaScript artifact.

    Produced by JSAnalysisEngine.analyze().
    """

    id: str = Field(default_factory=lambda: f"jsr-{uuid4().hex[:12]}")
    source_url: str = ""
    content_hash: str = ""
    content_size: int = 0

    bundle: JSBundle | None = None

    modules: list[JSModule] = Field(default_factory=list)
    api_endpoints: list[JSEndpointRef] = Field(default_factory=list)
    graphql_endpoints: list[JSEndpointRef] = Field(default_factory=list)
    routes: list[JSRoute] = Field(default_factory=list)
    auth_observations: list[JSAuthObs] = Field(default_factory=list)
    token_storage: list[JSTokenStorage] = Field(default_factory=list)
    cookie_usage: list[JSCookieUsage] = Field(default_factory=list)
    feature_flags: list[JSConfigObs] = Field(default_factory=list)
    config_values: list[JSConfigObs] = Field(default_factory=list)
    framework_observations: list[JSFrameworkObs] = Field(default_factory=list)
    secret_observations: list[JSSecretObs] = Field(default_factory=list)
    third_party_libraries: list[str] = Field(default_factory=list)
    build_tool_hints: list[str] = Field(default_factory=list)

    detected_frameworks: list[str] = Field(default_factory=list)
    is_bundle: bool = False
    has_source_map: bool = False

    original_source_url: str = ""

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    source_url: str = ""
    content_hash: str = ""
    content_size: int = 0

    bundle: JSBundle | None = None

    modules: list[JSModule] = Field(default_factory=list)
    api_endpoints: list[JSEndpointRef] = Field(default_factory=list)
    graphql_endpoints: list[JSEndpointRef] = Field(default_factory=list)
    routes: list[JSRoute] = Field(default_factory=list)
    auth_observations: list[JSAuthObs] = Field(default_factory=list)
    token_storage: list[JSTokenStorage] = Field(default_factory=list)
    cookie_usage: list[JSCookieUsage] = Field(default_factory=list)
    feature_flags: list[JSConfigObs] = Field(default_factory=list)
    config_values: list[JSConfigObs] = Field(default_factory=list)
    framework_observations: list[JSFrameworkObs] = Field(default_factory=list)
    secret_observations: list[JSSecretObs] = Field(default_factory=list)
    third_party_libraries: list[str] = Field(default_factory=list)
    build_tool_hints: list[str] = Field(default_factory=list)

    detected_frameworks: list[str] = Field(default_factory=list)
    is_bundle: bool = False
    has_source_map: bool = False

    original_source_url: str = ""

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
