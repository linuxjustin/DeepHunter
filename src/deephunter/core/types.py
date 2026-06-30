"""Core type definitions for the DeepHunter platform.

Defines enums and value objects shared across all modules.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DocumentType(str, Enum):
    """Types of documents that can be ingested."""

    MARKDOWN = "markdown"
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    YAML = "yaml"
    TEXT = "text"
    UNKNOWN = "unknown"


class SourceType(str, Enum):
    """Known sources of security knowledge."""

    HACKTRICKS = "hacktricks"
    PAYLOADS_ALL_THE_THINGS = "payloadsallthethings"
    OWASP = "owasp"
    PORSTWIGGER = "portswigger"
    NUCLEI = "nuclei"
    CVE = "cve"
    WRITEUP = "writeup"
    FRAMEWORK_DOCS = "framework_docs"
    CLOUD_DOCS = "cloud_docs"
    INTERNAL_NOTES = "internal_notes"
    OTHER = "other"


class Confidence(str, Enum):
    """Confidence level of a knowledge object or hypothesis."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class BugClass(str, Enum):
    """Common bug classes relevant to web security testing."""

    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    CSRF = "csrf"
    SSRF = "ssrf"
    RCE = "rce"
    LFI = "lfi"
    RFI = "rfi"
    IDOR = "idor"
    AUTH_BYPASS = "auth_bypass"
    RACE_CONDITION = "race_condition"
    DESERIALIZATION = "deserialization"
    XXE = "xxe"
    SSTI = "ssti"
    OPEN_REDIRECT = "open_redirect"
    PATH_TRAVERSAL = "path_traversal"
    COMMAND_INJECTION = "command_injection"
    LDAP_INJECTION = "ldap_injection"
    NO_SQL_INJECTION = "no_sql_injection"
    HTTP_REQUEST_SMUGGLING = "http_request_smuggling"
    CORS_MISCONFIG = "cors_misconfig"
    BROKEN_AUTH = "broken_auth"
    RATE_LIMIT_BYPASS = "rate_limit_bypass"
    BUSINESS_LOGIC = "business_logic"
    INFO_DISCLOSURE = "info_disclosure"
    CRYPTO_FAILURE = "crypto_failure"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DOS = "dos"
    OTHER = "other"


class Technology(str, Enum):
    """Technologies that may appear in target applications."""

    NODEJS = "nodejs"
    REACT = "react"
    ANGULAR = "angular"
    VUE = "vue"
    DJANGO = "django"
    FLASK = "flask"
    SPRING = "spring"
    ASPNET = "aspnet"
    RUBY_ON_RAILS = "ruby_on_rails"
    LARAVEL = "laravel"
    EXPRESS = "express"
    FASTAPI = "fastapi"
    GIN = "gin"
    OTHER = "other"


class Framework(str, Enum):
    """Security or development framework."""

    OWASP_ASVS = "owasp_asvs"
    OWASP_WSTG = "owasp_wstg"
    NIST = "nist"
    MITRE_ATTACK = "mitre_attack"
    PCI_DSS = "pci_dss"
    CUSTOM = "custom"


class CloudProvider(str, Enum):
    """Cloud providers."""

    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    HEROKU = "heroku"
    DIGITAL_OCEAN = "digital_ocean"
    OTHER = "other"


class AuthMechanism(str, Enum):
    """Authentication mechanisms."""

    JWT = "jwt"
    OAUTH2 = "oauth2"
    SESSION_COOKIE = "session_cookie"
    API_KEY = "api_key"
    BASIC_AUTH = "basic_auth"
    DIGEST_AUTH = "digest_auth"
    SAML = "saml"
    LDAP = "ldap"
    CUSTOM = "custom"
    NONE = "none"


class TrustBoundary(BaseModel):
    """Describes a trust boundary in the target application."""

    name: str = Field(description="Human-readable name of the boundary")
    description: str = Field(description="What crosses this boundary")
    direction: str = Field(
        description="Direction of data flow, e.g. 'client->server', 'internal->external'"
    )
    sensitivity: str = Field(
        default="medium", description="Sensitivity: low, medium, high"
    )


class TestChecklistItem(BaseModel):
    """A high-level testing idea derived from knowledge analysis."""

    description: str = Field(description="What to test")
    rationale: str = Field(description="Why this test is relevant")
    bug_classes: list[BugClass] = Field(default_factory=list)
    difficulty: str = Field(default="medium")
    references: list[str] = Field(default_factory=list)

    __test__ = False


class RelatedReference(BaseModel):
    """A reference to related knowledge."""

    title: str
    url: str | None = None
    source: str | None = None
    description: str | None = None


class Metadata(BaseModel):
    """Flexible metadata container for any knowledge object."""

    key: str
    value: Any
    tags: list[str] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)


class AttackSurfaceEntry(BaseModel):
    """An attack surface entry point in the target application."""

    name: str = Field(description="Human-readable name, e.g. 'Login endpoint'")
    description: str = Field(default="", description="What this entry point does")
    protocol: str = Field(default="https", description="Protocol (http, https, ws, etc.)")
    method: str = Field(default="", description="HTTP method if applicable (GET, POST, etc.)")
    path: str = Field(default="", description="URL path pattern, e.g. '/api/v1/login'")
    parameters: list[str] = Field(default_factory=list, description="Parameters accepted")
    authentication_required: bool = Field(default=True)
    authorization_required: bool = Field(default=True)
    bug_classes: list[str] = Field(default_factory=list)


class BusinessLogicConcern(BaseModel):
    """A business logic concern or flaw pattern."""

    description: str = Field(description="What the business logic does")
    impact: str = Field(default="", description="Potential security impact")
    attack_scenario: str = Field(default="", description="How this could be exploited")
    complexity: str = Field(default="medium", description="low, medium, high")
    requires_authentication: bool = Field(default=True)


class AuthorizationModel(BaseModel):
    """Describes an authorization check or model."""

    model_type: str = Field(description="Type, e.g. 'RBAC', 'ABAC', 'ACL', 'ownership'")
    description: str = Field(default="", description="How authorization works")
    roles: list[str] = Field(default_factory=list, description="Relevant roles")
    permissions: list[str] = Field(default_factory=list, description="Relevant permissions")
    bypass_scenarios: list[str] = Field(default_factory=list)


class ManualTestChecklistItem(BaseModel):
    """A single manual test step for a penetration testing checklist."""

    step_id: str = Field(default="", description="Checklist item identifier")
    category: str = Field(default="", description="Category, e.g. 'Authentication', 'Input Validation'")
    description: str = Field(description="What to test")
    expected_result: str = Field(default="", description="What a successful test looks like")
    tools: list[str] = Field(default_factory=list, description="Recommended tools")
    references: list[str] = Field(default_factory=list)


class PayloadReference(BaseModel):
    """A reference to a specific payload for testing."""

    payload: str = Field(description="The actual payload string")
    description: str = Field(default="", description="What this payload tests")
    bug_classes: list[str] = Field(default_factory=list)
    source: str = Field(default="", description="Where this payload was found")
    encoding: str = Field(default="raw", description="Encoding: raw, url, base64, etc.")
    effectiveness: str = Field(default="unknown", description="How often it works: low, medium, high, unknown")
