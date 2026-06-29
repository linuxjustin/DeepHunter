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


class TestingIdea(BaseModel):
    """A high-level testing idea derived from knowledge analysis."""

    description: str = Field(description="What to test")
    rationale: str = Field(description="Why this test is relevant")
    bug_classes: list[BugClass] = Field(default_factory=list)
    difficulty: str = Field(default="medium")
    references: list[str] = Field(default_factory=list)


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
