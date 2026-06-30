"""Data models for the Recon Intelligence Platform v1.

Organized into sections: enums, core identity, scope, assets, hosts,
DNS, HTTP, technology, applications, endpoints, parameters,
authentication/authorization, JavaScript, cloud, and integration wrappers.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


# ═══════════════════════════════════════════════════════════════════════════════
# Enums
# ═══════════════════════════════════════════════════════════════════════════════

class ReconSourceType(str, Enum):
    """Where a piece of recon data originated."""

    MANUAL = "manual"
    SUBDOMAIN_ENUMERATION = "subdomain_enumeration"
    DNS_ENUMERATION = "dns_enumeration"
    HTTP_PROBE = "http_probe"
    TECHNOLOGY_FINGERPRINT = "technology_fingerprint"
    URL_COLLECTION = "url_collection"
    JAVASCRIPT_ANALYSIS = "javascript_analysis"
    OPENAPI = "openapi"
    WEB_CRAWL = "web_crawl"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    WHOIS = "whois"
    CLOUD_ENUMERATION = "cloud_enumeration"
    GITHUB_DORK = "github_dork"
    SHODAN = "shodan"
    INTEGRATION = "integration"
    UNKNOWN = "unknown"


class HostStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    REDIRECT = "redirect"
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    HTTP = "http"
    HTTPS = "https"
    TCP = "tcp"
    UDP = "udp"
    TLS = "tls"
    WS = "ws"
    WSS = "wss"


class DNSRecordType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"
    MX = "MX"
    NS = "NS"
    TXT = "TXT"
    SOA = "SOA"
    CAA = "CAA"
    SRV = "SRV"
    PTR = "PTR"


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"
    TRACE = "TRACE"


class SecurityHeaderName(str, Enum):
    STRICT_TRANSPORT_SECURITY = "strict-transport-security"
    CONTENT_SECURITY_POLICY = "content-security-policy"
    X_FRAME_OPTIONS = "x-frame-options"
    X_CONTENT_TYPE_OPTIONS = "x-content-type-options"
    REFERRER_POLICY = "referrer-policy"
    PERMISSIONS_POLICY = "permissions-policy"
    CROSS_ORIGIN_OPENER_POLICY = "cross-origin-opener-policy"
    CROSS_ORIGIN_EMBEDDER_POLICY = "cross-origin-embedder-policy"
    CROSS_ORIGIN_RESOURCE_POLICY = "cross-origin-resource-policy"


class TechCategory(str, Enum):
    FRONTEND = "frontend"
    BACKEND = "backend"
    FRAMEWORK = "framework"
    RUNTIME = "runtime"
    CMS = "cms"
    WEB_SERVER = "web_server"
    APPLICATION_SERVER = "application_server"
    DATABASE = "database"
    CACHE = "cache"
    MESSAGE_QUEUE = "message_queue"
    IDENTITY_PROVIDER = "identity_provider"
    CLOUD_PROVIDER = "cloud_provider"
    CONTAINER_PLATFORM = "container_platform"
    CDN = "cdn"
    WAF = "waf"
    LOAD_BALANCER = "load_balancer"
    ANALYTICS = "analytics"
    MONITORING = "monitoring"
    PAYMENT = "payment"
    CDN_SECURITY = "cdn_security"
    UNKNOWN = "unknown"


class ParamLocation(str, Enum):
    QUERY = "query"
    PATH = "path"
    HEADER = "header"
    BODY = "body"
    COOKIE = "cookie"
    MATRIX = "matrix"


class ParamType(str, Enum):
    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"
    FILE = "file"
    UNKNOWN = "unknown"


class AuthType(str, Enum):
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    OAUTH2 = "oauth2"
    OIDC = "oidc"
    SAML = "saml"
    JWT = "jwt"
    SESSION_COOKIE = "session_cookie"
    API_KEY = "api_key"
    DIGEST = "digest"
    NTLM = "ntlm"
    KERBEROS = "kerberos"
    CUSTOM = "custom"
    UNKNOWN = "unknown"


class AuthCategory(str, Enum):
    LOGIN_PAGE = "login_page"
    REGISTRATION = "registration"
    PASSWORD_RESET = "password_reset"
    MFA = "mfa"
    OAUTH_FLOW = "oauth_flow"
    OPENID_DISCOVERY = "openid_discovery"
    SAML_METADATA = "saml_metadata"
    TOKEN_ENDPOINT = "token_endpoint"
    JWKS_ENDPOINT = "jwks_endpoint"
    LOGOUT = "logout"
    SESSION = "session"


class ApplicationType(str, Enum):
    WEB_APP = "web_app"
    API = "api"
    MICROSERVICE = "microservice"
    ADMIN_PANEL = "admin_panel"
    STATIC_SITE = "static_site"
    SINGLE_PAGE_APP = "single_page_app"
    MOBILE_API = "mobile_api"
    THIRD_PARTY = "third_party"
    AUTH_SERVICE = "auth_service"
    DASHBOARD = "dashboard"
    LANDING_PAGE = "landing_page"
    UNKNOWN = "unknown"


class CloudResourceType(str, Enum):
    BUCKET = "bucket"
    FUNCTION = "function"
    COMPUTE = "compute"
    DATABASE = "database"
    CDN = "cdn"
    DNS = "dns"
    QUEUE = "queue"
    TOPIC = "topic"
    TABLE = "table"
    SECRET = "secret"
    CERTIFICATE = "certificate"
    NETWORK = "network"
    LOAD_BALANCER = "load_balancer"
    UNKNOWN = "unknown"


class EndpointCategory(str, Enum):
    API = "api"
    STATIC = "static"
    ADMIN = "admin"
    AUTH = "auth"
    LOGIN = "login"
    LOGOUT = "logout"
    REGISTER = "register"
    PASSWORD_RESET = "password_reset"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    SEARCH = "search"
    GRAPHQL = "graphql"
    WEBSOCKET = "websocket"
    WEBHOOK = "webhook"
    HEALTH = "health"
    METRICS = "metrics"
    DEBUG = "debug"
    UNKNOWN = "unknown"


class GraphNodeType(str, Enum):
    PROGRAM = "program"
    SCOPE = "scope"
    ASSET = "asset"
    HOST = "host"
    APPLICATION = "application"
    TECHNOLOGY = "technology"
    ENDPOINT = "endpoint"
    PARAMETER = "parameter"
    AUTH_METHOD = "auth_method"
    CLOUD_RESOURCE = "cloud_resource"
    JS_ENDPOINT = "js_endpoint"
    JS_BUNDLE = "js_bundle"
    JS_MODULE = "js_module"
    JS_ROUTE = "js_route"
    API_ENDPOINT = "api_endpoint"
    DNS_RECORD = "dns_record"
    CERTIFICATE = "certificate"
    OBSERVATION = "observation"
    DOMAIN = "domain"
    IP = "ip"


class GraphEdgeType(str, Enum):
    BELONGS_TO = "belongs_to"
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    RUNS = "runs"
    HAS_ENDPOINT = "has_endpoint"
    HAS_PARAMETER = "has_parameter"
    USES_AUTH = "uses_auth"
    USES_TECHNOLOGY = "uses_technology"
    DEPLOYS_ON = "deploys_on"
    REDIRECTS_TO = "redirects_to"
    DERIVED_FROM = "derived_from"
    REFERENCES = "references"
    RELATED_TO = "related_to"
    CHILD_OF = "child_of"
    SUBDOMAIN_OF = "subdomain_of"
    HAS_DNS_RECORD = "has_dns_record"
    OBSERVED_AT = "observed_at"
    IMPORTS = "imports"
    CONTAINS = "contains"
    DEFINES_ROUTE = "defines_route"
    HAS_JS_FILE = "has_js_file"


# ═══════════════════════════════════════════════════════════════════════════════
# Scope & Program
# ═══════════════════════════════════════════════════════════════════════════════


class Program(BaseModel):
    """A bug bounty program or target engagement."""

    id: str = Field(default_factory=lambda: f"prog-{uuid4().hex[:12]}")
    name: str
    description: str = ""
    platform: str = ""
    url: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Scope(BaseModel):
    """A scope entry — domain, IP range, wildcard, or CIDR."""

    id: str = Field(default_factory=lambda: f"scope-{uuid4().hex[:12]}")
    program_id: str = ""
    target: str
    scope_type: str = "domain"
    in_scope: bool = True
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Asset
# ═══════════════════════════════════════════════════════════════════════════════


class Asset(BaseModel):
    """A discrete asset — domain, subdomain, IP, CIDR, or cloud resource."""

    id: str = Field(default_factory=lambda: f"ast-{uuid4().hex[:12]}")
    program_id: str = ""
    scope_id: str = ""
    identifier: str
    asset_type: str = "domain"
    source: ReconSourceType = ReconSourceType.MANUAL
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# DNS
# ═══════════════════════════════════════════════════════════════════════════════


class DNSRecord(BaseModel):
    """A single DNS record."""

    id: str = Field(default_factory=lambda: f"dns-{uuid4().hex[:12]}")
    host_id: str = ""
    record_type: DNSRecordType
    name: str = ""
    value: str
    ttl: int = 0
    priority: int | None = None
    source: ReconSourceType = ReconSourceType.DNS_ENUMERATION
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Host
# ═══════════════════════════════════════════════════════════════════════════════


class Host(BaseModel):
    """A resolved host — hostname bound to an IP, port, and protocol."""

    id: str = Field(default_factory=lambda: f"host-{uuid4().hex[:12]}")
    asset_id: str = ""
    hostname: str = ""
    ip: str = ""
    port: int = 443
    protocol: Protocol = Protocol.HTTPS
    status: HostStatus = HostStatus.UNKNOWN
    title: str = ""
    summary: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    dns_records: list[DNSRecord] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP Intelligence
# ═══════════════════════════════════════════════════════════════════════════════


class HTTPHeader(BaseModel):
    """An observed HTTP response header."""

    name: str
    value: str
    security_relevant: bool = False


class Cookie(BaseModel):
    """An observed HTTP cookie."""

    name: str
    domain: str = ""
    path: str = "/"
    http_only: bool = False
    secure: bool = False
    same_site: str = ""
    expires: str = ""
    value_preview: str = ""


class SecurityHeader(BaseModel):
    """A security-related HTTP response header with analysis."""

    name: SecurityHeaderName
    value: str
    present: bool = True
    secure: bool = False
    recommendation: str = ""


class HTTPObservation(BaseModel):
    """An HTTP probe result for a single host."""

    id: str = Field(default_factory=lambda: f"http-{uuid4().hex[:12]}")
    host_id: str = ""
    url: str = ""
    method: HttpMethod = HttpMethod.GET
    status_code: int = 0
    response_size: int = 0
    content_type: str = ""
    response_time_ms: float = 0.0
    headers: list[HTTPHeader] = Field(default_factory=list)
    security_headers: list[SecurityHeader] = Field(default_factory=list)
    cookies: list[Cookie] = Field(default_factory=list)
    title: str = ""
    technologies: list[str] = Field(default_factory=list)
    redirect_chain: list[str] = Field(default_factory=list)
    body_preview: str = ""
    source: ReconSourceType = ReconSourceType.HTTP_PROBE
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Technology
# ═══════════════════════════════════════════════════════════════════════════════


class Technology(BaseModel):
    """A detected technology on a host or application."""

    id: str = Field(default_factory=lambda: f"tech-{uuid4().hex[:12]}")
    name: str
    category: TechCategory = TechCategory.UNKNOWN
    version: str = ""
    confidence: float = 0.5
    cpe: str = ""
    source: ReconSourceType = ReconSourceType.TECHNOLOGY_FINGERPRINT
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Application
# ═══════════════════════════════════════════════════════════════════════════════


class Application(BaseModel):
    """A logical application or service running on a host."""

    id: str = Field(default_factory=lambda: f"app-{uuid4().hex[:12]}")
    host_id: str = ""
    name: str
    app_type: ApplicationType = ApplicationType.UNKNOWN
    version: str = ""
    base_path: str = "/"
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoint
# ═══════════════════════════════════════════════════════════════════════════════


class Parameter(BaseModel):
    """A request parameter observed at an endpoint."""

    id: str = Field(default_factory=lambda: f"param-{uuid4().hex[:12]}")
    endpoint_id: str = ""
    name: str
    location: ParamLocation = ParamLocation.QUERY
    param_type: ParamType = ParamType.UNKNOWN
    required: bool = False
    default_value: str = ""
    observed_values: list[str] = Field(default_factory=list)
    description: str = ""
    source: ReconSourceType = ReconSourceType.UNKNOWN
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


class Endpoint(BaseModel):
    """A discovered URL endpoint with metadata."""

    id: str = Field(default_factory=lambda: f"ep-{uuid4().hex[:12]}")
    application_id: str = ""
    host_id: str = ""
    path: str
    method: HttpMethod = HttpMethod.GET
    category: EndpointCategory = EndpointCategory.UNKNOWN
    auth_required: bool | None = None
    auth_type: AuthType = AuthType.UNKNOWN
    parameters: list[Parameter] = Field(default_factory=list)
    response_type: str = ""
    status_code: int | None = None
    content_length: int | None = None
    observed: bool = True
    source: ReconSourceType = ReconSourceType.UNKNOWN
    metadata: dict[str, Any] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Authentication
# ═══════════════════════════════════════════════════════════════════════════════


class AuthMechanism(BaseModel):
    """An observed authentication mechanism."""

    id: str = Field(default_factory=lambda: f"auth-{uuid4().hex[:12]}")
    host_id: str = ""
    application_id: str = ""
    auth_type: AuthType
    category: AuthCategory = AuthCategory.LOGIN_PAGE
    url: str = ""
    description: str = ""
    endpoints_in_scope: list[str] = Field(default_factory=list)
    source: ReconSourceType = ReconSourceType.MANUAL
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AuthObservation(BaseModel):
    """An observation about an authentication mechanism — not a finding."""

    id: str = Field(default_factory=lambda: f"aobs-{uuid4().hex[:12]}")
    host_id: str = ""
    description: str
    detail: str = ""
    auth_type: AuthType = AuthType.UNKNOWN
    source: ReconSourceType = ReconSourceType.MANUAL
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# JavaScript
# ═══════════════════════════════════════════════════════════════════════════════


class JavaScriptEndpoint(BaseModel):
    """A URL or endpoint discovered in JavaScript source."""

    id: str = Field(default_factory=lambda: f"js-{uuid4().hex[:12]}")
    host_id: str = ""
    source_url: str = ""
    discovered_url: str
    line_number: int | None = None
    context: str = ""
    source: ReconSourceType = ReconSourceType.JAVASCRIPT_ANALYSIS
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class JavaScriptFile(BaseModel):
    """A discovered JavaScript file with metadata."""

    id: str = Field(default_factory=lambda: f"jsf-{uuid4().hex[:12]}")
    host_id: str = ""
    url: str
    size: int = 0
    hash: str = ""
    contains_sources: bool = False
    contains_endpoints: bool = False
    contains_secrets: bool = False
    source: ReconSourceType = ReconSourceType.JAVASCRIPT_ANALYSIS
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# API Intelligence
# ═══════════════════════════════════════════════════════════════════════════════


class APIEndpoint(BaseModel):
    """An API endpoint from OpenAPI/Swagger or observed traffic."""

    id: str = Field(default_factory=lambda: f"api-{uuid4().hex[:12]}")
    application_id: str = ""
    host_id: str = ""
    path: str
    method: HttpMethod
    summary: str = ""
    description: str = ""
    tags: list[str] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    request_body_schema: str = ""
    response_schema: str = ""
    auth_required: bool = False
    auth_type: AuthType = AuthType.UNKNOWN
    deprecated: bool = False
    source: ReconSourceType = ReconSourceType.OPENAPI
    observed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Cloud
# ═══════════════════════════════════════════════════════════════════════════════


class CloudResource(BaseModel):
    """A discovered cloud resource."""

    id: str = Field(default_factory=lambda: f"cloud-{uuid4().hex[:12]}")
    program_id: str = ""
    provider: str  # aws, azure, gcp, etc.
    resource_type: CloudResourceType
    name: str
    region: str = ""
    url: str = ""
    ip: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    source: ReconSourceType = ReconSourceType.CLOUD_ENUMERATION
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Graph — Attack Surface Graph
# ═══════════════════════════════════════════════════════════════════════════════


class GraphNode(BaseModel):
    """A node in the Attack Surface Graph."""

    id: str = Field(default_factory=lambda: f"gn-{uuid4().hex[:12]}")
    node_type: GraphNodeType
    ref_id: str  # ID of the referenced entity (host-xxx, ep-xxx, etc.)
    label: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class GraphEdge(BaseModel):
    """A directed edge between two graph nodes."""

    id: str = Field(default_factory=lambda: f"ge-{uuid4().hex[:12]}")
    source_id: str
    target_id: str
    edge_type: GraphEdgeType
    label: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Session & Timeline
# ═══════════════════════════════════════════════════════════════════════════════

class ReconSessionConfig(BaseModel):
    """Configuration for a recon session."""

    id: str = Field(default_factory=lambda: f"rcfg-{uuid4().hex[:12]}")
    program_id: str = ""
    target: str = ""
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class TimelineEntry(BaseModel):
    """A single entry in the recon timeline."""

    id: str = Field(default_factory=lambda: f"tl-{uuid4().hex[:12]}")
    session_id: str = ""
    event_type: str
    description: str = ""
    entity_type: str = ""
    entity_id: str = ""
    detail: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


# ═══════════════════════════════════════════════════════════════════════════════
# Recon session — overall state
# ═══════════════════════════════════════════════════════════════════════════════

class ReconState(BaseModel):
    """Full mutable state of a reconnaissance session."""

    id: str = Field(default_factory=lambda: f"rec-{uuid4().hex[:12]}")
    target: str = ""
    programs: list[Program] = Field(default_factory=list)
    scopes: list[Scope] = Field(default_factory=list)
    assets: list[Asset] = Field(default_factory=list)
    hosts: list[Host] = Field(default_factory=list)
    http_observations: list[HTTPObservation] = Field(default_factory=list)
    technologies: list[Technology] = Field(default_factory=list)
    applications: list[Application] = Field(default_factory=list)
    endpoints: list[Endpoint] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    auth_mechanisms: list[AuthMechanism] = Field(default_factory=list)
    auth_observations: list[AuthObservation] = Field(default_factory=list)
    js_files: list[JavaScriptFile] = Field(default_factory=list)
    js_endpoints: list[JavaScriptEndpoint] = Field(default_factory=list)
    api_endpoints: list[APIEndpoint] = Field(default_factory=list)
    cloud_resources: list[CloudResource] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def model_dump_for_storage(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ReconState:
        return cls(**data)
