"""Recon Intelligence Platform — structured attack surface understanding."""

from deephunter.recon.application import ApplicationInventory
from deephunter.recon.asset import AssetInventory
from deephunter.recon.auth import AuthIntelligence
from deephunter.recon.cloud import CloudIntelligence
from deephunter.recon.endpoint import EndpointInventory
from deephunter.recon.events import (
    APIDiscoveredEvent,
    ApplicationDiscoveredEvent,
    AssetCreatedEvent,
    AuthObservedEvent,
    CloudResourceDiscoveredEvent,
    DNSRecordObservedEvent,
    EndpointAddedEvent,
    GraphUpdatedEvent,
    HTTPObservedEvent,
    HostDiscoveredEvent,
    JSEndpointDiscoveredEvent,
    ParameterAddedEvent,
    ReconEvent,
    ReconEventBus,
    ReconPipelineEvent,
    ScopeLoadedEvent,
    TechnologyDetectedEvent,
)
from deephunter.recon.graph import AttackSurfaceGraph
from deephunter.recon.host import HostRegistry
from deephunter.recon.http import HTTPIntelligence
from deephunter.recon.models import (
    APIEndpoint,
    Application,
    ApplicationType,
    Asset,
    AuthMechanism,
    AuthObservation,
    AuthType,
    CloudResource,
    CloudResourceType,
    Cookie,
    DNSRecord,
    DNSRecordType,
    Endpoint,
    EndpointCategory,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    HTTPHeader,
    HTTPObservation,
    Host,
    HostStatus,
    HttpMethod,
    JavaScriptEndpoint,
    JavaScriptFile,
    Parameter,
    ParamLocation,
    ParamType,
    Program,
    Protocol,
    ReconSessionConfig,
    ReconSourceType,
    ReconState,
    Scope,
    SecurityHeader,
    SecurityHeaderName,
    TechCategory,
    Technology,
    TimelineEntry,
)
from deephunter.recon.pipeline import PipelineReport, ReconPipeline, ReconStage
from deephunter.recon.plugin import PluginRegistry, PluginResult, ReconPlugin
from deephunter.recon.reporter import (
    endpoint_to_sko,
    host_to_sko,
    observations_to_sko_report,
    technology_to_sko,
)
from deephunter.recon.scope import ScopeManager
from deephunter.recon.session import ReconSession
from deephunter.recon.store import ReconStore, SQLiteReconStore
from deephunter.recon.technology import TechnologyIntelligence
from deephunter.recon.timeline import ReconTimeline
from deephunter.recon.http import (
    analyze_security_headers,
    classify_security_headers,
    find_missing_security_headers,
)

__all__ = [
    # Models
    "Program", "Scope", "Asset", "Host", "HostStatus", "Protocol",
    "DNSRecord", "DNSRecordType",
    "HTTPObservation", "HTTPHeader", "SecurityHeader", "SecurityHeaderName",
    "Cookie", "HttpMethod",
    "Technology", "TechCategory",
    "Application", "ApplicationType",
    "Endpoint", "EndpointCategory", "Parameter", "ParamLocation", "ParamType",
    "AuthMechanism", "AuthObservation", "AuthType",
    "JavaScriptFile", "JavaScriptEndpoint",
    "APIEndpoint",
    "CloudResource", "CloudResourceType",
    "GraphNode", "GraphNodeType", "GraphEdge", "GraphEdgeType",
    "ReconState", "ReconSessionConfig", "TimelineEntry",
    "ReconSourceType",
    # Events
    "ReconEvent", "ReconEventBus",
    "ScopeLoadedEvent", "AssetCreatedEvent", "HostDiscoveredEvent",
    "DNSRecordObservedEvent", "HTTPObservedEvent",
    "EndpointAddedEvent", "ParameterAddedEvent",
    "TechnologyDetectedEvent", "AuthObservedEvent",
    "ApplicationDiscoveredEvent",
    "CloudResourceDiscoveredEvent",
    "JSEndpointDiscoveredEvent", "APIDiscoveredEvent",
    "GraphUpdatedEvent", "ReconPipelineEvent",
    # Managers
    "ScopeManager", "AssetInventory", "HostRegistry",
    "HTTPIntelligence", "TechnologyIntelligence",
    "EndpointInventory", "AuthIntelligence",
    "ApplicationInventory", "CloudIntelligence",
    "AttackSurfaceGraph", "ReconTimeline", "ReconSession",
    # HTTP helpers
    "analyze_security_headers", "classify_security_headers",
    "find_missing_security_headers",
    # Pipeline
    "ReconPipeline", "ReconStage", "PipelineReport",
    # Store
    "ReconStore", "SQLiteReconStore",
    # Plugin
    "ReconPlugin", "PluginResult", "PluginRegistry",
    # Reporter
    "host_to_sko", "endpoint_to_sko", "technology_to_sko",
    "observations_to_sko_report",
]
