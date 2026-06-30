"""Core data models for the Knowledge Pack Ecosystem.

Every Knowledge Pack is a comprehensive, structured representation of
a technology, framework, protocol, or attack surface. Packs are designed
as first-class citizens that integrate with all DeepHunter subsystems.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from uuid import uuid4

from pydantic import BaseModel, Field

from deephunter.core.types import (
    AttackSurfaceEntry,
    AuthMechanism,
    BugClass,
    BusinessLogicConcern,
    CloudProvider,
    ManualTestChecklistItem,
    Technology,
    TrustBoundary,
)


# =============================================================================
# Enums
# =============================================================================


class KnowledgePackCategory(str, Enum):
    FRAMEWORK = "framework"
    LANGUAGE = "language"
    CLOUD = "cloud"
    API = "api"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    INFRASTRUCTURE = "infrastructure"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CMS = "cms"
    JS_FRAMEWORK = "js_framework"
    BUSINESS_LOGIC = "business_logic"
    OWASP = "owasp"
    CWE = "cwe"
    CAPEC = "capec"
    ATTACK_TECHNIQUE = "attack_technique"
    INVESTIGATION = "investigation"
    DATABASE = "database"
    PROTOCOL = "protocol"
    MESSAGING = "messaging"
    CACHE = "cache"
    WEBSERVER = "webserver"


class KnowledgeRelationshipType(str, Enum):
    USES = "uses"
    RUNS_ON = "runs_on"
    DEPLOYED_ON = "deployed_on"
    AUTHENTICATES_WITH = "authenticates_with"
    AUTHORIZES_WITH = "authorizes_with"
    STORES_DATA_IN = "stores_data_in"
    CACHES_WITH = "caches_with"
    QUEUES_WITH = "queues_with"
    DEPENDS_ON = "depends_on"
    EXTENDS = "extends"
    IMPLEMENTS = "implements"
    INTEGRATES_WITH = "integrates_with"
    COMPETES_WITH = "competes_with"
    REPLACES = "replaces"
    PREREQUISITE_OF = "prerequisite_of"
    RELATED_TO = "related_to"
    SIMILAR_TO = "similar_to"
    MONITORS_WITH = "monitors_with"
    PROXIED_BY = "proxied_by"
    LOAD_BALANCED_BY = "load_balanced_by"
    CONTAINERIZED_BY = "containerized_by"
    ORCHESTRATED_BY = "orchestrated_by"


# =============================================================================
# Sub-profiles
# =============================================================================


class TechnologyProfile(BaseModel):
    """Deep technology profile for a Knowledge Pack."""

    name: str
    version: str = ""
    supported_versions: list[str] = Field(default_factory=list)
    deprecated_versions: list[str] = Field(default_factory=list)
    minimum_version: str = ""
    vendor: str = ""
    language: str = ""
    framework: str = ""
    runtime: str = ""
    description: str = ""
    common_aliases: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    common_integrations: list[str] = Field(default_factory=list)
    architecture_description: str = ""
    request_lifecycle: str = ""
    documentation_url: str = ""
    tags: list[str] = Field(default_factory=list)


class TechnologyComponentProfile(BaseModel):
    """Key components and their security relevance."""

    name: str
    description: str = ""
    security_relevance: str = ""  # high, medium, low
    common_vulnerabilities: list[str] = Field(default_factory=list)
    investigation_priority: int = Field(default=50, ge=0, le=100)
    tags: list[str] = Field(default_factory=list)


class AttackSurfaceProfile(BaseModel):
    """Attack surface model for a Knowledge Pack."""

    entry_points: list[AttackSurfaceEntry] = Field(default_factory=list)
    endpoints: list[str] = Field(default_factory=list)
    parameters: list[str] = Field(default_factory=list)
    authentication: list[str] = Field(default_factory=list)
    authorization: list[str] = Field(default_factory=list)
    storage: list[str] = Field(default_factory=list)
    background_jobs: list[str] = Field(default_factory=list)
    queues: list[str] = Field(default_factory=list)
    caches: list[str] = Field(default_factory=list)
    admin_interfaces: list[str] = Field(default_factory=list)
    internal_apis: list[str] = Field(default_factory=list)
    external_apis: list[str] = Field(default_factory=list)
    cloud_resources: list[str] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    attack_surface_areas: list[str] = Field(default_factory=list)
    investigation_areas: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class FingerprintProfile(BaseModel):
    """Technology fingerprinting signatures."""

    http_headers: dict[str, str] = Field(default_factory=dict)  # header -> pattern
    cookies: list[str] = Field(default_factory=list)
    js_indicators: list[str] = Field(default_factory=list)
    directory_indicators: list[str] = Field(default_factory=list)
    file_indicators: list[str] = Field(default_factory=list)
    tls_signatures: list[str] = Field(default_factory=list)
    server_signatures: list[str] = Field(default_factory=list)
    error_page_signatures: list[str] = Field(default_factory=list)
    default_paths: list[str] = Field(default_factory=list)
    default_files: list[str] = Field(default_factory=list)
    metadata_patterns: dict[str, str] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)


class ReconProfile(BaseModel):
    """Reconnaissance patterns for technology discovery."""

    directories_to_check: list[str] = Field(default_factory=list)
    files_to_check: list[str] = Field(default_factory=list)
    endpoints_to_scan: list[str] = Field(default_factory=list)
    subdomains_to_check: list[str] = Field(default_factory=list)
    dns_records_to_check: list[str] = Field(default_factory=list)
    port_scan_targets: list[int] = Field(default_factory=list)
    js_files_to_analyze: list[str] = Field(default_factory=list)
    api_paths_to_probe: list[str] = Field(default_factory=list)
    admin_paths_to_check: list[str] = Field(default_factory=list)
    version_detection_paths: list[str] = Field(default_factory=list)
    debug_paths_to_check: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class KnowledgeRelationship(BaseModel):
    """A relationship between two knowledge packs."""

    target_pack_name: str
    relationship_type: KnowledgeRelationshipType
    description: str = ""
    direction: str = "outbound"  # outbound, inbound, bidirectional
    confidence: str = "high"  # high, medium, low
    tags: list[str] = Field(default_factory=list)


# =============================================================================
# Core Knowledge Pack
# =============================================================================


class KnowledgePack(BaseModel):
    """A comprehensive knowledge pack for a technology, framework, or domain.

    Every pack integrates with every DeepHunter subsystem and provides
    deep structured knowledge about its target.
    """

    # Identity
    name: str
    version: str = "1.0.0"
    category: KnowledgePackCategory = KnowledgePackCategory.FRAMEWORK
    description: str = ""
    author: str = "DeepHunter Knowledge Engine"

    # Technology metadata
    technology: TechnologyProfile = Field(default_factory=TechnologyProfile)
    fingerprints: FingerprintProfile = Field(default_factory=FingerprintProfile)
    recon: ReconProfile = Field(default_factory=ReconProfile)

    # Architecture
    components: list[TechnologyComponentProfile] = Field(default_factory=list)
    attack_surface: AttackSurfaceProfile = Field(default_factory=AttackSurfaceProfile)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)

    # Business logic
    business_logic_concerns: list[BusinessLogicConcern] = Field(default_factory=list)
    authorization_models: list[str] = Field(default_factory=list)

    # Relationships
    relationships: list[KnowledgeRelationship] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    related_packs: list[str] = Field(default_factory=list)

    # Investigation
    workflow: list[str] = Field(default_factory=list)
    checklists: list[ManualTestChecklistItem] = Field(default_factory=list)

    # Version-specific guidance
    version_specific_notes: dict[str, str] = Field(
        default_factory=dict,
        description="Version-specific investigation notes (version -> notes)",
    )
    version_specific_features: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Features introduced or changed per version (version -> [features])",
    )

    # References
    references: list[dict[str, str]] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)

    # Metadata
    tags: list[str] = Field(default_factory=list)
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    def to_technology_knowledge_entry(self) -> object:
        """Convert to TechnologyIntel TechnologyKnowledgeEntry."""
        from deephunter.tech_intel.models import (
            AttackSurfaceImplication,
            AuthMechanismClue as IntelAuthMechanismClue,
            InvestigationSuggestion,
            TechnologyKnowledgeEntry,
        )

        # Map attack surface areas to implications
        implications = [
            AttackSurfaceImplication(area=area, description=f"Attack surface from {self.name}")
            for area in self.attack_surface.attack_surface_areas
        ]

        # Map investigation areas to suggestions
        suggestions = [
            InvestigationSuggestion(
                title=area,
                description=f"Investigate {area} in {self.name}",
                priority=80,
            )
            for area in self.attack_surface.investigation_areas
        ]

        return TechnologyKnowledgeEntry(
            technology_name=self.name,
            aliases=self.technology.common_aliases,
            version=self.technology.version,
            description=self.description,
            tags=self.tags,
            related_technologies=[r.target_pack_name for r in self.relationships],
            attack_surface_implications=implications,
            investigation_suggestions=suggestions,
        )

    def to_planning_context_enrichment(self) -> dict:
        """Return planning-relevant data for MethodologyPackRule consumption."""
        return {
            "pack_name": self.name,
            "pack_category": self.category.value,
            "technologies": self.technology.name,
            "authentication": self.attack_surface.authentication,
            "attack_surface_areas": self.attack_surface.attack_surface_areas,
            "cwe_ids": self.cwe_ids,
            "cve_ids": self.cve_ids,
        }


class KnowledgePackIndex(BaseModel):
    """A versioned index of all registered knowledge packs."""

    version: str = "1.0.0"
    packs: dict[str, KnowledgePack] = Field(default_factory=dict)
    total_packs: int = 0
    total_categories: int = 0
    total_relationships: int = 0
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())

    def recalculate(self) -> None:
        self.total_packs = len(self.packs)
        categories = {p.category.value for p in self.packs.values()}
        self.total_categories = len(categories)
        self.total_relationships = sum(
            len(p.relationships) for p in self.packs.values()
        )


# =============================================================================
# Relationship Graph
# =============================================================================


class KnowledgeRelationshipGraph(BaseModel):
    """Directed graph of knowledge pack relationships."""

    nodes: dict[str, set[str]] = Field(default_factory=dict)
    edges: dict[str, list[KnowledgeRelationship]] = Field(default_factory=dict)

    def add_relationship(self, source: str, rel: KnowledgeRelationship) -> None:
        if source not in self.nodes:
            self.nodes[source] = set()
        self.nodes[source].add(rel.target_pack_name)
        if source not in self.edges:
            self.edges[source] = []
        self.edges[source].append(rel)

    def get_related(self, pack_name: str) -> list[KnowledgeRelationship]:
        return self.edges.get(pack_name, [])

    def get_technology_stack(self, pack_name: str, depth: int = 3) -> list[str]:
        """BFS traversal to get the technology stack."""
        visited: set[str] = set()
        stack: list[str] = [pack_name]
        result: list[str] = []
        while stack and len(result) < depth:
            current = stack.pop(0)
            if current in visited:
                continue
            visited.add(current)
            result.append(current)
            if current in self.nodes:
                for neighbor in self.nodes[current]:
                    if neighbor not in visited:
                        stack.append(neighbor)
        return result
