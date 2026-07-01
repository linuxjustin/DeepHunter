"""Execution profile models for the Investigation Orchestrator.

Defines configurable execution profiles that control which integrations
are enabled, what tools are run, and how the investigation workflow behaves.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ExecutionProfileType(str, Enum):
    """Available execution profile types."""

    PASSIVE = "passive"
    BUGBOUNTY = "bugbounty"
    API = "api"
    GRAPHQL = "graphql"
    CLOUD = "cloud"
    MOBILE = "mobile"
    CUSTOM = "custom"


class ToolGroup(str, Enum):
    """Tool groups for enabling/disabling."""

    SUBDOMAIN_ENUM = "subdomain_enum"
    DNS_ENUM = "dns_enum"
    WEB_CRAWLING = "web_crawling"
    URL_DISCOVERY = "url_discovery"
    TECH_DETECTION = "tech_detection"
    JS_ANALYSIS = "js_analysis"
    API_DISCOVERY = "api_discovery"
    CLOUD_DETECTION = "cloud_detection"
    VULN_SCAN = "vuln_scan"
    AUTH_TESTING = "auth_testing"


class ToolConfig(BaseModel):
    """Configuration for a single tool."""

    enabled: bool = Field(default=True)
    timeout: float = Field(default=120.0, ge=1.0)
    retry: int = Field(default=1, ge=0)
    args: dict[str, Any] = Field(default_factory=dict)


class ToolGroupConfig(BaseModel):
    """Configuration for a tool group."""

    enabled: bool = Field(default=True)
    tools: dict[str, ToolConfig] = Field(default_factory=dict)


class ExecutionProfile(BaseModel):
    """A named execution profile controlling investigation behavior.

    Profiles determine which integrations are enabled, what tools are run,
    and how the workflow behaves.
    """

    name: str
    profile_type: ExecutionProfileType
    description: str = ""
    version: str = "1.0"

    enabled_tool_groups: list[ToolGroup] = Field(default_factory=list)
    disabled_tool_groups: list[ToolGroup] = Field(default_factory=list)

    tool_groups: dict[str, ToolGroupConfig] = Field(default_factory=dict)

    workflow_name: str = "web_app_review"
    require_manual_approval: bool = True
    auto_approve_passive: bool = False

    max_concurrency: int = Field(default=4, ge=1, le=32)
    rate_limit_rpm: int = Field(default=60, ge=1)
    timeout_per_step: int = Field(default=600, ge=60)

    estimated_duration_minutes: int = Field(default=60)
    estimated_cost_usd: float = Field(default=0.0)

    metadata: dict[str, Any] = Field(default_factory=dict)

    def is_tool_group_enabled(self, group: ToolGroup) -> bool:
        if group.value in [g.value for g in self.disabled_tool_groups]:
            return False
        if group in self.enabled_tool_groups:
            return True
        if group.value in self.tool_groups:
            return self.tool_groups[group.value].enabled
        return False

    def get_tool_config(self, group: ToolGroup, tool_name: str) -> ToolConfig | None:
        group_config = self.tool_groups.get(group.value)
        if group_config and tool_name in group_config.tools:
            return group_config.tools[tool_name]
        return None


PASSIVE_PROFILE = ExecutionProfile(
    name="passive",
    profile_type=ExecutionProfileType.PASSIVE,
    description="Low-impact passive reconnaissance only. No active testing.",
    enabled_tool_groups=[
        ToolGroup.SUBDOMAIN_ENUM,
        ToolGroup.DNS_ENUM,
        ToolGroup.URL_DISCOVERY,
    ],
    require_manual_approval=False,
    auto_approve_passive=True,
    estimated_duration_minutes=30,
    estimated_cost_usd=0.0,
)

BUGBOUNTY_PROFILE = ExecutionProfile(
    name="bugbounty",
    profile_type=ExecutionProfileType.BUGBOUNTY,
    description="Full bug bounty investigation with all recon and testing modules.",
    enabled_tool_groups=[
        ToolGroup.SUBDOMAIN_ENUM,
        ToolGroup.DNS_ENUM,
        ToolGroup.WEB_CRAWLING,
        ToolGroup.URL_DISCOVERY,
        ToolGroup.TECH_DETECTION,
        ToolGroup.JS_ANALYSIS,
        ToolGroup.API_DISCOVERY,
        ToolGroup.CLOUD_DETECTION,
        ToolGroup.AUTH_TESTING,
    ],
    workflow_name="web_app_review",
    require_manual_approval=True,
    auto_approve_passive=False,
    estimated_duration_minutes=120,
    estimated_cost_usd=5.0,
)

API_PROFILE = ExecutionProfile(
    name="api",
    profile_type=ExecutionProfileType.API,
    description="API-focused investigation with OpenAPI and REST/GraphQL analysis.",
    enabled_tool_groups=[
        ToolGroup.SUBDOMAIN_ENUM,
        ToolGroup.DNS_ENUM,
        ToolGroup.URL_DISCOVERY,
        ToolGroup.API_DISCOVERY,
        ToolGroup.AUTH_TESTING,
    ],
    workflow_name="api_review",
    require_manual_approval=True,
    estimated_duration_minutes=90,
    estimated_cost_usd=3.0,
)

GRAPHQL_PROFILE = ExecutionProfile(
    name="graphql",
    profile_type=ExecutionProfileType.GRAPHQL,
    description="GraphQL-focused investigation with introspection and mutation testing.",
    enabled_tool_groups=[
        ToolGroup.SUBDOMAIN_ENUM,
        ToolGroup.DNS_ENUM,
        ToolGroup.URL_DISCOVERY,
        ToolGroup.API_DISCOVERY,
        ToolGroup.AUTH_TESTING,
    ],
    workflow_name="graphql_review",
    require_manual_approval=True,
    estimated_duration_minutes=60,
    estimated_cost_usd=2.0,
)

CLOUD_PROFILE = ExecutionProfile(
    name="cloud",
    profile_type=ExecutionProfileType.CLOUD,
    description="Cloud-focused investigation for AWS, Azure, GCP environments.",
    enabled_tool_groups=[
        ToolGroup.SUBDOMAIN_ENUM,
        ToolGroup.DNS_ENUM,
        ToolGroup.CLOUD_DETECTION,
        ToolGroup.API_DISCOVERY,
        ToolGroup.AUTH_TESTING,
    ],
    workflow_name="cloud_review",
    require_manual_approval=True,
    estimated_duration_minutes=90,
    estimated_cost_usd=4.0,
)

MOBILE_PROFILE = ExecutionProfile(
    name="mobile",
    profile_type=ExecutionProfileType.MOBILE,
    description="Mobile-focused investigation with APK and API testing.",
    enabled_tool_groups=[
        ToolGroup.API_DISCOVERY,
        ToolGroup.AUTH_TESTING,
        ToolGroup.URL_DISCOVERY,
    ],
    workflow_name="mobile_review",
    require_manual_approval=True,
    estimated_duration_minutes=120,
    estimated_cost_usd=5.0,
)

CUSTOM_PROFILE = ExecutionProfile(
    name="custom",
    profile_type=ExecutionProfileType.CUSTOM,
    description="Custom profile - configure as needed.",
    require_manual_approval=True,
    estimated_duration_minutes=60,
    estimated_cost_usd=1.0,
)


BUILTIN_PROFILES: dict[str, ExecutionProfile] = {
    "passive": PASSIVE_PROFILE,
    "bugbounty": BUGBOUNTY_PROFILE,
    "api": API_PROFILE,
    "graphql": GRAPHQL_PROFILE,
    "cloud": CLOUD_PROFILE,
    "mobile": MOBILE_PROFILE,
    "custom": CUSTOM_PROFILE,
}