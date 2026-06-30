"""Pydantic models for the Tool Integration SDK & Plugin Framework."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


now = lambda: datetime.now(timezone.utc)


class ToolStatus(str, Enum):
    pending = "pending"
    running = "running"
    success = "success"
    failed = "failed"
    skipped = "skipped"
    cancelled = "cancelled"
    timeout = "timeout"


class ToolCategory(str, Enum):
    subdomain_enum = "subdomain_enumeration"
    port_scan = "port_scanning"
    url_discovery = "url_discovery"
    technology_detect = "technology_detection"
    parameter_discovery = "parameter_discovery"
    js_analysis = "javascript_analysis"
    api_discovery = "api_discovery"
    cloud_enum = "cloud_enumeration"
    dns_enum = "dns_enumeration"
    auth_test = "authentication_testing"
    web_probe = "web_probing"
    content_discovery = "content_discovery"
    fuzzing = "fuzzing"
    vulnerability_scan = "vulnerability_scanning"
    osint = "osint"
    other = "other"


class ToolParameter(BaseModel):
    name: str
    description: str = ""
    type: str = "string"
    required: bool = False
    default: Any = None
    choices: list[str] = Field(default_factory=list)
    env_var: str = ""


class ToolMetadata(BaseModel):
    name: str
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    homepage: str = ""
    license: str = ""
    tags: list[str] = Field(default_factory=list)
    category: ToolCategory = ToolCategory.other
    supported_platforms: list[str] = Field(default_factory=lambda: ["linux", "darwin", "windows"])
    supported_formats: list[str] = Field(default_factory=lambda: ["json", "yaml", "csv", "txt", "ndjson"])
    requires_network: bool = False
    requires_installation: bool = True
    parameters: list[ToolParameter] = Field(default_factory=list)
    timeout_default: float = 120.0
    retry_default: int = 2


class ExecutionReport(BaseModel):
    id: str = Field(default_factory=lambda: f"er-{uuid4().hex[:12]}")
    tool_name: str
    plugin_name: str
    status: ToolStatus
    started_at: datetime = Field(default_factory=now)
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    command: str = ""
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = None
    error: str = ""
    retry_attempt: int = 0
    result_status: str = ""
    parsed_count: int = 0
    imported_count: int = 0
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


ToolReport = ExecutionReport


class PluginHealth(BaseModel):
    healthy: bool = True
    installed: bool = True
    executable_found: bool = True
    version_ok: bool = True
    config_ok: bool = True
    errors: list[str] = Field(default_factory=list)
