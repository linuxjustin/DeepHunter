"""OpenAPI and Swagger import for DeepHunter.

Imports OpenAPI 3.x and Swagger 2.0 specifications and converts
them to DeepHunter endpoints, schemas, parameters, authentication
methods, and attack surface graph nodes.
"""

from __future__ import annotations

import json
import yaml
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from deephunter.recon.models import (
    AuthMechanism,
    AuthCategory,
    Endpoint,
    EndpointCategory,
    GraphNodeType,
    GraphEdgeType,
    HTTPHeader,
    HTTPObservation,
    Host,
    HttpMethod,
    Parameter,
    ParamLocation,
    ParamType,
)
from deephunter.recon.graph import AttackSurfaceGraph


class OpenAPIServer(BaseModel):
    url: str = ""
    description: str = ""


class OpenAPIParameter(BaseModel):
    name: str
    location: str
    required: bool = False
    type: str = "string"
    description: str = ""
    enum_values: list[str] = Field(default_factory=list)
    default: Any = None
    schema_ref: str = ""


class OpenAPIOperation(BaseModel):
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    description: str = ""
    parameters: list[OpenAPIParameter] = Field(default_factory=list)
    request_body: dict[str, Any] | None = None
    responses: dict[str, Any] = Field(default_factory=dict)
    security: list[dict[str, list[str]]] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class OpenAPISchema(BaseModel):
    name: str
    type: str = "object"
    properties: dict[str, Any] = Field(default_factory=dict)
    required_fields: list[str] = Field(default_factory=list)
    description: str = ""
    example: dict[str, Any] = Field(default_factory=dict)
    ref: str = ""


class OpenAPIComponents(BaseModel):
    schemas: dict[str, dict[str, Any]] = Field(default_factory=dict)
    security_schemes: dict[str, dict[str, Any]] = Field(default_factory=dict)


class OpenAPISpec(BaseModel):
    openapi: str = ""
    info_title: str = ""
    info_description: str = ""
    info_version: str = ""
    servers: list[OpenAPIServer] = Field(default_factory=list)
    paths: dict[str, dict[str, Any]] = Field(default_factory=dict)
    components: OpenAPIComponents = Field(default_factory=OpenAPIComponents)
    tags: list[dict[str, str]] = Field(default_factory=list)
    security: list[dict[str, list[str]]] = Field(default_factory=list)


class OpenAPIImporter:
    """Imports OpenAPI 3.x and Swagger 2.0 specifications."""

    def __init__(self) -> None:
        self.spec: OpenAPISpec | None = None
        self.schemas: dict[str, OpenAPISchema] = {}
        self.operations: list[OpenAPIOperation] = []
        self.auth_methods: list[AuthMechanism] = []

    def load_spec(self, spec_path: str, spec_type: str = "auto") -> OpenAPISpec:
        """Load an OpenAPI/Swagger specification file.

        Args:
            spec_path: Path to the spec file (JSON or YAML)
            spec_type: 'openapi', 'swagger', or 'auto' to detect

        Returns:
            Parsed OpenAPISpec
        """
        with open(spec_path) as f:
            raw = f.read()

        if spec_type == "auto":
            if spec_path.endswith(".yaml") or spec_path.endswith(".yml"):
                spec_type = "openapi"
            else:
                spec_type = "openapi"

        if spec_type == "swagger" or "swagger" in raw[:200]:
            data = yaml.safe_load(raw) if spec_path.endswith((".yaml", ".yml")) else json.loads(raw)
            data = self._convert_swagger_to_openapi(data)

        data = yaml.safe_load(raw) if spec_path.endswith((".yaml", ".yml")) else json.loads(raw)

        self.spec = OpenAPISpec(
            openapi=data.get("openapi", data.get("swagger", "")),
            info_title=data.get("info", {}).get("title", ""),
            info_description=data.get("info", {}).get("description", ""),
            info_version=data.get("info", {}).get("version", ""),
        )

        servers = data.get("servers", [])
        if isinstance(servers, list):
            for s in servers:
                self.spec.servers.append(OpenAPIServer(url=s.get("url", ""), description=s.get("description", "")))
        elif isinstance(servers, dict):
            self.spec.servers.append(OpenAPIServer(url=servers.get("url", "")))

        if "paths" in data:
            self._parse_paths(data["paths"])

        if "components" in data:
            self.spec.components = OpenAPIComponents(**data["components"])
            self._parse_components(data["components"])
            self._parse_security_schemes(data["components"])

        global_security = data.get("security", [])
        if global_security:
            self.spec.security = global_security

        return self.spec

    def _convert_swagger_to_openapi(self, data: dict[str, Any]) -> dict[str, Any]:
        """Convert Swagger 2.0 to OpenAPI 3.0 structure."""
        if "swagger" in data and data["swagger"].startswith("2"):
            result = {"openapi": "3.0.0", "info": data.get("info", {}), "paths": {}}
            if "host" in data:
                base_path = data.get("basePath", "")
                schemes = data.get("schemes", ["https"])
                result["servers"] = [{"url": f"{schemes[0]}://{data['host']}{base_path}"}] if schemes and "host" in data else []
            result["paths"] = data.get("paths", {})
            if "securityDefinitions" in data:
                result["components"] = {"securitySchemes": self._convert_swagger_security(data["securityDefinitions"])}
            result["security"] = data.get("security", [])
            return result
        return data

    def _convert_swagger_security(self, sec_defs: dict[str, Any]) -> dict[str, Any]:
        result = {}
        for name, defn in sec_defs.items():
            if defn.get("type") == "apiKey":
                result[name] = {"type": "apiKey", "in": defn.get("in"), "name": defn.get("name")}
            elif defn.get("type") == "basic":
                result[name] = {"type": "http", "scheme": "basic"}
            elif defn.get("type") == "oauth2":
                result[name] = {"type": "oauth2", "flows": defn.get("flow", "implicit")}
        return result

    def _parse_paths(self, paths: dict[str, Any]) -> None:
        for path, path_item in paths.items():
            for method, operation in path_item.items():
                if method not in ("get", "post", "put", "delete", "patch", "options", "head"):
                    continue

                op = self._parse_operation(path, method.upper(), operation)
                self.operations.append(op)

    def _parse_operation(self, path: str, method: str, operation: dict[str, Any]) -> OpenAPIOperation:
        op = OpenAPIOperation(
            path=path,
            method=method,
            operation_id=operation.get("operationId", ""),
            summary=operation.get("summary", ""),
            description=operation.get("description", ""),
            security=operation.get("security", []),
            tags=operation.get("tags", []),
        )

        for param in operation.get("parameters", []):
            loc = param.get("in", "query")
            schema = param.get("schema", {})
            op_param = OpenAPIParameter(
                name=param.get("name", ""),
                location=loc,
                required=param.get("required", False),
                type=schema.get("type", "string"),
                description=param.get("description", ""),
                enum_values=schema.get("enum", []),
                default=schema.get("default"),
                schema_ref=param.get("schema", {}).get("$ref", ""),
            )
            op.parameters.append(op_param)

        if "requestBody" in operation:
            op.request_body = operation["requestBody"]

        if "responses" in operation:
            op.responses = operation["responses"]

        return op

    def _parse_components(self, components: dict[str, Any]) -> None:
        for name, schema_def in components.get("schemas", {}).items():
            schema = OpenAPISchema(
                name=name,
                type=schema_def.get("type", "object"),
                properties=schema_def.get("properties", {}),
                required_fields=schema_def.get("required", []),
                description=schema_def.get("description", ""),
                example=schema_def.get("example", {}),
                ref=f"#/components/schemas/{name}",
            )
            self.schemas[name] = schema

    def _parse_security_schemes(self, components: dict[str, Any]) -> None:
        for name, scheme in components.get("securitySchemes", {}).items():
            auth_type = scheme.get("type", "")
            if auth_type == "http":
                scheme_type = scheme.get("scheme", "")
                if scheme_type == "basic":
                    auth = AuthMechanism(type=AuthCategory.BASIC_AUTH, name=name, description=scheme.get("description", ""))
                elif scheme_type == "bearer":
                    auth = AuthMechanism(type=AuthCategory.BEARER_TOKEN, name=name, description=scheme.get("description", ""))
                else:
                    auth = AuthMechanism(type=AuthCategory.CUSTOM, name=name, description=scheme.get("description", ""))
                self.auth_methods.append(auth)
            elif auth_type == "apiKey":
                auth = AuthMechanism(type=AuthCategory.API_KEY, name=name, in_location=scheme.get("in", "header"), description=scheme.get("description", ""))
                self.auth_methods.append(auth)
            elif auth_type == "oauth2":
                auth = AuthMechanism(type=AuthCategory.OAUTH2, name=name, description=scheme.get("description", ""))
                self.auth_methods.append(auth)

    def convert_to_endpoints(self) -> list[Endpoint]:
        """Convert the spec to DeepHunter Endpoint models."""
        endpoints = []
        for op in self.operations:
            endpoint = Endpoint(
                path=op.path,
                method=HttpMethod(op.method),
                host="",
                port=443,
                category=EndpointCategory.API if "/api" in op.path else EndpointCategory.WEB,
                parameters=[],
                authenticated=False,
            )

            for param in op.parameters:
                p = Parameter(
                    name=param.name,
                    value=str(param.default) if param.default else "",
                    location=ParamLocation(param.location.upper() if param.location.upper() in ("QUERY", "PATH", "HEADER", "COOKIE") else "QUERY"),
                    type=ParamType(param.type.upper() if param.type.upper() in ("STRING", "INTEGER", "NUMBER", "BOOLEAN", "ARRAY", "OBJECT") else "STRING"),
                    required=param.required,
                )
                endpoint.parameters.append(p)

            if op.security or self.spec.security if self.spec else []:
                endpoint.authenticated = True

            endpoints.append(endpoint)
        return endpoints

    def convert_to_attack_surface(self, base_url: str = "") -> AttackSurfaceGraph:
        """Convert the spec to an attack surface graph."""
        graph = AttackSurfaceGraph()

        parsed = urlparse(base_url)
        host_node = GraphNodeType.HOST
        endpoint_node = GraphNodeType.ENDPOINT
        param_node = GraphNodeType.PARAMETER

        if base_url:
            graph.add_node(host_node, {"hostname": parsed.netloc.split(":")[0], "port": parsed.port or 443})

        for op in self.operations:
            full_url = f"{base_url}{op.path}"
            op_node_id = f"{op.method.upper()} {op.path}"
            graph.add_node(endpoint_node, {"path": op.path, "method": op.method, "operation_id": op.operation_id, "url": full_url})

            if base_url:
                graph.add_edge(parsed.netloc.split(":")[0], op_node_id, GraphEdgeType.HOSTS)

            for param in op.parameters:
                param_id = f"{op_node_id}:{param.name}"
                graph.add_node(param_node, {"name": param.name, "location": param.location, "type": param.type, "required": param.required})
                graph.add_edge(op_node_id, param_id, GraphEdgeType.HAS_PARAMETER)

            for auth in self.auth_methods:
                auth_id = f"auth:{auth.name}"
                graph.add_node(GraphNodeType.AUTH, {"name": auth.name, "type": auth.type.value})
                graph.add_edge(auth_id, op_node_id, GraphEdgeType.REQUIRES_AUTH)

        return graph

    def generate_planner_tasks(self) -> list[dict[str, Any]]:
        """Generate investigation planner tasks from the spec."""
        tasks = []

        for op in self.operations:
            task = {
                "title": f"Test {op.method.upper()} {op.path}",
                "description": f"Endpoint: {op.summary or op.description or 'No description'}",
                "category": "api_testing",
                "priority": "medium",
                "tags": op.tags + ["openapi"],
            }
            tasks.append(task)

        if self.auth_methods:
            tasks.append({
                "title": "Review authentication mechanisms",
                "description": f"Found {len(self.auth_methods)} auth methods: {', '.join(a.name for a in self.auth_methods)}",
                "category": "auth_review",
                "priority": "high",
                "tags": ["authentication"],
            })

        if self.schemas:
            tasks.append({
                "title": "Test schema validation",
                "description": f"Found {len(self.schemas)} schemas that may have validation issues",
                "category": "schema_testing",
                "priority": "medium",
                "tags": ["schema", "validation"],
            })

        return tasks


class OpenAPIImporterFacade:
    """High-level facade for importing OpenAPI specs into DeepHunter."""

    def __init__(self) -> None:
        self.importer = OpenAPIImporter()

    def import_spec(self, spec_path: str, base_url: str = "") -> dict[str, Any]:
        """Import an OpenAPI spec and return all converted data."""
        spec = self.importer.load_spec(spec_path)
        endpoints = self.importer.convert_to_endpoints()
        graph = self.importer.convert_to_attack_surface(base_url)
        tasks = self.importer.generate_planner_tasks()

        return {
            "spec": spec,
            "endpoints": endpoints,
            "attack_surface": graph,
            "planner_tasks": tasks,
            "auth_methods": self.importer.auth_methods,
            "schemas": self.importer.schemas,
            "operations": self.importer.operations,
        }