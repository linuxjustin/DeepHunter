"""Tests for the JavaScript Intelligence data models."""

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
    JSSecretObs,
    JSTokenStorage,
    ModuleType,
)
from deephunter.recon.models import EndpointCategory, HttpMethod


class TestModuleType:
    def test_values(self) -> None:
        assert ModuleType.ESM.value == "esm"
        assert ModuleType.COMMONJS.value == "commonjs"
        assert ModuleType.DYNAMIC.value == "dynamic"
        assert ModuleType.AMD.value == "amd"
        assert ModuleType.SYSTEMJS.value == "systemjs"


class TestJSBundle:
    def test_minimal(self) -> None:
        bundle = JSBundle(url="https://example.com/app.js")
        assert bundle.id.startswith("jsb-")
        assert bundle.url == "https://example.com/app.js"
        assert bundle.size == 0
        assert bundle.is_minified is False
        assert bundle.has_source_map_comment is False

    def test_full(self) -> None:
        bundle = JSBundle(
            url="https://example.com/app.js",
            size=1024,
            content_hash="abc123",
            build_tool="webpack",
            is_minified=True,
            has_source_map_comment=True,
            module_count=5,
            tags=["javascript"],
        )
        assert bundle.build_tool == "webpack"
        assert bundle.is_minified is True
        assert bundle.module_count == 5
        assert bundle.tags == ["javascript"]

    def test_serialization(self) -> None:
        bundle = JSBundle(url="https://example.com/app.js")
        data = bundle.model_dump(mode="json")
        restored = JSBundle(**data)
        assert restored.url == bundle.url
        assert restored.id == bundle.id


class TestJSModule:
    def test_minimal(self) -> None:
        mod = JSModule(name="react")
        assert mod.id.startswith("jsm-")
        assert mod.name == "react"
        assert mod.module_type == ModuleType.ESM
        assert mod.is_relative is False

    def test_relative(self) -> None:
        mod = JSModule(name="../utils/api", module_type=ModuleType.COMMONJS, is_relative=True)
        assert mod.is_relative is True
        assert mod.module_type == ModuleType.COMMONJS

    def test_serialization(self) -> None:
        mod = JSModule(name="lodash", line_number=10, context="const _ = require('lodash')")
        data = mod.model_dump(mode="json")
        restored = JSModule(**data)
        assert restored.name == "lodash"
        assert restored.line_number == 10


class TestJSEndpointRef:
    def test_minimal(self) -> None:
        ep = JSEndpointRef(url="/api/users")
        assert ep.id.startswith("jse-")
        assert ep.url == "/api/users"
        assert ep.methods == []
        assert ep.category == EndpointCategory.API

    def test_with_methods(self) -> None:
        ep = JSEndpointRef(url="/api/users", methods=[HttpMethod.GET, HttpMethod.POST])
        assert HttpMethod.GET in ep.methods
        assert ep.methods[1] == HttpMethod.POST

    def test_graphql(self) -> None:
        ep = JSEndpointRef(url="/graphql", is_graphql=True, graphql_operation="GetUsers")
        assert ep.is_graphql is True
        assert ep.graphql_operation == "GetUsers"

    def test_serialization(self) -> None:
        ep = JSEndpointRef(url="/api/data", methods=[HttpMethod.POST], params=["id"])
        data = ep.model_dump(mode="json")
        restored = JSEndpointRef(**data)
        assert restored.url == "/api/data"
        assert restored.params == ["id"]


class TestJSRoute:
    def test_minimal(self) -> None:
        route = JSRoute(path="/dashboard")
        assert route.id.startswith("jsr-")
        assert route.path == "/dashboard"
        assert route.is_dynamic is False

    def test_dynamic(self) -> None:
        route = JSRoute(path="/users/:id", is_dynamic=True, params=["id"])
        assert route.is_dynamic is True
        assert route.params == ["id"]

    def test_nested_lazy(self) -> None:
        route = JSRoute(path="/admin", is_nested=True, is_lazy=True, component="AdminPanel")
        assert route.is_nested is True
        assert route.is_lazy is True
        assert route.component == "AdminPanel"

    def test_serialization(self) -> None:
        route = JSRoute(path="/settings", component="Settings")
        data = route.model_dump(mode="json")
        restored = JSRoute(**data)
        assert restored.path == "/settings"
        assert restored.component == "Settings"


class TestJSAuthObs:
    def test_minimal(self) -> None:
        obs = JSAuthObs(mechanism="jwt", location="header")
        assert obs.id.startswith("jsa-")
        assert obs.mechanism == "jwt"
        assert obs.location == "header"

    def test_with_identifier(self) -> None:
        obs = JSAuthObs(mechanism="oauth", location="config", identifier="google-oauth")
        assert obs.identifier == "google-oauth"

    def test_serialization(self) -> None:
        obs = JSAuthObs(mechanism="csrf", location="cookie", identifier="XSRF-TOKEN")
        data = obs.model_dump(mode="json")
        restored = JSAuthObs(**data)
        assert restored.mechanism == "csrf"


class TestJSTokenStorage:
    def test_minimal(self) -> None:
        ts = JSTokenStorage(storage_type="localStorage", key="access_token")
        assert ts.id.startswith("jst-")
        assert ts.storage_type == "localStorage"
        assert ts.key == "access_token"


class TestJSCookieUsage:
    def test_minimal(self) -> None:
        c = JSCookieUsage(name="sessionid")
        assert c.id.startswith("jsc-")
        assert c.name == "sessionid"

    def test_flags(self) -> None:
        c = JSCookieUsage(name="auth", secure=True, http_only=True, same_site="Lax")
        assert c.secure is True
        assert c.http_only is True
        assert c.same_site == "Lax"


class TestJSConfigObs:
    def test_minimal(self) -> None:
        cfg = JSConfigObs(key="API_URL", value="https://api.example.com")
        assert cfg.id.startswith("jscf-")
        assert cfg.key == "API_URL"
        assert cfg.category == ""

    def test_feature_flag(self) -> None:
        cfg = JSConfigObs(key="FEATURE_NEW_DASHBOARD", value="true", category="feature_flag")
        assert cfg.category == "feature_flag"


class TestJSFrameworkObs:
    def test_minimal(self) -> None:
        fw = JSFrameworkObs(framework="React", evidence="React.createElement")
        assert fw.id.startswith("jsfw-")
        assert fw.framework == "React"
        assert fw.confidence == 0.5

    def test_custom_confidence(self) -> None:
        fw = JSFrameworkObs(framework="Next.js", evidence="next.config", confidence=0.9)
        assert fw.confidence == 0.9


class TestJSSecretObs:
    def test_minimal(self) -> None:
        s = JSSecretObs(secret_type="api_key", value_preview="sk-...")
        assert s.id.startswith("jss-")
        assert s.secret_type == "api_key"
        assert s.entropy == 0.0

    def test_with_entropy(self) -> None:
        s = JSSecretObs(secret_type="jwt", value_preview="eyJ...", entropy=4.5)
        assert s.entropy == 4.5


class TestJSAnalysisResult:
    def test_minimal(self) -> None:
        result = JSAnalysisResult()
        assert result.id.startswith("jsr-")
        assert result.modules == []
        assert result.api_endpoints == []
        assert result.detected_frameworks == []

    def test_with_data(self) -> None:
        result = JSAnalysisResult(
            source_url="https://example.com/app.js",
            content_hash="abc123",
            content_size=2048,
            detected_frameworks=["React", "Next.js"],
            is_bundle=True,
            has_source_map=True,
        )
        assert result.source_url == "https://example.com/app.js"
        assert len(result.detected_frameworks) == 2
        assert result.is_bundle is True

    def test_with_nested_models(self) -> None:
        result = JSAnalysisResult(
            modules=[JSModule(name="react")],
            api_endpoints=[JSEndpointRef(url="/api/test")],
            auth_observations=[JSAuthObs(mechanism="jwt", location="header")],
            routes=[JSRoute(path="/home")],
        )
        assert len(result.modules) == 1
        assert len(result.api_endpoints) == 1
        assert len(result.auth_observations) == 1
        assert len(result.routes) == 1

    def test_serialization(self) -> None:
        result = JSAnalysisResult(
            source_url="https://example.com/app.js",
            modules=[JSModule(name="react")],
            api_endpoints=[JSEndpointRef(url="/api/data")],
            detected_frameworks=["React"],
        )
        data = result.model_dump(mode="json")
        restored = JSAnalysisResult(**data)
        assert restored.source_url == result.source_url
        assert len(restored.modules) == 1
        assert restored.modules[0].name == "react"
        assert restored.detected_frameworks == ["React"]

    def test_empty_collections(self) -> None:
        result = JSAnalysisResult()
        assert result.modules == []
        assert result.api_endpoints == []
        assert result.graphql_endpoints == []
        assert result.auth_observations == []
        assert result.token_storage == []
        assert result.cookie_usage == []
        assert result.feature_flags == []
        assert result.config_values == []
        assert result.framework_observations == []
        assert result.secret_observations == []
        assert result.third_party_libraries == []
        assert result.build_tool_hints == []
        assert result.detected_frameworks == []

    def test_bundle_none(self) -> None:
        result = JSAnalysisResult()
        assert result.bundle is None
