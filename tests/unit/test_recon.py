"""Tests for the Recon Intelligence Platform v1."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from deephunter.recon import (
    APIEndpoint,
    Application,
    ApplicationDiscoveredEvent,
    ApplicationInventory,
    ApplicationType,
    Asset,
    AssetCreatedEvent,
    AssetInventory,
    AttackSurfaceGraph,
    AuthIntelligence,
    AuthMechanism,
    AuthObservation,
    AuthObservedEvent,
    AuthType,
    CloudIntelligence,
    CloudResource,
    CloudResourceDiscoveredEvent,
    CloudResourceType,
    Cookie,
    DNSRecord,
    DNSRecordObservedEvent,
    DNSRecordType,
    Endpoint,
    EndpointAddedEvent,
    EndpointCategory,
    EndpointInventory,
    GraphEdge,
    GraphEdgeType,
    GraphNode,
    GraphNodeType,
    GraphUpdatedEvent,
    HTTPHeader,
    HTTPIntelligence,
    HTTPObservation,
    HTTPObservedEvent,
    Host,
    HostDiscoveredEvent,
    HostRegistry,
    HostStatus,
    HttpMethod,
    JavaScriptEndpoint,
    JavaScriptFile,
    Parameter,
    ParameterAddedEvent,
    ParamLocation,
    ParamType,
    PipelineReport,
    PluginRegistry,
    PluginResult,
    Program,
    Protocol,
    ReconEventBus,
    ReconPipeline,
    ReconPlugin,
    ReconSession,
    ReconSourceType,
    ReconState,
    ReconStore,
    ReconTimeline,
    Scope,
    ScopeLoadedEvent,
    ScopeManager,
    SecurityHeader,
    SecurityHeaderName,
    SQLiteReconStore,
    TechCategory,
    Technology,
    TechnologyDetectedEvent,
    TechnologyIntelligence,
    TimelineEntry,
    analyze_security_headers,
    classify_security_headers,
    endpoint_to_sko,
    find_missing_security_headers,
    host_to_sko,
    observations_to_sko_report,
    technology_to_sko,
)
from deephunter.core.config import DeepHunterConfig, ReconConfig
from deephunter.core.exceptions import ReconError

# ═══════════════════════════════════════════════════════════════════════════════
# Model tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestModels:
    def test_program(self) -> None:
        p = Program(name="Test Bug Bounty", platform="hackerone", url="https://hackerone.com/test")
        assert p.id.startswith("prog-")
        assert p.name == "Test Bug Bounty"

    def test_scope_exact(self) -> None:
        s = Scope(target="example.com", scope_type="exact")
        assert s.id.startswith("scope-")
        assert s.in_scope is True

    def test_scope_out_of_scope(self) -> None:
        s = Scope(target="evil.com", in_scope=False)
        assert s.in_scope is False

    def test_asset(self) -> None:
        a = Asset(identifier="api.example.com", asset_type="subdomain", source=ReconSourceType.SUBDOMAIN_ENUMERATION)
        assert a.id.startswith("ast-")
        assert a.source == ReconSourceType.SUBDOMAIN_ENUMERATION

    def test_host(self) -> None:
        h = Host(hostname="www.example.com", ip="192.168.1.1", port=443, protocol=Protocol.HTTPS)
        assert h.id.startswith("host-")
        assert h.status == HostStatus.UNKNOWN

    def test_host_active_status(self) -> None:
        h = Host(hostname="active.example.com", ip="1.2.3.4", status=HostStatus.ACTIVE)
        assert h.status == HostStatus.ACTIVE

    def test_dns_record(self) -> None:
        d = DNSRecord(record_type=DNSRecordType.A, value="1.2.3.4", name="example.com", ttl=3600)
        assert d.id.startswith("dns-")
        assert d.record_type == DNSRecordType.A

    def test_dns_record_cname(self) -> None:
        d = DNSRecord(record_type=DNSRecordType.CNAME, value="proxy.example.com")
        assert d.record_type == DNSRecordType.CNAME

    def test_http_observation(self) -> None:
        obs = HTTPObservation(url="https://example.com/", status_code=200, content_type="text/html")
        assert obs.id.startswith("http-")
        assert obs.method == HttpMethod.GET

    def test_http_observation_with_post(self) -> None:
        obs = HTTPObservation(url="https://example.com/api", method=HttpMethod.POST, status_code=201)
        assert obs.method == HttpMethod.POST

    def test_http_header(self) -> None:
        h = HTTPHeader(name="Content-Type", value="application/json")
        assert h.security_relevant is False

    def test_security_header(self) -> None:
        sh = SecurityHeader(name=SecurityHeaderName.STRICT_TRANSPORT_SECURITY, value="max-age=31536000", secure=True)
        assert sh.name == SecurityHeaderName.STRICT_TRANSPORT_SECURITY
        assert sh.secure is True

    def test_cookie(self) -> None:
        c = Cookie(name="session", http_only=True, secure=True)
        assert c.http_only is True
        assert c.secure is True

    def test_technology(self) -> None:
        t = Technology(name="nginx", category=TechCategory.WEB_SERVER, version="1.24.0", confidence=0.95)
        assert t.id.startswith("tech-")
        assert t.category == TechCategory.WEB_SERVER

    def test_technology_frontend(self) -> None:
        t = Technology(name="React", category=TechCategory.FRONTEND)
        assert t.category == TechCategory.FRONTEND

    def test_application(self) -> None:
        app = Application(name="Main API", app_type=ApplicationType.API, base_path="/api/v1")
        assert app.id.startswith("app-")
        assert app.app_type == ApplicationType.API

    def test_application_admin_panel(self) -> None:
        app = Application(name="Admin", app_type=ApplicationType.ADMIN_PANEL, base_path="/admin")
        assert app.app_type == ApplicationType.ADMIN_PANEL

    def test_endpoint(self) -> None:
        ep = Endpoint(path="/api/v1/users", method=HttpMethod.GET, category=EndpointCategory.API)
        assert ep.id.startswith("ep-")
        assert ep.category == EndpointCategory.API

    def test_endpoint_auth(self) -> None:
        ep = Endpoint(path="/admin", method=HttpMethod.GET, auth_required=True, auth_type=AuthType.SESSION_COOKIE)
        assert ep.auth_required is True
        assert ep.auth_type == AuthType.SESSION_COOKIE

    def test_parameter(self) -> None:
        p = Parameter(name="userId", location=ParamLocation.PATH, param_type=ParamType.INTEGER, required=True)
        assert p.id.startswith("param-")
        assert p.location == ParamLocation.PATH

    def test_parameter_default_value(self) -> None:
        p = Parameter(name="page", location=ParamLocation.QUERY, default_value="1")
        assert p.default_value == "1"

    def test_auth_mechanism(self) -> None:
        am = AuthMechanism(auth_type=AuthType.JWT, url="https://example.com/auth/token", category="token_endpoint")
        assert am.id.startswith("auth-")
        assert am.auth_type == AuthType.JWT

    def test_auth_observation(self) -> None:
        ao = AuthObservation(description="Login page uses JWT in Authorization header", detail="Bearer token observed")
        assert ao.id.startswith("aobs-")

    def test_js_file(self) -> None:
        js = JavaScriptFile(url="https://example.com/app.js", size=50000)
        assert js.id.startswith("jsf-")

    def test_js_endpoint(self) -> None:
        js = JavaScriptEndpoint(source_url="https://example.com/app.js", discovered_url="/api/internal")
        assert js.id.startswith("js-")

    def test_api_endpoint(self) -> None:
        api = APIEndpoint(path="/api/v1/users", method=HttpMethod.GET, summary="List users", auth_required=True)
        assert api.id.startswith("api-")
        assert api.auth_required is True

    def test_cloud_resource(self) -> None:
        cr = CloudResource(provider="aws", resource_type=CloudResourceType.BUCKET, name="my-bucket", region="us-east-1")
        assert cr.id.startswith("cloud-")
        assert cr.resource_type == CloudResourceType.BUCKET

    def test_graph_node(self) -> None:
        gn = GraphNode(node_type=GraphNodeType.HOST, ref_id="host-abc123", label="Main web server")
        assert gn.id.startswith("gn-")

    def test_graph_edge(self) -> None:
        ge = GraphEdge(source_id="gn-1", target_id="gn-2", edge_type=GraphEdgeType.HOSTS)
        assert ge.id.startswith("ge-")

    def test_timeline_entry(self) -> None:
        te = TimelineEntry(session_id="rec-test", event_type="host_discovered", description="New host found")
        assert te.id.startswith("tl-")

    def test_recon_state_roundtrip(self) -> None:
        state = ReconState(target="example.com")
        state.hosts.append(Host(hostname="www.example.com", ip="1.2.3.4"))
        state.assets.append(Asset(identifier="example.com"))
        dumped = state.model_dump_for_storage()
        loaded = ReconState.from_dict(dumped)
        assert loaded.target == "example.com"
        assert len(loaded.hosts) == 1
        assert len(loaded.assets) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Event bus tests
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconEventBus:
    def test_subscribe_and_emit(self) -> None:
        bus = ReconEventBus()
        received: list[HostDiscoveredEvent] = []

        def handler(event: HostDiscoveredEvent) -> None:
            received.append(event)

        bus.subscribe(HostDiscoveredEvent, handler)
        bus.emit(HostDiscoveredEvent(hostname="test.com", ip="1.2.3.4"))
        assert len(received) == 1
        assert received[0].hostname == "test.com"

    def test_unsubscribe(self) -> None:
        bus = ReconEventBus()
        received: list[HostDiscoveredEvent] = []

        def handler(event: HostDiscoveredEvent) -> None:
            received.append(event)

        bus.subscribe(HostDiscoveredEvent, handler)
        bus.unsubscribe(HostDiscoveredEvent, handler)
        bus.emit(HostDiscoveredEvent(hostname="test.com"))
        assert len(received) == 0

    def test_emit_wrong_type_no_callback(self) -> None:
        bus = ReconEventBus()
        received: list[ScopeLoadedEvent] = []

        def handler(event: ScopeLoadedEvent) -> None:
            received.append(event)

        bus.subscribe(ScopeLoadedEvent, handler)
        bus.emit(HostDiscoveredEvent(hostname="test.com"))
        assert len(received) == 0

    def test_multiple_handlers(self) -> None:
        bus = ReconEventBus()
        count: list[int] = [0]

        def h1(event: AssetCreatedEvent) -> None:
            count[0] += 1

        def h2(event: AssetCreatedEvent) -> None:
            count[0] += 1

        bus.subscribe(AssetCreatedEvent, h1)
        bus.subscribe(AssetCreatedEvent, h2)
        bus.emit(AssetCreatedEvent(identifier="test"))
        assert count[0] == 2

    def test_handler_exception_is_caught(self) -> None:
        bus = ReconEventBus()
        count: list[int] = [0]

        def bad_handler(event: HostDiscoveredEvent) -> None:
            raise RuntimeError("handler error")

        def good_handler(event: HostDiscoveredEvent) -> None:
            count[0] += 1

        bus.subscribe(HostDiscoveredEvent, bad_handler)
        bus.subscribe(HostDiscoveredEvent, good_handler)
        bus.emit(HostDiscoveredEvent(hostname="test.com"))
        assert count[0] == 1

    def test_clear(self) -> None:
        bus = ReconEventBus()
        received: list[HostDiscoveredEvent] = []

        def handler(event: HostDiscoveredEvent) -> None:
            received.append(event)

        bus.subscribe(HostDiscoveredEvent, handler)
        bus.clear()
        bus.emit(HostDiscoveredEvent(hostname="test.com"))
        assert len(received) == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Scope Manager
# ═══════════════════════════════════════════════════════════════════════════════


class TestScopeManager:
    def test_add_program(self) -> None:
        mgr = ScopeManager()
        p = Program(name="Test")
        mgr.add_program(p)
        assert mgr.get_program(p.id) is p
        assert mgr.program_count == 1

    def test_add_duplicate_program(self) -> None:
        mgr = ScopeManager()
        existing = Program(name="Test", id="prog-dup")
        mgr.add_program(existing)
        duplicate = Program(name="Test2", id="prog-dup")
        with pytest.raises(ValueError, match="already exists"):
            mgr.add_program(duplicate)

    def test_remove_program(self) -> None:
        mgr = ScopeManager()
        p = Program(name="Test")
        mgr.add_program(p)
        assert mgr.remove_program(p.id) is True
        assert mgr.get_program(p.id) is None

    def test_remove_nonexistent_program(self) -> None:
        mgr = ScopeManager()
        assert mgr.remove_program("nonexistent") is False

    def test_list_programs(self) -> None:
        mgr = ScopeManager()
        mgr.add_program(Program(name="A"))
        mgr.add_program(Program(name="B"))
        assert len(mgr.list_programs()) == 2

    def test_add_scope(self) -> None:
        mgr = ScopeManager()
        s = Scope(target="example.com", scope_type="exact")
        mgr.add_scope(s)
        assert mgr.get_scope(s.id) is s
        assert mgr.scope_count == 1

    def test_remove_scope(self) -> None:
        mgr = ScopeManager()
        s = Scope(target="example.com", scope_type="exact")
        mgr.add_scope(s)
        assert mgr.remove_scope(s.id) is True
        assert mgr.get_scope(s.id) is None

    def test_list_scopes_by_program(self) -> None:
        mgr = ScopeManager()
        mgr.add_scope(Scope(target="a.com", program_id="prog1"))
        mgr.add_scope(Scope(target="b.com", program_id="prog1"))
        mgr.add_scope(Scope(target="c.com", program_id="prog2"))
        assert len(mgr.list_scopes("prog1")) == 2
        assert len(mgr.list_scopes("prog2")) == 1

    def test_list_in_scope(self) -> None:
        mgr = ScopeManager()
        mgr.add_scope(Scope(target="in.com", scope_type="exact", in_scope=True))
        mgr.add_scope(Scope(target="out.com", scope_type="exact", in_scope=False))
        assert len(mgr.list_in_scope()) == 1
        assert len(mgr.list_out_of_scope()) == 1

    def test_is_in_scope_exact(self) -> None:
        mgr = ScopeManager()
        mgr.add_scope(Scope(target="example.com", scope_type="exact"))
        assert mgr.is_in_scope("example.com") is True
        assert mgr.is_in_scope("not-example.com") is False

    def test_is_in_scope_wildcard(self) -> None:
        mgr = ScopeManager()
        mgr.add_scope(Scope(target="*.example.com", scope_type="wildcard"))
        assert mgr.is_in_scope("sub.example.com") is True
        assert mgr.is_in_scope("other.com") is False

    def test_is_out_of_scope(self) -> None:
        mgr = ScopeManager()
        mgr.add_scope(Scope(target="*.evil.com", scope_type="wildcard", in_scope=False))
        assert mgr.is_out_of_scope("sub.evil.com") is True
        assert mgr.is_out_of_scope("good.com") is False

    def test_clear(self) -> None:
        mgr = ScopeManager()
        mgr.add_program(Program(name="A"))
        mgr.add_scope(Scope(target="a.com"))
        mgr.clear()
        assert mgr.program_count == 0
        assert mgr.scope_count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Asset Inventory
# ═══════════════════════════════════════════════════════════════════════════════


class TestAssetInventory:
    def test_add_and_get(self) -> None:
        inv = AssetInventory()
        a = Asset(identifier="example.com")
        inv.add(a)
        assert inv.get(a.id) is a

    def test_add_duplicate(self) -> None:
        inv = AssetInventory()
        existing = Asset(identifier="a.com", id="ast-dup")
        inv.add(existing)
        duplicate = Asset(identifier="b.com", id="ast-dup")
        with pytest.raises(ValueError, match="already exists"):
            inv.add(duplicate)

    def test_remove(self) -> None:
        inv = AssetInventory()
        a = Asset(identifier="example.com")
        inv.add(a)
        assert inv.remove(a.id) is True
        assert inv.get(a.id) is None

    def test_find(self) -> None:
        inv = AssetInventory()
        inv.add(Asset(identifier="example.com"))
        assert inv.find("example.com") is not None
        assert inv.find("nonexistent.com") is None

    def test_find_by_program(self) -> None:
        inv = AssetInventory()
        inv.add(Asset(identifier="a.com", program_id="prog1"))
        inv.add(Asset(identifier="b.com", program_id="prog1"))
        inv.add(Asset(identifier="c.com", program_id="prog2"))
        assert len(inv.find_by_program("prog1")) == 2
        assert len(inv.find_by_program("prog2")) == 1

    def test_find_by_type(self) -> None:
        inv = AssetInventory()
        inv.add(Asset(identifier="a.com", asset_type="domain"))
        inv.add(Asset(identifier="1.2.3.4", asset_type="ip"))
        assert len(inv.find_by_type("domain")) == 1
        assert len(inv.find_by_type("ip")) == 1

    def test_add_batch(self) -> None:
        inv = AssetInventory()
        inv.add_batch([
            Asset(identifier="a.com"),
            Asset(identifier="b.com"),
        ])
        assert inv.count == 2

    def test_clear(self) -> None:
        inv = AssetInventory()
        inv.add(Asset(identifier="a.com"))
        inv.clear()
        assert inv.count == 0

    def test_len(self) -> None:
        inv = AssetInventory()
        assert len(inv) == 0
        inv.add(Asset(identifier="a.com"))
        assert len(inv) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Host Registry
# ═══════════════════════════════════════════════════════════════════════════════


class TestHostRegistry:
    def test_add_and_get(self) -> None:
        reg = HostRegistry()
        h = Host(hostname="www.example.com", ip="1.2.3.4")
        reg.add(h)
        assert reg.get(h.id) is h

    def test_find_by_hostname(self) -> None:
        reg = HostRegistry()
        reg.add(Host(hostname="www.example.com", ip="1.1.1.1"))
        reg.add(Host(hostname="www.example.com", ip="2.2.2.2"))
        assert len(reg.find_by_hostname("www.example.com")) == 2

    def test_find_by_ip(self) -> None:
        reg = HostRegistry()
        reg.add(Host(hostname="a.com", ip="1.2.3.4", port=443))
        reg.add(Host(hostname="b.com", ip="1.2.3.4", port=80))
        assert len(reg.find_by_ip("1.2.3.4")) == 2

    def test_find_by_port(self) -> None:
        reg = HostRegistry()
        reg.add(Host(hostname="a.com", ip="1.1.1.1", port=443))
        reg.add(Host(hostname="b.com", ip="2.2.2.2", port=80))
        assert len(reg.find_by_port(443)) == 1

    def test_find_by_protocol(self) -> None:
        reg = HostRegistry()
        reg.add(Host(hostname="a.com", ip="1.1.1.1", protocol=Protocol.HTTPS))
        reg.add(Host(hostname="b.com", ip="2.2.2.2", protocol=Protocol.HTTP))
        assert len(reg.find_by_protocol(Protocol.HTTPS)) == 1

    def test_find_active(self) -> None:
        reg = HostRegistry()
        reg.add(Host(hostname="a.com", ip="1.1.1.1", status=HostStatus.ACTIVE))
        reg.add(Host(hostname="b.com", ip="2.2.2.2", status=HostStatus.INACTIVE))
        assert len(reg.find_active()) == 1

    def test_add_dns_record(self) -> None:
        reg = HostRegistry()
        h = Host(hostname="example.com", ip="1.2.3.4")
        reg.add(h)
        rec = DNSRecord(record_type=DNSRecordType.A, value="5.6.7.8")
        reg.add_dns_record(h.id, rec)
        assert len(reg.get_dns_records(h.id)) == 1
        assert rec.host_id == h.id

    def test_find_dns_by_type(self) -> None:
        reg = HostRegistry()
        h = Host(hostname="example.com", ip="1.2.3.4")
        reg.add(h)
        reg.add_dns_record(h.id, DNSRecord(record_type=DNSRecordType.A, value="1.1.1.1"))
        reg.add_dns_record(h.id, DNSRecord(record_type=DNSRecordType.CNAME, value="proxy.example.com"))
        assert len(reg.find_dns_by_type(h.id, "A")) == 1
        assert len(reg.find_dns_by_type(h.id, "CNAME")) == 1

    def test_dns_record_on_nonexistent_host(self) -> None:
        reg = HostRegistry()
        with pytest.raises(ValueError, match="not found"):
            reg.add_dns_record("nonexistent", DNSRecord(record_type=DNSRecordType.A, value="1.2.3.4"))

    def test_add_batch(self) -> None:
        reg = HostRegistry()
        reg.add_batch([
            Host(hostname="a.com", ip="1.1.1.1"),
            Host(hostname="b.com", ip="2.2.2.2"),
        ])
        assert reg.count == 2

    def test_clear(self) -> None:
        reg = HostRegistry()
        reg.add(Host(hostname="a.com", ip="1.1.1.1"))
        reg.clear()
        assert reg.count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# HTTP Intelligence
# ═══════════════════════════════════════════════════════════════════════════════


class TestHTTPIntelligence:
    def test_add_observation(self) -> None:
        intel = HTTPIntelligence()
        obs = HTTPObservation(url="https://example.com/", status_code=200)
        intel.add_observation(obs)
        assert intel.get_observation(obs.id) is obs
        assert intel.count == 1

    def test_find_by_host(self) -> None:
        intel = HTTPIntelligence()
        intel.add_observation(HTTPObservation(host_id="host1", url="https://a.com/"))
        intel.add_observation(HTTPObservation(host_id="host1", url="https://a.com/api"))
        intel.add_observation(HTTPObservation(host_id="host2", url="https://b.com/"))
        assert len(intel.find_by_host("host1")) == 2
        assert len(intel.find_by_host("host2")) == 1

    def test_find_by_status(self) -> None:
        intel = HTTPIntelligence()
        intel.add_observation(HTTPObservation(url="https://a.com/", status_code=200))
        intel.add_observation(HTTPObservation(url="https://a.com/notfound", status_code=404))
        assert len(intel.find_by_status(200)) == 1
        assert len(intel.find_by_status(404)) == 1

    def test_security_headers_analyzed(self) -> None:
        intel = HTTPIntelligence()
        headers = [HTTPHeader(name="content-type", value="text/html")]
        obs = HTTPObservation(url="https://example.com/", status_code=200, headers=headers)
        intel.add_observation(obs)
        stored = intel.get_observation(obs.id)
        assert stored is not None
        # Should have analyzed all security headers
        sts = [h for h in stored.security_headers if h.name == SecurityHeaderName.STRICT_TRANSPORT_SECURITY]
        assert len(sts) == 1
        assert sts[0].present is False

    def test_clear(self) -> None:
        intel = HTTPIntelligence()
        intel.add_observation(HTTPObservation(url="https://a.com/", status_code=200))
        intel.clear()
        assert intel.count == 0


class TestSecurityHeaderAnalysis:
    def test_all_secure(self) -> None:
        headers = [
            HTTPHeader(name="strict-transport-security", value="max-age=31536000"),
            HTTPHeader(name="x-frame-options", value="DENY"),
            HTTPHeader(name="x-content-type-options", value="nosniff"),
        ]
        result = analyze_security_headers(headers)
        hsts = [h for h in result if h.name == SecurityHeaderName.STRICT_TRANSPORT_SECURITY][0]
        xfo = [h for h in result if h.name == SecurityHeaderName.X_FRAME_OPTIONS][0]
        assert hsts.present is True
        assert hsts.secure is True
        assert xfo.secure is True

    def test_all_missing(self) -> None:
        headers: list[HTTPHeader] = []
        result = analyze_security_headers(headers)
        assert all(h.present is False for h in result)

    def test_insecure_values(self) -> None:
        headers = [
            HTTPHeader(name="x-frame-options", value="ALLOWALL"),
        ]
        result = analyze_security_headers(headers)
        xfo = [h for h in result if h.name == SecurityHeaderName.X_FRAME_OPTIONS][0]
        assert xfo.present is True
        assert xfo.secure is False
        assert "X-Frame-Options" in xfo.recommendation

    def test_classify_security_headers(self) -> None:
        headers = [
            HTTPHeader(name="content-type", value="text/html"),
            HTTPHeader(name="strict-transport-security", value="max-age=3600"),
        ]
        result = classify_security_headers(headers)
        assert result[0].security_relevant is False
        assert result[1].security_relevant is True

    def test_find_missing_security_headers(self) -> None:
        headers = analyze_security_headers([])
        missing = find_missing_security_headers(headers)
        # All 9 security headers are missing
        assert len(missing) == len(SecurityHeaderName)


# ═══════════════════════════════════════════════════════════════════════════════
# Technology Intelligence
# ═══════════════════════════════════════════════════════════════════════════════


class TestTechnologyIntelligence:
    def test_add_and_get(self) -> None:
        intel = TechnologyIntelligence()
        t = Technology(name="nginx", category=TechCategory.WEB_SERVER)
        intel.add(t)
        assert intel.get(t.id) is t

    def test_find_by_name(self) -> None:
        intel = TechnologyIntelligence()
        intel.add(Technology(name="Nginx", category=TechCategory.WEB_SERVER))
        intel.add(Technology(name="React", category=TechCategory.FRONTEND))
        assert len(intel.find_by_name("nginx")) == 1
        assert len(intel.find_by_name("React")) == 1

    def test_find_by_category(self) -> None:
        intel = TechnologyIntelligence()
        intel.add(Technology(name="nginx", category=TechCategory.WEB_SERVER))
        intel.add(Technology(name="apache", category=TechCategory.WEB_SERVER))
        intel.add(Technology(name="react", category=TechCategory.FRONTEND))
        assert len(intel.find_by_category(TechCategory.WEB_SERVER)) == 2
        assert len(intel.find_by_category(TechCategory.FRONTEND)) == 1

    def test_get_frontend_technologies(self) -> None:
        intel = TechnologyIntelligence()
        intel.add(Technology(name="React", category=TechCategory.FRONTEND))
        intel.add(Technology(name="Django", category=TechCategory.BACKEND))
        intel.add(Technology(name="Express", category=TechCategory.FRAMEWORK))
        assert len(intel.get_frontend_technologies()) == 2

    def test_get_backend_technologies(self) -> None:
        intel = TechnologyIntelligence()
        intel.add(Technology(name="Django", category=TechCategory.BACKEND))
        intel.add(Technology(name="Gunicorn", category=TechCategory.APPLICATION_SERVER))
        intel.add(Technology(name="React", category=TechCategory.FRONTEND))
        assert len(intel.get_backend_technologies()) == 2

    def test_get_categories_summary(self) -> None:
        intel = TechnologyIntelligence()
        intel.add(Technology(name="nginx", category=TechCategory.WEB_SERVER))
        intel.add(Technology(name="apache", category=TechCategory.WEB_SERVER))
        summary = intel.get_categories_summary()
        assert "web_server" in summary
        assert len(summary["web_server"]) == 2

    def test_clear(self) -> None:
        intel = TechnologyIntelligence()
        intel.add(Technology(name="nginx", category=TechCategory.WEB_SERVER))
        intel.clear()
        assert intel.count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Endpoint Inventory
# ═══════════════════════════════════════════════════════════════════════════════


class TestEndpointInventory:
    def test_add_and_get(self) -> None:
        inv = EndpointInventory()
        ep = Endpoint(path="/api/users", method=HttpMethod.GET)
        inv.add(ep)
        assert inv.get(ep.id) is ep

    def test_find_by_path(self) -> None:
        inv = EndpointInventory()
        inv.add(Endpoint(path="/api/users", method=HttpMethod.GET))
        inv.add(Endpoint(path="/api/users", method=HttpMethod.POST))
        assert len(inv.find_by_path("/api/users")) == 2

    def test_find_by_method(self) -> None:
        inv = EndpointInventory()
        inv.add(Endpoint(path="/api/users", method=HttpMethod.GET))
        inv.add(Endpoint(path="/api/users", method=HttpMethod.POST))
        inv.add(Endpoint(path="/api/items", method=HttpMethod.GET))
        assert len(inv.find_by_method(HttpMethod.GET)) == 2
        assert len(inv.find_by_method(HttpMethod.POST)) == 1

    def test_find_by_application(self) -> None:
        inv = EndpointInventory()
        inv.add(Endpoint(path="/api/a", method=HttpMethod.GET, application_id="app1"))
        inv.add(Endpoint(path="/api/b", method=HttpMethod.GET, application_id="app1"))
        assert len(inv.find_by_application("app1")) == 2

    def test_find_by_host(self) -> None:
        inv = EndpointInventory()
        inv.add(Endpoint(path="/api/a", method=HttpMethod.GET, host_id="host1"))
        inv.add(Endpoint(path="/api/b", method=HttpMethod.GET, host_id="host1"))
        inv.add(Endpoint(path="/api/c", method=HttpMethod.GET, host_id="host2"))
        assert len(inv.find_by_host("host1")) == 2
        assert len(inv.find_by_host("host2")) == 1

    def test_find_by_category(self) -> None:
        inv = EndpointInventory()
        inv.add(Endpoint(path="/api/users", method=HttpMethod.GET, category=EndpointCategory.API))
        inv.add(Endpoint(path="/admin", method=HttpMethod.GET, category=EndpointCategory.ADMIN))
        assert len(inv.find_by_category(EndpointCategory.API)) == 1
        assert len(inv.find_by_category(EndpointCategory.ADMIN)) == 1

    def test_add_parameter(self) -> None:
        inv = EndpointInventory()
        ep = Endpoint(path="/api/users", method=HttpMethod.GET)
        inv.add(ep)
        p = Parameter(name="id", location=ParamLocation.PATH)
        inv.add_parameter(ep.id, p)
        assert len(inv.get_parameters(ep.id)) == 1
        assert p.endpoint_id == ep.id

    def test_add_parameter_nonexistent_endpoint(self) -> None:
        inv = EndpointInventory()
        with pytest.raises(ValueError, match="not found"):
            inv.add_parameter("nonexistent", Parameter(name="id"))

    def test_find_parameters_by_name(self) -> None:
        inv = EndpointInventory()
        ep1 = Endpoint(path="/a", method=HttpMethod.GET)
        ep2 = Endpoint(path="/b", method=HttpMethod.GET)
        inv.add(ep1)
        inv.add(ep2)
        inv.add_parameter(ep1.id, Parameter(name="page"))
        inv.add_parameter(ep2.id, Parameter(name="page"))
        assert len(inv.find_parameters_by_name("page")) == 2

    def test_clear(self) -> None:
        inv = EndpointInventory()
        inv.add(Endpoint(path="/api", method=HttpMethod.GET))
        inv.clear()
        assert inv.count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Auth Intelligence
# ═══════════════════════════════════════════════════════════════════════════════


class TestAuthIntelligence:
    def test_add_mechanism(self) -> None:
        intel = AuthIntelligence()
        m = AuthMechanism(auth_type=AuthType.JWT, url="https://example.com/auth")
        intel.add_mechanism(m)
        assert intel.get_mechanism(m.id) is m
        assert intel.mechanism_count == 1

    def test_find_by_type(self) -> None:
        intel = AuthIntelligence()
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.JWT, url="https://a.com/jwt"))
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.OAUTH2, url="https://a.com/oauth"))
        assert len(intel.find_by_type(AuthType.JWT)) == 1
        assert len(intel.find_by_type(AuthType.OAUTH2)) == 1

    def test_find_by_host(self) -> None:
        intel = AuthIntelligence()
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.JWT, url="/auth", host_id="host1"))
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.OAUTH2, url="/oauth", host_id="host1"))
        assert len(intel.find_by_host("host1")) == 2

    def test_add_observation(self) -> None:
        intel = AuthIntelligence()
        ao = AuthObservation(description="Observed JWT in Authorization header")
        intel.add_observation(ao)
        assert intel.observation_count == 1

    def test_get_auth_types_summary(self) -> None:
        intel = AuthIntelligence()
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.JWT, url="/a"))
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.JWT, url="/b"))
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.OAUTH2, url="/c"))
        summary = intel.get_auth_types_summary()
        assert summary[AuthType.JWT] == 2
        assert summary[AuthType.OAUTH2] == 1

    def test_clear(self) -> None:
        intel = AuthIntelligence()
        intel.add_mechanism(AuthMechanism(auth_type=AuthType.JWT, url="/auth"))
        intel.clear()
        assert intel.mechanism_count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Application Inventory
# ═══════════════════════════════════════════════════════════════════════════════


class TestApplicationInventory:
    def test_add_application(self) -> None:
        inv = ApplicationInventory()
        app = Application(name="Main API", app_type=ApplicationType.API)
        inv.add_application(app)
        assert inv.get_application(app.id) is app
        assert inv.application_count == 1

    def test_find_by_host(self) -> None:
        inv = ApplicationInventory()
        inv.add_application(Application(name="A", host_id="h1"))
        inv.add_application(Application(name="B", host_id="h1"))
        inv.add_application(Application(name="C", host_id="h2"))
        assert len(inv.find_by_host("h1")) == 2
        assert len(inv.find_by_host("h2")) == 1

    def test_add_api_endpoint(self) -> None:
        inv = ApplicationInventory()
        api = APIEndpoint(path="/api/users", method=HttpMethod.GET)
        inv.add_api_endpoint(api)
        assert inv.get_api_endpoint(api.id) is api
        assert inv.api_count == 1

    def test_find_api_by_application(self) -> None:
        inv = ApplicationInventory()
        inv.add_api_endpoint(APIEndpoint(path="/a", method=HttpMethod.GET, application_id="app1"))
        inv.add_api_endpoint(APIEndpoint(path="/b", method=HttpMethod.GET, application_id="app1"))
        assert len(inv.find_api_by_application("app1")) == 2

    def test_find_api_by_path(self) -> None:
        inv = ApplicationInventory()
        inv.add_api_endpoint(APIEndpoint(path="/api/users", method=HttpMethod.GET))
        inv.add_api_endpoint(APIEndpoint(path="/api/users", method=HttpMethod.POST))
        assert len(inv.find_api_by_path("/api/users")) == 2

    def test_clear(self) -> None:
        inv = ApplicationInventory()
        inv.add_application(Application(name="A"))
        inv.add_api_endpoint(APIEndpoint(path="/a", method=HttpMethod.GET))
        inv.clear()
        assert inv.application_count == 0
        assert inv.api_count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Cloud Intelligence
# ═══════════════════════════════════════════════════════════════════════════════


class TestCloudIntelligence:
    def test_add_and_get(self) -> None:
        intel = CloudIntelligence()
        r = CloudResource(provider="aws", resource_type=CloudResourceType.BUCKET, name="my-bucket")
        intel.add(r)
        assert intel.get(r.id) is r
        assert intel.count == 1

    def test_find_by_provider(self) -> None:
        intel = CloudIntelligence()
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.BUCKET, name="a"))
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.FUNCTION, name="b"))
        intel.add(CloudResource(provider="gcp", resource_type=CloudResourceType.BUCKET, name="c"))
        assert len(intel.find_by_provider("aws")) == 2
        assert len(intel.find_by_provider("gcp")) == 1

    def test_find_by_type(self) -> None:
        intel = CloudIntelligence()
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.BUCKET, name="a"))
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.COMPUTE, name="b"))
        assert len(intel.find_by_type(CloudResourceType.BUCKET)) == 1
        assert len(intel.find_by_type(CloudResourceType.COMPUTE)) == 1

    def test_get_providers_summary(self) -> None:
        intel = CloudIntelligence()
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.BUCKET, name="a"))
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.FUNCTION, name="b"))
        intel.add(CloudResource(provider="gcp", resource_type=CloudResourceType.BUCKET, name="c"))
        summary = intel.get_providers_summary()
        assert summary["aws"] == 2
        assert summary["gcp"] == 1

    def test_clear(self) -> None:
        intel = CloudIntelligence()
        intel.add(CloudResource(provider="aws", resource_type=CloudResourceType.BUCKET, name="a"))
        intel.clear()
        assert intel.count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Attack Surface Graph
# ═══════════════════════════════════════════════════════════════════════════════


class TestAttackSurfaceGraph:
    def test_add_node(self) -> None:
        g = AttackSurfaceGraph()
        n = GraphNode(node_type=GraphNodeType.HOST, ref_id="host-abc", label="web")
        g.add_node(n)
        assert g.get_node(n.id) is n
        assert g.node_count == 1

    def test_add_duplicate_node(self) -> None:
        g = AttackSurfaceGraph()
        existing = GraphNode(node_type=GraphNodeType.HOST, ref_id="h1", id="gn-dup")
        g.add_node(existing)
        duplicate = GraphNode(node_type=GraphNodeType.HOST, ref_id="h2", id="gn-dup")
        with pytest.raises(ValueError, match="already exists"):
            g.add_node(duplicate)

    def test_find_node_by_ref(self) -> None:
        g = AttackSurfaceGraph()
        n = GraphNode(node_type=GraphNodeType.HOST, ref_id="host-abc")
        g.add_node(n)
        assert g.find_node_by_ref("host-abc") is n
        assert g.find_node_by_ref("nonexistent") is None

    def test_find_nodes_by_type(self) -> None:
        g = AttackSurfaceGraph()
        g.add_node(GraphNode(node_type=GraphNodeType.HOST, ref_id="h1"))
        g.add_node(GraphNode(node_type=GraphNodeType.HOST, ref_id="h2"))
        g.add_node(GraphNode(node_type=GraphNodeType.ENDPOINT, ref_id="e1"))
        assert len(g.find_nodes_by_type(GraphNodeType.HOST)) == 2
        assert len(g.find_nodes_by_type(GraphNodeType.ENDPOINT)) == 1

    def test_add_edge(self) -> None:
        g = AttackSurfaceGraph()
        n1 = GraphNode(node_type=GraphNodeType.HOST, ref_id="h1")
        n2 = GraphNode(node_type=GraphNodeType.ENDPOINT, ref_id="e1")
        g.add_node(n1)
        g.add_node(n2)
        e = GraphEdge(source_id=n1.id, target_id=n2.id, edge_type=GraphEdgeType.HAS_ENDPOINT)
        g.add_edge(e)
        assert g.edge_count == 1
        assert len(g.get_outgoing(n1.id)) == 1
        assert len(g.get_incoming(n2.id)) == 1

    def test_add_edge_missing_source(self) -> None:
        g = AttackSurfaceGraph()
        n = GraphNode(node_type=GraphNodeType.HOST, ref_id="h1")
        g.add_node(n)
        with pytest.raises(ValueError, match="not found"):
            g.add_edge(GraphEdge(source_id="nonexistent", target_id=n.id, edge_type=GraphEdgeType.HOSTS))

    def test_get_neighbors(self) -> None:
        g = AttackSurfaceGraph()
        n1 = g.ensure_node("h1", GraphNodeType.HOST)
        n2 = g.ensure_node("e1", GraphNodeType.ENDPOINT)
        g.link("h1", "e1", GraphEdgeType.HAS_ENDPOINT)
        neighbors = g.get_neighbors(n1.id)
        assert len(neighbors) == 1
        assert neighbors[0].id == n2.id

    def test_link_by_ref(self) -> None:
        g = AttackSurfaceGraph()
        g.ensure_node("h1", GraphNodeType.HOST, "host1")
        g.ensure_node("e1", GraphNodeType.ENDPOINT, "ep1")
        edge = g.link("h1", "e1", GraphEdgeType.HAS_ENDPOINT)
        assert edge is not None
        assert edge.edge_type == GraphEdgeType.HAS_ENDPOINT
        assert g.edge_count == 1

    def test_link_missing_ref(self) -> None:
        g = AttackSurfaceGraph()
        g.ensure_node("h1", GraphNodeType.HOST)
        edge = g.link("h1", "nonexistent", GraphEdgeType.HOSTS)
        assert edge is None

    def test_ensure_node_existing(self) -> None:
        g = AttackSurfaceGraph()
        n1 = g.ensure_node("h1", GraphNodeType.HOST)
        n2 = g.ensure_node("h1", GraphNodeType.HOST)
        assert n1.id == n2.id
        assert g.node_count == 1

    def test_find_path(self) -> None:
        g = AttackSurfaceGraph()
        g.ensure_node("h1", GraphNodeType.HOST)
        g.ensure_node("e1", GraphNodeType.ENDPOINT)
        g.ensure_node("p1", GraphNodeType.PARAMETER)
        g.link("h1", "e1", GraphEdgeType.HAS_ENDPOINT)
        g.link("e1", "p1", GraphEdgeType.HAS_PARAMETER)
        h_node = g.find_node_by_ref("h1")
        p_node = g.find_node_by_ref("p1")
        assert h_node and p_node
        paths = g.find_path(h_node.id, p_node.id)
        assert len(paths) == 1

    def test_remove_node(self) -> None:
        g = AttackSurfaceGraph()
        n1 = g.ensure_node("h1", GraphNodeType.HOST)
        g.ensure_node("e1", GraphNodeType.ENDPOINT)
        g.link("h1", "e1", GraphEdgeType.HAS_ENDPOINT)
        assert g.remove_node(n1.id) is True
        assert g.node_count == 1
        assert g.edge_count == 0

    def test_clear(self) -> None:
        g = AttackSurfaceGraph()
        g.ensure_node("h1", GraphNodeType.HOST)
        g.clear()
        assert g.node_count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Store
# ═══════════════════════════════════════════════════════════════════════════════


class TestSQLiteReconStore:
    @pytest.fixture
    def store(self, tmp_path: Any) -> SQLiteReconStore:
        return SQLiteReconStore(str(tmp_path / "recon.db"))

    def test_save_and_load_state(self, store: SQLiteReconStore) -> None:
        state = ReconState(target="example.com")
        state.hosts.append(Host(hostname="www.example.com", ip="1.2.3.4"))
        store.save_state(state)
        loaded = store.load_state(state.id)
        assert loaded is not None
        assert loaded.target == "example.com"
        assert len(loaded.hosts) == 1

    def test_load_nonexistent(self, store: SQLiteReconStore) -> None:
        loaded = store.load_state("nonexistent")
        assert loaded is None

    def test_list_states(self, store: SQLiteReconStore) -> None:
        s1 = ReconState(target="a.com")
        s2 = ReconState(target="b.com")
        store.save_state(s1)
        store.save_state(s2)
        states = store.list_states()
        assert len(states) == 2

    def test_delete_state(self, store: SQLiteReconStore) -> None:
        state = ReconState(target="example.com")
        store.save_state(state)
        assert store.delete_state(state.id) is True
        assert store.load_state(state.id) is None

    def test_delete_nonexistent(self, store: SQLiteReconStore) -> None:
        assert store.delete_state("nonexistent") is False

    def test_clear(self, store: SQLiteReconStore) -> None:
        store.save_state(ReconState(target="a.com"))
        store.clear()
        assert len(store.list_states()) == 0

    def test_close(self, store: SQLiteReconStore) -> None:
        store.close()
        # Should not crash on double close
        store.close()


# ═══════════════════════════════════════════════════════════════════════════════
# Timeline
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconTimeline:
    def test_add_entry(self) -> None:
        tl = ReconTimeline()
        tl.add_entry(TimelineEntry(session_id="s1", event_type="host_discovered"))
        assert tl.count == 1

    def test_list_by_event_type(self) -> None:
        tl = ReconTimeline()
        tl.add_entry(TimelineEntry(session_id="s1", event_type="host_discovered"))
        tl.add_entry(TimelineEntry(session_id="s1", event_type="endpoint_added"))
        tl.add_entry(TimelineEntry(session_id="s1", event_type="host_discovered"))
        assert len(tl.list_by_event_type("host_discovered")) == 2
        assert len(tl.list_by_event_type("endpoint_added")) == 1

    def test_auto_subscribe_via_event_bus(self) -> None:
        bus = ReconEventBus()
        tl = ReconTimeline(session_id="s1", event_bus=bus)
        bus.emit(ScopeLoadedEvent(description="scope loaded"))
        bus.emit(HostDiscoveredEvent(hostname="test.com", ip="1.2.3.4", port=443))
        assert len(tl.list_by_event_type("scope_loaded")) == 1
        assert len(tl.list_by_event_type("host_discovered")) == 1

    def test_auto_subscribe_asset(self) -> None:
        bus = ReconEventBus()
        tl = ReconTimeline(session_id="s1", event_bus=bus)
        bus.emit(AssetCreatedEvent(identifier="test.com", asset_type="domain"))
        assert len(tl.list_by_event_type("asset_created")) == 1

    def test_index_access(self) -> None:
        tl = ReconTimeline()
        tl.add_entry(TimelineEntry(session_id="s1", event_type="first"))
        tl.add_entry(TimelineEntry(session_id="s1", event_type="second"))
        assert tl[0].event_type == "first"
        assert tl[1].event_type == "second"

    def test_clear(self) -> None:
        tl = ReconTimeline()
        tl.add_entry(TimelineEntry(session_id="s1", event_type="test"))
        tl.clear()
        assert tl.count == 0


# ═══════════════════════════════════════════════════════════════════════════════
# Pipeline
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconPipeline:
    @pytest.fixture
    def bus(self) -> ReconEventBus:
        return ReconEventBus()

    @pytest.fixture
    def managers(self, bus: ReconEventBus) -> dict[str, Any]:
        from deephunter.recon.application import ApplicationInventory
        return {
            "scope_mgr": ScopeManager(event_bus=bus),
            "assets": AssetInventory(event_bus=bus),
            "hosts": HostRegistry(event_bus=bus),
            "http_intel": HTTPIntelligence(event_bus=bus),
            "tech_intel": TechnologyIntelligence(event_bus=bus),
            "endpoints": EndpointInventory(event_bus=bus),
            "auth_intel": AuthIntelligence(event_bus=bus),
            "app_inv": ApplicationInventory(event_bus=bus),
            "cloud_intel": CloudIntelligence(event_bus=bus),
            "graph": AttackSurfaceGraph(event_bus=bus),
        }

    def test_pipeline_empty_data(self, managers: dict[str, Any], bus: ReconEventBus) -> None:
        pipeline = ReconPipeline()
        report = pipeline.run(
            data={},
            **managers,
            event_bus=bus,
        )
        assert isinstance(report, PipelineReport)
        assert report.total_seconds >= 0

    def test_pipeline_with_data(self, managers: dict[str, Any], bus: ReconEventBus) -> None:
        pipeline = ReconPipeline()
        data = {
            "scopes": [{"target": "example.com", "scope_type": "exact"}],
            "assets": [{"identifier": "example.com", "asset_type": "domain"}],
            "hosts": [{"hostname": "www.example.com", "ip": "1.2.3.4", "port": 443}],
            "technologies": [{"name": "nginx", "category": "web_server"}],
            "endpoints": [{"path": "/api/users", "method": "GET"}],
            "auth_mechanisms": [{"auth_type": "jwt", "url": "/auth/token"}],
            "cloud_resources": [{"provider": "aws", "resource_type": "bucket", "name": "my-bucket"}],
        }
        report = pipeline.run(data=data, **managers, event_bus=bus)
        assert report.entities_added > 0
        assert managers["scope_mgr"].scope_count > 0
        assert managers["assets"].count > 0
        assert managers["hosts"].count > 0
        assert managers["tech_intel"].count > 0
        assert managers["endpoints"].count > 0
        assert managers["auth_intel"].mechanism_count > 0
        assert managers["cloud_intel"].count > 0
        assert managers["graph"].node_count > 0


# ═══════════════════════════════════════════════════════════════════════════════
# Session
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconSession:
    def test_create_session(self) -> None:
        session = ReconSession(target="example.com")
        assert session.target == "example.com"
        assert session.id.startswith("rec-")

    def test_process_data(self) -> None:
        session = ReconSession(target="example.com")
        data = {
            "scopes": [{"target": "*.example.com", "scope_type": "wildcard"}],
            "hosts": [{"hostname": "www.example.com", "ip": "1.2.3.4", "port": 443}],
        }
        report = session.process(data)
        assert report.entities_added > 0
        assert session.last_report is report

    def test_summary(self) -> None:
        session = ReconSession(target="example.com")
        summary = session.summary()
        assert summary["target"] == "example.com"
        assert summary["session_id"] == session.id

    def test_summary_after_processing(self) -> None:
        session = ReconSession(target="example.com")
        session.process({
            "scopes": [{"target": "test.com", "scope_type": "exact"}],
        })
        summary = session.summary()
        assert summary["scopes"] == 1

    def test_save_no_store(self) -> None:
        session = ReconSession(target="example.com")
        with pytest.raises(ValueError, match="No store configured"):
            session.save()

    def test_save_with_store(self, tmp_path: Any) -> None:
        store = SQLiteReconStore(str(tmp_path / "recon.db"))
        session = ReconSession(target="example.com", store=store)
        session.process({
            "hosts": [{"hostname": "www.example.com", "ip": "1.2.3.4"}],
        })
        session.save()
        loaded = store.load_state(session.id)
        assert loaded is not None
        assert len(loaded.hosts) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Plugin Architecture
# ═══════════════════════════════════════════════════════════════════════════════


class TestPluginArchitecture:
    def test_plugin_registry(self) -> None:
        class TestPlugin(ReconPlugin):
            name = "test_plugin"
            description = "Test plugin"

            def process(self, raw_data: Any) -> PluginResult:
                return PluginResult(success=True)

        registry = PluginRegistry()
        plugin = TestPlugin()
        registry.register(plugin)
        assert registry.get("test_plugin") is plugin
        assert "test_plugin" in registry.list_names()

    def test_plugin_duplicate(self) -> None:
        registry = PluginRegistry()

        class P1(ReconPlugin):
            name = "dup"
            def process(self, raw_data: Any) -> PluginResult:
                return PluginResult()

        registry.register(P1())
        with pytest.raises(ValueError, match="already registered"):
            registry.register(P1())

    def test_plugin_process(self) -> None:
        class TestPlugin(ReconPlugin):
            name = "test"
            def process(self, raw_data: Any) -> PluginResult:
                return PluginResult(
                    success=True,
                    hosts=[Host(hostname="test.com", ip="1.2.3.4")],
                )

        plugin = TestPlugin()
        result = plugin.process({"data": "test"})
        assert result.success is True
        assert len(result.hosts) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Reporter (SKO integration)
# ═══════════════════════════════════════════════════════════════════════════════


class TestReporter:
    def test_host_to_sko(self) -> None:
        host = Host(hostname="www.example.com", ip="1.2.3.4", port=443)
        sko = host_to_sko(host)
        assert "www.example.com" in sko.title
        assert "recon.internal" in sko.source
        assert sko.source.endswith(host.id)

    def test_endpoint_to_sko(self) -> None:
        ep = Endpoint(path="/api/v1/users", method=HttpMethod.GET)
        sko = endpoint_to_sko(ep)
        assert "/api/v1/users" in sko.title
        assert sko.interesting_endpoints == ["/api/v1/users"]

    def test_technology_to_sko(self) -> None:
        tech = Technology(name="nginx", category=TechCategory.WEB_SERVER)
        sko = technology_to_sko(tech)
        assert "nginx" in sko.title
        assert sko.confidence.value == "medium"

    def test_technology_to_sko_low_confidence(self) -> None:
        tech = Technology(name="unknown", category=TechCategory.UNKNOWN, confidence=0.3)
        sko = technology_to_sko(tech)
        assert sko.confidence.value == "low"

    def test_observations_to_sko_report(self) -> None:
        hosts = [Host(hostname="www.example.com", ip="1.2.3.4")]
        endpoints = [Endpoint(path="/api/login", method=HttpMethod.POST)]
        technologies = [Technology(name="React", category=TechCategory.FRONTEND)]
        sko = observations_to_sko_report(hosts, endpoints, technologies)
        assert "Reconnaissance" in sko.title
        assert len(sko.attack_surface) == 1
        assert len(sko.interesting_endpoints) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Config
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconConfig:
    def test_default_values(self) -> None:
        config = ReconConfig()
        assert config.enabled is True
        assert config.store_backend == "sqlite"
        assert config.graph_max_nodes == 1_000_000
        assert config.enable_event_bus is True

    def test_can_be_nested_in_deephunter_config(self) -> None:
        cfg = DeepHunterConfig.default()
        assert cfg.recon.enabled is True
        assert cfg.recon.store_backend == "sqlite"


# ═══════════════════════════════════════════════════════════════════════════════
# Exceptions
# ═══════════════════════════════════════════════════════════════════════════════


class TestReconException:
    def test_recon_error_is_deephunter_error(self) -> None:
        from deephunter.core.exceptions import DeepHunterError
        err = ReconError("test")
        assert isinstance(err, DeepHunterError)

    def test_recon_error_message(self) -> None:
        err = ReconError("Recon operation failed")
        assert str(err) == "Recon operation failed"


# ═══════════════════════════════════════════════════════════════════════════════
# Edge cases & validation
# ═══════════════════════════════════════════════════════════════════════════════


class TestEdgeCases:
    def test_host_with_minimal_fields(self) -> None:
        h = Host()
        assert h.hostname == ""
        assert h.ip == ""
        assert h.port == 443
        assert h.protocol == Protocol.HTTPS
        assert h.status == HostStatus.UNKNOWN

    def test_scope_defaults(self) -> None:
        s = Scope(target="test.com")
        assert s.scope_type == "domain"
        assert s.in_scope is True

    def test_endpoint_defaults(self) -> None:
        ep = Endpoint(path="/test")
        assert ep.method == HttpMethod.GET
        assert ep.category == EndpointCategory.UNKNOWN
        assert ep.auth_type == AuthType.UNKNOWN

    def test_graph_node_defaults(self) -> None:
        n = GraphNode(node_type=GraphNodeType.OBSERVATION, ref_id="obs-1")
        assert n.label == ""

    def test_recon_state_defaults(self) -> None:
        state = ReconState()
        assert state.target == ""
        assert len(state.hosts) == 0
        assert len(state.endpoints) == 0
        assert len(state.timeline) == 0

    def test_asset_with_tags(self) -> None:
        a = Asset(identifier="test.com", tags=["juicy", "critical"])
        assert "critical" in a.tags

    def test_technology_with_cpe(self) -> None:
        t = Technology(name="Apache", category=TechCategory.WEB_SERVER, version="2.4.51", cpe="cpe:2.3:a:apache:http_server:2.4.51")
        assert t.cpe.startswith("cpe:")

    def test_application_host_link(self) -> None:
        h = Host(hostname="app.example.com", ip="10.0.0.1")
        app = Application(host_id=h.id, name="MyApp", base_path="/")
        assert app.host_id == h.id
