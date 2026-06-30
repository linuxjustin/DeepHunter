# Recon Intelligence Platform v1

Builds structured attack surface intelligence from reconnaissance data
without executing any external tools.

## Architecture

```
External data (subdomain enum, DNS, HTTP probes, etc.)
    │
    ▼
ReconPipeline (stage-based ingestion)
    │
    ├── LoadScopeStage
    ├── ProcessAssetsStage
    ├── ProcessHostsStage
    ├── ProcessTechnologiesStage
    ├── ProcessEndpointsStage
    ├── ProcessAuthStage
    └── ProcessCloudStage
    │
    ▼
┌─────────────────────────────────────────────────────┐
│  ReconSession                                       │
│  ┌──────┬──────┬──────┬──────┬──────┬──────┬──────┐│
│  │Scope │Asset │Host  │Tech  │EP    │Auth  │Cloud ││
│  │Mgr   │Inv   │Reg   │Intel │Inv   │Intel │Intel ││
│  └──────┴──────┴──────┴──────┴──────┴──────┴──────┘│
│  ┌─────────────────────────────────────────────────┐│
│  │  AttackSurfaceGraph (in-memory)                 ││
│  └─────────────────────────────────────────────────┘│
│  ┌──────────────────┐  ┌──────────────────────────┐│
│  │  ReconTimeline    │  │  ReconStore (SQLite)     ││
│  └──────────────────┘  └──────────────────────────┘│
└─────────────────────────────────────────────────────┘
    │
    ▼
SKO Reporter → Knowledge Store → Reasoning Engine / Investigation Planner
```

## Design Principles

- **No external tool execution** — accepts already-collected data
- **Modular ingestion** — plugins isolate data source integrations
- **Typed models** — Pydantic v2 throughout
- **Standard event bus** — matches `PlanningEventBus`, `ReasoningEventBus`
- **Stage-based pipeline** — matches `PlanningPipeline`, `ReasoningPipeline`
- **Interface-based storage** — `ReconStore` ABC, `SQLiteReconStore` impl

## Core Components

| Component | File | Purpose |
|-----------|------|---------|
| `ScopeManager` | `scope.py` | Programs, scopes, containment checks |
| `AssetInventory` | `asset.py` | Discovered assets (domains, subdomains, IPs) |
| `HostRegistry` | `host.py` | Hosts + DNS records |
| `HTTPIntelligence` | `http.py` | HTTP probes, headers, cookies, security headers |
| `TechnologyIntelligence` | `technology.py` | Tech stack per host/app |
| `EndpointInventory` | `endpoint.py` | URL endpoints + parameters |
| `AuthIntelligence` | `auth.py` | Observed auth mechanisms |
| `ApplicationInventory` | `application.py` | Apps, services, API endpoints |
| `CloudIntelligence` | `cloud.py` | Cloud resources across providers |
| `AttackSurfaceGraph` | `graph.py` | In-memory directed graph |
| `ReconTimeline` | `timeline.py` | Event-sourced timeline |
| `ReconSession` | `session.py` | Top-level session |
| `ReconPipeline` | `pipeline.py` | Stage-based processing |
| `ReconStore` | `store.py` | Storage interface + SQLite |
| `PluginRegistry` | `plugin.py` | Plugin architecture |
| `SKO Reporter` | `reporter.py` | Produces SKOs for engine consumption |

## Attack Surface Graph

Built in-memory — not a graph database.  Nodes and edges are typed:

```
Program ──belongs_to──► Scope ──belongs_to──► Asset
                                                 │
                                            resolves_to
                                                 │
                                                 ▼
                                              Host ──has_endpoint──► Endpoint
                                                │                       │
                                            uses                   has_parameter
                                                │                       │
                                                ▼                       ▼
                                          Technology               Parameter
```

Query methods: `find_path()`, `get_neighbors()`, `get_upstream()`, `get_downstream()`.

## Quick Start

```python
from deephunter.recon import ReconSession

session = ReconSession(target="example.com")
data = {
    "scopes": [{"target": "*.example.com", "scope_type": "wildcard"}],
    "assets": [{"identifier": "example.com", "asset_type": "domain"}],
    "hosts": [
        {"hostname": "www.example.com", "ip": "93.184.216.34", "port": 443},
    ],
    "technologies": [
        {"name": "nginx", "category": "web_server", "confidence": 0.95},
    ],
    "endpoints": [
        {"path": "/api/v1/users", "method": "GET"},
        {"path": "/api/v1/login", "method": "POST"},
    ],
    "auth_mechanisms": [
        {"auth_type": "jwt", "url": "/api/v1/auth/token"},
    ],
}
report = session.process(data)
print(session.summary())
# {
#     "scopes": 1, "assets": 1, "hosts": 1,
#     "endpoints": 2, "auth_mechanisms": 1,
#     "graph_nodes": ..., "graph_edges": ...,
# }

# Persist
from deephunter.recon import SQLiteReconStore
store = SQLiteReconStore("recon.db")
session.store = store
session.save()
```

## Security Header Analysis

```python
from deephunter.recon.http import analyze_security_headers
from deephunter.recon.models import HTTPHeader

headers = [HTTPHeader(name="strict-transport-security", value="max-age=31536000")]
result = analyze_security_headers(headers)
for sh in result:
    print(f"{sh.name.value}: present={sh.present} secure={sh.secure}")
```

## Event Bus

```python
from deephunter.recon import ReconEventBus, HostDiscoveredEvent

bus = ReconEventBus()
bus.subscribe(HostDiscoveredEvent, lambda e: print(f"Host: {e.hostname}"))
```

## SKO Integration

```python
from deephunter.recon import host_to_sko, endpoint_to_sko, technology_to_sko

sko = host_to_sko(host)         # → SecurityKnowledgeObject
sko = endpoint_to_sko(endpoint) # → SecurityKnowledgeObject
sko = technology_to_sko(tech)   # → SecurityKnowledgeObject
```

## Plugin Architecture

```python
from deephunter.recon import ReconPlugin, PluginResult, PluginRegistry

class SubdomainPlugin(ReconPlugin):
    name = "subdomain_enum"
    description = "Ingests subdomain enumeration results"

    def process(self, raw_data):
        assets = [Asset(identifier=d, asset_type="subdomain")
                  for d in raw_data.get("subdomains", [])]
        return PluginResult(success=True, assets=assets)

registry = PluginRegistry()
registry.register(SubdomainPlugin())
```

## File Layout

| File | Contents |
|------|----------|
| `models.py` | 40+ Pydantic models, 35+ enums |
| `events.py` | `ReconEventBus` + 15 typed event types |
| `scope.py` | `ScopeManager` — programs & scopes |
| `asset.py` | `AssetInventory` — discovered assets |
| `host.py` | `HostRegistry` — hosts & DNS records |
| `http.py` | `HTTPIntelligence` — HTTP probes & security headers |
| `technology.py` | `TechnologyIntelligence` — tech stack |
| `endpoint.py` | `EndpointInventory` — endpoints & parameters |
| `auth.py` | `AuthIntelligence` — authentication observations |
| `application.py` | `ApplicationInventory` — apps & API endpoints |
| `cloud.py` | `CloudIntelligence` — cloud resources |
| `graph.py` | `AttackSurfaceGraph` — in-memory graph |
| `store.py` | `ReconStore` ABC + `SQLiteReconStore` |
| `session.py` | `ReconSession` — top-level orchestration |
| `timeline.py` | `ReconTimeline` — event log |
| `plugin.py` | `ReconPlugin` ABC + `PluginRegistry` |
| `pipeline.py` | `ReconPipeline` — 7 processing stages |
| `reporter.py` | SKO conversion for engine integration |
