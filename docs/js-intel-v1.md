# JS Intel v1 — JavaScript Intelligence Platform

## Purpose

The JavaScript Intelligence Platform analyzes JavaScript source artifacts that have already been collected and converts them into structured reconnaissance intelligence. It enriches the Attack Surface Graph, produces Security Knowledge Objects, and feeds the Planner and Reasoning Engine.

This subsystem is **completely independent** of any specific crawler or browser. It accepts JavaScript content as text — from file imports, tool output, manual paste, or future integrations.

## Independence

- Does **NOT** crawl websites
- Does **NOT** execute JavaScript
- Does **NOT** bypass security mechanisms
- Does **NOT** fuzz endpoints
- Does **NOT** exploit applications
- Does **NOT** perform network reconnaissance

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    JS Intel Platform                             │
│                                                                  │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────┐ │
│  │ JSParser  │──▶│ JSEngine │──▶│JSGraph   │──▶│AttackSurface │ │
│  │ (regex)   │   │(facade)  │   │Builder   │   │Graph         │ │
│  └──────────┘   └────┬─────┘   └──────────┘   └──────────────┘ │
│                      │                                           │
│                      ▼                                           │
│              ┌──────────────┐   ┌──────────────┐                 │
│              │ JSSKOGenerator│──▶│KnowledgeStore│                 │
│              └──────────────┘   └──────────────┘                 │
│                      │                                           │
│                      ▼                                           │
│              ┌──────────────┐                                    │
│              │ PluginResult │  (for tool/pipeline integration)   │
│              └──────────────┘                                    │
└─────────────────────────────────────────────────────────────────┘
```

## Module Layout

```
src/deephunter/js_intel/
├── __init__.py       # Public API exports
├── models.py         # Data models (12 Pydantic v2 models)
├── patterns.py       # 30+ compiled regex patterns
├── parser.py         # JSParser — regex-based static analysis engine
├── engine.py         # JSAnalysisEngine — top-level orchestrator facade
├── graph.py          # JSGraphBuilder — AttackSurfaceGraph enrichment
├── sko.py            # JSSKOGenerator — SKO generation
└── adapter.py        # JavaScriptIntelAdapter — BaseToolPlugin import adapter
```

## Data Models

| Model | Prefix | Description |
|-------|--------|-------------|
| `JSBundle` | `jsb-` | Bundle metadata (hash, minification, build tool) |
| `JSModule` | `jsm-` | Imported module (ESM, CommonJS, AMD, dynamic) |
| `JSEndpointRef` | `jse-` | API endpoint reference in JS source |
| `JSRoute` | `jsr-` | Client-side route definition |
| `JSAuthObs` | `jsa-` | Authentication observation (JWT, OAuth, CSRF, cookies) |
| `JSTokenStorage` | `jst-` | Token storage mechanism (localStorage, sessionStorage) |
| `JSCookieUsage` | `jsc-` | Cookie usage observation |
| `JSConfigObs` | `jscf-` | Configuration value or feature flag |
| `JSFrameworkObs` | `jsfw-` | Framework detection evidence |
| `JSSecretObs` | `jss-` | Potential secret or credential |
| `JSAnalysisResult` | `jsr-` | Complete analysis result (all observations) |
| `ModuleType` | — | Enum: esm, commonjs, dynamic, amd, systemjs |

## Extraction Coverage

### Module Imports
- ES module imports (`import X from '...'`)
- Dynamic imports (`import('...')`)
- CommonJS require (`require('...')`)
- AMD define (`define(['...'], ...)`)
- Relative vs. third-party path detection

### API Endpoints
- `fetch()` calls
- Axios (`.get()`, `.post()`, etc.)
- jQuery AJAX
- XHR `.open()`
- SuperAgent, Got, Ky HTTP clients
- Generic API URL patterns (`/api/`, `/v1/`, `/rest/`, etc.)
- CDN URL exclusion

### GraphQL
- Endpoint path discovery (`/graphql`, `/gql`, etc.)
- Operation name extraction (query/mutation/subscription)
- `gql` tagged template literals

### Client Routing
- React Router path patterns
- Vue Router path patterns
- Dynamic route detection
- Lazy-loaded module references

### Authentication
- JWT token detection (inline and variable references)
- OAuth/OIDC configuration references
- CSRF token patterns
- Authorization header references
- Session/localStorage access patterns
- Cookie access patterns

### Configuration
- Environment variables (`REACT_APP_*`, `NEXT_PUBLIC_*`, `VUE_APP_*`, `VITE_*`, etc.)
- Feature flags
- Runtime environment checks (`process.env.*`, `import.meta.env.*`)

### Framework Detection
| Framework | Confidence | Evidence patterns |
|-----------|-----------|-------------------|
| React | 0.8 | JSX, react-dom, hooks |
| Next.js | 0.9 | next.config, data fetching |
| Vue | 0.8 | createApp, directives, `'vue'` import |
| Nuxt | 0.9 | nuxt.config, async data |
| Angular | 0.8 | @angular decorators |
| Svelte | 0.7 | Svelte component syntax |
| Astro | 0.7 | Astro.props/generator |
| Remix | 0.9 | @remix-run, loaders |
| jQuery | 0.7 | `$()`, jQuery |
| Express | 0.8 | express(), Router |
| Axios | 0.9 | HTTP methods |
| Lodash | 0.6 | `_` chain |
| Moment | 0.8 | date formatting |

### Build Tools
- webpack (`__webpack_require__`, `webpackJsonp`)
- Vite (`import.meta.hot`, `__vite__`)
- Rollup (`System.register`, `define()`)
- Parcel (`parcelRequire`)
- ESBuild (`__esModule`)

### Other
- WebSocket endpoint discovery (`new WebSocket(...)`)
- Server-Sent Events (`new EventSource(...)`)
- Source map URL detection
- Minification heuristics
- Potential secret detection (API keys, passwords)
- Entropy estimation for secret classification
- Third-party library identification (from CDN URLs or import paths)

## Graph Integration

`JSGraphBuilder.integrate()` adds the following to the AttackSurfaceGraph:

### Node Types
| Node Type | Source | Label |
|-----------|--------|-------|
| `JS_BUNDLE` | Each JS file | URL or "JavaScript Bundle" |
| `JS_MODULE` | Each imported module | Module name |
| `JS_ENDPOINT` | Each API/GQL endpoint | URL |
| `JS_ROUTE` | Each client route | Route path |
| `TECHNOLOGY` | Each detected framework | Framework name |
| `OBSERVATION` | Each auth observation | `auth:<mechanism>` |

### Edge Types
| Edge Type | Source → Target | Label |
|-----------|----------------|-------|
| `HAS_JS_FILE` | Host → Bundle | `serves_js` |
| `CONTAINS` | App/Bundle → Module | `imports_*` |
| `IMPORTS` | Module → Bundle (ext. deps) | `external_dep_*` |
| `DERIVED_FROM` | Bundle → Endpoint | `extracted_from_js` |
| `DEFINES_ROUTE` | Bundle → Route | `client_route` |
| `REFERENCES` | Route → Component | `renders` |
| `USES_TECHNOLOGY` | Bundle → Tech | `uses_*` |

## SKO Generation

`JSSKOGenerator.generate()` produces:
1. **Main SKO** — one per JS file, with title, summary, detected frameworks, module/endpoint counts, tags, and metadata
2. **Secret SKOs** — one per discovered secret, with type, line number, entropy score, and `INFO_DISCLOSURE` bug class

## Plugin Adapter

`JavaScriptIntelAdapter` extends `BaseToolPlugin` following the same pattern as `HTTPxAdapter`, `SubfinderAdapter`, etc.:

- **Category**: `ToolCategory.js_analysis`
- **Formats**: `js`, `txt`
- **Normalize targets**: `JavaScriptFile`, `JavaScriptEndpoint`, `Technology`, `Application` in `PluginResult`
- **Import-only**: raises `NotImplementedError` for `execute()`

## Extension Points

### Adding new patterns
Add patterns to `patterns.py` and register extraction logic in `parser.py`.

### Adding new framework detection
Add a `(name, regex, confidence)` tuple to `FRAMEWORK_PATTERNS` in `patterns.py`.

### Adding new model types
Add Pydantic models to `models.py` and wire them into `JSAnalysisResult`.

### Custom graph relationships
Extend `JSGraphBuilder.integrate()`.

### Custom SKO generation
Extend `JSSKOGenerator.generate()`.

## Future Integrations

All integrations follow the import-only adapter pattern:

| Tool | Integration |
|------|-------------|
| Katana | Pass JS responses to `JavaScriptIntelAdapter` |
| Playwright | Extract page JS, pass to `JSParser` |
| Burp Suite | Extract JS responses from proxy history |
| Manual import | CLI tool accepts file paths |
| Static files | Recursive directory scanner → batch analysis |

## Dependencies

- Python 3.12+
- Pydantic v2 (existing)
- `re` (stdlib)
- `hashlib` (stdlib)
- `math` (stdlib)

No external JavaScript parser or runtime is required.

## File Tree

```
src/deephunter/
├── js_intel/
│   ├── __init__.py
│   ├── models.py          # 12 models, 1 enum
│   ├── patterns.py         # 30+ compiled regex patterns
│   ├── parser.py           # JSParser (single class, 500+ lines)
│   ├── engine.py           # JSAnalysisEngine (facade)
│   ├── graph.py            # JSGraphBuilder
│   ├── sko.py              # JSSKOGenerator
│   └── adapter.py          # JavaScriptIntelAdapter
├── recon/
│   ├── models.py           # Extended GraphNodeType, GraphEdgeType
│   └── ...
tests/unit/
├── test_js_intel_models.py    # 26 tests
├── test_js_intel_parser.py    # 44 tests
├── test_js_intel_engine.py    # 21 tests
├── test_js_intel_graph.py     # 13 tests
├── test_js_intel_adapter.py   # 15 tests
docs/
└── js-intel-v1.md             # This file
```
