"""Regex patterns for JavaScript static analysis.

Organized by observation category. Each pattern captures a specific class
of intelligence from JavaScript source code.

Patterns are compiled once at module load time for performance.
"""

from __future__ import annotations

import re

# ════════════════════════════════════════════════════════════════════════
# Module imports
# ════════════════════════════════════════════════════════════════════════

ESM_IMPORT = re.compile(
    r"""import\s+(?:
        (?P<default>\w+(?:\s*,\s*\{[^}]*\})?)\s+from\s+|
        \{[^}]*\}\s+from\s+|
        \*\s+as\s+\w+\s+from\s+
    )['"](?P<path>[^'"]+)['"]""",
    re.VERBOSE,
)

DYNAMIC_IMPORT = re.compile(
    r"""import\(['"](?P<path>[^'"]+)['"]\)""",
)

REQUIRE = re.compile(
    r"""(?:const|let|var)\s+\w+\s*=\s*require\(['"](?P<path>[^'"]+)['"]\)""",
)

DEFINE_REQUIRE = re.compile(
    r"""define\(\[(?P<deps>(?:['"][^'"]+['"],?\s*)*)\]""",
)

# ════════════════════════════════════════════════════════════════════════
# API endpoints — HTTP client calls
# ════════════════════════════════════════════════════════════════════════

FETCH_CALL = re.compile(
    r"""fetch\(['"](?P<url>[^'"]+)['"](?:\s*,\s*\{[^}]*\})?""",
)

AXIOS_CALL = re.compile(
    r"""(?:axios|\.)\s*\.\s*(?P<method>get|post|put|patch|delete|head|options|request)\(['"](?P<url>[^'"]+)['"]""",
    re.IGNORECASE,
)

JQUERY_AJAX = re.compile(
    r"""\$\s*\.\s*(?:ajax|get|post|put|delete)\((?:\s*['"](?P<url>[^'"]+)['"]|\s*\{[^}]*url\s*:\s*['"](?P<url2>[^'"]+)['"])""",
)

XHR_OPEN = re.compile(
    r"""\.open\(['"](?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]\s*,\s*['"](?P<url>[^'"]+)['"]""",
)

SUPERAGENT = re.compile(
    r"""\.(?:get|post|put|patch|del|delete|head|options)\(['"](?P<url>[^'"]+)['"]""",
)

GOT_FETCH = re.compile(
    r"""got\(['"](?P<url>[^'"]+)['"]""",
)

KY_FETCH = re.compile(
    r"""ky\.(?P<method>get|post|put|patch|delete|head)\(['"](?P<url>[^'"]+)['"]""",
    re.IGNORECASE,
)

# ════════════════════════════════════════════════════════════════════════
# GraphQL
# ════════════════════════════════════════════════════════════════════════

GRAPHQL_ENDPOINT = re.compile(
    r"""['"](?P<url>[^'"]*(?:graphql|gql|graphiql)[^'"]*)['"]""",
    re.IGNORECASE,
)

GRAPHQL_OPERATION = re.compile(
    r"""(?:query|mutation|subscription)\s+(?P<name>\w+)\s*(?:\([^)]*\))?\s*\{""",
)

GQL_TAG = re.compile(
    r"""gql`[^`]*`""",
)

# ════════════════════════════════════════════════════════════════════════
# Client-side routing
# ════════════════════════════════════════════════════════════════════════

REACT_ROUTER_PATH = re.compile(
    r"""(?:path|to)\s*:\s*['"](?P<path>[^'"]+)['"]""",
)

REACT_ROUTER_COMPONENT = re.compile(
    r"""component\s*:\s*(?P<component>\w+)""",
)

VUE_ROUTER_PATH = re.compile(
    r"""\{\s*path\s*:\s*['"](?P<path>[^'"]+)['"]""",
)

LAZY_LOAD = re.compile(
    r"""(?:lazy\s*\(\s*\)\s*=>\s*import|React\.lazy\s*\(\s*\)\s*=>\s*import)\(['"](?P<path>[^'"]+)['"]""",
    re.DOTALL,
)

# ════════════════════════════════════════════════════════════════════════
# Authentication observations
# ════════════════════════════════════════════════════════════════════════

SESSION_STORAGE = re.compile(
    r"""sessionStorage\.(?:getItem|setItem|removeItem)\(['"](?P<key>[^'"]+)['"]""",
)

LOCAL_STORAGE = re.compile(
    r"""localStorage\.(?:getItem|setItem|removeItem)\(['"](?P<key>[^'"]+)['"]""",
)

COOKIE_ACCESS = re.compile(
    r"""document\.cookie\s*(?::?=)?\s*['"]?(?P<value>[^;'"]*)""",
)

JWT_PATTERN = re.compile(
    r"""(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})""",
)

JWT_REFERENCE = re.compile(
    r"""['"](?:access_token|refresh_token|id_token|token|jwt)['"]\s*:\s*['"](?P<value>[^'"]+)['"]""",
    re.IGNORECASE,
)

AUTH_HEADER = re.compile(
    r"""['"](?:Authorization|Bearer|X-API-Key|X-Auth-Token)['"]""",
)

CSRF_TOKEN = re.compile(
    r"""['"]csrf_token['"]|['"]X-CSRF-Token['"]|['"]csrfmiddlewaretoken['"]""",
    re.IGNORECASE,
)

OAUTH_PATTERN = re.compile(
    r"""(?:oauth|oauth2|oidc|openid)\s*(?::|=)\s*['"](?P<value>[^'"]+)['"]""",
    re.IGNORECASE,
)

# ════════════════════════════════════════════════════════════════════════
# Configuration & feature flags
# ════════════════════════════════════════════════════════════════════════

CONFIG_VALUE = re.compile(
    r"""(?P<key>(?:REACT_APP_|VUE_APP_|NEXT_PUBLIC_|GATSBY_|SANITY_STUDIO_|CDN_|API_|APP_|FEATURE_|VITE_)[A-Z_]+)\s*:\s*['"](?P<value>[^'"]*)['"]""",
)

FEATURE_FLAG = re.compile(
    r"""['"]?(?:featureFlag|feature_flag|isEnabled|isActive|enabled)['"]?\s*:\s*(?:true|false)""",
    re.IGNORECASE,
)

ENVIRONMENT_CHECK = re.compile(
    r"""process\.env\.(?:NODE_ENV|REACT_APP_\w+|VUE_APP_\w+|NEXT_PUBLIC_\w+)|import\.meta\.env\.\w+""",
)

# ════════════════════════════════════════════════════════════════════════
# Framework detection
# ════════════════════════════════════════════════════════════════════════

FRAMEWORK_PATTERNS: list[tuple[str, str, float]] = [
    # (framework_name, regex_pattern, confidence)
    ("React", r"""React(\.|["'])|react-dom|create-react-app|useState|useEffect""", 0.8),
    ("Next.js", r"""next[/\\]|next\.config|getStaticProps|getServerSideProps""", 0.9),
    ("Vue", r"""Vue\.|vue-router|createApp|defineComponent|v-model|['"]vue['"]""", 0.8),
    ("Nuxt", r"""nuxt\.config|useAsyncData|nuxt-link|@nuxt/""", 0.9),
    ("Angular", r"""@angular|ngModule|Component|ngFor|ngIf|router-outlet""", 0.8),
    ("Svelte", r"""svelte[/\\]|SvelteComponent|on:click|bind:value""", 0.7),
    ("Astro", r"""astro[/\\]|---\s*\n\s*Astro\.(?:props|request|generator)""", 0.7),
    ("Remix", r"""@remix-run|remix\.config|useLoaderData|useActionData""", 0.9),
    ("jQuery", r"""jQuery|jquery|\.ready\(|\$\(['"#]""", 0.7),
    ("Express", r"""express\(\)|express\.Router""", 0.8),
    ("Axios", r"""axios\.(?:get|post|put|patch|delete|create)""", 0.9),
    ("Lodash", r"""lodash|_\.[a-z]""", 0.6),
    ("Moment", r"""moment\(|moment\.(?:format|fromNow)""", 0.8),
]

# ════════════════════════════════════════════════════════════════════════
# Build tool detection
# ════════════════════════════════════════════════════════════════════════

BUILD_TOOL_PATTERNS: list[tuple[str, str, float]] = [
    ("webpack", r"""webpack[/\\]|__webpack_require__|webpackJsonp""", 0.9),
    ("Vite", r"""vite[/\\]|__vite__|import\.meta\.hot""", 0.9),
    ("Rollup", r"""rollup[/\\]|System\.register|define\(['"][^'"]+['"],\s*\[""", 0.7),
    ("Parcel", r"""parcelRequire|parcel[/\\]""", 0.8),
    ("ESBuild", r"""esbuild[/\\]|__esModule""", 0.6),
]

# ════════════════════════════════════════════════════════════════════════
# Third-party library detection (from import paths or CDN references)
# ════════════════════════════════════════════════════════════════════════

THIRD_PARTY_PATH = re.compile(
    r"""['"](?:https?://[^'"]*/(?:cdn|lib|unpkg|jsdelivr|cdnjs|bundle)[^'"]*)['"]""",
    re.IGNORECASE,
)

# ════════════════════════════════════════════════════════════════════════
# Source map hints
# ════════════════════════════════════════════════════════════════════════

SOURCE_MAP_COMMENT = re.compile(
    r"""//#\s*sourceMappingURL=(?P<url>.+)""",
)

SOURCE_MAP_HEADER = re.compile(
    r"""sourceMappingURL=(?P<url>.+)""",
)

# ════════════════════════════════════════════════════════════════════════
# WebSocket & SSE
# ════════════════════════════════════════════════════════════════════════

WEBSOCKET = re.compile(
    r"""new\s+WebSocket\(['"](?P<url>[^'"]+)['"]""",
)

EVENT_SOURCE = re.compile(
    r"""new\s+EventSource\(['"](?P<url>[^'"]+)['"]""",
)

# ════════════════════════════════════════════════════════════════════════
# Potential secrets (high-entropy or known patterns)
# ════════════════════════════════════════════════════════════════════════

API_KEY_PATTERN = re.compile(
    r"""['"]?(?:api[_-]?key|apikey|secret[_-]?key|api_secret)['"]?\s*[:=]\s*['"](?P<value>[^'"]{8,})['"]""",
    re.IGNORECASE,
)

PASSWORD_PATTERN = re.compile(
    r"""['"]?(?:password|passwd|pwd)['"]?\s*[:=]\s*['"](?P<value>[^'"]+)['"]""",
    re.IGNORECASE,
)

# ════════════════════════════════════════════════════════════════════════
# Minification detection
# ════════════════════════════════════════════════════════════════════════

MINIFIED_HEURISTIC_SHORT_LINES = re.compile(r".{500,}")
MINIFIED_HEURISTIC_MANY_BREAKS = re.compile(r"[;{}]\s*[;\w]")

# ════════════════════════════════════════════════════════════════════════
# Endpoint URL extraction (generic — catches /api/, /v1/, /rest/, etc.)
# ════════════════════════════════════════════════════════════════════════

GENERIC_API_URL = re.compile(
    r"""['"](?P<url>(?:https?://[^'"]*/)?(?:/|\./)?(?:api|rest|v[12]|v\d+\.\d+)[^'"]*)['"]""",
    re.IGNORECASE,
)
