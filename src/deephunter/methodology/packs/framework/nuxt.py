"""Nuxt Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch,
    DecisionTreeNode,
    MethodologyPack,
    PackCategory,
    PackChecklist,
    PackFrameworkProfile,
    PackPlannerRule,
)

PACK = MethodologyPack(
    name="Nuxt",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing Nuxt 3 applications. Covers server routes, universal rendering, nitro engine, auto-imports, and module security.",
    supported_technologies=["Nuxt", "Vue.js", "Node.js"],
    supported_frameworks=["Nuxt"],
    supported_languages=["JavaScript", "TypeScript"],
    attack_surface_areas=["authentication", "api", "ssr", "middleware", "configuration", "ssrf"],
    investigation_priority=80,
    related_packs=["REST API", "JWT", "Session Management"],

    profile=PackFrameworkProfile(
        architecture_description="Nuxt 3 with Vue 3, Nitro server engine, file-based routing, auto-imports, server routes (server/api, server/routes), hybrid rendering (SSR + SSG + SWR).",
        authentication_components=["useAuth composable", "Custom middleware for auth", "Session cookies", "JWT via server/api routes"],
        trust_boundaries=["Client vs server in universal rendering", "Server route boundary", "Middleware route guard boundary", "Nitro engine boundary"],
        investigation_areas=[
            "Server route auth bypass",
            "Nitro engine config exposure",
            "Universal rendering data leakage",
            "Middleware navigation guard bypass",
            "Auto-imported component security",
            "Module vulnerability analysis",
        ],
    ),

    workflow=[
        "Nuxt Identified",
        "Rendering Mode Analysis (SSR vs SSG vs SWR)",
        "Server Route Enumeration",
        "Server Route Auth Review",
        "Middleware Security Review",
        "Universal Rendering Data Flow Review",
        "Configuration Exposure Check",
        "Module Dependency Review",
        "Evidence Collection",
    ],

    checklists=[
        PackChecklist(
            objective="Enumerate server routes and check auth protection",
            description="Identify all server routes (server/api, server/routes) and test for missing authentication.",
            procedure="1. Check server/api/ and server/routes/ source files or guess routes\n2. Enumerate common server route paths\n3. Test each route without auth headers\n4. Check for CRUD operations without authorization\n5. Test parameterized server routes for IDOR",
            priority="critical", difficulty="medium",
            required_evidence=["Server route accessible without auth"],
            expected_result="Server route auth assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.IDOR],
            tags=["nuxt", "server routes", "api"],
        ),
        PackChecklist(
            objective="Check Nitro engine configuration exposure",
            description="Review Nitro configuration for debug endpoints, exposed config, and server middleware.",
            procedure="1. Check for /__nuxt_vite_node__ or debug endpoints\n2. Review nitro.config for exposed environment variables\n3. Test server middleware error handling for stack traces\n4. Check for SSR error page exposing server-side data\n5. Review publicRuntimeConfig vs privateRuntimeConfig",
            priority="high", difficulty="easy",
            required_evidence=["Nitro debug endpoint accessible", "Config data exposed"],
            expected_result="Nitro configuration exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["nuxt", "nitro", "config"],
        ),
        PackChecklist(
            objective="Test universal rendering data leakage",
            description="Check if server-side data in SSR mode leaks to the client unnecessarily.",
            procedure="1. Identify pages using useAsyncData or useFetch with server:true\n2. Inspect page HTML source for embedded state\n3. Compare server payload with required client data\n4. Look for API keys, tokens, or internal IDs in payload\n5. Check window.__NUXT__ state object",
            priority="high", difficulty="easy",
            required_evidence=["Sensitive data in window.__NUXT__"],
            expected_result="SSR data leakage assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["nuxt", "ssr", "data leakage"],
        ),
        PackChecklist(
            objective="Test middleware navigation guards",
            description="Test Nuxt middleware for auth bypass via client-side manipulation.",
            procedure="1. Identify middleware files in middleware/\n2. Test direct navigation to protected pages\n3. Check if middleware runs only on client side\n4. Test middleware redirect bypass via URL manipulation\n5. Check middleware for role/permission logic errors",
            priority="high", difficulty="medium",
            required_evidence=["Protected page accessible without auth"],
            expected_result="Middleware navigation guard security assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["nuxt", "middleware", "auth"],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="Nuxt", description="Prioritize server route enumeration", priority_modifier=0.15, phase="recon"),
        PackPlannerRule(technology="Nuxt", description="Prioritize universal rendering data leakage review", priority_modifier=0.10, phase="api_analysis"),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="nuxt-root",
            question="What Nuxt-specific attack vector to test?",
            branches=[
                DecisionTreeBranch(condition="Server routes present", conclusion="TEST: 1. Server route auth bypass 2. Direct access to server/api/ 3. Parameterized route IDOR"),
                DecisionTreeBranch(condition="Universal/SSR mode", conclusion="TEST: 1. window.__NUXT__ data leakage 2. SSR state containing secrets 3. useAsyncData payload exposure"),
                DecisionTreeBranch(condition="Nitro engine config", conclusion="CHECK: 1. Debug endpoints 2. Nitro config env exposure 3. Server middleware error output"),
            ],
        ),
    ],
    references=[
        {"source": "Nuxt", "id": "DOCS", "title": "Nuxt 3 Security", "url": "https://nuxt.com/docs/getting-started/security"},
    ],
    tags=["nuxt", "vuejs", "typescript", "web"],
)
