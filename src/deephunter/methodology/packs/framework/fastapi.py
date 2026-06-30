"""FastAPI Expert Methodology Pack."""

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
    name="FastAPI",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing FastAPI applications. Covers Pydantic schema leakage, dependency injection abuse, OpenAPI exposure, WebSocket security, and ASGI middleware analysis.",
    supported_technologies=["FastAPI", "Python"],
    supported_frameworks=["FastAPI"],
    supported_languages=["Python"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "websocket", "schema exposure", "configuration"],
    investigation_priority=80,
    related_packs=["REST API", "JWT", "OAuth", "Session Management", "Microservices"],

    profile=PackFrameworkProfile(
        architecture_description="ASGI-based (Starlette under the hood), auto-generates OpenAPI/Swagger, uses Pydantic v2 for validation, supports WebSockets, background tasks, and dependency injection.",
        authentication_components=["OAuth2PasswordBearer + JWT", "API Key via Header dependency", "SessionMiddleware (Starlette)", "HTTPBasic", "Bearer token"],
        api_layer="Auto-generated OpenAPI at /docs and /openapi.json, Pydantic models for request/response, dependency injection for auth, database sessions, permissions",
        trust_boundaries=["ASGI middleware boundary", "Dependency injection boundary", "Pydantic validation boundary", "WebSocket message boundary"],
        investigation_areas=[
            "Pydantic model field exposure (extra fields, hidden fields)",
            "OpenAPI schema leakage (/docs, /openapi.json, /redoc)",
            "Dependency injection over-injection",
            "File upload via UploadFile (path traversal)",
            "WebSocket message validation gaps",
            "Background task exception leakage",
            "CORS misconfiguration (allow_origins=['*'])",
            "Path operation overloading",
            "OAuth2 flow misconfiguration",
        ],
    ),

    workflow=[
        "FastAPI Identified",
        "OpenAPI Schema Analysis",
        "Route Enumeration from OpenAPI",
        "Pydantic Schema Review",
        "Dependency Injection Analysis",
        "Authentication Flow Review",
        "WebSocket Security Testing",
        "File Upload Security Review",
        "Background Task Security Review",
        "Evidence Collection",
    ],

    checklists=[
        PackChecklist(
            objective="Analyze OpenAPI/Swagger schema for sensitive data",
            description="Extract the full OpenAPI schema to identify all endpoints, parameters, and data models.",
            procedure="1. Fetch /openapi.json, /docs, /redoc\n2. Analyze all operationIds and paths\n3. Identify endpoints without security requirements\n4. Review response schemas for data leakage\n5. Check for deprecated/debug endpoints",
            priority="critical", difficulty="easy",
            required_evidence=["OpenAPI schema accessible", "Endpoint list with security requirements"],
            expected_result="Full API surface documented from OpenAPI",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["fastapi", "openapi", "swagger", "recon"],
        ),
        PackChecklist(
            objective="Test Pydantic model field exposure",
            description="Test for extra fields being accepted by Pydantic models and hidden/private fields being exposed.",
            procedure="1. Identify Pydantic model schemas from OpenAPI\n2. Send extra fields beyond model definition\n3. Check Config.extra = 'allow' (forbid by default but common in legacy)\n4. Test for sensitive fields in response that aren't in schema\n5. Test alias-based field access",
            priority="high", difficulty="medium",
            required_evidence=["Extra field accepted in request", "Sensitive field exposed in response"],
            expected_result="Pydantic model exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.PRIVILEGE_ESCALATION],
            tags=["fastapi", "pydantic", "schema"],
        ),
        PackChecklist(
            objective="Test dependency injection auth bypass",
            description="Test if dependency injection for authentication/permissions can be bypassed via missing headers, parameter manipulation, or override via sub-dependency.",
            procedure="1. Identify Depends() used for auth\n2. Test endpoints without required auth headers\n3. Test with malformed tokens\n4. Check dependency caching (lifespan)\n5. Test subclass/override attacks on dependencies",
            priority="high", difficulty="hard",
            required_evidence=["Endpoint accessible without valid auth"],
            expected_result="Dependency injection auth bypass confirmed or ruled out",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["fastapi", "dependency injection", "authentication"],
        ),
        PackChecklist(
            objective="Test file upload via UploadFile",
            description="Test UploadFile handling for path traversal, size bypass, and content-type spoofing.",
            procedure="1. Identify UploadFile parameters in path operations\n2. Test filename path traversal (../../../etc/passwd)\n3. Bypass max file size (chunked transfer, multiple files)\n4. Spoof content-type header\n5. Test for stored file access without auth",
            priority="high", difficulty="medium",
            required_evidence=["File written outside upload directory"],
            expected_result="File upload security assessed",
            bug_classes=[BugClass.PATH_TRAVERSAL, BugClass.RCE],
            tags=["fastapi", "upload", "file"],
        ),
        PackChecklist(
            objective="Test WebSocket message validation",
            description="Test WebSocket endpoints for message injection, auth bypass, and data leakage.",
            procedure="1. Identify WebSocket endpoints via OpenAPI\n2. Test without proper authentication\n3. Send malformed JSON messages\n4. Test for message replay\n5. Test WebSocket channel subscription bypass\n6. Check for sensitive data in WebSocket messages",
            priority="high", difficulty="medium",
            required_evidence=["Unauthorized WebSocket access", "Sensitive data via WebSocket"],
            expected_result="WebSocket security assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.INFO_DISCLOSURE],
            tags=["fastapi", "websocket"],
        ),
        PackChecklist(
            objective="Review CORS configuration",
            description="Check CORS middleware for overly permissive settings exposing the API to cross-origin attacks.",
            procedure="1. Check for CORSMiddleware import and arguments\n2. Test allow_origins=['*']\n3. Test allow_credentials=True with wildcard origin\n4. Check expose_headers for sensitive header exposure\n5. Test preflight response caching time",
            priority="medium", difficulty="easy",
            required_evidence=["CORS misconfiguration found"],
            expected_result="CORS configuration assessed",
            bug_classes=[BugClass.CORS_MISCONFIG],
            tags=["fastapi", "cors"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="fastapi-root",
            question="What FastAPI component to investigate?",
            branches=[
                DecisionTreeBranch(condition="OpenAPI schema accessible", child=DecisionTreeNode(
                    id="fastapi-openapi", question="What to check in OpenAPI?",
                    branches=[
                        DecisionTreeBranch(condition="Sensitive schemas exposed", conclusion="REVIEW: 1. User model with password hashes 2. Internal request/response models 3. Hidden endpoints"),
                        DecisionTreeBranch(condition="Unsecured endpoints", conclusion="TEST: 1. Direct access to these endpoints 2. Auth bypass via missing dependency injection"),
                    ],
                )),
                DecisionTreeBranch(condition="WebSocket endpoints present", conclusion="TEST: 1. Auth on connect 2. Message validation 3. Channel subscription isolation 4. Rate limiting"),
                DecisionTreeBranch(condition="File upload endpoints", conclusion="TEST: 1. Path traversal 2. Content-type spoofing 3. Size limits 4. Stored file access"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="FastAPI", description="Prioritize OpenAPI schema analysis", priority_modifier=0.15, phase="recon"),
        PackPlannerRule(technology="FastAPI", description="Prioritize Pydantic field exposure testing", priority_modifier=0.10, phase="api_analysis"),
    ],

    references=[
        {"source": "FastAPI", "id": "SEC", "title": "FastAPI Security", "url": "https://fastapi.tiangolo.com/tutorial/security/"},
        {"source": "OWASP", "id": "API", "title": "OWASP API Security Top 10"},
    ],
    tags=["fastapi", "python", "asgi", "pydantic", "web"],
)
