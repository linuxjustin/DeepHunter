"""Express.js Expert Methodology Pack."""

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
    name="Express",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing Express.js applications. Covers prototype pollution, middleware ordering, NoSQL injection, JWT attacks, path traversal, and body parser misconfiguration.",
    supported_technologies=["Express", "Node.js"],
    supported_frameworks=["Express"],
    supported_languages=["JavaScript", "TypeScript"],
    attack_surface_areas=["authentication", "api", "input validation", "nosql injection", "prototype pollution", "file upload", "configuration"],
    investigation_priority=80,
    related_packs=["JWT", "REST API", "Session Management", "File Upload", "OAuth"],

    profile=PackFrameworkProfile(
        architecture_description="Express.js minimal framework on Node.js with middleware pipeline, router-level and app-level middleware, and template engines.",
        authentication_components=["Passport.js strategies", "jsonwebtoken library", "express-session", "Session stores (Redis, PostgreSQL)", "helmet for security headers"],
        middleware="Middleware pipeline order is critical: helmet -> cors -> body-parser -> session -> auth -> routes -> error handler",
        api_layer="Express Router for modular routes, body-parser for JSON/URL-encoded parsing, cookie-parser for cookies",
        trust_boundaries=["Middleware stack ordering", "Error handling middleware boundary", "Body parser boundary", "Session middleware boundary"],
        investigation_areas=[
            "Prototype pollution via merge/assign",
            "NoSQL injection via $ operators",
            "JWT none/algorithm confusion",
            "Middleware ordering bypass",
            "Path traversal in static files",
            "CORS misconfiguration",
            "express-session signature bypass",
            "Body parser type confusion",
        ],
    ),

    workflow=[
        "Express Identified",
        "Middleware Stack Analysis",
        "Route Enumeration",
        "Authentication Review",
        "Prototype Pollution Testing",
        "NoSQL Injection Testing",
        "JWT Security Review",
        "Path Traversal Testing",
        "CORS and Header Review",
        "Evidence Collection",
    ],

    checklists=[
        PackChecklist(
            objective="Test prototype pollution",
            description="Find prototype pollution vulnerabilities via __proto__ and constructor.prototype manipulation.",
            procedure="1. Test JSON bodies with {\"__proto__\": {\"isAdmin\": true}}\n2. Test query parameters with ?__proto__[isAdmin]=true\n3. Test via JSON merge operations\n4. Check for vulnerable libraries (lodash.merge, jQuery.extend)\n5. Test constructor.prototype pollution",
            priority="critical", difficulty="hard",
            required_evidence=["Pollution confirmed via admin access or isAdmin flag"],
            expected_result="Prototype pollution confirmed or ruled out",
            bug_classes=[BugClass.RCE, BugClass.PRIVILEGE_ESCALATION],
            tags=["express", "nodejs", "prototype pollution"],
        ),
        PackChecklist(
            objective="Test NoSQL injection",
            description="Find NoSQL injection in MongoDB queries via $ operators in JSON body and query parameters.",
            procedure="1. Test login forms with {\"$gt\": \"\"} or {\"$ne\": \"\"}\n2. Test query params with ?username[$gt]=\n3. Test $where operator injection\n4. Test $regex for blind data extraction\n5. Test $nin, $in for unauthorized access",
            priority="critical", difficulty="medium",
            required_evidence=["Database query manipulation proof", "Auth bypass proof"],
            expected_result="NoSQL injection confirmed or ruled out",
            bug_classes=[BugClass.NO_SQL_INJECTION, BugClass.AUTH_BYPASS],
            tags=["express", "nosql", "mongodb", "injection"],
        ),
        PackChecklist(
            objective="Test JWT implementation",
            description="Test JWT token handling for algorithm confusion, key confusion, KID injection, and signature bypass.",
            procedure="1. Decode JWT and check header (alg, kid, typ)\n2. Change alg from RS256 to HS256 (key confusion)\n3. Set alg to 'none'\n4. Test KID SQL injection / path traversal\n5. Test JWT expiration bypass\n6. Check secret key strength",
            priority="critical", difficulty="medium",
            required_evidence=["Modified JWT accepted by server"],
            expected_result="JWT security assessed and weaknesses identified",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["express", "jwt", "authentication"],
        ),
        PackChecklist(
            objective="Review middleware ordering",
            description="Analyze middleware registration order for security gaps where auth middleware is applied after routes.",
            procedure="1. Read app.js or server.js middleware registration order\n2. Identify routes registered before auth middleware\n3. Check error handler placement (before or after routes)\n4. Review helmet and CORS middleware position",
            priority="high", difficulty="medium",
            required_evidence=["Route accessible without auth"],
            expected_result="Middleware ordering security reviewed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["express", "middleware"],
        ),
        PackChecklist(
            objective="Test path traversal in static files",
            description="Test express.static and custom serveStatic for directory traversal outside the web root.",
            procedure="1. Test ..%2f, ..\\, ....//....// patterns on static routes\n2. Check express.static root path configuration\n3. Test for symlink following\n4. Test dotfile access (.env, .git/config)\n5. Test encoded path traversal (%2e%2e%2f)",
            priority="high", difficulty="easy",
            required_evidence=["File outside web root accessible"],
            expected_result="Path traversal confirmed or ruled out",
            bug_classes=[BugClass.PATH_TRAVERSAL, BugClass.INFO_DISCLOSURE],
            tags=["express", "path traversal", "static"],
        ),
        PackChecklist(
            objective="Test CORS configuration",
            description="Check CORS middleware for reflecting Origin header or allowing all origins.",
            procedure="1. Send request with custom Origin: https://evil.com\n2. Check Access-Control-Allow-Origin response\n3. Test with Origin: null\n4. Check allowedMethods for sensitive verbs\n5. Test preflight cache poisoning",
            priority="high", difficulty="easy",
            required_evidence=["CORS header reflects arbitrary origin"],
            expected_result="CORS posture assessed",
            bug_classes=[BugClass.CORS_MISCONFIG],
            tags=["express", "cors"],
        ),
        PackChecklist(
            objective="Review body parser configuration",
            description="Check body-parser limits and type parsing for abuse potential.",
            procedure="1. Check body parser size limits (100kb default may be increased)\n2. Test URL-encoded body parsing with duplicate keys (parameter pollution)\n3. Test raw body parsing for injection\n4. Check for disabled body parsing on certain routes",
            priority="medium", difficulty="medium",
            required_evidence=["Parameter pollution causing unexpected behavior"],
            expected_result="Body parser configuration reviewed",
            bug_classes=[BugClass.BUSINESS_LOGIC],
            tags=["express", "body-parser"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="express-root",
            question="What Express attack vector to prioritize?",
            branches=[
                DecisionTreeBranch(condition="JSON API endpoints", conclusion="TEST: 1. Prototype pollution via __proto__ 2. NoSQL injection via $ operators 3. JSON body parsing bypass"),
                DecisionTreeBranch(condition="JWT authentication", conclusion="TEST: 1. alg=none 2. RS256->HS256 key confusion 3. KID injection 4. Weak secret brute force"),
                DecisionTreeBranch(condition="Static file serving", conclusion="TEST: 1. Path traversal 2. .env access 3. Source map exposure 4. .git exposure"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="Express", description="Prioritize prototype pollution testing", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(technology="Express", description="Prioritize NoSQL injection testing", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(technology="Express", description="Prioritize JWT security review", priority_modifier=0.10, phase="authentication_analysis"),
    ],

    references=[
        {"source": "OWASP", "id": "WSTG-INPV-05", "title": "NoSQL Injection"},
        {"source": "CWE", "id": "CWE-1321", "title": "Prototype Pollution"},
        {"source": "CWE", "id": "CWE-22", "title": "Path Traversal"},
    ],
    tags=["express", "nodejs", "javascript", "web"],
)
