"""REST API Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="REST API",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing REST APIs. Covers resource enumeration, authentication/authorization testing, mass assignment, parameter pollution, rate limiting, pagination abuse, and content-type negotiation attacks.",
    supported_technologies=["REST", "RESTful", "JSON API", "HAL", "OData"],
    attack_surface_areas=["api", "authentication", "authorization", "input validation", "rate limiting"],
    investigation_priority=95,
    related_packs=["GraphQL", "JWT", "OAuth", "Business Logic", "File Upload"],

    checklists=[
        PackChecklist(
            objective="Enumerate all API endpoints and resources",
            description="Discover and enumerate all REST API endpoints through documentation, crawling, and pattern-guessing.",
            procedure="1. Check /api, /api/v1, /api/v2, /swagger, /openapi.json\n2. Crawl the application to discover API usage patterns\n3. Guess common resource names (/users, /admin, /config, /health)\n4. Check HTTP response headers for API version info\n5. Check for API tokens or keys in client-side code\n6. Review JavaScript for embedded API endpoints and patterns",
            priority="critical", difficulty="easy",
            required_evidence=["API endpoint list with methods"],
            expected_result="Full API surface documented",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["api", "recon", "rest"],
        ),
        PackChecklist(
            objective="Test API authentication bypass",
            description="Test REST API endpoints for missing or weak authentication controls.",
            procedure="1. Map endpoints with their required auth headers/parameters\n2. Send requests without auth headers\n3. Test with empty/malformed auth tokens\n4. Test with tokens from different users\n5. Test HTTP method override for auth bypass (X-HTTP-Method-Override: GET)\n6. Test deprecated API versions that may lack auth\n7. Try array notation for auth headers (Authorization[], Authorization[0])",
            priority="critical", difficulty="medium",
            required_evidence=["API endpoint accessible without valid auth"],
            expected_result="API authentication assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["api", "authentication"],
        ),
        PackChecklist(
            objective="Test mass assignment/extra fields in API requests",
            description="Test API endpoints that accept JSON/XML bodies for accepting unexpected properties.",
            procedure="1. Identify POST/PUT/PATCH endpoints accepting structured data\n2. Add unexpected fields to request body (is_admin, role, permissions)\n3. Try nesting unexpected objects\n4. Test array notation for fields (permissions[])\n5. Try GraphQL-like field selection in REST (fields[])\n6. Test with JSON key collision (duplicate keys)",
            priority="critical", difficulty="medium",
            required_evidence=["Extra field accepted and persisted"],
            expected_result="Mass assignment vulnerability assessed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION, BugClass.IDOR],
            tags=["api", "mass assignment", "validation"],
        ),
        PackChecklist(
            objective="Test IDOR and authorization on API resources",
            description="Test each API resource for Insecure Direct Object References by manipulating resource IDs.",
            procedure="1. Identify endpoints with user/resource IDs in URL or body\n2. Create resource as User A, try accessing it as User B\n3. Use UUID enumeration / sequential ID guessing\n4. Try numeric ID manipulation (id=1, id=2, id=3)\n5. Test for vertical IDOR (low-priv user accessing admin resources)\n6. Test batch operations for IDOR\n7. Check response for other users' data in list endpoints",
            priority="critical", difficulty="medium",
            required_evidence=["Another user's resource accessible"],
            expected_result="API authorization assessed for IDOR",
            bug_classes=[BugClass.IDOR, BugClass.PRIVILEGE_ESCALATION],
            tags=["api", "idor", "authorization"],
        ),
        PackChecklist(
            objective="Test API rate limiting and resource exhaustion",
            description="Test API endpoint rate limiting, pagination abuse, and resource exhaustion protection.",
            procedure="1. Send rapid requests to sensitive endpoints (auth, password reset)\n2. Test pagination abuse (per_page=999999, page parameter manipulation)\n3. Test concurrent requests for race conditions\n4. Check for total resource count exposure\n5. Test batch operation size limits\n6. Check for timeout/abuse on slow endpoints",
            priority="high", difficulty="medium",
            required_evidence=["Rate limit bypassed", "Large data set returned"],
            expected_result="Rate limiting and pagination security assessed",
            bug_classes=[BugClass.RATE_LIMIT_BYPASS, BugClass.INFO_DISCLOSURE],
            tags=["api", "rate limiting", "dos"],
        ),
        PackChecklist(
            objective="Test HTTP parameter pollution",
            description="Test for parameter pollution via duplicate parameters, different content-types, and HTTP parameter smuggling.",
            procedure="1. Send requests with duplicate parameters (id=1&id=2)\n2. Change content-type between JSON, URL-encoded, multipart\n3. Test mixed parameter sources (query + body + path)\n4. Use parameter segregation (id[0]=1&id[1]=2)\n5. Check for parameter injection via HTTP headers\n6. Test body parameter overriding query parameters",
            priority="high", difficulty="hard",
            required_evidence=["Parameter pollution causing unexpected behavior"],
            expected_result="Parameter pollution security assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC, BugClass.AUTH_BYPASS],
            tags=["api", "parameter pollution"],
        ),
        PackChecklist(
            objective="Test content-type negotiation and deserialization",
            description="Test API content-type handling for deserialization attacks and content-type confusion.",
            procedure="1. Change Content-Type to application/xml (XXE testing)\n2. Test with application/x-yaml (YAML deserialization)\n3. Test with content-type: application/x-www-form-urlencoded on JSON endpoints\n4. Check Accept header for available response formats\n5. Test binary content-types (MessagePack, BSON, Protobuf)\n6. Test file upload via multipart/form-data on non-file endpoints",
            priority="high", difficulty="medium",
            required_evidence=["Deserialization via content-type change"],
            expected_result="Content-type security assessed",
            bug_classes=[BugClass.DESERIALIZATION, BugClass.XXE],
            tags=["api", "content-type", "deserialization"],
        ),
        PackChecklist(
            objective="Test API pagination for data extrusion",
            description="Test API pagination to determine if it can be abused for mass data extraction.",
            procedure="1. Identify paginated endpoints (page, offset, limit, per_page)\n2. Increase page size to maximum\n3. Iterate through all pages to collect total records\n4. Use cursor-based pagination to navigate entire dataset\n5. Check for count/total in pagination responses\n6. Test negative pagination values\n7. Check if pagination is enforced on authenticated data",
            priority="medium", difficulty="easy",
            required_evidence=["Large data extraction via pagination"],
            expected_result="Pagination data exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["api", "pagination"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="rest-root", question="What REST API attack vector?",
            branches=[
                DecisionTreeBranch(condition="Auth on most endpoints", conclusion="TEST: 1. Auth token manipulation 2. Missing auth on less-common methods 3. Auth on deprecated versions"),
                DecisionTreeBranch(condition="Resource IDs exposed", conclusion="TEST: 1. Sequential ID access 2. UUID enumeration 3. Creating/accessing with different user context"),
                DecisionTreeBranch(condition="JSON input endpoints", conclusion="TEST: 1. Extra fields for mass assignment 2. Nested object creation 3. Array/dictionary injection"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="api", description="Prioritize API endpoint enumeration", priority_modifier=0.20, phase="recon"),
        PackPlannerRule(attack_surface="api", description="Prioritize API mass assignment testing", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(attack_surface="api", description="Prioritize IDOR testing on API resources", priority_modifier=0.15, phase="authorization_analysis"),
    ],
    references=[{"source": "OWASP", "id": "API", "title": "OWASP API Security Top 10", "url": "https://owasp.org/www-project-api-security/"}],
    tags=["api", "rest", "web"],
)
