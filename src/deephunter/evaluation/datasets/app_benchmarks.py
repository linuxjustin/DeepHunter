"""App benchmark datasets — ground truth for known vulnerable applications.

Each dataset describes a target application, its technologies, known
vulnerabilities, and expected findings.  Used to benchmark planner,
reasoning, methodology, and reporting subsystems.

Applications covered:
  - OWASP Juice Shop
  - DVWA (Damn Vulnerable Web Application)
  - WebGoat
  - NodeGoat
  - VAmPI
  - GraphQL Labs
  - PortSwigger Academy labs (representative sample)
"""

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    DatasetType,
    ExpectedMethodology,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
)


def _make_entry(
    name: str,
    desc: str,
    techs: list[str],
    areas: list[str],
    bugs: list[str],
    steps: list[tuple[str, str, str]],
    hyps: list[str],
    packs: list[str] | None = None,
    cwes: list[str] | None = None,
    difficulty: str = "medium",
) -> BenchmarkEntry:
    return BenchmarkEntry(
        name=name,
        description=desc,
        input=BenchmarkInput(
            technologies=techs,
            bug_classes=bugs,
            attack_surface_areas=areas,
            description=desc,
        ),
        expected=ExpectedOutput(
            planner_steps=[ExpectedStep(phase=p, title=t, description=d) for p, t, d in steps],
            technologies=techs,
            attack_surface=areas,
            reasoning=ExpectedReasoning(hypotheses=hyps, confidence=0.85),
            checklists=[f"Verify {b} on {a}" for b in bugs for a in areas[:2]],
            workflows=[f"Test {b}" for b in bugs],
            knowledge_packs=packs or [],
        ),
        tags=bugs + ["app_benchmark"],
        difficulty=difficulty,
        cwe_ids=cwes or [],
    )


JUICE_SHOP_TECHS = ["Node.js", "Express", "Angular", "SQLite", "JSON Web Token", "Bcrypt"]
JUICE_SHOP_AREAS = ["Product search", "Login form", "Registration", "Shopping cart", "Checkout",
                     "User profile", "Basket API", "Reviews", "Complaints", "Contact form"]
JUICE_SHOP_BUGS = ["sql_injection", "xss", "idor", "mass_assignment", "jwt_attack",
                    "ssrf", "privilege_escalation", "authentication_bypass", "file_upload",
                    "path_traversal", "xxe", "broken_access_control", "insecure_direct_object_reference"]


DVWA_TECHS = ["PHP", "MySQL", "Apache", "SQLite"]
DVWA_AREAS = ["Login form", "SQL injection page", "XSS page", "Command execution", "File upload",
               "File inclusion", "CSRF form", "Brute force page", "CAPTCHA bypass"]
DVWA_BUGS = ["sql_injection", "xss", "command_injection", "file_upload", "path_traversal",
              "csrf", "brute_force", "captcha_bypass"]


WEBGOAT_TECHS = ["Java", "Spring", "H2 Database", "Bootstrap"]
WEBGOAT_AREAS = ["Login", "Registration", "SQL injection lessons", "XSS lessons",
                  "Authentication flaws", "Access control flaws", "Injection flaws",
                  "Session management", "SSRF lesson", "XXE lesson"]
WEBGOAT_BUGS = ["sql_injection", "xss", "authentication_bypass", "broken_access_control",
                 "ssrf", "xxe", "path_traversal", "injection"]

NODEGOAT_TECHS = ["Node.js", "Express", "MongoDB", "Mongoose", "Handlebars"]
NODEGOAT_AREAS = ["Login form", "Registration", "Profile settings", "Contributions",
                   "Admin page", "Session management", "API endpoints"]
NODEGOAT_BUGS = ["sql_injection", "xss", "idor", "mass_assignment", "authentication_bypass",
                  "privilege_escalation", "broken_access_control"]

VAMPI_TECHS = ["Python", "Flask", "SQLAlchemy", "MySQL", "REST API"]
VAMPI_AREAS = ["User registration", "Login", "User profile", "Admin panel",
                "API v1 endpoints", "API v2 endpoints"]
VAMPI_BUGS = ["idor", "mass_assignment", "authentication_bypass", "privilege_escalation",
               "sql_injection", "broken_access_control"]

GRAPHQL_TECHS = ["Node.js", "Express", "GraphQL", "Apollo Server", "MongoDB"]
GRAPHQL_AREAS = ["GraphQL endpoint", "GraphQL queries", "GraphQL mutations",
                  "Introspection query", "Authentication resolvers"]
GRAPHQL_BUGS = ["graphql_introspection", "graphql_injection", "graphql_batching",
                 "graphql_authorization", "graphql_denial_of_service"]

PORTSWIGGER_AREAS = ["Input fields", "Authentication", "Authorization", "API endpoints",
                      "Session tokens", "File upload", "WebSocket"]
PORTSWIGGER_BUGS = ["sql_injection", "xss", "ssrf", "xxe", "path_traversal",
                     "authentication_bypass", "broken_access_control"]


GOLDEN_JUICE_SHOP = _make_entry(
    "juice_shop_full",
    "OWASP Juice Shop — comprehensive benchmarking of all subsystems against the most popular intentionally vulnerable Node.js application with 100+ challenges spanning all major vulnerability classes",
    JUICE_SHOP_TECHS, JUICE_SHOP_AREAS, JUICE_SHOP_BUGS,
    steps=[
        ("recon", "Technology Detection", "Identify Node.js, Express, Angular stack"),
        ("recon", "Attack Surface Mapping", "Enumerate all routes and endpoints"),
        ("recon", "Authentication Analysis", "Review JWT-based auth, registration, login flow"),
        ("sql_injection", "SQLi Testing", "Test all input fields for SQL injection"),
        ("xss", "XSS Testing", "Test reflected, stored, DOM-based XSS vectors"),
        ("authorization", "IDOR Testing", "Test basket access, order history, profile access"),
        ("authorization", "Privilege Escalation", "Test admin access controls"),
        ("jwt", "JWT Attacks", "Test none algorithm, weak secret, token forgery"),
        ("ssrf", "SSRF Testing", "Test server-side request forgery vectors"),
        ("file_upload", "Malicious File Upload", "Test file upload restrictions"),
        ("path_traversal", "Path Traversal", "Test directory traversal in file access"),
    ],
    hyps=[
        "SQL injection in product search via query parameter interpolation",
        "JWT none algorithm bypass on authentication endpoint",
        "IDOR in basket API allowing access to other users' baskets",
        "Mass assignment in user registration allowing role escalation",
        "SSRF in image import feature allowing internal network access",
        "XSS in product reviews stored without sanitization",
        "Path traversal in file download endpoint",
    ],
    packs=["node.js", "express", "angular", "jwt"],
    cwes=["CWE-89", "CWE-79", "CWE-284", "CWE-639", "CWE-287", "CWE-918", "CWE-22", "CWE-915", "CWE-347"],
    difficulty="hard",
)

GOLDEN_DVWA = _make_entry(
    "dvwa_full",
    "Damn Vulnerable Web Application — PHP/MySQL application with configurable security levels for testing SQL injection, XSS, file upload, CSRF, command injection, and more",
    DVWA_TECHS, DVWA_AREAS, DVWA_BUGS,
    steps=[
        ("recon", "Technology Detection", "Identify PHP, MySQL, Apache stack"),
        ("recon", "Login Analysis", "Analyze authentication mechanism and brute force protection"),
        ("sql_injection", "SQLi Testing", "Test SQL injection page at multiple security levels"),
        ("xss", "XSS Testing", "Test reflected and stored XSS pages"),
        ("command_injection", "Command Injection", "Test command execution page"),
        ("file_upload", "File Upload Testing", "Test file upload restrictions and bypasses"),
        ("path_traversal", "File Inclusion", "Test local and remote file inclusion"),
        ("csrf", "CSRF Testing", "Test cross-site request forgery on password change"),
    ],
    hyps=[
        "SQL injection in user ID parameter with no sanitization at low security",
        "Command injection via ping parameter at low security",
        "File upload restrictions bypass via content-type manipulation",
        "Local file inclusion via page parameter",
        "CSRF on password change form without tokens",
        "Stored XSS in guestbook at all security levels",
    ],
    packs=["php", "mysql", "apache", "sqlite"],
    cwes=["CWE-89", "CWE-79", "CWE-78", "CWE-434", "CWE-22", "CWE-352", "CWE-307"],
    difficulty="medium",
)

GOLDEN_WEBGOAT = _make_entry(
    "webgoat_full",
    "WebGoat — Java/Spring-based deliberately vulnerable web application with lessons covering injection, broken authentication, XXE, SSRF, access control, and cryptographic flaws",
    WEBGOAT_TECHS, WEBGOAT_AREAS, WEBGOAT_BUGS,
    steps=[
        ("recon", "Technology Detection", "Identify Java, Spring, H2 stack"),
        ("recon", "Attack Surface Mapping", "Map all lesson endpoints"),
        ("sql_injection", "SQLi Testing", "Test SQL injection lesson endpoints"),
        ("xss", "XSS Testing", "Test cross-site scripting lesson endpoints"),
        ("authentication", "Auth Bypass", "Test authentication bypass scenarios"),
        ("ssrf", "SSRF Testing", "Test server-side request forgery exercises"),
        ("xxe", "XXE Testing", "Test XML external entity injection exercises"),
        ("access_control", "Access Control", "Test insecure direct object references"),
    ],
    hyps=[
        "SQL injection in login form bypasses authentication",
        "ChangeMe session ID is predictable and can be hijacked",
        "Blind XXE in comment submission leaks file contents",
        "SSRF in mod rewrite lesson accesses internal resources",
        "IDOR in assignment access allows viewing other users' work",
    ],
    packs=["java", "spring", "h2"],
    cwes=["CWE-89", "CWE-79", "CWE-287", "CWE-918", "CWE-611", "CWE-639"],
    difficulty="medium",
)

GOLDEN_NODEGOAT = _make_entry(
    "nodegoat_full",
    "NodeGoat — Node.js/Express/MongoDB vulnerable application demonstrating OWASP Top 10 with NoSQL injection, IDOR, mass assignment, and privilege escalation",
    NODEGOAT_TECHS, NODEGOAT_AREAS, NODEGOAT_BUGS,
    steps=[
        ("recon", "Technology Detection", "Identify Node.js, Express, MongoDB stack"),
        ("recon", "Attack Surface Mapping", "Map all routes, API endpoints, and admin areas"),
        ("injection", "NoSQL Injection", "Test login and search for NoSQL injection"),
        ("authentication", "Auth Testing", "Test session management and auth bypass"),
        ("authorization", "IDOR Testing", "Test user contributions and profile IDOR"),
        ("authorization", "Privilege Escalation", "Test admin page access controls"),
        ("mass_assignment", "Mass Assignment", "Test registration for role manipulation"),
    ],
    hyps=[
        "NoSQL injection in login bypasses authentication via $ne operator",
        "IDOR in contributions allows viewing/editing other users' data",
        "Mass assignment in registration allows setting admin role",
        "Session token is not invalidated on logout allowing session fixation",
        "Admin page accessible via direct URL without authorization check",
    ],
    packs=["node.js", "express", "mongodb"],
    cwes=["CWE-943", "CWE-639", "CWE-915", "CWE-384", "CWE-862"],
    difficulty="medium",
)

GOLDEN_VAMPI = _make_entry(
    "vampi_full",
    "VAmPI — Vulnerable REST API built with Python Flask and SQLAlchemy, featuring OWASP API Security Top 10 vulnerabilities including broken object-level authorization and mass assignment",
    VAMPI_TECHS, VAMPI_AREAS, VAMPI_BUGS,
    steps=[
        ("recon", "API Discovery", "Discover all API v1 and v2 endpoints"),
        ("recon", "Technology Detection", "Identify Flask, SQLAlchemy, MySQL stack"),
        ("authorization", "IDOR Testing", "Test user profile endpoints for IDOR"),
        ("authorization", "Privilege Escalation", "Test admin endpoint authorization"),
        ("authentication", "Auth Testing", "Test token management and auth bypasses"),
        ("mass_assignment", "Mass Assignment", "Test user creation for role overriding"),
    ],
    hyps=[
        "IDOR in /api/v1/users/{id} returns any user's data without auth",
        "Mass assignment in POST /api/v1/users allows setting is_admin flag",
        "Authentication bypass via missing token validation on v1 endpoints",
        "Privilege escalation via direct access to admin endpoints",
        "SQL injection in user search parameter",
    ],
    packs=["python", "flask", "sqlalchemy", "mysql"],
    cwes=["CWE-639", "CWE-915", "CWE-287", "CWE-862", "CWE-89"],
    difficulty="easy",
)

GOLDEN_GRAPHQL = _make_entry(
    "graphql_labs_full",
    "GraphQL Labs — deliberately vulnerable GraphQL APIs with introspection enabled, batching attacks, injection resolvers, and broken authorization",
    GRAPHQL_TECHS, GRAPHQL_AREAS, GRAPHQL_BUGS,
    steps=[
        ("recon", "GraphQL Introspection", "Query __schema to discover all types, queries, and mutations"),
        ("recon", "Technology Detection", "Identify Apollo Server, Node.js, MongoDB"),
        ("graphql", "Injection Testing", "Test resolver arguments for injection"),
        ("graphql", "Batch Attack", "Test parallelized batching for rate limit bypass"),
        ("graphql", "Auth Testing", "Test resolver-level authorization checks"),
        ("graphql", "Rate Limiting", "Test query complexity and depth limiting"),
    ],
    hyps=[
        "GraphQL introspection is enabled exposing full schema including admin mutations",
        "Resolver arguments are not sanitized allowing NoSQL injection",
        "Batched queries bypass rate limiting allowing data scraping",
        "Authorization is not enforced at resolver level for sensitive mutations",
        "Deeply nested queries cause denial of service via resource exhaustion",
    ],
    packs=["node.js", "express", "graphql", "mongodb"],
    cwes=["CWE-200", "CWE-943", "CWE-770", "CWE-862", "CWE-400"],
    difficulty="medium",
)

GOLDEN_PORTSWIGGER_REPRESENTATIVE = _make_entry(
    "portswigger_academy_representative",
    "PortSwigger Academy representative — consolidated benchmark from PortSwigger's Web Security Academy labs covering SQL injection, XSS, SSRF, XXE, path traversal, authentication bypass, and access control in a generic web context",
    ["Web", "REST API"], PORTSWIGGER_AREAS, PORTSWIGGER_BUGS,
    steps=[
        ("recon", "Input Enumeration", "Enumerate all user-controlled inputs across the application"),
        ("sql_injection", "SQLi Testing", "Test all DB-interacting endpoints for SQL injection"),
        ("xss", "XSS Testing", "Test all reflection and storage points for XSS"),
        ("ssrf", "SSRF Testing", "Test features that fetch remote resources for SSRF"),
        ("xxe", "XXE Testing", "Test XML processing endpoints for XXE injection"),
        ("path_traversal", "Path Traversal", "Test file access endpoints for path traversal"),
        ("authentication", "Auth Bypass", "Test authentication logic for bypasses"),
        ("authorization", "Access Control", "Test role-based access controls"),
    ],
    hyps=[
        "SQL injection in tracking ID cookie via unsanitized query interpolation",
        "Reflected XSS in search parameter with no encoding",
        "SSRF in stock check feature accesses internal metadata endpoint",
        "XXE in product XML import leaks /etc/passwd",
        "Path traversal in image download allows reading /etc/passwd",
        "Authentication bypass via parameter modification on login",
        "IDOR in account details allows accessing other users' data via modified ID",
    ],
    packs=[],
    cwes=["CWE-89", "CWE-79", "CWE-918", "CWE-611", "CWE-22", "CWE-287", "CWE-639"],
    difficulty="medium",
)


APP_BENCHMARKS: dict[str, BenchmarkEntry] = {
    "juice_shop": GOLDEN_JUICE_SHOP,
    "dvwa": GOLDEN_DVWA,
    "webgoat": GOLDEN_WEBGOAT,
    "nodegoat": GOLDEN_NODEGOAT,
    "vampi": GOLDEN_VAMPI,
    "graphql_labs": GOLDEN_GRAPHQL,
    "portswigger_academy": GOLDEN_PORTSWIGGER_REPRESENTATIVE,
}


def get_app_benchmarks() -> list[BenchmarkEntry]:
    return list(APP_BENCHMARKS.values())


def get_app_benchmark(name: str) -> BenchmarkEntry | None:
    return APP_BENCHMARKS.get(name)
