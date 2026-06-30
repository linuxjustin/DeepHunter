"""Built-in knowledge base for common technologies.

Each entry describes security-relevant aspects of a technology:
related tools, authentication mechanisms, trust boundaries,
attack surface implications, and manual investigation suggestions.
"""

from __future__ import annotations

from deephunter.core.types import BugClass
from deephunter.tech_intel.models import (
    AttackSurfaceImplication,
    AuthMechanismClue,
    Confidence,
    InvestigationSuggestion,
    TechnologyKnowledgeEntry,
)


def _build_knowledge_base() -> dict[str, TechnologyKnowledgeEntry]:
    entries: dict[str, TechnologyKnowledgeEntry] = {}

    def add(entry: TechnologyKnowledgeEntry) -> None:
        key = entry.technology_name.lower().strip()
        entries[key] = entry
        for alias in entry.aliases:
            entries[alias.lower().strip()] = entry

    # ════════════════════════════════════════════════════════════════
    # Laravel
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Laravel",
        aliases=["laravel framework"],
        category="framework",
        description="PHP web application framework by Taylor Otwell",
        tags=["php", "mvc", "orm", "blade", "artisan"],
        related_technologies=["PHP", "MySQL", "Redis", "Nginx", "Apache", "Composer"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="session_cookie", description="Laravel uses session-based authentication with encrypted cookies", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="sanctum", description="Laravel Sanctum for SPA and API token auth", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="passport", description="Laravel Passport for full OAuth2 server", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "APP_KEY encryption key separation",
            "Session cookie encryption vs. signing",
            "Queue worker vs. web server isolation",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Debug Mode", description="APP_DEBUG=true exposes full error stack traces, environment vars, and query logs", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="APP_KEY", description="Compromised APP_KEY allows session decryption, cookie forgery, and encrypted data access", bug_classes=[BugClass.CRYPTO_FAILURE, BugClass.AUTH_BYPASS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Mass Assignment", description="Unprotected Eloquent models may allow mass assignment vulnerabilities", bug_classes=[BugClass.PRIVILEGE_ESCALATION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Serialization", description="unserialize() calls on user input can lead to RCE via PHP object injection", bug_classes=[BugClass.DESERIALIZATION, BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Blade Templates", description="Unescaped Blade output {{ }} vs {!! !!} can lead to XSS", bug_classes=[BugClass.XSS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Signed URLs", description="Temporary signed URLs may be bruteforced if APP_KEY is weak", bug_classes=[BugClass.AUTH_BYPASS], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="File Uploads", description="Laravel's filesystem and storage may expose unrestricted file upload", bug_classes=[BugClass.RCE, BugClass.PATH_TRAVERSAL], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Queues & Jobs", description="Horizon/queue workers with serialized job data may be exploited", bug_classes=[BugClass.DESERIALIZATION], confidence=Confidence.LOW),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check APP_DEBUG in production", description="Verify debug mode is disabled in production environments", references=["https://laravel.com/docs/errors"], priority=90),
            InvestigationSuggestion(title="Review mass assignment protection", description="Check $fillable/$guarded properties on all Eloquent models", priority=80),
            InvestigationSuggestion(title="Test signed URL bruteforce", description="Attempt to enumerate or forge signed URLs", priority=60),
            InvestigationSuggestion(title="Audit Blade escaping", description="Review templates for unescaped output with {!! !!}", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Spring Boot
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Spring Boot",
        aliases=["spring", "spring framework", "springboot"],
        category="framework",
        description="Java-based framework for microservices and web applications",
        tags=["java", "microservice", "actuator", "mvc"],
        related_technologies=["Java", "Tomcat", "Jetty", "MySQL", "PostgreSQL", "JPA", "Hibernate", "Kafka", "Redis"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="spring_security", description="Spring Security with filter chains and authentication providers", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="Spring Security may use JWT tokens via nimbus-jose-jwt or auth0", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="oauth2", description="Spring Security OAuth2 client/resource server support", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="session_cookie", description="JSESSIONID-based session management", likelihood=Confidence.HIGH),
        ],
        trust_boundaries=[
            "Actuator endpoints access control",
            "Method-level security annotations",
            "Eureka/Config server internal network",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Actuator Exposure", description="Spring Actuator endpoints exposed without authentication leak sensitive data and allow shutdown", bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.DOS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SpEL Injection", description="Spring Expression Language injection in @Value or template parsing", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Method Security", description="Improper @PreAuthorize / @PostAuthorize annotations can allow privilege escalation", bug_classes=[BugClass.PRIVILEGE_ESCALATION, BugClass.AUTH_BYPASS], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="JWT Weakness", description="Weak or default JWT signing keys allow token forgery", bug_classes=[BugClass.AUTH_BYPASS], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="H2 Console", description="H2 database console exposed in development mode can lead to RCE", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="XXE in XML parsers", description="Default XML parsers may be vulnerable to XXE attacks", bug_classes=[BugClass.XXE], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Scan for exposed actuator endpoints", description="Check /actuator, /actuator/env, /actuator/health, /actuator/dump", priority=90),
            InvestigationSuggestion(title="Test JWT token strength", description="Verify JWT signing key is not the default or weak", references=["https://github.com/jwtk/jjwt"], priority=80),
            InvestigationSuggestion(title="Review method security annotations", description="Audit @PreAuthorize on all controller methods", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Next.js
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Next.js",
        aliases=["nextjs", "next"],
        category="framework",
        description="React-based framework with server-side rendering and API routes",
        tags=["react", "ssr", "ssg", "vercel", "nodejs"],
        related_technologies=["React", "Node.js", "Vercel", "TypeScript", "Webpack", "Tailwind CSS"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="next_auth", description="NextAuth.js for authentication (OAuth, JWT)", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT tokens stored in cookies or localStorage", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="session_cookie", description="Server-side sessions via NextAuth or custom implementation", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "Server-side vs client-side data exposure",
            "API route authentication",
            "getServerSideProps vs getStaticProps data sensitivity",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="SSRF in API Routes", description="API routes may proxy user-controlled URLs leading to SSRF", bug_classes=[BugClass.SSRF], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Environment Variable Exposure", description="NEXT_PUBLIC_* env vars are shipped to the browser; sensitive data may leak", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="ISR / On-Demand Revalidation", description="On-demand ISR revalidation secrets may be guessable or leaked", bug_classes=[BugClass.AUTH_BYPASS], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="API Route Auth Bypass", description="API routes under /api/ may lack authentication if middleware is misconfigured", bug_classes=[BugClass.AUTH_BYPASS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="XSS via dangerouslySetInnerHTML", description="SSR content rendered with dangerouslySetInnerHTML may enable XSS", bug_classes=[BugClass.XSS], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Audit NEXT_PUBLIC_ variables", description="Check for API keys or secrets exposed to the client bundle", priority=90),
            InvestigationSuggestion(title="Test API route authentication", description="Verify all /api/* routes require proper authentication", priority=80),
            InvestigationSuggestion(title="Check middleware for auth logic", description="Review next.config.js and middleware.ts for authentication logic", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Express
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Express",
        aliases=["express.js", "expressjs"],
        category="framework",
        description="Minimalist Node.js web application framework",
        tags=["nodejs", "javascript", "middleware", "rest"],
        related_technologies=["Node.js", "Passport.js", "Helmet", "CORS", "Express Session", "Body Parser"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="passport_js", description="Passport.js authentication middleware (local, OAuth)", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT tokens via jsonwebtoken library", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="session_cookie", description="express-session with signed cookies", likelihood=Confidence.HIGH),
        ],
        trust_boundaries=[
            "Middleware execution order",
            "Error handler exposure",
            "CORS policy boundaries",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="CORS Misconfiguration", description="Wildcard or overly permissive CORS headers allow cross-origin data access", bug_classes=[BugClass.CORS_MISCONFIG], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Error Handling", description="Default Express error handler may leak stack traces", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Body Parser Limits", description="Missing or high body size limits enable DoS via large payloads", bug_classes=[BugClass.DOS], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Prototype Pollution", description="Unsafe object merging in middleware can lead to prototype pollution", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Path Traversal", description="Static file serving may allow path traversal if not properly configured", bug_classes=[BugClass.PATH_TRAVERSAL], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Test CORS configuration", description="Check Access-Control-Allow-Origin for wildcard or untrusted origins", priority=80),
            InvestigationSuggestion(title="Review error handlers", description="Ensure custom error handlers don't leak stack traces", priority=70),
            InvestigationSuggestion(title="Audit middleware order", description="Verify security middleware (Helmet, rate limiting) is applied before routes", priority=60),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Django
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Django",
        aliases=["django framework"],
        category="framework",
        description="High-level Python web framework with batteries-included design",
        tags=["python", "orm", "admin", "mvt"],
        related_technologies=["Python", "PostgreSQL", "MySQL", "Redis", "Celery", "Gunicorn", "Nginx"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="session_auth", description="Django's built-in session-based authentication", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT tokens via djangorestframework-simplejwt", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="oauth2", description="django-oauth-toolkit or social-auth-app-django", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="django_allauth", description="django-allauth for social auth and email verification", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "SECRET_KEY cryptographic separation",
            "Database vs cache session storage",
            "Admin panel vs public site isolation",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Admin Panel", description="Django admin at /admin/ may be exposed without proper access control", bug_classes=[BugClass.AUTH_BYPASS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SECRET_KEY", description="Compromised SECRET_KEY allows session forgery, CSRF bypass, and signed data tampering", bug_classes=[BugClass.CRYPTO_FAILURE, BugClass.AUTH_BYPASS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Debug Mode", description="DEBUG=True exposes detailed error pages with settings and source code", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Mass Assignment", description="Missing or improper field-level permissions in DRF serializers", bug_classes=[BugClass.PRIVILEGE_ESCALATION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="SQL Injection", description="Raw SQL queries via .raw() or extra() may introduce SQLi", bug_classes=[BugClass.SQL_INJECTION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="File Upload", description="Unrestricted file upload in FileField/ImageField can lead to RCE", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Template Injection", description="Server-side template injection if user input reaches Django templates unsafely", bug_classes=[BugClass.SSTI], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check admin panel exposure", description="Verify /admin/ is not publicly accessible or has IP restrictions", priority=90),
            InvestigationSuggestion(title="Audit DRF permissions", description="Review permission classes on all APIView and ViewSet classes", priority=80),
            InvestigationSuggestion(title="Review DEBUG setting", description="Ensure DEBUG=False in production settings", priority=90),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Rails
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Ruby on Rails",
        aliases=["rails", "ruby on rails"],
        category="framework",
        description="Full-stack Ruby web framework emphasizing convention over configuration",
        tags=["ruby", "mvc", "orm", "activerecord", "erb"],
        related_technologies=["Ruby", "PostgreSQL", "MySQL", "Redis", "Sidekiq", "Puma", "Nginx"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="session_cookie", description="Rails encrypted cookie-based sessions", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="devise", description="Devise authentication gem (database, OAuth)", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT tokens via devise-jwt or knock gem", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="doorkeeper", description="Doorkeeper OAuth2 provider gem", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "secret_key_base signing vs encryption",
            "Cookie serializer configuration",
            "Asset pipeline vs application code",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Mass Assignment", description="Unprotected ActiveModel attributes allow mass assignment (mitigated in Rails 4+)", bug_classes=[BugClass.PRIVILEGE_ESCALATION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="YAML Deserialization", description="Rails may deserialize YAML from cookies or params leading to RCE", bug_classes=[BugClass.DESERIALIZATION, BugClass.RCE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SQL Injection", description="Raw SQL conditions in .where() or .find_by_sql() may introduce SQLi", bug_classes=[BugClass.SQL_INJECTION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="SSTI via ERB", description="Server-side template injection if user input reaches ERB templates", bug_classes=[BugClass.SSTI], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="secret_key_base", description="Weak or leaked secret_key_base allows session forgery and cookie tampering", bug_classes=[BugClass.CRYPTO_FAILURE, BugClass.AUTH_BYPASS], confidence=Confidence.HIGH),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check cookie serializer", description="Verify cookies are using JSON serializer, not Marshal", priority=80),
            InvestigationSuggestion(title="Review Devise configuration", description="Check for weak password policies or exposed registration endpoints", priority=70),
            InvestigationSuggestion(title="Audit mass assignment", description="Verify strong_parameters are configured on all controllers", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # WordPress
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="WordPress",
        aliases=["wordpress", "wp"],
        category="cms",
        description="PHP-based content management system powering a large portion of the web",
        tags=["php", "cms", "plugins", "themes", "mysql"],
        related_technologies=["PHP", "MySQL", "MariaDB", "Nginx", "Apache", "WooCommerce"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="cookie_auth", description="WordPress cookie-based authentication with wp_logged_in cookies", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT authentication via plugins like JWTAuth", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="oauth", description="OAuth via plugins for social login", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "wp-admin vs front-end isolation",
            "Plugin sandboxing",
            "File permissions (wp-config.php)",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="XML-RPC", description="XML-RPC endpoint at /xmlrpc.php allows brute force and SSRF", bug_classes=[BugClass.SSRF, BugClass.BROKEN_AUTH], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Plugin Vulnerabilities", description="Third-party plugins are the primary source of vulnerabilities", bug_classes=[BugClass.RCE, BugClass.SQL_INJECTION, BugClass.XSS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="User Enumeration", description="WordPress user enumeration via author archives and REST API", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="wp-config.php Exposure", description="Exposed wp-config.php leaks database credentials and salts", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="REST API", description="WP REST API may expose sensitive endpoints without authentication", bug_classes=[BugClass.AUTH_BYPASS, BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Scan installed plugins", description="Identify all plugins and versions for known vulnerabilities", priority=90),
            InvestigationSuggestion(title="Test XML-RPC", description="Check if xmlrpc.php is enabled and accessible", priority=80),
            InvestigationSuggestion(title="Enumerate users", description="Try ID-based user enumeration via /?author=1", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Drupal
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Drupal",
        aliases=["drupal cms"],
        category="cms",
        description="PHP-based content management framework with modular architecture",
        tags=["php", "cms", "modules", "twig"],
        related_technologies=["PHP", "MySQL", "PostgreSQL", "Nginx", "Apache", "Drush"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="session_cookie", description="Drupal session-based authentication", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="oauth", description="OAuth via contributed modules", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "/admin vs public access",
            "Trusted host configuration",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Drupalgeddon", description="CVE-2018-7600 / CVE-2019-6340 — RCE via Drupal core", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Module Vulnerabilities", description="Contributed modules may introduce SQLi, XSS, or RCE", bug_classes=[BugClass.RCE, BugClass.SQL_INJECTION, BugClass.XSS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="User Enumeration", description="Drupal exposes usernames via registration and profile pages", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check Drupal version", description="Determine Drupal version and check for known CVEs", priority=90),
            InvestigationSuggestion(title="Audit contributed modules", description="List enabled modules and check for vulnerabilities", priority=80),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Magento
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Magento",
        aliases=["magento", "adobe commerce"],
        category="cms",
        description="E-commerce platform by Adobe (formerly Magento)",
        tags=["php", "ecommerce", "mysql", "elasticsearch"],
        related_technologies=["PHP", "MySQL", "Elasticsearch", "Redis", "Varnish", "Nginx"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="session_cookie", description="Magento session-based frontend authentication", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT tokens for API authentication", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="oauth", description="OAuth for integrations", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "/admin vs storefront",
            "Payment processing isolation",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="SQL Injection", description="Magento has a history of SQLi vulnerabilities in core and extensions", bug_classes=[BugClass.SQL_INJECTION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="RCE via Theme/Plugin", description="Malicious or vulnerable themes/plugins can lead to RCE", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Admin Exposure", description="Magento admin panel at /admin may be exposed", bug_classes=[BugClass.BROKEN_AUTH], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check admin panel location", description="Verify /admin is not the default path", priority=80),
            InvestigationSuggestion(title="Scan for known CVEs", description="Check Magento patch level for known vulnerabilities", priority=90),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Flask
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Flask",
        aliases=["flask framework"],
        category="framework",
        description="Lightweight Python WSGI web application framework",
        tags=["python", "wsgi", "jinja2", "werkzeug"],
        related_technologies=["Python", "Werkzeug", "Jinja2", "Gunicorn", "Flask-Login", "Flask-SQLAlchemy"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="session_cookie", description="Flask signed cookie-based sessions (session cookie)", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="flask_login", description="Flask-Login for user session management", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt", description="JWT tokens via Flask-JWT-Extended", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "SECRET_KEY session signing",
            "Debug mode vs production",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Debug Mode", description="Flask debug mode enabled exposes the Werkzeug debugger with RCE capabilities", bug_classes=[BugClass.RCE, BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SSTI via Jinja2", description="Server-side template injection in Jinja2 templates with user input", bug_classes=[BugClass.SSTI, BugClass.RCE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SECRET_KEY", description="Weak or leaked SECRET_KEY allows session forgery", bug_classes=[BugClass.CRYPTO_FAILURE, BugClass.AUTH_BYPASS], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Open Redirect", description="Flask's redirect() with user-controlled URLs may allow open redirect", bug_classes=[BugClass.OPEN_REDIRECT], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Test for SSTI", description="Inject {{7*7}} in parameters to detect Jinja2 SSTI", priority=90),
            InvestigationSuggestion(title="Check debug mode", description="Verify debug=False in production", priority=80),
            InvestigationSuggestion(title="Review secret key strength", description="Ensure SECRET_KEY is a strong random value", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # FastAPI
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="FastAPI",
        aliases=["fastapi framework"],
        category="framework",
        description="Modern Python web framework for building APIs with automatic OpenAPI docs",
        tags=["python", "async", "openapi", "pydantic", "uvicorn"],
        related_technologies=["Python", "Uvicorn", "Pydantic", "Starlette", "SQLAlchemy", "Redis"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="jwt", description="JWT tokens via python-jose or fastapi-jwt-auth", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="oauth2", description="OAuth2 with password flow built-in", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="api_key", description="API key authentication via Header or Query parameters", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "OpenAPI docs exposure (/docs, /redoc)",
            "Pydantic model validation",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="OpenAPI Docs Exposure", description="Auto-generated docs at /docs or /redoc may expose API surface to unauthenticated users", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Pydantic Validation", description="Missing or improper Pydantic validation may allow unexpected input types", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Path Operation Bypass", description="Improper dependency injection order may bypass authentication", bug_classes=[BugClass.AUTH_BYPASS], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="CORS Misconfiguration", description="CORS middleware misconfiguration may allow cross-origin attacks", bug_classes=[BugClass.CORS_MISCONFIG], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check OpenAPI docs accessibility", description="Verify /docs and /redoc are disabled in production", priority=80),
            InvestigationSuggestion(title="Review dependency injection", description="Audit Depends() usage across all routes for auth bypass", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # ASP.NET
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="ASP.NET",
        aliases=["asp.net", "dotnet", ".net core", "aspnet core"],
        category="framework",
        description="Microsoft's web framework for building web apps and APIs",
        tags=["dotnet", "csharp", "mvc", "razor", "iis"],
        related_technologies=["IIS", "SQL Server", "Entity Framework", "Azure", "SignalR", "Blazor"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="jwt", description="JWT tokens via Microsoft.AspNetCore.Authentication.JwtBearer", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="session_cookie", description="ASP.NET Core session with cookie authentication", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="oauth2", description="Azure AD / OAuth2 integration", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="windows_auth", description="Windows Integrated Authentication (NTLM/Kerberos)", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "ViewState MAC validation",
            "Anti-forgery token separation",
            "MachineKey configuration",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="ViewState", description="EnableViewStateMac=false allows ViewState tampering and potentially RCE", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="MachineKey", description="Default or leaked MachineKey allows ViewState deserialization attacks", bug_classes=[BugClass.DESERIALIZATION, BugClass.RCE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="Path Traversal", description="IIS misconfiguration may allow path traversal via Unicode or encoding tricks", bug_classes=[BugClass.PATH_TRAVERSAL], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="XXE", description="XML parsing with legacy XmlDocument may be vulnerable to XXE", bug_classes=[BugClass.XXE], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check ViewState configuration", description="Verify EnableViewStateMac=true and ViewStateEncryptionMode=Always", priority=80),
            InvestigationSuggestion(title="Review authentication middleware", description="Audit ASP.NET Core middleware pipeline for auth ordering", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Cloudflare
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Cloudflare",
        aliases=["cloudflare cdn", "cloudflare waf"],
        category="cdn_security",
        description="Content delivery network, DDoS protection, and WAF provider",
        tags=["cdn", "waf", "ddos", "tls", "proxy"],
        related_technologies=["Nginx", "WAF", "CDN"],
        potential_auth_mechanisms=[],
        trust_boundaries=[
            "Cloudflare proxy vs origin IP",
            "SSL/TLS encryption mode",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Origin IP Discovery", description="Cloudflare-protected origins may be found via historical DNS, shodan, or certificate transparency", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="WAF Bypass", description="Cloudflare WAF rules may be bypassed via HTTP parameter pollution, encoding, or path normalization", bug_classes=[BugClass.OTHER], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="SSL Mode", description="Flexible SSL mode sends traffic unencrypted between Cloudflare and origin", bug_classes=[BugClass.OTHER], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Find origin IP", description="Search historical DNS records, Shodan, and Certificate Transparency logs for origin IPs", priority=80),
            InvestigationSuggestion(title="Test WAF bypass techniques", description="Try path normalization, parameter pollution, and encoding to bypass WAF rules", priority=70),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # AWS
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="AWS",
        aliases=["amazon web services", "amazon aws"],
        category="cloud_provider",
        description="Amazon Web Services cloud computing platform",
        tags=["cloud", "s3", "ec2", "lambda", "iam"],
        related_technologies=["Cloudflare", "Terraform", "Docker", "Kubernetes"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="iam", description="AWS IAM roles and policies for service-to-service auth", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="cognito", description="AWS Cognito for user authentication", likelihood=Confidence.MEDIUM),
            AuthMechanismClue(mechanism="api_gateway", description="API Gateway with Lambda authorizers", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "IAM role vs service boundaries",
            "VPC and security group isolation",
            "S3 bucket policy vs public access",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="S3 Bucket Exposure", description="Misconfigured S3 buckets may allow public read/write access", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="IAM Privilege Escalation", description="Overly permissive IAM policies allow privilege escalation", bug_classes=[BugClass.PRIVILEGE_ESCALATION], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="SSRF to Metadata", description="SSRF vulnerabilities can access EC2 metadata (IMDS) for credentials", bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="Lambda Injection", description="Unvalidated input to Lambda functions may allow event injection", bug_classes=[BugClass.RCE], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check S3 bucket permissions", description="Use bucket enumeration tools to check for open buckets", priority=90),
            InvestigationSuggestion(title="Test IMDS SSRF", description="If SSRF is found, attempt to access 169.254.169.254/latest/meta-data/", priority=80),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Azure
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Azure",
        aliases=["microsoft azure", "azure cloud"],
        category="cloud_provider",
        description="Microsoft Azure cloud computing platform",
        tags=["cloud", "azure ad", "blob", "functions", "devops"],
        related_technologies=["ASP.NET", "Azure AD", "Terraform", "Docker"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="azure_ad", description="Azure Active Directory with OAuth2/OIDC", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="managed_identity", description="Azure Managed Identities for service auth", likelihood=Confidence.HIGH),
        ],
        trust_boundaries=[
            "Azure AD tenant isolation",
            "Resource group boundaries",
            "Managed identity scope",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Blob Storage Exposure", description="Misconfigured Azure Blob storage allows public access", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SSRF to Metadata", description="Azure Instance Metadata Service (IMDS) accessible via SSRF", bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check blob storage access", description="Test for open Azure Blob containers", priority=80),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # GCP
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="GCP",
        aliases=["google cloud", "google cloud platform"],
        category="cloud_provider",
        description="Google Cloud Platform",
        tags=["cloud", "gcs", "gke", "cloud functions", "iam"],
        related_technologies=["Kubernetes", "Terraform", "Docker"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="iam", description="GCP IAM roles and service accounts", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="firebase_auth", description="Firebase Authentication", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "GCP project organization boundaries",
            "Service account key management",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="GCS Bucket Exposure", description="Misconfigured Google Cloud Storage buckets allow public access", bug_classes=[BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
            AttackSurfaceImplication(area="SSRF to Metadata", description="GCP metadata endpoint accessible via SSRF at 169.254.169.254", bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE], confidence=Confidence.HIGH),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check GCS bucket permissions", description="Test for open Google Cloud Storage buckets", priority=80),
        ],
    ))

    # ════════════════════════════════════════════════════════════════
    # Nginx
    # ════════════════════════════════════════════════════════════════
    add(TechnologyKnowledgeEntry(
        technology_name="Nginx",
        aliases=["nginx web server", "nginx proxy"],
        category="web_server",
        description="High-performance web server and reverse proxy",
        tags=["web server", "proxy", "load balancer", "http"],
        related_technologies=["PHP", "Python", "Node.js", "Let's Encrypt", "Cloudflare"],
        potential_auth_mechanisms=[
            AuthMechanismClue(mechanism="basic_auth", description="HTTP Basic Authentication via htpasswd", likelihood=Confidence.HIGH),
            AuthMechanismClue(mechanism="jwt_auth", description="JWT validation via nginx auth_request module", likelihood=Confidence.MEDIUM),
        ],
        trust_boundaries=[
            "Reverse proxy vs upstream separation",
            "Client body buffer limits",
        ],
        attack_surface_implications=[
            AttackSurfaceImplication(area="Path Traversal", description="Misconfigured alias directive allows path traversal", bug_classes=[BugClass.PATH_TRAVERSAL], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="HTTP Request Smuggling", description="proxy_pass with inconsistent Content-Length/Transfer-Encoding may allow request smuggling", bug_classes=[BugClass.HTTP_REQUEST_SMUGGLING], confidence=Confidence.MEDIUM),
            AttackSurfaceImplication(area="SSRF via proxy_pass", description="proxy_pass with user-controlled URLs enables SSRF", bug_classes=[BugClass.SSRF], confidence=Confidence.MEDIUM),
        ],
        investigation_suggestions=[
            InvestigationSuggestion(title="Check alias directives", description="Review nginx config for path traversal via alias", priority=70),
            InvestigationSuggestion(title="Test proxy_pass SSRF", description="If proxy_pass uses variables, test for SSRF", priority=60),
        ],
    ))

    return entries


KB = _build_knowledge_base()
