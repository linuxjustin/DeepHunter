"""Predefined framework security profiles.

Each profile captures the unique security-relevant characteristics,
trust boundaries, common components, and testing approaches for a
specific web framework. Used by the methodology pipeline to tailor
checklists and workflows.

These are DATA objects, not code — they describe *how* to test each
framework, not how to detect it.
"""

from __future__ import annotations

from deephunter.methodology.models import FrameworkProfile

LARAVEL_PROFILE = FrameworkProfile(
    framework_name="Laravel",
    version="11.x",
    architecture_notes=[
        "MVC architecture with Eloquent ORM",
        "Middleware pipeline for request filtering",
        "Service container with dependency injection",
        "Facades provide static-like proxy access",
    ],
    trust_boundaries=[
        "Web middleware boundary (before/after kernel handles request)",
        "Eloquent model serialization boundary (API resources)",
        "Session/database boundary for authenticated state",
        "Queue worker boundary for async job processing",
    ],
    common_components=[
        "Eloquent ORM models and relationships",
        "Form requests with authorization policies",
        "Blade templates and view composers",
        "API resource classes and transformers",
        "Artisan commands and scheduled tasks",
        "Mailables, notifications, events/listeners",
    ],
    auth_patterns=[
        "Laravel Sanctum for SPA/token auth",
        "Laravel Jetstream with Teams",
        "API token authentication (Sanctum/Passport)",
        "Session-based auth with remember tokens",
    ],
    deployment_patterns=[
        "PHP-FPM behind Nginx or Apache",
        "Environment-based config (.env)",
        "Horizon for Redis queue management",
        "Telescope for local debugging (exposed in prod?)",
    ],
    investigation_areas=[
        "Mass assignment vulnerabilities (unguarded models)",
        "Eloquent SQL injection (raw queries, whereRaw)",
        "Blade template injection (unescaped {!! !!})",
        "Middleware misconfiguration (except/auth filters)",
        "API resource leakage (hidden fields exposed)",
        "Session fixation / remember token strength",
        "File upload validation bypass",
        "Debug mode enabled in production (APP_DEBUG)",
        "Serialization attacks (unserialize calls)",
        "Artisan console exposed via routes",
    ],
    testing_workflows=[
        "Recon: enumerate routes (php artisan route:list, or via error stack traces)",
        "Static analysis: scan for raw queries, unguarded models, debug endpoints",
        "Auth: test session management, token expiry, password reset tokens",
        "API: enumerate Sanctum/Passport endpoints, test token scoping",
        "Exploitation: mass assignment to escalate privileges",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Laravel Security Checklist"],
    tags=["php", "laravel", "eloquent", "mvc", "web"],
)

SPRING_BOOT_PROFILE = FrameworkProfile(
    framework_name="Spring Boot",
    version="3.x",
    architecture_notes=[
        "Auto-configuration with @SpringBootApplication",
        "Embedded Tomcat/Netty/Jetty containers",
        "Actuator endpoints for monitoring and management",
        "AOP-based security with @PreAuthorize",
    ],
    trust_boundaries=[
        "Controller interceptor boundary",
        "Method security boundary (AOP proxies)",
        "Spring Security filter chain boundary",
        "REST API serialization boundary (Jackson)",
    ],
    common_components=[
        "Spring Data JPA repositories",
        "Spring Security configuration",
        "REST controllers and DTOs",
        "Spring Cloud Gateway / Zuul",
        "Spring Boot Actuator endpoints",
        "Message converters (Jackson, Gson)",
    ],
    auth_patterns=[
        "Spring Security with JWT (jjwt / nimbus-jose)",
        "OAuth2 / OIDC with Spring Security",
        "Session-based auth with JSESSIONID",
        "PreAuthorize / PostAuthorize annotations",
    ],
    deployment_patterns=[
        "Fat JAR running on JDK (17/21)",
        "Docker containers (often with Jib)",
        "Kubernetes with ConfigMaps for external config",
        "Environment profiles (application-{profile}.yml)",
    ],
    investigation_areas=[
        "Actuator exposure (/actuator/env, /actuator/heapdump)",
        "SpEL injection in @PreAuthorize expressions",
        "JPA/Hibernate injection (native queries, SpEL in @Query)",
        "Spring Boot DevTools classloader deserialization",
        "Insecure direct object references in REST APIs",
        "CORS misconfiguration on API endpoints",
        "JSON deserialization (Jackson polymorphic types)",
        "X-Forwarded-For header trust issues",
        "Method security annotation bypass",
    ],
    testing_workflows=[
        "Enumeration: scan common actuator endpoints, Swagger UI, error pages",
        "Static: review @PreAuthorize annotations for SpEL injection",
        "Dynamic: test REST endpoints for IDOR, mass assignment",
        "Deep: Jackson polymorphic deserialization testing",
        "Exploitation: if actuator open, dump heap for secrets",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Spring Security Checklist"],
    tags=["java", "spring", "spring-boot", "jvm", "web"],
)

DJANGO_PROFILE = FrameworkProfile(
    framework_name="Django",
    version="5.x",
    architecture_notes=[
        "MTV pattern with Django ORM",
        "Middleware stack for request/response processing",
        "Django REST Framework (DRF) for APIs",
        "Admin interface auto-generated from models",
    ],
    trust_boundaries=[
        "Middleware boundary (process_request -> process_response)",
        "CSRF middleware boundary",
        "Authentication middleware (request.user setup)",
        "DRF permission and throttle classes",
    ],
    common_components=[
        "Django ORM models and migrations",
        "Class-based and function-based views",
        "Django REST Framework viewsets and serializers",
        "Django Admin configuration",
        "Template engine (Django templates)",
        "Forms and model forms",
    ],
    auth_patterns=[
        "Session-based auth with Django auth framework",
        "DRF token authentication (SimpleJWT / drf-token)",
        "Social auth (django-allauth)",
        "Passwordless / magic link auth (django-rest-passwordless)",
    ],
    deployment_patterns=[
        "WSGI/ASGI behind Gunicorn + Nginx",
        "Docker with Postgres and Redis",
        "Whitenoise for static file serving",
        "Environment variables via python-decouple or environs",
    ],
    investigation_areas=[
        "Mass assignment (no protection in DRF vs Django forms)",
        "Django ORM SQL injection (extra(), raw(), connection.cursor())",
        "Template injection in Django templates (auto-escaped, but unsafe filters)",
        "Admin interface exposed and misconfigured",
        "DRF serializer leakage (exposing nested relations)",
        "Session hijacking via insecure cookie settings",
        "Media file upload path traversal (MEDIA_ROOT + filename)",
        "Debug=True left enabled in production",
        "CORS headers misconfigured in DRF settings",
        "Django REST Framework browseable API left enabled",
    ],
    testing_workflows=[
        "Recon: enumerate routes, check debug mode, scan admin endpoints",
        "Static: review models for missing __str__ leaking data, extra() calls",
        "Auth: test session cookie flags, CSRF protection, token expiry",
        "API: test DRF serializer exposure, mass assignment via extra fields",
        "Exploitation: admin takeover via CRLF in LogEntry, file upload RCE",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Django Security Checklist"],
    tags=["python", "django", "drf", "orm", "web"],
)

RAILS_PROFILE = FrameworkProfile(
    framework_name="Ruby on Rails",
    version="7.x",
    architecture_notes=[
        "CoC and DRY principles with ActiveRecord ORM",
        "Middleware stack (Rack-based)",
        "Asset pipeline (Sprockets / Propshaft)",
        "ActiveJob for background processing",
    ],
    trust_boundaries=[
        "Rack middleware boundary",
        "Controller filter (before_action / around_action) boundary",
        "ActiveRecord serialization boundary",
        "Strong Parameters whitelist boundary",
    ],
    common_components=[
        "ActiveRecord models and associations",
        "ActionController API / rendering",
        "ActionView templates (ERB, Haml, Slim)",
        "ActiveJob with Sidekiq or GoodJob",
        "Devise or auth0 for authentication",
    ],
    auth_patterns=[
        "Devise with Warden strategy",
        "session cookie with signed/encrypted cookies",
        "API tokens (has_secure_token)",
        "JWT via devise-jwt or ruby-jwt",
    ],
    deployment_patterns=[
        "Puma/Unicorn behind Nginx",
        "Docker with YJIT-enabled Ruby 3.x",
        "Capistrano or Kamal for deployment",
        "Credentials encrypted with rails credentials:edit",
    ],
    investigation_areas=[
        "Mass assignment (strong parameters bypass)",
        "ActiveRecord SQL injection (where(params[:x]), unsafe binds)",
        "Template injection (render params[:template] unsafe)",
        "YAML serialization / unsafe.load on session store",
        "Cookie tampering (signed but not encrypted cookies)",
        "Render-to-string / inline template execution",
        "Sprockets directory traversal (if enabled)",
    ],
    testing_workflows=[
        "Recon: scan routes, check session store config, check credentials",
        "Static: audit strong_parameters, SQL raw calls, YAML usage",
        "Dynamic: mass assignment, SQLi, template injection",
        "Session: cookie tampering, CSRF token reuse",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Rails Security Guide"],
    tags=["ruby", "rails", "activerecord", "mvc", "web"],
)

EXPRESS_PROFILE = FrameworkProfile(
    framework_name="Express.js",
    version="4.x",
    architecture_notes=[
        "Minimalist web framework on Node.js",
        "Middleware pipeline (req/res cycle)",
        "Router-level and application-level middleware",
        "Template engines (EJS, Pug, Handlebars)",
    ],
    trust_boundaries=[
        "Express middleware stack (order matters)",
        "Error handling middleware (4-arg function)",
        "Body parser and query parser boundaries",
        "Session middleware boundary",
    ],
    common_components=[
        "Express Router and route handlers",
        "Middleware for auth, logging, CORS",
        "Session stores (express-session + connect-redis/connect-pg-simple)",
        "Helmet for security headers",
        "csurf/csurf-csrf or double-submit pattern",
    ],
    auth_patterns=[
        "JWT via jsonwebtoken library",
        "Passport.js strategies (local, OAuth, JWT)",
        "Session-based with express-session",
        "API key via custom middleware",
    ],
    deployment_patterns=[
        "Node.js process behind Nginx reverse proxy",
        "PM2 or Docker for process management",
        "Environment variables via dotenv",
        "Cluster mode for multi-core",
    ],
    investigation_areas=[
        "Prototype pollution (merge, assign, spread)",
        "Eval-like injections (vm.runInNewContext, new Function)",
        "Path traversal in static file serving",
        "Mass assignment via body-parser parsed objects",
        "JWT alg:none attacks (if using jsonwebtoken <9.x)",
        "express-session signature bypass",
        "CORS misconfig (reflect Origin header)",
        "Error stack traces exposing full paths",
        "XSS via unescaped template rendering",
        "NoSQL injection (MongoDB $ operators in req.body)",
    ],
    testing_workflows=[
        "Recon: identify middleware stack via errors/headers, enumerate routes",
        "Prototype: test JSON parse with __proto__, constructor",
        "Auth: JWT header manipulation, session token analysis",
        "Injection: NoSQL in query params, path traversal in URLs",
        "Config: security headers, CORS, rate limiting",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Node.js Security Checklist"],
    tags=["nodejs", "express", "javascript", "web"],
)

ASPNET_PROFILE = FrameworkProfile(
    framework_name="ASP.NET Core",
    version="8.x",
    architecture_notes=[
        "Middleware pipeline (IApplicationBuilder)",
        "Dependency injection out of the box",
        "Razor Pages / MVC / Minimal APIs",
        "Blazor for interactive components",
    ],
    trust_boundaries=[
        "Middleware pipeline (order-sensitive)",
        "Authentication middleware boundary",
        "Authorization policy boundary",
        "Anti-forgery token validation boundary",
    ],
    common_components=[
        "ASP.NET Core Identity (user management)",
        "Entity Framework Core (ORM)",
        "Razor views and tag helpers",
        "SignalR for real-time communication",
        "gRPC services",
    ],
    auth_patterns=[
        "ASP.NET Core Identity with cookie auth",
        "JWT Bearer token auth (Microsoft.AspNetCore.Authentication.JwtBearer)",
        "OAuth2 / OIDC with Microsoft.Identity.Web",
        "Windows Authentication (NTLM/Kerberos) for intranet",
    ],
    deployment_patterns=[
        "IIS / IIS Express on Windows",
        "Docker with Linux containers",
        "Azure App Services with slot swaps",
        "Kestrel behind Nginx or IIS reverse proxy",
    ],
    investigation_areas=[
        "Mass assignment (BindAttribute excluding fields)",
        "EF Core SQL injection (FromSqlRaw, Interpolated)",
        "Razor view injection (unsafe @Html.Raw)",
        "IDOR in minimal APIs / MVC controllers",
        "SignalR hub method authorization bypass",
        "JSON serialization (System.Text.Json vs Newtonsoft)",
        "Anti-forgery token validation gaps",
        "Swagger UI exposed in production",
        "Kestrel header parsing issues",
        "Blazor server circuit authentication",
    ],
    testing_workflows=[
        "Recon: scan endpoints, check Swagger, check anti-forgery",
        "Static: review Bind attributes, raw SQL calls, Html.Raw usage",
        "Dynamic: IDOR via controller route params, auth bypass",
        "SignalR: test hub method auth, connection hijacking",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "ASP.NET Core Security"],
    tags=["dotnet", "csharp", "aspnet", "web"],
)

NEXTJS_PROFILE = FrameworkProfile(
    framework_name="Next.js",
    version="14.x",
    architecture_notes=[
        "React-based full-stack framework (pages & app router)",
        "Server Components and Client Components",
        "API routes (pages/api or app/api)",
        "Middleware (edge functions) for request filtering",
    ],
    trust_boundaries=[
        "Server vs Client Component boundary",
        "Middleware edge function boundary",
        "API route server boundary (Node.js vs Edge runtime)",
        "getServerSideProps / getStaticProps data boundary",
    ],
    common_components=[
        "App Router (layout.tsx, page.tsx, route.ts)",
        "Server Actions (form mutations)",
        "NextAuth.js / Auth.js for authentication",
        "Vercel deployment host",
    ],
    auth_patterns=[
        "NextAuth.js / Auth.js (credentials, OAuth, magic links)",
        "Clerk / Supabase Auth / Lucia",
        "JWT in cookies or localStorage",
        "Middleware-based route protection (matcher config)",
    ],
    deployment_patterns=[
        "Vercel (serverless functions)",
        "Docker with Node.js standalone output",
        "Static export to CDN",
        "Incremental Static Regeneration (ISR)",
    ],
    investigation_areas=[
        "Server Action CSRF (no built-in CSRF protection for actions)",
        "Middleware bypass via path traversal",
        "getServerSideProps leaking data (no serialization filter)",
        "API route RCE via dynamic imports or eval",
        "_next/image SSRF (unvalidated image URLs)",
        "Source maps exposed (.map files in _next/static/chunks)",
        "Edge function environment variable leakage",
        "XSS in Server Components (no client-side XSS protection)",
        "Insecure direct object reference in dynamic routes",
    ],
    testing_workflows=[
        "Recon: sitemap.xml, robots.txt, _next/static/chunks source maps",
        "Auth: test middleware protection logic, NextAuth callbacks",
        "Server Actions: CSRF testing, argument manipulation",
        "API: parameter pollution, method override, SSRF in images",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Next.js Security Checklist"],
    tags=["react", "nextjs", "typescript", "vercel", "web"],
)

FLASK_PROFILE = FrameworkProfile(
    framework_name="Flask",
    version="3.x",
    architecture_notes=[
        "Micro-framework with WSGI (Werkzeug)",
        "Blueprints for modular routing",
        "Jinja2 template engine (auto-escape by default in Jinja2 3.x)",
        "Flask extensions ecosystem",
    ],
    trust_boundaries=[
        "WSGI middleware boundary (Werkzeug proxy)",
        "Blueprint prefix routing boundary",
        "before_request / after_request hook boundary",
        "Session signing boundary (itsdangerous)",
    ],
    common_components=[
        "Flask-SQLAlchemy or SQLAlchemy directly",
        "Flask-Login for session management",
        "Flask-Migrate (Alembic) for DB migrations",
        "Flask-RESTful or Flask-RESTx for APIs",
        "Flask-Admin for admin interfaces",
    ],
    auth_patterns=[
        "Flask-Login with session cookies",
        "JWT via Flask-JWT-Extended",
        "HTTP Basic / Digest auth",
        "OAuth via Flask-Dance or Authlib",
    ],
    deployment_patterns=[
        "Gunicorn / uWSGI behind Nginx",
        "Docker with Gunicorn + gevent workers",
        "Environment variables (os.environ or python-dotenv)",
    ],
    investigation_areas=[
        "Jinja2 Server-Side Template Injection (SSTI)",
        "Flask session cookie tampering (decoding + re-signing)",
        "Mass assignment (Flask request.form to model)",
        "SQLAlchemy SQL injection (text(), raw SQL)",
        "File upload path traversal / extension bypass",
        "Flask-Admin misconfig (authentication gaps)",
        "CORS via flask-cors misconfiguration",
        "Debug mode / Werkzeug debugger exposed",
        "HTTP parameter pollution (Werkzeug parser quirks)",
    ],
    testing_workflows=[
        "Recon: /console endpoint, session cookie decode, error pages",
        "SSTI: scan for user input in render_template_string",
        "Session: decode flask session, brute secret key",
        "Dynamic: parameter pollution, mass assignment, path traversal",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Flask Security Checklist"],
    tags=["python", "flask", "jinja2", "werkzeug", "web"],
)

FASTAPI_PROFILE = FrameworkProfile(
    framework_name="FastAPI",
    version="0.111.x",
    architecture_notes=[
        "ASGI-based (Starlette under the hood)",
        "Pydantic v2 for request/response validation",
        "OpenAPI/Swagger auto-generated documentation",
        "Dependency injection system (Depends)",
    ],
    trust_boundaries=[
        "ASGI middleware boundary",
        "Starlette middleware stack (CORSMiddleware, etc.)",
        "Dependency injection resolution boundary",
        "Pydantic model validation boundary",
    ],
    common_components=[
        "Pydantic models (schemas) for request/response",
        "SQLAlchemy async (session per request)",
        "Background tasks (BackgroundTasks)",
        "WebSocket endpoints",
        "OAuth2 password flow with JWT",
    ],
    auth_patterns=[
        "OAuth2PasswordBearer + JWT (python-jose / PyJWT)",
        "API key via Header dependency",
        "Session via Starlette SessionMiddleware",
    ],
    deployment_patterns=[
        "Uvicorn / Gunicorn with uvicorn workers",
        "Docker with multi-stage builds",
        "Terraform / Pulumi for cloud deployment",
        "Environment validation via pydantic-settings",
    ],
    investigation_areas=[
        "Pydantic model field exposure (extra fields, hidden fields)",
        "Dependency injection over-injection (unused Depends with side effects)",
        "OpenAPI schema leakage (operationId, requestBody schemas)",
        "File upload via UploadFile (path traversal, size bypass)",
        "WebSocket message validation gaps",
        "CORS misconfiguration (allow_origins=['*'])",
        "JSON response serialization (exposing internal IDs)",
        "Background task exception leakage",
        "Path operation overloading (multiple methods on one path)",
    ],
    testing_workflows=[
        "Recon: /docs, /openapi.json, redoc",
        "Schema: analyze OpenAPI for exposed internal schemas",
        "Dependency: test auth dependency bypass via missing headers",
        "Dynamic: SQL injection in query/filter params, file upload tests",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "FastAPI Security"],
    tags=["python", "fastapi", "asgi", "pydantic", "web"],
)

WORDPRESS_PROFILE = FrameworkProfile(
    framework_name="WordPress",
    version="6.x",
    architecture_notes=[
        "PHP-based CMS with plugin/theme architecture",
        "WP REST API (wp-json)",
        "WPDB database abstraction layer",
        "Hook system (actions and filters)",
    ],
    trust_boundaries=[
        "REST API auth vs public endpoint boundary",
        "Nonce verification boundary",
        "User capability check boundary (current_user_can)",
        "AJAX handler (admin-ajax.php) auth boundary",
    ],
    common_components=[
        "Plugins and themes (mu-plugins, child themes)",
        "Custom post types and meta boxes",
        "WPDB queries",
        "WP REST API endpoints",
        "Shortcodes and widgets",
    ],
    auth_patterns=[
        "WP cookie auth (wp_*, wordpress_*, wordpress_logged_in_*)",
        "Application passwords (REST API)",
        "OAuth via plugins (WPOAuth Server)",
    ],
    deployment_patterns=[
        "PHP-FPM + Nginx/Apache",
        "Docker with Bedrock (roots.io) or wp-cli",
        "WAF via Cloudflare / Sucuri",
        "Redis/Object Cache for page caching",
    ],
    investigation_areas=[
        "SQL injection via WPDB (wpdb->prepare bypass)",
        "Stored/Reflected XSS via plugin shortcodes",
        "File upload RCE through media library",
        "Privilege escalation via AJAX hooks (admin-ajax.php)",
        "Plugin/theme vulnerability scanning",
        "REST API endpoint enumeration and auth bypass",
        "wp-config.php backup file exposure",
        "PHP file inclusion via theme/plugin files",
        "XML-RPC (xmlrpc.php) DDoS / auth brute force",
        "User enumeration via REST API / author archives",
    ],
    testing_workflows=[
        "Recon: wpscan, enumerate users, plugins, themes, REST API",
        "Static: scan plugin code, check nonce usage, capability checks",
        "Auth: test privilege escalation via AJAX, nonce reuse",
        "Dynamic: SQL injection, XSS, file upload, LFI",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "WPScan Methodology", "WordPress Security"],
    tags=["php", "wordpress", "cms", "mysql", "web"],
)

DRUPAL_PROFILE = FrameworkProfile(
    framework_name="Drupal",
    version="10.x",
    architecture_notes=[
        "PHP-based CMS with hook system (Drupal 10 uses Symfony components)",
        "Entity system (nodes, users, taxonomy, custom entities)",
        "Routing system (YAML-based + Symfony routing)",
        "Render array system for theming",
    ],
    trust_boundaries=[
        "Route access check boundary (requirements in routing YAML)",
        "Entity access control boundary (hook_entity_access)",
        "Form API validation and submission boundary",
        "REST/JSON:API resource permission boundary",
    ],
    common_components=[
        "Core modules: Node, User, Taxonomy, Views, CKEditor",
        "Contrib modules (thousands on drupal.org)",
        "Custom modules with hooks and plugins",
        "Drush CLI for administration",
    ],
    auth_patterns=[
        "Drupal user system with session cookies",
        "API keys via REST UI / simple_oauth module",
        "OAuth2 via simple_oauth or openid-connect contrib modules",
    ],
    deployment_patterns=[
        "PHP-FPM + Nginx with clean URLs",
        "Docker with Lando or DDEV for local dev",
        "Config management via CMI (drush cim/cex)",
    ],
    investigation_areas=[
        "Drupalgeddon SA-CORE vulnerabilities (especially SA-CORE-2019, SA-CORE-2020)",
        "Access bypass via route permission misconfiguration",
        "XSS in render arrays / Twig templates",
        "Entity SQL injection (EntityQuery condition injection)",
        "REST/JSON:API resource exposure and auth bypass",
        "Drupalgeddon2 (CVE-2018-7600) SA exploitation",
        "Form API cross-site request forgery",
        "Session fixation / cookie handling",
        "Malicious contributed module analysis",
        "Drush config export leaks",
    ],
    testing_workflows=[
        "Recon: version detection, module enumeration, /jsonapi",
        "Version-specific: check for known SA-CORE exploits",
        "Auth: test access bypass on custom routes, entity access",
        "Dynamic: SQL injection in Views, XSS in custom blocks",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Drupal Security Checklist"],
    tags=["php", "drupal", "cms", "symfony", "web"],
)

MAGENTO_PROFILE = FrameworkProfile(
    framework_name="Magento",
    version="2.4.x",
    architecture_notes=[
        "PHP-based e-commerce on Adobe Commerce / Magento Open Source",
        "Modular architecture with XML configuration",
        "Layout XML + block/template rendering system",
        "Service contract / API layer (REST + SOAP legacy)",
    ],
    trust_boundaries=[
        "Admin scope vs storefront boundary",
        "REST API authentication boundary (integration tokens, OAuth)",
        "Checkout / payment processing boundary",
        "Admin session boundary",
    ],
    common_components=[
        "Magento modules (app/code or vendor/)",
        "EAV entity system (products, categories, customers)",
        "Checkout and quote management",
        "Payment integration modules",
        "Admin panel (adminhtml area)",
    ],
    auth_patterns=[
        "Admin login (username + password, MFA via Google Authenticator)",
        "REST API integration tokens (admin tokens, customer tokens)",
        "Magento OAuth (legacy, for external integrations)",
    ],
    deployment_patterns=[
        "PHP-FPM with Varnish (Full Page Cache)",
        "Redis for session/cache storage",
        "Elasticsearch for catalog search",
        "Docker with Warden or local dev setups",
    ],
    investigation_areas=[
        "SQL injection via search / filter parameters",
        "Admin panel exposure and brute force",
        "XML eXternal Entity (XXE) injection in SOAP API (legacy)",
        "Stored XSS in product/category descriptions",
        "CSRF on admin actions (massActions, config save)",
        "API session hijacking (token leakage in logs)",
        "Checkout bypass / price manipulation",
        "File upload RCE in product images / import CSVs",
        "Unserialize vulnerabilities in legacy code paths",
        "GraphQL introspection and data leakage",
    ],
    testing_workflows=[
        "Recon: detect Magento version, probe admin panel, GraphQL introspection",
        "Auth: test admin CSRF, API token generation abuse",
        "E-commerce: price manipulation, coupon abuse, checkout bypass",
        "Dynamic: SQL injection in layered navigation, XXE in SOAP",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Magento Security Scan"],
    tags=["php", "magento", "adobe-commerce", "ecommerce", "web"],
)

VUEJS_PROFILE = FrameworkProfile(
    framework_name="Vue.js",
    version="3.x",
    architecture_notes=[
        "Progressive JS framework with Composition API (Vue 3)",
        "Component-based SPA architecture",
        "Vue Router for client-side routing",
        "Pinia or Vuex for state management",
    ],
    trust_boundaries=[
        "Client-side vs API server trust boundary (all client code is visible)",
        "Route navigation guard boundary (can be bypassed client-side)",
        "API proxy boundary (Vite dev server vs production)",
    ],
    common_components=[
        "Single File Components (.vue with template/script/style)",
        "Composition API (setup(), ref(), reactive())",
        "Vue Router guards (beforeEach, beforeResolve)",
        "API service layer (axios, fetch)",
    ],
    auth_patterns=[
        "JWT stored in localStorage or cookies (httpOnly ideal)",
        "Route navigation guards for protected routes",
        "OAuth2 implicit/pkce flow (redirect-based)",
    ],
    deployment_patterns=[
        "Vite build to static assets on CDN or Nginx",
        "SSR via Nuxt 3 (not pure Vue.js)",
        "Docker with multi-stage (build + nginx static serve)",
    ],
    investigation_areas=[
        "API key exposure in environment variables bundled to client",
        "Route guard bypass via direct navigation or URL manipulation",
        "Local storage / session storage secrets in XSS scenarios",
        "Pinia state mutation from browser console",
        "Component prop injection (child component receives unsanitized data)",
        "CSRF if API uses cookie auth without proper tokens",
        "Sensitive data in Vue Devtools / Vue.js __vue_app__ global (dev mode)",
        "Source map exposure (.vue.map files in production assets)",
        "Prototype pollution via JSON-based API responses",
    ],
    testing_workflows=[
        "Recon: source maps in _nuxt/ or js/ directories, check /api proxy",
        "Client: inspect localStorage, route guards, API calls in network tab",
        "Auth: test navigation guard bypass, token refresh logic",
        "API: test CSRF tokens, rate limiting, auth checks on backend",
    ],
    related_methodologies=["OWASP Web Security Testing Guide", "Vue.js Security"],
    tags=["javascript", "vuejs", "spa", "frontend", "web"],
)


FRAMEWORK_PROFILES: dict[str, FrameworkProfile] = {}
"""Lazy-loaded registry of all framework profiles, keyed by framework_name."""


def _build_registry() -> dict[str, FrameworkProfile]:
    """Build registry lazily. Import profile variables in module scope."""
    profiles = {
        "Laravel": LARAVEL_PROFILE,
        "Spring Boot": SPRING_BOOT_PROFILE,
        "Django": DJANGO_PROFILE,
        "Ruby on Rails": RAILS_PROFILE,
        "Express": EXPRESS_PROFILE,
        "ASP.NET Core": ASPNET_PROFILE,
        "Next.js": NEXTJS_PROFILE,
        "Flask": FLASK_PROFILE,
        "FastAPI": FASTAPI_PROFILE,
        "WordPress": WORDPRESS_PROFILE,
        "Drupal": DRUPAL_PROFILE,
        "Magento": MAGENTO_PROFILE,
        "Vue.js": VUEJS_PROFILE,
    }
    # By default, also register versions (for partial matching)
    return profiles


def get_framework_profiles() -> dict[str, FrameworkProfile]:
    if not FRAMEWORK_PROFILES:
        FRAMEWORK_PROFILES.update(_build_registry())
    return FRAMEWORK_PROFILES
