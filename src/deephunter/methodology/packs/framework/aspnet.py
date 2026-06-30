"""ASP.NET Core Expert Methodology Pack."""

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
    name="ASP.NET Core",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing ASP.NET Core applications. Covers middleware pipeline, Entity Framework injection, Razor injection, SignalR security, anti-forgery tokens, and Kestrel/IIS configuration.",
    supported_technologies=["ASP.NET Core", "C#", ".NET"],
    supported_frameworks=["ASP.NET Core"],
    supported_languages=["C#", "F#"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "signalr", "middleware", "configuration", "database"],
    investigation_priority=80,
    related_packs=["REST API", "JWT", "OAuth", "Session Management"],

    profile=PackFrameworkProfile(
        architecture_description="ASP.NET Core with middleware pipeline, dependency injection, MVC/Razor Pages/Minimal APIs/Blazor, Entity Framework Core, SignalR for real-time.",
        authentication_components=["ASP.NET Core Identity", "JWT Bearer (Microsoft.AspNetCore.Authentication.JwtBearer)", "OAuth2/OIDC with Microsoft.Identity.Web", "Windows Authentication (NTLM/Kerberos)", "Cookie authentication"],
        trust_boundaries=["Middleware pipeline order", "Authentication middleware boundary", "Anti-forgery token validation boundary", "Authorization policy boundary"],
        investigation_areas=[
            "Entity Framework SQL injection (FromSqlRaw, ExecuteSqlRaw)",
            "Razor view injection (Html.Raw)",
            "SignalR hub auth bypass",
            "Anti-forgery token validation gaps",
            "Swagger UI exposed in production",
            "Kestrel header parsing issues",
            "Blazor server circuit authentication",
            "Mass assignment in MVC model binding",
        ],
    ),

    workflow=["ASP.NET Core Identified", "Middleware Pipeline Analysis", "Authentication Configuration Review", "Authorization Policy Review", "EF Core SQL Injection Testing", "Razor View Injection Testing", "SignalR Security Review", "Anti-Forgery Token Review", "Evidence Collection"],

    checklists=[
        PackChecklist(
            objective="Test EF Core SQL injection",
            description="Find FromSqlRaw, ExecuteSqlRaw, and interpolated SQL strings for injection.",
            procedure="1. Search for FromSqlRaw, ExecuteSqlRaw, ExecuteSqlCommand\n2. Test interpolated SQL ($\"SELECT * FROM Users WHERE Id = {id}\")\n3. Check for unsafe LINQ expression concatenation\n4. Test raw SQL in migrations or seed methods\n5. Test stored procedure calls with user input",
            priority="critical", difficulty="hard",
            required_evidence=["SQL injection via EF Core"],
            expected_result="EF Core SQL injection confirmed or ruled out",
            bug_classes=[BugClass.SQL_INJECTION],
            tags=["aspnet", "efcore", "sql injection"],
        ),
        PackChecklist(
            objective="Test Razor view injection",
            description="Find @Html.Raw and other unsafe rendering methods that could lead to XSS or template injection.",
            procedure="1. Search for @Html.Raw, @Html.RenderRaw, HtmlString\n2. Check for user input passed to JavaScriptResult or Content with content type text/html\n3. Test MVC ViewData/ViewBag for unescaped rendering\n4. Check for unsafe string concatenation in views\n5. Test JSON serialization with user-controlled property names",
            priority="critical", difficulty="medium",
            required_evidence=["XSS via Razor view injection"],
            expected_result="Razor view injection confirmed or ruled out",
            bug_classes=[BugClass.XSS],
            tags=["aspnet", "razor", "xss"],
        ),
        PackChecklist(
            objective="Test SignalR hub authorization",
            description="Review SignalR hub methods for missing [Authorize] attributes and test unauthorized access.",
            procedure="1. Identify SignalR hubs (Hub<T> or Hub)\n2. Check which hubs/methods have [Authorize] attribute\n3. Try connecting to unauthorized hubs\n4. Test invoking hub methods without proper claims\n5. Check for group/channel authorization bypass\n6. Test connection ID reuse or prediction",
            priority="high", difficulty="medium",
            required_evidence=["Unauthorized access to hub method"],
            expected_result="SignalR authorization assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["aspnet", "signalr", "websocket"],
        ),
        PackChecklist(
            objective="Review anti-forgery token implementation",
            description="Check that anti-forgery tokens are properly applied to all state-changing endpoints.",
            procedure="1. Identify POST/PUT/PATCH/DELETE endpoints\n2. Check for [ValidateAntiForgeryToken] or [AutoValidateAntiforgeryToken]\n3. Test submitting request without anti-forgery token\n4. Test token reuse across sessions\n5. Check for token validation on AJAX endpoints\n6. Verify token cookie flags (HttpOnly, Secure, SameSite)",
            priority="high", difficulty="medium",
            required_evidence=["State-changing request without valid token accepted"],
            expected_result="Anti-forgery token implementation assessed",
            bug_classes=[BugClass.CSRF],
            tags=["aspnet", "csrf", "anti-forgery"],
        ),
        PackChecklist(
            objective="Check Swagger/OpenAPI exposure in production",
            description="Verify Swagger UI or OpenAPI endpoints are not accessible in production environment.",
            procedure="1. Check /swagger, /swagger/v1/swagger.json, /swagger/index.html\n2. Check if Swagger is conditionally enabled in non-development\n3. Extract all API endpoints from exposed schema\n4. Identify endpoints without security schemes\n5. Review request/response schemas for data leakage",
            priority="medium", difficulty="easy",
            required_evidence=["Swagger UI accessible in production"],
            expected_result="API surface documented via Swagger",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["aspnet", "swagger", "openapi"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="aspnet-root",
            question="What ASP.NET Core component to test?",
            branches=[
                DecisionTreeBranch(condition="SignalR hubs present", conclusion="TEST: 1. Hub authorization attributes 2. Group isolation 3. Connection ID security 4. User context middleware"),
                DecisionTreeBranch(condition="EF Core with raw SQL", conclusion="TEST: 1. FromSqlRaw parameters 2. Interpolated SQL ($) 3. Stored procedures 4. LINQ injection"),
                DecisionTreeBranch(condition="Razor pages", conclusion="TEST: 1. Html.Raw usage 2. ViewData/ViewBag injection 3. Client-side validation bypass"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="ASP.NET Core", description="Prioritize SignalR security review", priority_modifier=0.10, phase="authentication_analysis"),
        PackPlannerRule(technology="ASP.NET Core", description="Prioritize EF Core SQL injection testing", priority_modifier=0.15, phase="input_validation"),
    ],

    references=[
        {"source": "CWE", "id": "CWE-89", "title": "SQL Injection"},
        {"source": "CWE", "id": "CWE-79", "title": "XSS"},
        {"source": "Microsoft", "id": "SEC", "title": "ASP.NET Core Security", "url": "https://learn.microsoft.com/en-us/aspnet/core/security/"},
    ],
    tags=["aspnet", "dotnet", "csharp", "web"],
)
