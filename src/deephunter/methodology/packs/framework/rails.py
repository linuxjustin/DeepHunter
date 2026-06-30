"""Ruby on Rails Expert Methodology Pack."""

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
    name="Ruby on Rails",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing Ruby on Rails applications. Covers mass assignment, SQL injection, YAML deserialization, template injection, session security, and cookie tampering.",
    supported_technologies=["Ruby on Rails", "Ruby"],
    supported_frameworks=["Ruby on Rails"],
    supported_languages=["Ruby"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "session management", "deserialization", "template injection", "database"],
    investigation_priority=85,
    related_packs=["REST API", "JWT", "Session Management", "File Upload"],

    profile=PackFrameworkProfile(
        architecture_description="MVC with ActiveRecord ORM, Rack middleware stack, ActionView template engine (ERB), ActionCable for WebSockets, ActiveJob for background jobs.",
        authentication_components=["Devise (Warden strategy)", "has_secure_token", "JWT via devise-jwt or ruby-jwt", "Cookie-based sessions", "API tokens"],
        trust_boundaries=["Rack middleware boundary", "Strong Parameters boundary", "ActiveRecord serialization boundary", "Session cookie signing boundary"],
        investigation_areas=[
            "Mass assignment (strong parameters bypass)",
            "ActiveRecord SQL injection",
            "YAML deserialization in sessions",
            "ERB template injection",
            "Cookie tampering",
            "Render-to-string code execution",
            "Sprockets directory traversal",
        ],
    ),

    workflow=[
        "Rails Identified",
        "Route Enumeration (rake routes)",
        "Session Store Analysis",
        "Strong Parameters Review",
        "Mass Assignment Testing",
        "SQL Injection Testing",
        "Template Injection Testing",
        "YAML Deserialization Testing",
        "Evidence Collection",
    ],

    checklists=[
        PackChecklist(
            objective="Review strong parameters for mass assignment",
            description="Analyze strong parameters permit() calls for over-permissive attribute whitelisting.",
            procedure="1. Review params.require().permit() in controllers\n2. Look for permit(:all) or permit! or .permit! without arguments\n3. Test with extra attributes not in permit list (if using without protection)\n4. Check nested attributes accepts_nested_attributes_for\n5. Test role escalation via extra parameters",
            priority="critical", difficulty="medium",
            required_evidence=["Extra attribute accepted", "Protected field modified"],
            expected_result="Mass assignment vulnerability assessed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION],
            tags=["rails", "strong parameters", "mass assignment"],
        ),
        PackChecklist(
            objective="Test ActiveRecord SQL injection",
            description="Find ActiveRecord queries using string interpolation or unsafe conditions.",
            procedure="1. Search for where(\"#{user_input}\"), User.where(params)\n2. Test order parameters with SQL expressions\n3. Test JSON/JSONB column query injection\n4. Check for unsafe Arel table manipulations\n5. Test LIKE operator with % wildcards",
            priority="critical", difficulty="hard",
            required_evidence=["SQL error response", "Time-based blind confirmation"],
            expected_result="SQL injection confirmed or ruled out",
            bug_classes=[BugClass.SQL_INJECTION],
            tags=["rails", "activerecord", "sql injection"],
        ),
        PackChecklist(
            objective="Test YAML deserialization in session store",
            description="Check if Rails uses YAML-based session serialization (CookieStore with YAML) for deserialization attacks.",
            procedure="1. Decode session cookie from the application\n2. Check if it's YAML serialized (starts with ---)\n3. Craft YAML payload with gadget chain\n4. Resign cookie with known secret or brute force weak secret\n5. Submit malicious cookie",
            priority="critical", difficulty="hard",
            required_evidence=["YAML payload executed", "Code execution proof"],
            expected_result="YAML deserialization confirmed or ruled out",
            bug_classes=[BugClass.DESERIALIZATION, BugClass.RCE],
            tags=["rails", "yaml", "deserialization", "session"],
        ),
        PackChecklist(
            objective="Test ERB template injection",
            description="Test for template injection via unsafe render calls or inline template execution.",
            procedure="1. Search for render(params[:template]), render inline: params[:content]\n2. Test render_to_string with user input\n3. Test ERB.new(params[:template]).result(binding)\n4. Check for custom template handlers accepting user input\n5. Test partial rendering with user-controlled partial name",
            priority="critical", difficulty="medium",
            required_evidence=["Ruby code execution via template"],
            expected_result="Template injection confirmed or ruled out",
            bug_classes=[BugClass.SSTI, BugClass.RCE],
            tags=["rails", "erb", "template injection"],
        ),
        PackChecklist(
            objective="Test cookie tampering and session security",
            description="Test Rails signed/encrypted cookie session store for tampering and information disclosure.",
            procedure="1. Identify session cookie name (_app_session)\n2. Check if cookies are signed or encrypted\n3. Attempt to modify cookie value\n4. Check session cookie flags (HttpOnly, Secure, SameSite)\n5. Test session fixation (pre/post login session ID)\n6. Check CSRF token generation and validation",
            priority="high", difficulty="medium",
            required_evidence=["Modified cookie accepted", "Session fixation proof"],
            expected_result="Session security assessed",
            bug_classes=[BugClass.BROKEN_AUTH, BugClass.CSRF],
            tags=["rails", "session", "cookies", "csrf"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="rails-root",
            question="What Rails attack vector?",
            branches=[
                DecisionTreeBranch(condition="Cookie-based sessions", conclusion="TEST: 1. Decode session cookie 2. Check YAML format 3. Attempt deserialization 4. Check cookie signing"),
                DecisionTreeBranch(condition="Strong parameters permissive", conclusion="TEST: Mass assignment via extra params in create/update actions"),
                DecisionTreeBranch(condition="render/inline template calls", conclusion="TEST: Server-Side Template Injection via user-controlled template content"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="Ruby on Rails", description="Prioritize YAML deserialization testing", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(technology="Ruby on Rails", description="Prioritize mass assignment testing", priority_modifier=0.15, phase="input_validation"),
    ],

    references=[
        {"source": "CWE", "id": "CWE-915", "title": "Mass Assignment"},
        {"source": "CWE", "id": "CWE-502", "title": "Deserialization"},
        {"source": "Rails", "id": "SEC", "title": "Ruby on Rails Security Guide", "url": "https://guides.rubyonrails.org/security.html"},
    ],
    tags=["rails", "ruby", "activerecord", "mvc", "web"],
)
