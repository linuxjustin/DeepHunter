"""Magento Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackFrameworkProfile, PackPlannerRule,
)

PACK = MethodologyPack(
    name="Magento",
    version="1.0.0", category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing Adobe Commerce/Magento applications. Covers SQL injection in search, admin exposure, XXE in SOAP, checkout bypass, price manipulation, and GraphQL introspection.",
    supported_technologies=["Magento", "Adobe Commerce", "PHP"],
    supported_frameworks=["Magento"],
    supported_languages=["PHP"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "ecommerce", "graphql", "payment", "file upload"],
    investigation_priority=75,
    related_packs=["GraphQL", "REST API", "OAuth", "File Upload", "Business Logic"],

    profile=PackFrameworkProfile(
        architecture_description="E-commerce platform on PHP, modular architecture with XML layout, EAV entity system, service contracts, REST + GraphQL + SOAP APIs, checkout/quote management, and payment integration.",
        authentication_components=["Admin login + MFA", "REST API integration tokens", "Magento OAuth (legacy)", "Customer session cookies"],
        trust_boundaries=["Admin vs storefront boundary", "REST API auth boundary", "Checkout/payment boundary", "GraphQL permission boundary"],
        investigation_areas=[
            "SQL injection via search/filter parameters",
            "XXE in SOAP API (legacy)",
            "Checkout bypass / price manipulation",
            "Admin panel brute force",
            "GraphQL introspection",
            "File upload RCE",
            "API session hijacking",
            "Unserialize in legacy code",
        ],
    ),
    workflow=["Magento Identified", "Version Detection", "GraphQL Introspection", "Admin Panel Security Review", "Checkout Logic Review", "Payment Security Review", "SQL Injection in Layered Navigation", "SOAP API XXE Testing", "File Upload Security Review", "Evidence Collection"],

    checklists=[
        PackChecklist(
            objective="Perform GraphQL introspection",
            description="Query Magento GraphQL for full schema disclosure and explore mutation/query permissions.",
            procedure="1. POST query { __schema { types { name fields { name } } } }\n2. Extract all mutations and queries\n3. Check for admin-only mutations accessible without auth\n4. Test for GraphQL batch/resource exhaustion\n5. Check for field-level authorization gaps\n6. Try introspecting disabled endpoints",
            priority="critical", difficulty="easy",
            required_evidence=["Full GraphQL schema extracted"],
            expected_result="GraphQL API surface documented",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["magento", "graphql", "api"],
        ),
        PackChecklist(
            objective="Test checkout bypass and price manipulation",
            description="Test Magento checkout flow for price manipulation, coupon abuse, and payment bypass.",
            procedure="1. Intercept checkout POST requests\n2. Modify item prices, shipping costs, tax values\n3. Test coupon abuse (stacking, unlimited use, expired coupons)\n4. Test negative quantity or price values\n5. Bypass payment step (manipulate payment_method)\n6. Test race condition on order placement\n7. Check stored payment method reuse without CVV",
            priority="critical", difficulty="hard",
            required_evidence=["Item purchased at modified price", "Checkout completed without payment"],
            expected_result="E-commerce logic security assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC, BugClass.RACE_CONDITION],
            tags=["magento", "checkout", "payment"],
        ),
        PackChecklist(
            objective="Test SQL injection in layered navigation",
            description="Test Magento catalog layered navigation and search filters for SQL injection.",
            procedure="1. Identify filterable attributes in category/search\n2. Test SQL metacharacters in filter parameters\n3. Test price filter, attribute filter SQL injection\n4. Test GraphQL product filter injection\n5. Check for numeric vs string type confusion in filters",
            priority="critical", difficulty="hard",
            required_evidence=["SQL error from catalog search", "Time-based blind confirmation"],
            expected_result="SQL injection in catalog filters assessed",
            bug_classes=[BugClass.SQL_INJECTION],
            tags=["magento", "sql injection", "catalog"],
        ),
        PackChecklist(
            objective="Test admin panel security",
            description="Review Magento admin panel for default credentials, MFA bypass, and admin URL exposure.",
            procedure="1. Identify admin URL (/admin, /backend, custom)\n2. Test default credentials (admin/admin123)\n3. Check MFA enforcement\n4. Test for admin CSRF on config changes\n5. Check admin session timeout and lockout\n6. Test brute force rate limiting on admin login",
            priority="high", difficulty="easy",
            required_evidence=["Admin panel accessible", "Default credentials work"],
            expected_result="Admin panel security assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["magento", "admin", "authentication"],
        ),
        PackChecklist(
            objective="Test SOAP API XXE (legacy)",
            description="Test Magento SOAP API for XML External Entity injection.",
            procedure="1. Check if SOAP API is enabled (/soap/, /api/v2_soap/)\n2. Send SOAP request with XXE payload\n3. Test file:/, expect:/, php:// wrapper injection\n4. Try to read /etc/passwd or local files\n5. Test for SSRF via XXE (http://internal)\n6. Check WSDL exposure",
            priority="high", difficulty="medium",
            required_evidence=["File read via XXE", "SSRF callback via XXE"],
            expected_result="XXE in SOAP API identified or ruled out",
            bug_classes=[BugClass.XXE, BugClass.SSRF],
            tags=["magento", "soap", "xxe"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="magento-root", question="What Magento attack surface?",
            branches=[
                DecisionTreeBranch(condition="GraphQL accessible", conclusion="INTROSPECT: Full schema extraction, identify privileged mutations, test auth gaps"),
                DecisionTreeBranch(condition="Checkout flow", conclusion="TEST: Price modification, coupon abuse, payment method bypass, negative quantities"),
                DecisionTreeBranch(condition="SOAP API accessible", conclusion="TEST: XXE injection, WSDL exposure, legacy endpoint exploitation"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="Magento", description="Prioritize GraphQL introspection", priority_modifier=0.15, phase="recon"),
        PackPlannerRule(technology="Magento", description="Prioritize checkout/price manipulation", priority_modifier=0.20, phase="business_logic_analysis"),
    ],
    references=[{"source": "Magento", "id": "SEC", "title": "Magento Security Center", "url": "https://magento.com/security"}],
    tags=["magento", "adobe-commerce", "php", "ecommerce", "web"],
)
