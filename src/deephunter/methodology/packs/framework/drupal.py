"""Drupal Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackFrameworkProfile, PackPlannerRule,
)

PACK = MethodologyPack(
    name="Drupal",
    version="1.0.0", category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing Drupal applications. Covers Drupalgeddon SA-CORE vulnerabilities, access bypass, Twig injection, Entity API injection, and contributed module security.",
    supported_technologies=["Drupal", "PHP"],
    supported_frameworks=["Drupal"],
    supported_languages=["PHP"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "template injection", "configuration", "file upload"],
    investigation_priority=75,
    related_packs=["REST API", "OAuth", "File Upload", "JWT"],

    profile=PackFrameworkProfile(
        architecture_description="PHP-based CMS using Symfony components, entity system (nodes/users/taxonomy), hook system, render arrays, Twig templating, and REST/JSON:API.",
        authentication_components=["Drupal user system with session cookies", "API keys via REST UI / simple_oauth", "OAuth2 via simple_oauth module"],
        trust_boundaries=["Route access check boundary", "Entity access control boundary", "Form API validation boundary", "REST/JSON:API permission boundary"],
        investigation_areas=[
            "Drupalgeddon SA-CORE vulnerabilities",
            "Twig template injection (render array)",
            "Entity API SQL injection",
            "JSON:API resource exposure",
            "Access bypass via route permissions",
            "Session fixation",
            "Drush config exposure",
        ],
    ),
    workflow=["Drupal Identified", "Version & Patch Level Detection", "Drupalgeddon Vulnerability Testing", "JSON:API Resource Analysis", "Route Permission Review", "Twig Template Analysis", "Entity Access Review", "Session & Auth Testing", "Drush & Config Exposure Check", "Evidence Collection"],

    checklists=[
        PackChecklist(
            objective="Test for Drupalgeddon vulnerabilities",
            description="Test for known Drupal core critical vulnerabilities (SA-CORE-2019, SA-CORE-2020, CVE-2018-7600 Drupalgeddon2).",
            procedure="1. Check Drupal version against SA-CORE advisories\n2. Test CVE-2018-7600 (Drupalgeddon2) with crafted form API requests\n3. Test CVE-2019-6340 (Drupalgeddon3) for JSON:API RCE\n4. Test SA-CORE-2019-003 for REST API access bypass\n5. Test SA-CORE-2020-002 for file upload RCE\n6. Test SA-CORE-2020-004 for Twig injection",
            priority="critical", difficulty="medium",
            required_evidence=["Drupalgeddon exploit confirmed"],
            expected_result="Known Drupal vulnerability status assessed",
            bug_classes=[BugClass.RCE, BugClass.AUTH_BYPASS],
            tags=["drupal", "drupalgeddon", "cve"],
        ),
        PackChecklist(
            objective="Enumerate JSON:API resources",
            description="Discover all Drupal JSON:API resources and check for sensitive data exposure.",
            procedure="1. Fetch /jsonapi and list all available resource types\n2. Test /jsonapi/node/article for unpublished content\n3. Test /jsonapi/user/user for user data exposure\n4. Check for custom resource type exposure\n5. Test filtering/pagination for data extrusion\n6. Test JSON:API CRUD operations without proper auth",
            priority="high", difficulty="easy",
            required_evidence=["Unauthorized resource access via JSON:API"],
            expected_result="JSON:API exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.AUTH_BYPASS],
            tags=["drupal", "jsonapi", "rest"],
        ),
        PackChecklist(
            objective="Test entity access bypass",
            description="Test Drupal entity access controls for viewing, creating, updating entities without proper permissions.",
            procedure="1. Identify entity types (node, taxonomy_term, user, custom)\n2. Test direct entity load via /node/NID\n3. Test entity creation via POST without proper permissions\n4. Test entity update by manipulating entity ID\n5. Check for hook_entity_access implementation bypasses\n6. Test revision access for unpublished content",
            priority="high", difficulty="medium",
            required_evidence=["Entity accessed without proper permissions"],
            expected_result="Entity access control assessed",
            bug_classes=[BugClass.IDOR, BugClass.AUTH_BYPASS],
            tags=["drupal", "entity", "access control"],
        ),
        PackChecklist(
            objective="Test Drush config exposure",
            description="Check if Drush configuration or backup files are accessible via the web.",
            procedure="1. Check /.drush/, /drush/, /sites/default/files/backup_migrate/\n2. Check for .htaccess protection on sensitive directories\n3. Look for settings.php backup files\n4. Check for temporary files or sync directories\n5. Test Drupal console and drush command exposure via routes",
            priority="medium", difficulty="easy",
            required_evidence=["Drush config or database backup accessible"],
            expected_result="Configuration exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["drupal", "drush", "config"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="drupal-root", question="What Drupal version and attack vector?",
            branches=[
                DecisionTreeBranch(condition="Drupal < 8.8", conclusion="CRITICAL: Test Drupalgeddon2 (CVE-2018-7600) and Drupalgeddon3 (CVE-2019-6340) immediately"),
                DecisionTreeBranch(condition="Drupal >= 8.8", conclusion="TEST: JSON:API resource enumeration, Twig injection, entity access bypass"),
                DecisionTreeBranch(condition="JSON:API enabled", conclusion="ENUMERATE: /jsonapi for all resource types, check CRUD permissions on each"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="Drupal", description="Prioritize Drupalgeddon vulnerability testing", priority_modifier=0.25, phase="input_validation"),
        PackPlannerRule(technology="Drupal", description="Prioritize JSON:API resource enumeration", priority_modifier=0.15, phase="recon"),
    ],
    references=[{"source": "Drupal", "id": "SA", "title": "Drupal Security Advisories", "url": "https://www.drupal.org/security"}],
    tags=["drupal", "php", "cms", "web"],
)
