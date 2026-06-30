"""WordPress Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackFrameworkProfile, PackPlannerRule,
)

PACK = MethodologyPack(
    name="WordPress",
    version="1.0.0", category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing WordPress applications. Covers SQL injection via WPDB, stored XSS via plugins, privilege escalation via AJAX, REST API exposure, and XML-RPC attacks.",
    supported_technologies=["WordPress", "PHP"],
    supported_frameworks=["WordPress"],
    supported_languages=["PHP"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "file upload", "plugin/theme security", "xml-rpc", "configuration"],
    investigation_priority=75,
    related_packs=["REST API", "JWT", "File Upload", "OAuth"],

    profile=PackFrameworkProfile(
        architecture_description="PHP-based CMS with plugin/theme architecture, WP REST API, WPDB database layer, action/filter hook system, shortcodes, and admin-ajax.php.",
        authentication_components=["WP cookie auth (wordpress_logged_in_*)", "Application passwords (REST API)", "OAuth via plugins"],
        trust_boundaries=["REST API public vs auth boundary", "Nonce verification boundary", "current_user_can capability boundary", "AJAX handler auth boundary"],
        investigation_areas=[
            "SQL injection via WPDB (wpdb->prepare bypass)",
            "Stored/Reflected XSS via shortcodes/plugins",
            "File upload RCE via media library",
            "Privilege escalation via admin-ajax.php hooks",
            "REST API endpoint enumeration",
            "XML-RPC DDoS / auth brute force",
            "User enumeration via REST API",
            "Plugin/theme vulnerability scanning",
        ],
    ),

    workflow=["WordPress Identified", "Version Detection", "Plugin & Theme Enumeration", "wp-config Exposure Check", "WP-Cron & XML-RPC Review", "REST API Analysis", "User Enumeration", "Auth & Session Review", "File Upload Security Review", "Plugin Vulnerability Analysis", "Evidence Collection"],

    checklists=[
        PackChecklist(
            objective="Enumerate WordPress plugins and themes",
            description="Use WPScan or manual enumeration to identify installed plugins, themes, and their versions for known vulnerabilities.",
            procedure="1. Scan with wpscan --enumerate vp,vt,tt,cb\n2. Check /wp-content/plugins/ directory listing\n3. Check /wp-content/themes/ directory listing\n4. Read plugin readme.txt files for version info\n5. Cross-reference versions with CVE databases\n6. Check for abandoned plugins",
            priority="critical", difficulty="easy",
            required_evidence=["Plugin/theme list with versions", "Known vulnerable version found"],
            expected_result="Plugin/theme inventory with vulnerability assessment",
            bug_classes=[BugClass.RCE, BugClass.XSS, BugClass.SQL_INJECTION],
            tags=["wordpress", "plugins", "recon", "wpscan"],
        ),
        PackChecklist(
            objective="Test REST API user enumeration and auth bypass",
            description="Check WordPress REST API (/wp-json/wp/v2/users) for user enumeration and test endpoint authentication.",
            procedure="1. Fetch /wp-json/wp/v2/users and /wp-json/wp/v2/users/1\n2. Check REST API authentication requirements\n3. Test /wp-json/wp/v2/posts for draft/private post access\n4. Check application passwords endpoint (/wp-json/wp/v2/users/{id}/application-passwords)\n5. Test custom REST endpoints added by plugins\n6. Check for REST API disabled (?rest_route=/)",
            priority="high", difficulty="easy",
            required_evidence=["User list via REST API", "Unauthorized post content"],
            expected_result="REST API security posture assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.AUTH_BYPASS],
            tags=["wordpress", "rest api", "user enumeration"],
        ),
        PackChecklist(
            objective="Test SQL injection via WPDB",
            description="Find unsafe WPDB queries in custom/plugin code and test for SQL injection.",
            procedure="1. Search for $wpdb->query, $wpdb->get_results, $wpdb->prepare\n2. Check for interpolated variables in queries\n3. Test prepare() with %s vs %d type confusion\n4. Test ORDER BY/LIMIT injection\n5. Check shortcode attribute injection into queries\n6. Test meta_query and tax_query injection",
            priority="critical", difficulty="hard",
            required_evidence=["SQL error from WordPress", "Time-based blind confirmation"],
            expected_result="WPDB SQL injection confirmed or ruled out",
            bug_classes=[BugClass.SQL_INJECTION],
            tags=["wordpress", "wpdb", "sql injection"],
        ),
        PackChecklist(
            objective="Test admin-ajax.php privilege escalation",
            description="Identify AJAX actions that allow privilege escalation by missing capability checks.",
            procedure="1. Identify AJAX actions via POST to /wp-admin/admin-ajax.php\n2. Test actions with missing nonce validation\n3. Try AJAX actions that should be admin-only from subscriber-level\n4. Check for wp_ajax_{action} vs wp_ajax_nopriv_{action} registration\n5. Test direct function execution via AJAX hooks",
            priority="high", difficulty="medium",
            required_evidence=["Admin-level action accessible from low-privilege role"],
            expected_result="AJAX privilege escalation confirmed or ruled out",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION],
            tags=["wordpress", "ajax", "privilege escalation"],
        ),
        PackChecklist(
            objective="Test XML-RPC security",
            description="Check XML-RPC for system.listMethods, pingback, and credential brute force via system.multicall.",
            procedure="1. Check /xmlrpc.php exists\n2. system.listMethods() to enumerate available methods\n3. Test pingback for SSRF (external server callback)\n4. Test multicall brute force (credential stuffing via single request)\n5. Check for XML external entity injection\n6. Try blocking by .htaccess or plugin",
            priority="high", difficulty="easy",
            required_evidence=["XML-RPC enabled with dangerous methods"],
            expected_result="XML-RPC security assessed",
            bug_classes=[BugClass.SSRF, BugClass.AUTH_BYPASS],
            tags=["wordpress", "xmlrpc", "pingback"],
        ),
        PackChecklist(
            objective="Test file upload via media library",
            description="Test WordPress media upload for extension bypass and RCE.",
            procedure="1. Try uploading PHP files via media library\n2. Test double extension (.jpg.php)\n3. Test content-type spoofing\n4. Check .htaccess in uploads directory\n5. Test if uploaded files are accessible\n6. Check for PHAR deserialization in image files",
            priority="high", difficulty="medium",
            required_evidence=["PHP file uploaded and executed"],
            expected_result="File upload security assessed",
            bug_classes=[BugClass.RCE],
            tags=["wordpress", "upload", "media"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="wp-root",
            question="What WordPress attack surface?",
            branches=[
                DecisionTreeBranch(condition="Known plugins/themes", conclusion="SCAN: 1. Cross-reference with public vulnerability databases 2. Test known CVEs 3. Check for vulnerable version ranges"),
                DecisionTreeBranch(condition="REST API accessible", conclusion="TEST: 1. User enumeration 2. Private post access 3. Application password abuse 4. Custom route discovery"),
                DecisionTreeBranch(condition="XML-RPC enabled", conclusion="TEST: 1. pingback SSRF 2. Multicall brute force 3. system.listMethods for exposed functions"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="WordPress", description="Prioritize plugin/theme vulnerability scanning", priority_modifier=0.20, phase="recon"),
        PackPlannerRule(technology="WordPress", description="Prioritize admin-ajax.php privilege escalation", priority_modifier=0.10, phase="authentication_analysis"),
    ],
    references=[{"source": "WPScan", "id": "DOCS", "title": "WPScan WordPress Security", "url": "https://wpscan.com/"}],
    tags=["wordpress", "php", "cms", "web"],
)
