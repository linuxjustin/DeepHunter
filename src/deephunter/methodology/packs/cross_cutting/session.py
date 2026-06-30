"""Session Management Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="Session Management",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing session management. Covers session fixation, cookie attribute analysis, session token entropy, concurrent session handling, CSRF token validation, and secure session termination.",
    attack_surface_areas=["authentication", "session management", "cookies", "csrf"],
    investigation_priority=90,
    related_packs=["JWT", "OAuth", "OIDC", "REST API"],

    checklists=[
        PackChecklist(
            objective="Analyze session cookie attributes",
            description="Review session cookie flags and configuration for security weaknesses.",
            procedure="1. Identify session cookie during login\n2. Verify HttpOnly, Secure, SameSite flags\n3. Check cookie domain and path scope\n4. Determine cookie expiration/max-age\n5. Check for __Host- and __Secure- prefix usage\n6. Verify cookie name doesn't leak framework info\n7. Test cookie injection via subdomain",
            priority="high", difficulty="easy",
            required_evidence=["Cookie flag screenshot"],
            expected_result="Session cookie attributes assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["session", "cookies"],
        ),
        PackChecklist(
            objective="Test session fixation",
            description="Test if session ID remains unchanged after login (session fixation vulnerability).",
            procedure="1. Capture session cookie before login\n2. Log in with valid credentials\n3. Compare session ID before and after login\n4. If session ID is the same, test with pre-set session\n5. Set session ID cookie to known value, then login\n6. Check if session ID is regenerated on privilege change",
            priority="critical", difficulty="easy",
            required_evidence=["Session ID unchanged after login"],
            expected_result="Session fixation assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["session", "fixation"],
        ),
        PackChecklist(
            objective="Test session token entropy",
            description="Analyze session token randomness for predictability.",
            procedure="1. Collect 100+ consecutive session tokens\n2. Analyze pattern (timestamp-based, incremental, weak PRNG)\n3. Check for user information encoded in session token\n4. Decode session token if base64/hex\n5. Test for session token with sequential counter\n6. Check if session ID uses system time with low precision",
            priority="high", difficulty="medium",
            required_evidence=["Predictable session token pattern"],
            expected_result="Session token entropy assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["session", "entropy"],
        ),
        PackChecklist(
            objective="Test CSRF token implementation",
            description="Review CSRF token generation, validation, and session binding.",
            procedure="1. Identify CSRF token in forms/AJAX headers\n2. Test if CSRF token is bound to user session\n3. Reuse CSRF token from one session to another\n4. Test token prediction (are tokens sequential?)\n5. Test request forgery with missing token\n6. Check if CSRF token is validated on state-changing methods\n7. Test double-submit cookie pattern for CSRF\n8. Check CSRF token in multipart/form requests",
            priority="high", difficulty="medium",
            required_evidence=["CSRF token validation bypass"],
            expected_result="CSRF protection assessed",
            bug_classes=[BugClass.CSRF],
            tags=["csrf", "session"],
        ),
        PackChecklist(
            objective="Test concurrent session handling",
            description="Test how the application handles multiple simultaneous sessions.",
            procedure="1. Log in from two different browsers/devices\n2. Verify both sessions are active\n3. Check if configurable concurrent session limit exists\n4. Log out from one session, check if other remains active\n5. Change password in one session, check other session\n6. Transfer session token between users (session hijacking)\n7. Test session timeout on inactivity",
            priority="medium", difficulty="easy",
            required_evidence=["Concurrent session handling behavior"],
            expected_result="Concurrent session management assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["session", "concurrent"],
        ),
        PackChecklist(
            objective="Test session termination",
            description="Test logout and session termination completeness.",
            procedure="1. Log in, then log out properly\n2. Try to use the same session cookie after logout\n3. Check if server-side session is invalidated\n4. Test session timeout implementation\n5. Test idle timeout vs absolute timeout\n6. Check all tabs/windows for session termination\n7. Test logout from one device terminates all sessions\n8. Check if session persists after browser close",
            priority="high", difficulty="easy",
            required_evidence=["Session still valid after logout/timeout"],
            expected_result="Session termination assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["session", "logout", "termination"],
        ),
        PackChecklist(
            objective="Test session hijacking via token leakage",
            description="Test for session token leakage through various side channels.",
            procedure="1. Check via Referer header when navigating to external links\n2. Check for session in URL parameters or hash fragments\n3. Check browser history for session tokens\n4. Check server logs for session token logging\n5. Test if session appears in error messages\n6. Check XSS-based session theft\n7. Test if session is sent over unencrypted connections\n8. Check HTML source for embedded session data",
            priority="critical", difficulty="easy",
            required_evidence=["Session token leaked via side channel"],
            expected_result="Session token leakage assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["session", "leakage", "hijacking"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="session-root", question="What session management aspect to test?",
            branches=[
                DecisionTreeBranch(condition="Session cookie set on login", conclusion="TEST: 1. Fixation test 2. Cookie attributes 3. Token entropy 4. Concurrent session handling"),
                DecisionTreeBranch(condition="CSRF token in forms", conclusion="TEST: 1. Token binding validation 2. Token prediction 3. Cross-origin request forgery"),
                DecisionTreeBranch(condition="Session term", conclusion="TEST: 1. Post-logout token validity 2. Server-side invalidation 3. Timeout enforcement"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="session management", description="Prioritize session fixation testing", priority_modifier=0.20, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="session management", description="Prioritize CSRF token validation testing", priority_modifier=0.15, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="session management", description="Prioritize session token leakage review", priority_modifier=0.15, phase="authentication_analysis"),
    ],
    references=[{"source": "OWASP", "id": "WSTG-SESS", "title": "OWASP Session Management Testing", "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/"}],
    tags=["session", "authentication", "cookies"],
)
