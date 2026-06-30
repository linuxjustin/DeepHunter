"""OAuth 2.0 Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="OAuth",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing OAuth 2.0 implementations. Covers redirect URI validation, CSRF via state parameter, token leakage, scope escalation, authorization code interception, and PKCE implementation review.",
    attack_surface_areas=["authentication", "authorization", "oauth", "sso"],
    investigation_priority=90,
    related_packs=["OIDC", "JWT", "Session Management", "REST API"],

    checklists=[
        PackChecklist(
            objective="Test redirect URI validation",
            description="Test OAuth redirect URIs for open redirect and validation bypass.",
            procedure="1. Register client with arbitrary redirect_uri\n2. Test redirect URI validation with path traversal (https://app.com/callback/../evil)\n3. Test with subdomain takeover (https://evil.app.com/callback)\n4. Test with DNS rebinding domains\n5. Test protocol confusion (http vs https)\n6. Try redirect_uri=https://evil.com (open redirect)\n7. Check for redirect URI fragment handling",
            priority="critical", difficulty="hard",
            required_evidence=["Authorization code delivered to attacker-controlled URI"],
            expected_result="Redirect URI validation assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["oauth", "redirect", "validation"],
        ),
        PackChecklist(
            objective="Test CSRF via state parameter",
            description="Test OAuth flow for CSRF protection via state parameter validation.",
            procedure="1. Start OAuth flow and capture state parameter\n2. Replay with modified state parameter\n3. Start flow without state parameter\n4. Cross-user state reuse (use state from User A for User B)\n5. Predictable state generation analysis\n6. Check if state is validated or just echoed",
            priority="critical", difficulty="medium",
            required_evidence=["OAuth CSRF via state bypass"],
            expected_result="CSRF protection assessed",
            bug_classes=[BugClass.CSRF],
            tags=["oauth", "csrf", "state"],
        ),
        PackChecklist(
            objective="Test authorization code interception",
            description="Test if authorization codes can be intercepted via referrer leakage, browser history, or logging.",
            procedure="1. Check if auth code appears in URL fragment (implicit flow) or query (code flow)\n2. Check Referer header during redirect (code leakage via Referer)\n3. Test code replay (can the same code be used twice)\n4. Check code expiration time\n5. Test for code injection via 3rd party scripts\n6. Check HTTP logs for code in URLs",
            priority="critical", difficulty="medium",
            required_evidence=["Authorization code leaked or replayed"],
            expected_result="Authorization code security assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["oauth", "authorization code"],
        ),
        PackChecklist(
            objective="Test PKCE implementation",
            description="Test Proof Key for Code Exchange (PKCE) implementation for bypasses.",
            procedure="1. Check if PKCE is enforced\n2. Start flow without code_challenge\n3. Use invalid code_challenge_method (plain vs S256)\n4. Modify code_verifier after token exchange\n5. Reuse code_verifier across different codes\n6. Test null/none code_challenge",
            priority="high", difficulty="medium",
            required_evidence=["PKCE bypassed"],
            expected_result="PKCE implementation assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["oauth", "pkce"],
        ),
        PackChecklist(
            objective="Test scope escalation",
            description="Test for OAuth scope escalation by requesting higher privilege scopes.",
            procedure="1. Identify available scopes from documentation or error messages\n2. Request scope escalation during authorization\n3. Test scope parameter modification\n4. Request sensitive scopes from low-privilege tokens\n5. Test scope injection via parameter pollution\n6. Check scope enforcement at both auth server and resource server",
            priority="critical", difficulty="medium",
            required_evidence=["Token with higher scope than authorized"],
            expected_result="Scope security assessed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION],
            tags=["oauth", "scope", "privilege"],
        ),
        PackChecklist(
            objective="Test token leakage via various channels",
            description="Test for access/refresh token leakage through insecure channels.",
            procedure="1. Check if tokens appear in URL query parameters\n2. Check Referer header for token leakage\n3. Check browser history for token-containing URLs\n4. Check server logs for token logging\n5. Check for token in error messages and stack traces\n6. Test for token in WebSocket connection URLs\n7. Check iframe postMessage for token exposure",
            priority="high", difficulty="medium",
            required_evidence=["Token leaked through unintended channel"],
            expected_result="Token leakage assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.AUTH_BYPASS],
            tags=["oauth", "tokens", "leakage"],
        ),
        PackChecklist(
            objective="Test client credentials grant security",
            description="Test OAuth client credentials grant for insecure client authentication.",
            procedure="1. Check client_secret strength and storage\n2. Test client authentication via request body vs header\n3. Check client_secret expiry\n4. Test for client_secret in client-side code (public clients)\n5. Try client_id/secret stuffing across endpoints\n6. Check different client authentication methods (basic, post, jwt_bearer)",
            priority="high", difficulty="medium",
            required_evidence=["Client credential weakness found"],
            expected_result="Client security assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["oauth", "client credentials"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="oauth-root", question="What OAuth flow is used?",
            branches=[
                DecisionTreeBranch(condition="Authorization Code Flow (with PKCE)", conclusion="TEST: 1. Code interception via referrer/logs 2. PKCE bypass 3. redirect_uri validation 4. state CSRF"),
                DecisionTreeBranch(condition="Implicit Flow (deprecated)", conclusion="CRITICAL: Access token in URL fragment, token leakage via referrer, no client auth"),
                DecisionTreeBranch(condition="Client Credentials Flow", conclusion="TEST: 1. Client secret strength 2. Secret in client-side code 3. Scope escalation"),
                DecisionTreeBranch(condition="Resource Owner Password Credentials", conclusion="CRITICAL: Direct credential exposure, no refresh token rotation, legacy flow"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="oauth", description="Prioritize redirect URI validation testing", priority_modifier=0.20, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="oauth", description="Prioritize scope escalation testing", priority_modifier=0.15, phase="authorization_analysis"),
        PackPlannerRule(attack_surface="oauth", description="Prioritize CSRF via state parameter", priority_modifier=0.15, phase="authentication_analysis"),
    ],
    references=[{"source": "IETF", "id": "RFC6749", "title": "The OAuth 2.0 Authorization Framework"}, {"source": "OWASP", "id": "OAUTH", "title": "OAuth 2.0 Security Cheat Sheet"}],
    tags=["oauth", "authentication", "authorization"],
)
