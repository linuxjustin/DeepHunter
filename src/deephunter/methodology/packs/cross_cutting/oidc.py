"""OpenID Connect Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="OIDC",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing OpenID Connect implementations. Covers ID token validation, userinfo endpoint security, claim manipulation, token confusion, and SSO integration review.",
    attack_surface_areas=["authentication", "authorization", "sso", "oidc"],
    investigation_priority=90,
    related_packs=["OAuth", "JWT", "Session Management"],

    checklists=[
        PackChecklist(
            objective="Test ID token validation",
            description="Test OpenID Connect ID token validation for signature verification, expiry, and issuer checks.",
            procedure="1. Capture ID token JWT from OIDC flow\n2. Decode and inspect JWT header (alg, kid, typ, iss)\n3. Change alg to 'none' and modify claims\n4. Try RS256 to HS256 key confusion\n5. Modify iss to attacker domain\n6. Remove or modify aud claim\n7. Modify exp to far future date\n8. Modify sub claim to impersonate user",
            priority="critical", difficulty="hard",
            required_evidence=["Modified ID token accepted"],
            expected_result="ID token validation assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["oidc", "jwt", "id_token"],
        ),
        PackChecklist(
            objective="Test userinfo endpoint security",
            description="Test OIDC userinfo endpoint for proper authentication and data access controls.",
            procedure="1. Access /userinfo without access token\n2. Use access token from different user at userinfo\n3. Test expired/revoked tokens at userinfo\n4. Check userinfo response for sensitive claims (email_verified, phone, address)\n5. Test token vs userinfo claim discrepancy\n6. Check for userinfo caching issues",
            priority="high", difficulty="medium",
            required_evidence=["Userinfo accessible with wrong/invalid token"],
            expected_result="Userinfo endpoint security assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.AUTH_BYPASS],
            tags=["oidc", "userinfo"],
        ),
        PackChecklist(
            objective="Test claim manipulation",
            description="Test for OIDC claim manipulation to escalate privileges or impersonate users.",
            procedure="1. Identify all available claims from ID token and userinfo\n2. Add custom claims to auth request (claims parameter)\3. Test essential vs voluntary claims handling\n4. Test for claim injection via acr_values or ui_locales\n5. Check claims parameter maximal size\n6. Test claims_locale manipulation",
            priority="high", difficulty="hard",
            required_evidence=["Unauthorized claims added to token"],
            expected_result="Claim security assessed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION],
            tags=["oidc", "claims"],
        ),
        PackChecklist(
            objective="Test token confusion (access token vs ID token)",
            description="Test if resource server accepts ID tokens where access tokens are expected.",
            procedure="1. Capture both ID token and access token from OIDC flow\n2. Submit ID token to API endpoint that expects access token\n3. Check if ID token's claims are trusted as authorization\n4. Try using the other token type for different operations",
            priority="critical", difficulty="medium",
            required_evidence=["ID token accepted as access token by resource server"],
            expected_result="Token confusion assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["oidc", "token confusion"],
        ),
        PackChecklist(
            objective="Test SSO logout security",
            description="Test OIDC single logout (SLO) and session management for proper termination.",
            procedure="1. Initiate OIDC login and establish session\n2. Perform RP-initiated logout (end_session_endpoint)\n3. Check if id_token_hint validation is enforced\n4. Test logout without required parameters\n5. Check if SSO session terminates at OP\n6. Test post_logout_redirect_uri validation\n7. Verify session clearing on all RP instances",
            priority="medium", difficulty="medium",
            required_evidence=["Logout incomplete or bypassable"],
            expected_result="Logout implementation assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["oidc", "logout", "session"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="oidc-root", question="What OIDC component to test?",
            branches=[
                DecisionTreeBranch(condition="ID token present", conclusion="TEST: 1. alg=none 2. Key confusion 3. Claim modification 4. Token reuse across providers"),
                DecisionTreeBranch(condition="userinfo endpoint", conclusion="TEST: 1. Unauthenticated access 2. Cross-user access 3. Claim inconsistency"),
                DecisionTreeBranch(condition="RP-initiated logout", conclusion="TEST: 1. post_logout_redirect_uri validation 2. id_token_hint requirement 3. Complete session termination"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="oidc", description="Prioritize ID token validation testing", priority_modifier=0.20, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="oidc", description="Prioritize token confusion testing", priority_modifier=0.15, phase="authentication_analysis"),
    ],
    references=[{"source": "IETF", "id": "OIDC", "title": "OpenID Connect Core 1.0", "url": "https://openid.net/specs/openid-connect-core-1_0.html"}],
    tags=["oidc", "sso", "authentication"],
)
