"""JWT Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="JWT",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing JSON Web Token implementations. Covers algorithm confusion, key confusion, KID injection, weak secret brute force, claim manipulation, and JWK/JKU header attacks.",
    attack_surface_areas=["authentication", "authorization", "api"],
    investigation_priority=95,
    related_packs=["OAuth", "OIDC", "REST API", "Session Management"],

    checklists=[
        PackChecklist(
            objective="Test algorithm confusion (alg=none)",
            description="Test if JWT library accepts 'none' algorithm or allows attacker-chosen algorithm.",
            procedure="1. Decode the JWT header\n2. Set alg to 'none'\n3. Set signature to empty\n4. Modify payload claims (sub, role, iat)\n5. Send modified JWT to server\n6. Try variations: None, NONE, nOnE, none, NoneAlgorithm\n7. Try without signature part (header.payload.)",
            priority="critical", difficulty="easy",
            required_evidence=["Modified JWT with no algorithm accepted"],
            expected_result="Algorithm confusion vulnerability confirmed or ruled out",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["jwt", "algorithm"], dependencies=["Capture and decode JWT"],
        ),
        PackChecklist(
            objective="Test RS256 to HS256 key confusion",
            description="Test if server's public key can be used as HMAC secret to forge valid tokens.",
            procedure="1. Obtain the server's public RSA key (from well-known/jwks.json, common endpoint)\n2. Change JWT header alg from RS256 to HS256\n3. Sign the modified token using the public key as HMAC secret\n4. Send forged token to server\n5. Try other RS signing variants (RS384, RS512 to HS384, HS512)",
            priority="critical", difficulty="medium",
            required_evidence=["HS256 token signed with public key accepted"],
            expected_result="Key confusion vulnerability assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["jwt", "key confusion"], dependencies=["Obtain public key"],
        ),
        PackChecklist(
            objective="Test KID header injection",
            description="Test JWT Key ID (kid) header for injection vulnerabilities (SQLi, path traversal, command injection).",
            procedure="1. Extract kid value from JWT header\n2. Test SQL injection in kid: ' UNION SELECT 'secret'--\n3. Test path traversal in kid: ../../../../etc/passwd\n4. Test command injection if kid is used in shell command\n5. Test null/empty kid\n6. Test array kid: ['key1', 'key2']\n7. Test kid with special characters (newlines, null bytes)",
            priority="critical", difficulty="hard",
            required_evidence=["Injection via kid header successful"],
            expected_result="KID injection assessed",
            bug_classes=[BugClass.SQL_INJECTION, BugClass.PATH_TRAVERSAL, BugClass.RCE],
            tags=["jwt", "kid", "injection"],
        ),
        PackChecklist(
            objective="Test weak HMAC secret brute force",
            description="Brute force the JWT HMAC secret if the token uses a symmetric signing algorithm.",
            procedure="1. Capture a JWT with HS256/HS384/HS512 algorithm\n2. Use jwt_tool, hashcat, or JohnTheRipper\n3. Brute force with common weak passwords (secret, password, 123456)\n4. Test with framework default secrets (django-secret-key, jwt_secret)\n5. Test with application name and domain as secret\n6. Try rockyou/top 1000 password lists",
            priority="critical", difficulty="medium",
            required_evidence=["JWT secret recovered"],
            expected_result="JWT secret strength assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["jwt", "brute force", "secret"],
        ),
        PackChecklist(
            objective="Test JWK/JKU header injection",
            description="Test if JWT library accepts embedded JWK (jwk header) or JWK Set URL (jku header) for key retrieval.",
            procedure="1. Add jwk header with attacker-generated RSA key\n2. Sign payload with attacker's private key\n3. Send JWT with embedded JWK\n4. Try jku header pointing to attacker-controlled JWKS endpoint\n5. Test x5u, x5c certificate chain embedding\n6. Test crit header (critical) bypass",
            priority="critical", difficulty="hard",
            required_evidence=["Attacker's JWK-embedded JWT accepted"],
            expected_result="JWK/JKU injection assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["jwt", "jwk", "jku"],
        ),
        PackChecklist(
            objective="Test JWT claim manipulation",
            description="Test modifying JWT claims (sub, role, iat, exp, aud, iss) for authorization bypass.",
            procedure="1. Decode JWT and examine all claims\n2. Modify sub to a different user ID\n3. Add/modify role/isAdmin to escalated privileges\n4. Set exp to far future date\n5. Remove/modify iat or nbf\n6. Change aud to different audience\n7. Modify iss to different issuer\n8. Test for large payload buffer overflow",
            priority="high", difficulty="medium",
            required_evidence=["Modified claims accepted without signature verification"],
            expected_result="Claim manipulation assessment",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["jwt", "claims"],
        ),
        PackChecklist(
            objective="Test JWT token lifecycle",
            description="Test token expiration, refresh token rotation, and token revocation.",
            procedure="1. Check token expiration enforcement (use expired token)\n2. Check if token can be used before nbf (not before)\n3. Test refresh token rotation (can refresh token be reused)\n4. Test token revocation (logout, password change)\n5. Check for token reuse in different contexts\n6. Test token on multiple concurrent sessions\n7. Check if token carries session state that shouldn't be there",
            priority="high", difficulty="medium",
            required_evidence=["Expired/revoked token accepted"],
            expected_result="Token lifecycle security assessed",
            bug_classes=[BugClass.BROKEN_AUTH],
            tags=["jwt", "lifecycle", "expiration"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="jwt-root", question="What JWT attack vector to test?",
            branches=[
                DecisionTreeBranch(condition="JWT header has alg", conclusion="TEST: 1. alg:none 2. alg:HS256 (if RS256 expected) 3. kid injection 4. jwk/jku injection"),
                DecisionTreeBranch(condition="Public key discovered", conclusion="CRITICAL: Test RS256->HS256 key confusion immediately"),
                DecisionTreeBranch(condition="HS256 algorithm", conclusion="TEST: 1. Weak secret brute force 2. Common secrets dictionary"),
                DecisionTreeBranch(condition="KID header present", conclusion="TEST: 1. SQL injection 2. Path traversal 3. Directory traversal for key file"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="jwt", description="Prioritize algorithm confusion (alg=none) testing", priority_modifier=0.25, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="jwt", description="Prioritize key confusion (RS->HS) testing", priority_modifier=0.20, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="jwt", description="Prioritize KID injection testing", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(attack_surface="jwt", description="Prioritize JWK/JKU injection testing", priority_modifier=0.15, phase="authentication_analysis"),
    ],
    references=[
        {"source": "CWE", "id": "CWE-347", "title": "Improper Verification of Cryptographic Signature"},
        {"source": "OWASP", "id": "JWT", "title": "JSON Web Token Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html"},
    ],
    tags=["jwt", "authentication", "token"],
)
