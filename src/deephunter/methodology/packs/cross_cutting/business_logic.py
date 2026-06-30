"""Business Logic Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="Business Logic",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing business logic flaws. Covers workflow bypass, race conditions, integer/currency manipulation, coupon abuse, multi-step flow tampering, state transition attacks, and rate limit circumvention.",
    attack_surface_areas=["business logic", "ecommerce", "workflow", "api"],
    investigation_priority=85,
    related_packs=["REST API", "File Upload", "Cloud Review", "Microservices"],

    checklists=[
        PackChecklist(
            objective="Test multi-step workflow bypass",
            description="Test applications with multi-step workflows for step skipping, reordering, and parameter tampering between steps.",
            procedure="1. Map out all steps in the workflow (checkout, registration, password reset)\n2. Attempt to skip steps (POST directly to final step)\n3. Complete steps in wrong order\n4. Modify parameters between steps (price, amount, tier)\n5. Replay individual steps multiple times\n6. Go back to previous step and change values\n7. Test with browser back button during workflow",
            priority="critical", difficulty="medium",
            required_evidence=["Workflow step bypass achieved"],
            expected_result="Multi-step workflow security assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC],
            tags=["business logic", "workflow"],
        ),
        PackChecklist(
            objective="Test race conditions",
            description="Test for race conditions in state-changing operations (coupon usage, fund transfers, inventory).",
            procedure="1. Identify operations that are prone to race conditions\n2. Send multiple concurrent requests to the endpoint\n3. Use race condition tool (Turbo Intruder, Burp Intruder)\n4. Test coupon redemption race (redeem same coupon 10x simultaneously)\n5. Test fund transfer race (send same amount 10x)\n6. Test account creation race\n7. Test likes/votes race (same user voting multiple times)\n8. Test concurrent session edge cases",
            priority="critical", difficulty="hard",
            required_evidence=["Race condition confirmed (duplicate operation)"],
            expected_result="Race condition security assessed",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.BUSINESS_LOGIC],
            tags=["business logic", "race condition"],
        ),
        PackChecklist(
            objective="Test integer/currency manipulation",
            description="Test for integer overflow, underflow, and currency manipulation in financial operations.",
            procedure="1. Test negative quantities (-1, -100)\n2. Test very large numbers (9999999999)\n3. Test decimal manipulation (0.01 vs 0.001)\n4. Test integer overflow (2147483647 + 1)\n5. Test negative prices\n6. Test currency type confusion\n7. Test fractional cent accumulation\n8. Test with maximum precision decimals",
            priority="critical", difficulty="medium",
            required_evidence=["Price manipulation confirmed"],
            expected_result="Integer/currency manipulation assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC],
            tags=["business logic", "integer", "currency"],
        ),
        PackChecklist(
            objective="Test coupon/discount abuse",
            description="Test coupon, discount, and promotional code logic for abuse scenarios.",
            procedure="1. Redeem same coupon code multiple times\n2. Stack multiple coupons/codes\n3. Test expired coupon codes\n4. Test not-yet-active coupon codes\n5. Test coupon code enumeration\n6. Modify coupon value in request\n7. Test coupon with minimum order bypass\n8. Test first-time user coupon from existing accounts\n9. Generate coupon codes via predictable pattern",
            priority="high", difficulty="medium",
            required_evidence=["Coupon abuse confirmed"],
            expected_result="Coupon/discount security assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC],
            tags=["business logic", "coupon"],
        ),
        PackChecklist(
            objective="Test privilege tier/role escalation via logic",
            description="Test business logic flaws that allow users to escalate their privileges bypassing intended restrictions.",
            procedure="1. Identify actions restricted by user tier/role\n2. Test direct access to higher-tier endpoints\n3. Manipulate tier/role parameters in requests\n4. Modify account type during registration/signup\n5. Downgrade from paid plan without losing features\n6. Extend trial period indefinitely\n7. Access features intended for enterprise tier\n8. Bypass feature flags/gates",
            priority="critical", difficulty="medium",
            required_evidence=["Tier escalation achieved"],
            expected_result="Privilege tier security assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC, BugClass.PRIVILEGE_ESCALATION],
            tags=["business logic", "tier", "escalation"],
        ),
        PackChecklist(
            objective="Test state transition enforcement",
            description="Test that application state transitions are properly enforced server-side.",
            procedure="1. Map allowed state transitions (order: pending -> paid -> shipped -> delivered)\n2. Try illegal transitions (pending -> delivered)\n3. Try simultaneous transitions\n4. Go back to earlier state\n5. Check if state transitions are validated server-side\n6. Test with multiple tabs on same workflow\n7. Check for TOCTOU in state-dependent operations",
            priority="high", difficulty="hard",
            required_evidence=["Illegal state transition confirmed"],
            expected_result="State transition enforcement assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC],
            tags=["business logic", "state", "workflow"],
        ),
        PackChecklist(
            objective="Test rate limiting circumvention",
            description="Test rate limiting for bypass via various techniques.",
            procedure="1. Test IP-based rate limiting with X-Forwarded-For header spoofing\n2. Test with different HTTP methods\n3. Test with different User-Agents\n4. Test slow-rate attacks (just below limit)\n5. Test distributed attacks (spread across many IPs)\n6. Test rate limit reset behavior\n7. Test account lockout bypass (password reset, lockout timer)\n8. Test concurrent requests before rate limit is applied",
            priority="high", difficulty="medium",
            required_evidence=["Rate limiting bypassed"],
            expected_result="Rate limiting effectiveness assessed",
            bug_classes=[BugClass.RATE_LIMIT_BYPASS],
            tags=["business logic", "rate limiting"],
        ),
        PackChecklist(
            objective="Test mass assignment/parameter manipulation in logic operations",
            description="Test for crucial business logic parameters that can be manipulated via request modification.",
            procedure="1. Identify all parameters in business operations (checkout, transfer, subscription)\n2. Modify parameters that should be server-side enforced (shipping cost, tax, discount)\n3. Add extra parameters not expected (tip, handling_fee)\n4. Remove parameters to skip validation\n5. Manipulate boolean flags (isPaid, verified, confirmed)\n6. Change subscription interval/billing frequency",
            priority="critical", difficulty="medium",
            required_evidence=["Business parameter manipulation confirmed"],
            expected_result="Business parameter security assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC],
            tags=["business logic", "parameter manipulation"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="bizlogic-root", question="What business logic aspect to test?",
            branches=[
                DecisionTreeBranch(condition="Multi-step flow (checkout, registration)", conclusion="TEST: 1. Step skipping 2. Parameter modification between steps 3. Step replay 4. Back button manipulation"),
                DecisionTreeBranch(condition="Financial operations (payments, transfers)", conclusion="TEST: 1. Negative numbers 2. Integer overflow 3. Race conditions 4. Currency rounding"),
                DecisionTreeBranch(condition="Coupon/codes system", conclusion="TEST: 1. Multiple use 2. Stacking 3. Enumeration 4. Expired code 5. Value modification"),
                DecisionTreeBranch(condition="User tier/role system", conclusion="TEST: 1. Direct endpoint access 2. Tier param manipulation 3. Trial extension"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="business logic", description="Prioritize workflow bypass testing", priority_modifier=0.20, phase="business_logic_analysis"),
        PackPlannerRule(attack_surface="business logic", description="Prioritize race condition testing", priority_modifier=0.20, phase="business_logic_analysis"),
        PackPlannerRule(attack_surface="business logic", description="Prioritize integer/currency manipulation", priority_modifier=0.15, phase="business_logic_analysis"),
    ],
    references=[
        {"source": "OWASP", "id": "WSTG-BUSL", "title": "Business Logic Testing Guide", "url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"},
    ],
    tags=["business logic", "workflow", "ecommerce"],
)
