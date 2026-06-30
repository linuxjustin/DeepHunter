"""Race Conditions Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch,
    DecisionTreeNode,
    MethodologyPack,
    PackCategory,
    PackChecklist,
    PackPlannerRule,
)


PACK = MethodologyPack(
    name="Race Conditions",
    version="1.0.0",
    category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for detecting and exploiting race condition vulnerabilities. Covers time-of-check to time-of-use (TOCTOU) attacks, concurrent request manipulation, session racing, and state-based exploitation in multi-threaded applications.",
    supported_technologies=["Any web framework with concurrent request handling"],
    attack_surface_areas=["race-condition", "toctou", "concurrent", "stateless-protocol", "state-manipulation"],
    investigation_priority=90,
    related_packs=["Business Logic", "Authentication", "SSRF", "IDOR"],

    checklists=[
        PackChecklist(
            objective="Identify state-changing operations vulnerable to race conditions",
            description="Find operations that rely on sequential read-write cycles without proper locking or atomicity.",
            procedure="1. Look for operations involving: balance transfers, vote counting, stock updates, coupon usage, OTP verification, PIN entry, password reset token use, API rate counters\n2. Identify read-modify-write sequences: read value -> modify -> write back\n3. Look for operations without database transactions or row-level locking\n4. Check for in-memory state that persists across requests (caches, session variables)\n5. Look for file operations: read file -> modify -> write file (especially in multi-process servers)\n6. Identify OTP, token, and nonce reuse scenarios",
            priority="critical",
            difficulty="medium",
            required_evidence=["List of potential race condition entry points"],
            expected_result="All TOCTOU/race condition entry points identified",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.BUSINESS_LOGIC],
            tags=["race-condition", "toctou", "concurrency", "state"],
        ),
        PackChecklist(
            objective="Test race conditions with concurrent requests",
            description="Send simultaneous overlapping requests to exploit TOCTOU vulnerabilities.",
            procedure="1. Use Burp Suite Turbo Intruder or parallel curl requests\n2. Send 5-10 concurrent requests to same endpoint within same millisecond\n3. Test balance transfer: initiate two transfers simultaneously\n4. Test coupon use: apply same coupon twice simultaneously\n5. Test OTP reuse: send same OTP with 2 concurrent requests\n6. Test rate limit: send N+1 concurrent requests when limit is N\n7. Use HTTP/1.1 pipelining or HTTP/2 multiplexing for true concurrency\n8. Tools: Turbo Intruder, wfuzz -Z, httpx -x, parallel curl",
            priority="critical",
            difficulty="hard",
            required_evidence=["Race condition confirmed: unintended state or double-use"],
            expected_result="Race condition exploited — unintended state achieved",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.BUSINESS_LOGIC],
            tags=["race-condition", "concurrent", "exploitation", "turbo-intruder"],
        ),
        PackChecklist(
            objective="Test session race conditions and fixation",
            description="Test for race conditions in session handling that can lead to session hijacking or fixation.",
            procedure="1. Create session, then quickly authenticate while holding the session\n2. Send multiple auth requests with same session ID to see if race creates duplicate sessions\n3. Check session fixation during login: does server reject or accept both logins?\n4. Test session token reuse across multiple concurrent logins\n5. Check session state on server for concurrent access issues\n6. Look for session locking on server — does concurrent access cause corruption?",
            priority="high",
            difficulty="hard",
            required_evidence=["Session corruption, fixation, or token reuse"],
            expected_result="Session race condition found",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.BROKEN_AUTH],
            tags=["race-condition", "session", "auth", "concurrent"],
        ),
        PackChecklist(
            objective="Test TOCTOU in file operations",
            description="Find time-of-check to time-of-use vulnerabilities in file operations.",
            procedure="1. Upload file -> check extension -> write file: can attacker swap file between check and write?\n2. Read file permissions -> check if writable -> write: can attacker modify permissions between?\n3. Check if server creates temp files with predictable names\n4. Look for symlink attacks: does application write to user-supplied paths?\n5. Check if uploaded files are executed or included after writing\n6. Tools: racepwn, python threading with symlinks",
            priority="high",
            difficulty="hard",
            required_evidence=["TOCTOU file operation exploited"],
            expected_result="File-based TOCTOU vulnerability confirmed",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.PATH_TRAVERSAL],
            tags=["race-condition", "toctou", "file", "symlink"],
        ),
        PackChecklist(
            objective="Test race conditions in authentication and authorization",
            description="Exploit race conditions in login, password reset, and access control.",
            procedure="1. Password reset race: request reset for two different users simultaneously with same token\n2. Login race: attempt two concurrent logins with wrong password to see if lockout is applied\n3. OTP/2FA race: send same OTP twice simultaneously to check if both accepted\n4. Privilege escalation race: concurrently modify own role field while making admin request\n5. Token generation race: can two requests get the same JWT or session ID?\n6. Brute-force race: send N attempts simultaneously when rate limit is N",
            priority="high",
            difficulty="hard",
            required_evidence=["Auth/authz race condition exploited"],
            expected_result="Authentication race condition confirmed",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.AUTH_BYPASS],
            tags=["race-condition", "authentication", "brute-force", "2fa"],
        ),
        PackChecklist(
            objective="Test race conditions in financial operations",
            description="Detect race conditions in money transfers, gift cards, coupons, and inventory.",
            procedure="1. Transfer money: send $100 when balance is $100, twice simultaneously\n2. Gift card balance: redeem same code twice at exact same time\n3. Coupon: apply same coupon code simultaneously when limit is 1\n4. Stock/inventory: buy 1 item when only 1 in stock, twice simultaneously\n5. Gift card balance check: balance inquiry during redemption\n6. Try double-spending with cryptocurrency or payment systems\n7. Tools: Turbo Intruder, parallel curl, Python threading with asyncio",
            priority="critical",
            difficulty="hard",
            required_evidence=["Financial race condition exploited (money/inventory discrepancy)"],
            expected_result="Financial race condition found",
            bug_classes=[BugClass.RACE_CONDITION, BugClass.BUSINESS_LOGIC],
            tags=["race-condition", "finance", "payment", "inventory"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="race-root",
            question="What race condition type?",
            branches=[
                DecisionTreeBranch(
                    condition="Financial operation (transfer, purchase, coupon)",
                    conclusion="TEST: 1. Send 2+ concurrent requests 2. Use Turbo Intruder with multiple threads 3. Verify double-execution 4. Measure financial impact",
                ),
                DecisionTreeBranch(
                    condition="Authentication/authorization",
                    conclusion="TEST: 1. Concurrent login/reset/auth requests 2. Test with same OTP/token 3. Test privilege modification during request 4. Measure auth bypass",
                ),
                DecisionTreeBranch(
                    condition="File upload or access",
                    conclusion="TEST: 1. Upload file with symlink to target 2. Swap file between check and write 3. Race on temp file creation 4. Measure file access",
                ),
                DecisionTreeBranch(
                    condition="Rate limit or quota",
                    conclusion="TEST: 1. Send N+1 concurrent requests when limit is N 2. Test concurrent OTP attempts 3. Verify limit bypassed",
                ),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="race-condition", description="Prioritize race condition testing on financial operations (transfers, coupons, inventory)", priority_modifier=0.30, phase="exploitation"),
        PackPlannerRule(attack_surface="race-condition", description="Use concurrent request tools (Turbo Intruder) for race condition testing", priority_modifier=0.20, phase="exploitation"),
        PackPlannerRule(attack_surface="race-condition", description="Test race conditions on any read-modify-write sequence without transaction locking", priority_modifier=0.20, phase="input_validation"),
    ],

    references=[
        {"source": "OWASP", "id": "RC", "title": "Race Conditions", "url": "https://owasp.org/www-community/vulnerabilities/Race_conditions"},
        {"source": "PortSwigger", "id": "RC2", "title": "Race Conditions", "url": "https://portswigger.net/web-security/race-conditions"},
        {"source": "Google", "id": "RCP", "title": "Race Condition Puzzles", "url": "https://google.github.io/eng/tools/race-condition-puzzles/"},
    ],
    tags=["race-condition", "concurrent", "toctou", "business-logic"],
)