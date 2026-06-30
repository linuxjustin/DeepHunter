"""GraphQL API Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="GraphQL",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing GraphQL APIs. Covers introspection, batching attacks, auth bypass, field-level authorization, injection through arguments, and depth/resource exhaustion.",
    supported_technologies=["GraphQL", "Apollo", "Relay", "Hasura"],
    attack_surface_areas=["api", "authentication", "authorization", "input validation", "rate limiting", "graphql"],
    investigation_priority=90,
    related_packs=["REST API", "JWT", "OAuth", "Business Logic"],

    checklists=[
        PackChecklist(
            objective="Perform full GraphQL introspection",
            description="Query GraphQL schema introspection to discover all types, queries, mutations, subscriptions, and fields.",
            procedure="1. POST {\"query\": \"{ __schema { types { name fields { name args { name type { name } } } } } }\"}\n2. POST {\"query\": \"{ __schema { mutationType { fields { name } } } }\"}\n3. Extract all types, queries, and mutations\n4. Check for deprecated or debug fields\n5. Look for fields that indicate admin/internal functionality",
            priority="critical", difficulty="easy",
            required_evidence=["Full GraphQL schema extracted"],
            expected_result="Complete API surface documented",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["graphql", "introspection", "recon"],
        ),
        PackChecklist(
            objective="Test field-level authorization",
            description="Test GraphQL field-level authorization by directly querying fields that should be restricted.",
            procedure="1. From schema, identify sensitive fields (email, roles, isAdmin, password, token)\n2. Query each sensitive field directly\n3. Test aliased queries for field access ({ real: isAdmin, masked: isAdmin })\n4. Test nested object traversal to access protected fields\n5. Use fragments to probe field access control\n6. Compare authenticated vs unauthenticated field availability",
            priority="critical", difficulty="medium",
            required_evidence=["Sensitive field accessible without authorization"],
            expected_result="Field-level authorization assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE, BugClass.PRIVILEGE_ESCALATION],
            tags=["graphql", "authorization", "field-level"],
        ),
        PackChecklist(
            objective="Test GraphQL injection in arguments",
            description="Test for injection vulnerabilities through GraphQL arguments.",
            procedure="1. Identify string/id argument fields\n2. Test SQL injection payloads in string arguments\n3. Test NoSQL injection ($regex, $gt) in arguments\n4. Test command injection in String arguments\n5. Test numeric arguments for integer overflow\n6. Test JSON arguments for deserialization",
            priority="critical", difficulty="hard",
            required_evidence=["Injection through GraphQL argument"],
            expected_result="Injection through GraphQL assessed",
            bug_classes=[BugClass.SQL_INJECTION, BugClass.NO_SQL_INJECTION, BugClass.RCE],
            tags=["graphql", "injection", "arguments"],
        ),
        PackChecklist(
            objective="Test GraphQL batching/resource exhaustion",
            description="Test for GraphQL batching (batched queries) and depth-based denial of service.",
            procedure="1. Send query with maximum depth (10+ nested levels)\n2. Send batched query with many operations in one request\n3. Test alias-based over-fetching (100+ aliases of same field)\n4. Test circular query patterns\n5. Check for query cost analysis implementation\n6. Test pagination field abuse (first: 999999)",
            priority="high", difficulty="easy",
            required_evidence=["Server slowdown or crash from query"],
            expected_result="Resource exhaustion resilience assessed",
            bug_classes=[BugClass.DOS],
            tags=["graphql", "dos", "batching"],
        ),
        PackChecklist(
            objective="Test GraphQL mutation authorization",
            description="Test GraphQL mutations for authorization gaps that allow unauthorized data modification.",
            procedure="1. List all mutations from schema\n2. Identify mutations that modify data (create, update, delete)\n3. Test each mutation without proper auth\n4. Try mutations that belong to different roles/scopes\n5. Test user ID manipulation in mutations\n6. Test input object extra fields for mass assignment\n7. Check mutation responses for sensitive data leakage",
            priority="critical", difficulty="medium",
            required_evidence=["Unauthorized data modification via mutation"],
            expected_result="Mutation authorization assessed",
            bug_classes=[BugClass.AUTH_BYPASS, BugClass.PRIVILEGE_ESCALATION],
            tags=["graphql", "mutations", "authorization"],
        ),
        PackChecklist(
            objective="Test GraphQL information disclosure via errors",
            description="Analyze GraphQL error messages for stack traces, database details, and schema information.",
            procedure="1. Send invalid queries and mutations\n2. Check for detailed error messages with stack traces\n3. Test with invalid arguments (type mismatch)\n4. Send queries with missing required arguments\n5. Enable debug mode testing via GraphQL extensions\n6. Check if GraphQL playground is enabled in production",
            priority="medium", difficulty="easy",
            required_evidence=["Stack trace or DB details in error response"],
            expected_result="Error handling information disclosure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["graphql", "errors"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="graphql-root", question="What GraphQL attack vector to pursue?",
            branches=[
                DecisionTreeBranch(condition="Introspection enabled", conclusion="CRITICAL: Extract full schema, identify all fields/mutations, look for admin/internal fields"),
                DecisionTreeBranch(condition="Sensitive fields found", conclusion="TEST: Field-level authorization, aliased queries, fragment probes"),
                DecisionTreeBranch(condition="Auth mutations present", conclusion="TEST: Mutations without auth, user ID manipulation, mass assignment in input objects"),
                DecisionTreeBranch(condition="No introspection", conclusion="RECON: Dictionary attack for common field names, error-based schema discovery, side-channel analysis"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="graphql", description="Prioritize GraphQL introspection", priority_modifier=0.25, phase="recon"),
        PackPlannerRule(attack_surface="graphql", description="Prioritize mutation authorization testing", priority_modifier=0.15, phase="authorization_analysis"),
        PackPlannerRule(attack_surface="graphql", description="Prioritize injection via arguments", priority_modifier=0.15, phase="input_validation"),
    ],
    references=[{"source": "OWASP", "id": "GRAPHQL", "title": "OWASP GraphQL Security Cheat Sheet", "url": "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"}],
    tags=["graphql", "api", "web"],
)
