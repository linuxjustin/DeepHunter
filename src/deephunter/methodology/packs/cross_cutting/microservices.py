"""Microservices Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="Microservices",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for testing microservice-based architectures. Covers service-to-service trust, API gateway bypass, service mesh security, inter-service authentication, data consistency, and distributed tracing exposure.",
    attack_surface_areas=["api", "authentication", "authorization", "infrastructure", "configuration"],
    investigation_priority=75,
    related_packs=["REST API", "Cloud Review", "GraphQL", "JWT"],

    checklists=[
        PackChecklist(
            objective="Map service topology and inter-service communication",
            description="Identify microservice boundaries, service discovery, and communication patterns.",
            procedure="1. Check for API gateway patterns (Kong, Traefik, Nginx, Envoy)\n2. Identify Service Mesh (Istio, Linkerd, Consul)\n3. Check for service discovery endpoints (Consul, etcd, Eureka)\n4. Identify inter-service communication patterns (HTTP, gRPC, message queues)\n5. Look for service-specific subdomains or paths\n6. Review response headers for internal service names\n7. Check for service version headers (X-Service-Version, X-API-Version)\n8. Look for error messages revealing internal architecture",
            priority="high", difficulty="medium",
            required_evidence=["Service architecture map created"],
            expected_result="Service topology documented",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["microservices", "architecture", "recon"],
        ),
        PackChecklist(
            objective="Test API gateway bypass",
            description="Test for direct service access bypassing the API gateway.",
            procedure="1. Identify API gateway endpoints\n2. Try bypassing gateway by accessing internal service directly\n3. Test subdomain enumeration for internal services\n4. Test exposed ports (8080, 8081, 3000, 5000, 9000)\n5. Use X-Forwarded-For, X-Real-IP to bypass gateway restrictions\n6. Try different host headers to route to internal services\n7. Access hidden API paths (/internal, /admin, /private)\n8. Test HTTP version downgrade",
            priority="critical", difficulty="hard",
            required_evidence=["Direct service access without gateway"],
            expected_result="API gateway bypass assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["microservices", "gateway", "bypass"],
        ),
        PackChecklist(
            objective="Test inter-service authentication",
            description="Test that inter-service communication has proper authentication and does not trust internal requests blindly.",
            procedure="1. Check for internal auth tokens in service-to-service calls\n2. Test if internal endpoints trust X-Forwarded-For or similar\n3. Check if internal services validate auth on every request\n4. Test replay of inter-service tokens\n5. Check if expired service tokens are accepted\n6. Review internal API authentication bypass\n7. Test service-to-service auth with forged internal headers",
            priority="critical", difficulty="hard",
            required_evidence=["Inter-service auth bypass confirmed"],
            expected_result="Inter-service authentication assessed",
            bug_classes=[BugClass.AUTH_BYPASS],
            tags=["microservices", "authentication", "internal"],
        ),
        PackChecklist(
            objective="Test distributed tracing exposure",
            description="Check distributed tracing systems (Jaeger, Zipkin, OpenTelemetry) for data exposure.",
            procedure="1. Check for tracing endpoints /jaeger, /zipkin, /api/traces\n2. Access Jaeger UI for trace querying\n3. Access Zipkin UI for trace analysis\n4. Check if traces contain sensitive request data\n5. Test trace injection via headers (uber-trace-id, x-b3-traceid)\n6. Check for unsecured trace export endpoints\n7. Extract sensitive data from traces (auth tokens, API keys, PII)",
            priority="high", difficulty="easy",
            required_evidence=["Distributed trace data exposed"],
            expected_result="Tracing exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["microservices", "tracing", "jaeger", "zipkin"],
        ),
        PackChecklist(
            objective="Test data consistency vulnerabilities",
            description="Test for business logic flaws in data consistency between services (eventual consistency exploits).",
            procedure="1. Identify operations that span multiple services\n2. Test concurrent operations that create inconsistent state\n3. Cancel transaction in one service but not another\n4. Exploit race conditions due to asynchronous processing\n5. Trigger error in one service mid-transaction\n6. Test timeout behavior between services\n7. Check compensating transaction implementation\n8. Test stale data reads after incomplete writes",
            priority="high", difficulty="hard",
            required_evidence=["Data inconsistency exploitable"],
            expected_result="Data consistency assessed",
            bug_classes=[BugClass.BUSINESS_LOGIC, BugClass.RACE_CONDITION],
            tags=["microservices", "consistency", "transactions"],
        ),
        PackChecklist(
            objective="Check service mesh and sidecar configuration",
            description="Review service mesh (Istio, Linkerd) configuration for security gaps.",
            procedure="1. Check for Istio sidecar injection in application endpoints\n2. Check mTLS enforcement between services\n3. Review authorization policies (K8s NetworkPolicy, Istio AuthorizationPolicy)\n4. Check for permissive mTLS mode (PERMISSIVE vs STRICT)\n5. Review rate limiting and circuit breaker configuration\n6. Check for excessive service-to-service permissions\n7. Check service mesh dashboard exposure (Kiali, Grafana)",
            priority="medium", difficulty="medium",
            required_evidence=["Service mesh configuration weakness"],
            expected_result="Service mesh security assessed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION],
            tags=["microservices", "service mesh", "istio"],
        ),
        PackChecklist(
            objective="Test service discovery and registry exposure",
            description="Check service discovery and registry systems for information disclosure and unauthorized access.",
            procedure="1. Check for Consul UI, etcd manager endpoints\n2. Access /v1/agent/services, /v1/catalog/services (Consul)\n3. Check for K8s API server exposure\n4. Access /api/v1/namespaces, /api/v1/pods (K8s)\n5. Check for unsecured registries (Docker registry, ECR)\n6. Test if service registration is unauthenticated\n7. Extract service addresses and port numbers",
            priority="high", difficulty="medium",
            required_evidence=["Service registry exposed"],
            expected_result="Service discovery security assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["microservices", "discovery", "kubernetes", "consul"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="ms-root", question="What microservice aspect to test?",
            branches=[
                DecisionTreeBranch(condition="API gateway present", conclusion="TEST: 1. Gateway bypass via host header 2. Direct service access 3. Internal path exposure"),
                DecisionTreeBranch(condition="Distributed tracing", conclusion="CHECK: 1. Tracing UI access 2. Sensitive data in traces 3. Trace injection"),
                DecisionTreeBranch(condition="Service mesh", conclusion="REVIEW: 1. mTLS mode 2. Auth policies 3. Sidecar config 4. Dashboard exposure"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="microservices", description="Prioritize service topology mapping", priority_modifier=0.15, phase="recon"),
        PackPlannerRule(attack_surface="microservices", description="Prioritize API gateway bypass testing", priority_modifier=0.20, phase="authentication_analysis"),
        PackPlannerRule(attack_surface="microservices", description="Prioritize inter-service authentication testing", priority_modifier=0.15, phase="authentication_analysis"),
    ],
    references=[{"source": "OWASP", "id": "MICRO", "title": "OWASP Microservices Security"}],
    tags=["microservices", "architecture", "infrastructure"],
)
