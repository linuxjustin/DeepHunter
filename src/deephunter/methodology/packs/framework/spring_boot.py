"""Spring Boot Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch,
    DecisionTreeNode,
    MethodologyPack,
    PackCategory,
    PackChecklist,
    PackFrameworkProfile,
    PackPlannerRule,
)

PACK = MethodologyPack(
    name="Spring Boot",
    version="1.0.0",
    category=PackCategory.FRAMEWORK,
    description="Expert methodology for testing Spring Boot applications. Covers Actuator exposure, SpEL injection, JPA injection, Jackson deserialization, method security, and autoconfiguration review.",
    supported_technologies=["Spring Boot", "Java", "Spring"],
    supported_frameworks=["Spring Boot"],
    supported_languages=["Java", "Kotlin"],
    attack_surface_areas=["authentication", "authorization", "api", "input validation", "actuator", "deserialization", "configuration", "database"],
    investigation_priority=85,
    related_packs=["JWT", "REST API", "OAuth", "Session Management"],

    profile=PackFrameworkProfile(
        architecture_description="Spring Boot auto-configuration with embedded Tomcat/Netty, Spring Security filter chain, AOP proxies, and Actuator endpoints.",
        authentication_components=["Spring Security filter chain", "JWT (jjwt/nimbus-jose)", "OAuth2/OIDC with Spring Security", "Session-based JSESSIONID", "Basic auth", "PreAuthorize annotations"],
        authorization_components=["@PreAuthorize / @PostAuthorize", "@Secured / @RolesAllowed", "Security annotation AOP proxies", "MethodSecurityExpressionHandler"],
        api_layer="Spring MVC @RestController, Spring Data REST, Spring Cloud Gateway, OpenAPI/Swagger auto-generation",
        trust_boundaries=["Controller interceptor boundary", "Method security AOP proxy boundary", "Spring Security filter chain boundary", "JSON serialization (Jackson) boundary"],
        investigation_areas=[
            "Actuator exposure (/actuator/env, /actuator/heapdump, /actuator/loggers)",
            "SpEL injection in @PreAuthorize expressions",
            "JPA/Hibernate injection (native queries, SpEL in @Query)",
            "Jackson polymorphic deserialization",
            "Method security annotation bypass",
            "CORS misconfiguration",
            "DevTools classloader deserialization",
            "Swagger/OpenAPI endpoint exposure",
            "X-Forwarded-For header trust",
        ],
    ),

    workflow=[
        "Spring Boot Identified",
        "Actuator Endpoint Enumeration",
        "Actuator Data Analysis",
        "Authentication Configuration Review",
        "Method Security Analysis",
        "SpEL Injection Testing",
        "JPA Repository Injection Testing",
        "Jackson Deserialization Testing",
        "OpenAPI/Swagger Review",
        "CORS and Header Review",
        "Evidence Collection",
    ],

    checklists=[
        PackChecklist(
            objective="Enumerate and exploit Actuator endpoints",
            description="Scan for exposed Spring Boot Actuator endpoints to extract env, heap dump, loggers, and thread dumps.",
            procedure="1. Scan /actuator, /actuator/env, /actuator/heapdump, /actuator/loggers\n2. Check /actuator/env for secrets, API keys, database passwords\n3. Download /actuator/heapdump and extract credentials\n4. Check /actuator/loggers for log level changes\n5. Check /actuator/threaddump for sensitive data\n6. Test /actuator/shutdown if enabled",
            priority="critical", difficulty="easy",
            required_evidence=["Actuator index JSON", "Environment variables with secrets", "Heap dump downloaded"],
            expected_result="Actuator exposure identified and data extracted",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["spring", "actuator", "exposure", "recon"],
        ),
        PackChecklist(
            objective="Test SpEL injection in annotations",
            description="Find SpEL expressions in @PreAuthorize and @PostAuthorize that evaluate user-controlled input.",
            procedure="1. Search for @PreAuthorize with string concatenation or user input\n2. Test {#param} and {#result} expressions\n3. Inject SpEL payloads in method parameters\n4. Test custom MethodSecurityExpressionHandler implementations",
            priority="critical", difficulty="hard",
            required_evidence=["SpEL expression execution proof"],
            expected_result="SpEL injection confirmed or ruled out",
            bug_classes=[BugClass.RCE],
            tags=["spring", "spel", "expression injection"],
        ),
        PackChecklist(
            objective="Test Jackson deserialization",
            description="Find polymorphic Jackson deserialization that can lead to RCE via gadget chains.",
            procedure="1. Check for @JsonTypeInfo on interfaces/abstract classes\n2. Test @JsonSubTypes for available implementation classes\n3. Send unexpected @class values in JSON payloads\n4. Test for default typing enabled\n5. Check for known gadget chain classes (Runtime, ProcessBuilder)",
            priority="critical", difficulty="hard",
            required_evidence=["Deserialization gadget chain triggered"],
            expected_result="Jackson deserialization vulnerability confirmed or ruled out",
            bug_classes=[BugClass.DESERIALIZATION, BugClass.RCE],
            tags=["spring", "jackson", "deserialization"],
        ),
        PackChecklist(
            objective="Review method security annotations",
            description="Review @PreAuthorize, @PostAuthorize, @Secured annotations for misconfiguration and bypass scenarios.",
            procedure="1. List all annotated service methods\n2. Check for @PreAuthorize(\"permitAll\") on sensitive methods\n3. Verify expression correctness\n4. Check for role hierarchy bypass\n5. Test AOP proxy bypass via self-invocation",
            priority="high", difficulty="medium",
            required_evidence=["Access to method without proper role"],
            expected_result="Method security configuration reviewed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION],
            tags=["spring", "security", "annotations"],
        ),
        PackChecklist(
            objective="Review CORS configuration",
            description="Check for overly permissive CORS policies that allow cross-origin data theft.",
            procedure="1. Identify @CrossOrigin annotations and WebMvcConfigurer CORS mappings\n2. Check for allowOrigins=\"*\"\n3. Test with custom Origin header reflecting\n4. Check allowedMethods and allowedHeaders\n5. Test preflight caching behavior",
            priority="high", difficulty="easy",
            required_evidence=["CORS header reflecting any origin"],
            expected_result="CORS configuration documented",
            bug_classes=[BugClass.CORS_MISCONFIG],
            tags=["spring", "cors", "headers"],
        ),
        PackChecklist(
            objective="Test JPA/Hibernate injection",
            description="Find JPA repository methods using native queries, SpEL in @Query, or unsafe sorting/filtering.",
            procedure="1. Search for @Query with nativeQuery=true\n2. Check for #{#entityName} SpEL in @Query\n3. Test Sort objects from user input\n4. Check Specification and Example matchers for injection\n5. Test LIKE operators with user-controlled wildcards",
            priority="critical", difficulty="hard",
            required_evidence=["SQL injection via JPA payload"],
            expected_result="JPA injection confirmed or ruled out",
            bug_classes=[BugClass.SQL_INJECTION],
            tags=["spring", "jpa", "hibernate", "sql injection"],
        ),
        PackChecklist(
            objective="Review OpenAPI/Swagger exposure",
            description="Check if Swagger UI or OpenAPI spec is exposed in production, revealing full API surface.",
            procedure="1. Check /swagger-ui.html, /swagger-ui/, /v3/api-docs, /v2/api-docs\n2. Extract all endpoint definitions from OpenAPI spec\n3. Identify endpoints without security requirements\n4. Check for request/response schema information disclosure\n5. Test API key in documentation",
            priority="medium", difficulty="easy",
            required_evidence=["OpenAPI spec accessible", "Endpoint list without auth"],
            expected_result="API surface documented from Swagger exposure",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["spring", "swagger", "openapi", "api"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="spring-root",
            question="What Spring Boot component to investigate?",
            branches=[
                DecisionTreeBranch(
                    condition="Actuator endpoints accessible",
                    conclusion="ACTIONS: 1. Dump env vars (secrets, keys, passwords) 2. Download heap dump 3. Change log levels via /actuator/loggers 4. Check /actuator/health for database info 5. Try /actuator/shutdown",
                ),
                DecisionTreeBranch(
                    condition="Method security annotations used",
                    child=DecisionTreeNode(
                        id="spring-method-security",
                        question="What annotation pattern?",
                        branches=[
                            DecisionTreeBranch(condition="SpEL in annotations", conclusion="TEST: SpEL injection in @PreAuthorize expressions with user-controlled input"),
                            DecisionTreeBranch(condition="Role-based (@Secured)", conclusion="TEST: Role hierarchy bypass, annotation missing on key methods"),
                        ],
                    ),
                ),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(technology="Spring Boot", description="Prioritize Actuator endpoint enumeration", priority_modifier=0.20, phase="recon"),
        PackPlannerRule(technology="Spring Boot", description="Prioritize SpEL injection testing", priority_modifier=0.15, phase="input_validation"),
        PackPlannerRule(technology="Spring Boot", description="Prioritize Jackson deserialization testing", priority_modifier=0.15, phase="input_validation"),
    ],

    references=[
        {"source": "CWE", "id": "CWE-917", "title": "Expression Language Injection"},
        {"source": "CWE", "id": "CWE-502", "title": "Deserialization of Untrusted Data"},
        {"source": "Spring", "id": "ACT", "title": "Spring Boot Actuator", "url": "https://docs.spring.io/spring-boot/docs/current/actuator/htmlsingle/"},
    ],
    tags=["spring", "spring-boot", "java", "actuator"],
)
