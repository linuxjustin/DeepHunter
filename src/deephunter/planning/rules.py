"""Rule engine for the Investigation Planner.

Rules are the core building blocks of the planning engine.
Each rule takes a PlannerContext and produces zero or more
InvestigationStep candidates.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from deephunter.planning.models import (
    InvestigationStep,
    ManualTest,
    PlannerContext,
    PlanningPhase,
    RiskScore,
)
from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class PlanningRule(ABC):
    """Abstract base for a planning rule.

    Every rule must define:
    - ``name``: unique identifier
    - ``description``: human-readable explanation
    - ``phase``: which PlanningPhase this rule belongs to
    - ``evaluate()``: produce steps from a PlannerContext
    """

    name: str = ""
    description: str = ""
    phase: PlanningPhase = PlanningPhase.INPUT_VALIDATION
    priority: int = 100  # lower = evaluated earlier

    @abstractmethod
    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        """Generate candidate steps from the planner context.

        Args:
            context: The current planner context.

        Returns:
            A list of InvestigationStep candidates (may be empty).
        """


class RuleRegistry:
    """Registry for planning rules.

    Rules can be registered by name, queried by phase or technology,
    and evaluated in priority order.
    """

    def __init__(self) -> None:
        self._rules: dict[str, PlanningRule] = {}

    def register(self, rule: PlanningRule) -> None:
        if rule.name in self._rules:
            logger.warning("Overriding existing rule: %s", rule.name)
        self._rules[rule.name] = rule

    def deregister(self, name: str) -> None:
        self._rules.pop(name, None)

    def get(self, name: str) -> PlanningRule | None:
        return self._rules.get(name)

    def list_rules(self) -> list[PlanningRule]:
        return sorted(self._rules.values(), key=lambda r: r.priority)

    def get_by_phase(self, phase: PlanningPhase) -> list[PlanningRule]:
        return sorted(
            [r for r in self._rules.values() if r.phase == phase],
            key=lambda r: r.priority,
        )

    def evaluate_all(self, context: PlannerContext) -> list[InvestigationStep]:
        """Evaluate every registered rule against the context.

        Returns:
            A combined list of steps in rule priority order.
        """
        all_steps: list[InvestigationStep] = []
        for rule in self.list_rules():
            try:
                steps = rule.evaluate(context)
                all_steps.extend(steps)
            except Exception:
                logger.exception("Rule %s failed during evaluation", rule.name)
        return all_steps

    def evaluate_phase(
        self, context: PlannerContext, phase: PlanningPhase
    ) -> list[InvestigationStep]:
        """Evaluate only rules for a specific phase."""
        steps: list[InvestigationStep] = []
        for rule in self.get_by_phase(phase):
            try:
                steps.extend(rule.evaluate(context))
            except Exception:
                logger.exception("Rule %s failed during evaluation", rule.name)
        return steps

    @classmethod
    def with_default_rules(cls) -> RuleRegistry:
        """Create a registry pre-populated with all built-in rules."""
        registry = cls()
        for rule_cls in _BUILTIN_RULES:
            registry.register(rule_cls())
        return registry


# ── Built-in rules ──────────────────────────────────────────────────────────


class TechnologyRule(PlanningRule):
    """Generate steps based on detected technologies."""

    name = "technology"
    description = "Generates investigation steps for each detected technology"
    phase = PlanningPhase.FINGERPRINT
    priority = 10

    _TECH_STEPS: dict[str, tuple[str, str, float]] = {
        "laravel": ("Laravel Framework Analysis", "Review Laravel-specific attack surface including APP_KEY, signed routes, queue workers, and Sanctum/Auth configuration.", 0.85),
        "django": ("Django Framework Analysis", "Check Django-specific settings: SECRET_KEY strength, DEBUG mode, allowed hosts, CSRF middleware, and session security.", 0.85),
        "flask": ("Flask Framework Analysis", "Review Flask configuration: secret key, debug mode, session cookie security, template injection surface, and CORS settings.", 0.75),
        "spring": ("Spring Framework Analysis", "Examine Spring Boot actuators, SpEL injection surface, method security annotations, and autoconfiguration exposure.", 0.85),
        "nodejs": ("Node.js Runtime Analysis", "Audit Node.js specific concerns: prototype pollution, dependency vulnerabilities, error handling, and middleware ordering.", 0.70),
        "express": ("Express.js Middleware Analysis", "Review Express middleware chain, error handlers, CORS configuration, and route parameter handling.", 0.75),
        "react": ("React Client-Side Analysis", "Check React-specific XSS vectors: dangerouslySetInnerHTML, client-side routing, and state management security.", 0.55),
        "angular": ("Angular Client-Side Analysis", "Review Angular binding security, DOM sanitization, route guards, and HTTP interceptor configuration.", 0.55),
        "aspnet": ("ASP.NET Framework Analysis", "Examine ASP.NET view state, request validation, anti-forgery tokens, and authentication pipeline.", 0.80),
        "fastapi": ("FastAPI Framework Analysis", "Check FastAPI automatic OpenAPI exposure, input validation schemas, dependency injection security.", 0.70),
        "gin": ("Gin Framework Analysis", "Review Gin router configuration, binding validation, middleware chain, and error handling.", 0.65),
    }

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []
        for tech in context.technologies:
            key = tech.lower().strip()
            if key in self._TECH_STEPS:
                title, desc, priority = self._TECH_STEPS[key]
                steps.append(InvestigationStep(
                    phase=self.phase,
                    title=title,
                    description=desc,
                    technologies=[tech],
                    priority_score=priority,
                    risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.7),
                    estimated_cost_hours=2.0,
                    complexity=0.4,
                ))
        return steps


class AuthenticationRule(PlanningRule):
    """Generate steps based on detected authentication mechanisms."""

    name = "authentication"
    description = "Generates authentication testing steps for detected auth mechanisms"
    phase = PlanningPhase.AUTHENTICATION_ANALYSIS
    priority = 20

    _AUTH_STEPS: dict[str, tuple[str, str, float]] = {
        "jwt": ("JWT Authentication Analysis", "Test JWT implementation: algorithm confusion (none/HS256/RS256), key confusion, KID injection, token expiration, and signature bypass.", 0.90),
        "oauth2": ("OAuth2 Flow Analysis", "Review OAuth2 implementation: redirect URI validation, state parameter usage, token leakage in referrers, and scope escalation.", 0.85),
        "session_cookie": ("Session Management Analysis", "Test session handling: cookie flags (HttpOnly, Secure, SameSite), session fixation, predictable tokens, and concurrent session controls.", 0.80),
        "api_key": ("API Key Security Analysis", "Review API key handling: key generation entropy, key rotation, rate limiting, key leakage in URLs/headers, and revocation mechanisms.", 0.75),
        "basic_auth": ("Basic Authentication Review", "Check for exposed credentials in transit, weak password policies, and lack of account lockout.", 0.65),
        "saml": ("SAML SSO Analysis", "Review SAML implementation: signature validation, XML digital signature wrapping attacks, Assertion Consumer Service URL validation.", 0.85),
        "ldap": ("LDAP Authentication Review", "Test LDAP injection, anonymous binds, and credential exposure in search filters.", 0.70),
    }

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []
        for auth in context.auth_mechanisms:
            key = auth.lower().strip()
            if key in self._AUTH_STEPS:
                title, desc, priority = self._AUTH_STEPS[key]
                steps.append(InvestigationStep(
                    phase=self.phase,
                    title=title,
                    description=desc,
                    priority_score=priority,
                    technologies=context.technologies,
                    risk=RiskScore(likelihood=8.0, impact=9.0, confidence=0.6),
                    estimated_cost_hours=3.0,
                    complexity=0.5,
                ))
        return steps


class BugClassRule(PlanningRule):
    """Generate steps from bug classes found in existing hypotheses."""

    name = "bug_class"
    description = "Generates testing steps for each identified bug class"
    phase = PlanningPhase.INPUT_VALIDATION
    priority = 30

    _BUG_STEPS: dict[str, tuple[str, str, float]] = {
        "sql_injection": ("SQL Injection Testing", "Test all input vectors for SQL injection: parameterized queries, WAF bypass techniques, time-based and out-of-band detection.", 0.95),
        "xss": ("Cross-Site Scripting Testing", "Test all user-controlled inputs for reflected, stored, and DOM-based XSS with context-aware payloads.", 0.85),
        "csrf": ("CSRF Testing", "Review anti-CSRF token implementation, SameSite cookie attributes, and state-changing endpoints without tokens.", 0.75),
        "ssrf": ("Server-Side Request Forgery Testing", "Test URL parameters, file uploads, and redirect following for SSRF. Include cloud metadata endpoints.", 0.90),
        "rce": ("Remote Code Execution Testing", "Test input points that may reach dangerous functions: deserialization, eval(), file operations, and command execution.", 0.95),
        "lfi": ("Local File Inclusion Testing", "Test path traversal in file parameters, include paths, and template loading mechanisms.", 0.80),
        "idor": ("Insecure Direct Object Reference Testing", "Test object IDs in URLs, parameters, and API responses for horizontal and vertical privilege escalation.", 0.80),
        "auth_bypass": ("Authentication Bypass Testing", "Test for authentication bypass: direct page access, parameter manipulation, cookie tampering, and rate limit bypass.", 0.85),
        "deserialization": ("Deserialization Attack Testing", "Test for insecure deserialization in JSON, YAML, pickle, PHP serialized data, and Java serialized streams.", 0.90),
        "ssti": ("Server-Side Template Injection Testing", "Test template injection in user-controlled inputs that may be rendered by server-side template engines.", 0.85),
        "business_logic": ("Business Logic Flaw Testing", "Test business logic workflows for abuse: discount manipulation, tier bypass, multi-step flow tampering, and race conditions.", 0.80),
    }

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []
        for bc in context.bug_classes:
            key = bc.lower().strip()
            if key in self._BUG_STEPS:
                title, desc, priority = self._BUG_STEPS[key]
                steps.append(InvestigationStep(
                    phase=self.phase,
                    title=title,
                    description=desc,
                    bug_classes=[key],
                    priority_score=priority,
                    risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.5),
                    estimated_cost_hours=2.0,
                    complexity=0.4,
                ))
        return steps


class EndpointAnalysisRule(PlanningRule):
    """Generate API endpoint analysis steps from discovered endpoints."""

    name = "endpoint_analysis"
    description = "Generates API analysis steps from interesting endpoints"
    phase = PlanningPhase.API_ANALYSIS
    priority = 40

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        if not context.interesting_endpoints:
            return []

        return [
            InvestigationStep(
                phase=self.phase,
                title="API Endpoint Security Analysis",
                description=f"Analyze {len(context.interesting_endpoints)} discovered endpoints for injection, auth bypass, and data exposure. Endpoints include: {', '.join(context.interesting_endpoints[:5])}",
                priority_score=0.80,
                risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.6),
                estimated_cost_hours=min(len(context.interesting_endpoints) * 0.5, 8.0),
                complexity=0.5,
            )
        ]


class CloudProviderRule(PlanningRule):
    """Generate cloud-specific investigation steps."""

    name = "cloud_provider"
    description = "Generates cloud-specific security testing steps"
    phase = PlanningPhase.CLOUD_ANALYSIS
    priority = 50

    _CLOUD_STEPS: dict[str, tuple[str, str, float]] = {
        "aws": ("AWS Security Review", "Check S3 bucket permissions, IAM role trust policies, EC2 metadata service (IMDS), CloudFormation template exposure, and Lambda function permissions.", 0.85),
        "azure": ("Azure Security Review", "Review Azure RBAC assignments, managed identity configuration, Key Vault access policies, storage account firewalls, and MSI token leakage.", 0.80),
        "gcp": ("GCP Security Review", "Examine GCP IAM roles, service account key management, Cloud Storage bucket ACLs, and metadata server hardening.", 0.80),
    }

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []
        for provider in context.cloud_providers:
            key = provider.lower().strip()
            if key in self._CLOUD_STEPS:
                title, desc, priority = self._CLOUD_STEPS[key]
                steps.append(InvestigationStep(
                    phase=self.phase,
                    title=title,
                    description=desc,
                    technologies=[key],
                    priority_score=priority,
                    risk=RiskScore(likelihood=6.0, impact=9.0, confidence=0.5),
                    estimated_cost_hours=3.0,
                    complexity=0.6,
                ))
        return steps


class ReconRule(PlanningRule):
    """Generate recon steps. Always produces a baseline step."""

    name = "recon"
    description = "Generates baseline recon steps"
    phase = PlanningPhase.RECON
    priority = 5

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        return [
            InvestigationStep(
                phase=self.phase,
                title="Target Reconnaissance",
                description="Perform initial recon: subdomain enumeration, port scanning, technology identification, and directory brute-force against the target.",
                priority_score=0.90,
                technologies=context.technologies,
                risk=RiskScore(likelihood=9.0, impact=5.0, confidence=0.9),
                estimated_cost_hours=2.0,
                complexity=0.2,
            )
        ]


class BusinessLogicRule(PlanningRule):
    """Generate business logic testing steps."""

    name = "business_logic"
    description = "Generates business logic analysis steps"
    phase = PlanningPhase.BUSINESS_LOGIC_ANALYSIS
    priority = 60

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        steps: list[InvestigationStep] = []

        if "business_logic" in context.observation_types or any(
            "business" in ot.lower() for ot in context.observation_types
        ):
            steps.append(
                InvestigationStep(
                    phase=self.phase,
                    title="Business Logic Workflow Analysis",
                    description="Analyze multi-step workflows for logic flaws: discount abuse, account creation bypass, tier escalation, coupon manipulation, and race conditions.",
                    priority_score=0.80,
                    risk=RiskScore(likelihood=7.0, impact=7.0, confidence=0.5),
                    estimated_cost_hours=4.0,
                    complexity=0.6,
                )
            )

        return steps


class FileUploadRule(PlanningRule):
    """Generate file upload testing steps."""

    name = "file_upload"
    description = "Generates file upload vulnerability testing steps"
    phase = PlanningPhase.FILE_UPLOAD_ANALYSIS
    priority = 70

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        upload_keywords = ["upload", "file", "attachment", "avatar", "document", "media", "image"]
        has_upload = any(
            any(kw in ep.lower() for kw in upload_keywords)
            for ep in context.interesting_endpoints
        )
        if not has_upload:
            return []

        return [
            InvestigationStep(
                phase=self.phase,
                title="File Upload Security Analysis",
                description="Test file upload functionality: extension filtering, content-type validation, double extension, malware upload, path traversal in filename, and stored XSS via file names.",
                priority_score=0.75,
                risk=RiskScore(likelihood=7.0, impact=8.0, confidence=0.5),
                estimated_cost_hours=2.0,
                complexity=0.4,
            )
        ]


class AuthorizationRule(PlanningRule):
    """Generate authorization testing steps."""

    name = "authorization"
    description = "Generates authorization testing steps"
    phase = PlanningPhase.AUTHORIZATION_ANALYSIS
    priority = 25

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        return [
            InvestigationStep(
                phase=self.phase,
                title="Authorization Testing",
                description="Test role-based access controls: horizontal privilege escalation (same-role resource access), vertical privilege escalation (low-priv to admin), and missing function-level access controls.",
                priority_score=0.85,
                risk=RiskScore(likelihood=8.0, impact=9.0, confidence=0.6),
                estimated_cost_hours=3.0,
                complexity=0.5,
            )
        ]


class PrivilegeEscalationRule(PlanningRule):
    """Generate privilege escalation testing steps."""

    name = "privilege_escalation"
    description = "Generates privilege escalation testing steps"
    phase = PlanningPhase.PRIVILEGE_ESCALATION
    priority = 80

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        return [
            InvestigationStep(
                phase=self.phase,
                title="Privilege Escalation Analysis",
                description="Analyze for privilege escalation vectors: insecure direct object references, role manipulation, forced browsing, missing admin function checks, and token/claim tampering.",
                priority_score=0.80,
                risk=RiskScore(likelihood=6.0, impact=9.0, confidence=0.4),
                estimated_cost_hours=3.0,
                complexity=0.6,
            )
        ]


class FrameworkDetectionRule(PlanningRule):
    """Generate framework detection steps."""

    name = "framework_detection"
    description = "Generates framework detection and analysis steps"
    phase = PlanningPhase.FRAMEWORK_DETECTION
    priority = 15

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        if context.frameworks:
            return [
                InvestigationStep(
                    phase=self.phase,
                    title="Framework Version and Configuration Analysis",
                    description=f"Verify versions and configurations for detected frameworks: {', '.join(context.frameworks[:5])}. Check for known CVEs, default credentials, and debug endpoints.",
                    priority_score=0.80,
                    technologies=context.technologies,
                    risk=RiskScore(likelihood=7.0, impact=7.0, confidence=0.7),
                    estimated_cost_hours=1.5,
                    complexity=0.3,
                )
            ]
        return []


class ReportPreparationRule(PlanningRule):
    """Generate report preparation steps."""

    name = "report_preparation"
    description = "Generates report preparation steps"
    phase = PlanningPhase.REPORT_PREPARATION
    priority = 100

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        return [
            InvestigationStep(
                phase=self.phase,
                title="Investigation Report Preparation",
                description="Compile findings, evidence, screenshots, and reproduction steps into a structured security assessment report.",
                priority_score=0.90,
                risk=RiskScore(likelihood=5.0, impact=5.0, confidence=0.9),
                estimated_cost_hours=2.0,
                complexity=0.2,
            )
        ]


class MethodologyRule(PlanningRule):
    """Generate methodology-driven investigation steps.

    Runs the methodology pipeline using the detected technologies, frameworks,
    and attack surface areas from the planner context. Produces investigation
    steps from the resulting checklist items with full methodology traceability.
    """

    name = "methodology"
    description = "Generates methodology-driven investigation steps from framework profiles"
    phase = PlanningPhase.FINGERPRINT
    priority = 50

    def evaluate(self, context: PlannerContext) -> list[InvestigationStep]:
        from deephunter.methodology.pipeline import MethodologyPipeline

        pipeline = MethodologyPipeline()

        technologies = context.technologies
        frameworks = context.frameworks
        attack_surface = context.attack_surface_areas

        result = pipeline.run(
            technologies=technologies,
            frameworks=frameworks,
            attack_surface_areas=attack_surface,
        )

        # Store result as dict for downstream rules (avoid Pydantic Any issues)
        object.__setattr__(context, "methodology_result", result.model_dump())

        steps: list[InvestigationStep] = []
        for cl in result.checklists:
            for item in cl.items:
                # Map checklist item priority to score
                if item.priority.value == "critical":
                    priority_score = 0.95
                elif item.priority.value == "high":
                    priority_score = 0.80
                elif item.priority.value == "medium":
                    priority_score = 0.55
                else:
                    priority_score = 0.30

                risk = RiskScore(
                    likelihood=7.0,
                    impact=8.0,
                    confidence=0.6,
                )

                step = InvestigationStep(
                    phase=self.phase,
                    title=item.objective,
                    description=item.description,
                    priority_score=priority_score,
                    risk=risk,
                    estimated_cost_hours=1.0,
                    complexity=0.5,
                    technologies=list(item.related_technologies),
                    metadata={
                        "methodology_id": cl.methodology_id,
                        "checklist_item_id": item.id,
                        "methodology_step_id": item.id,
                    },
                )

                # Add manual tests from the methodology pipeline
                for mt in result.manual_tests:
                    if mt.checklist_item_id == item.id:
                        step.recommended_tests.append(
                            ManualTest(
                                description=mt.description,
                                procedure=mt.procedure,
                                expected_result=mt.expected_result,
                                bug_classes=[bc.value for bc in mt.bug_classes],
                                priority=mt.priority,
                                estimated_effort_hours=mt.estimated_effort_hours,
                                methodology_id=mt.methodology_id,
                                checklist_item_id=mt.checklist_item_id,
                            )
                        )

                steps.append(step)

        return steps


_BUILTIN_RULES: list[type[PlanningRule]] = [
    ReconRule,
    TechnologyRule,
    FrameworkDetectionRule,
    MethodologyRule,
    AuthenticationRule,
    AuthorizationRule,
    BugClassRule,
    EndpointAnalysisRule,
    BusinessLogicRule,
    FileUploadRule,
    CloudProviderRule,
    PrivilegeEscalationRule,
    ReportPreparationRule,
]
