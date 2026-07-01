"""Security testing agents powered by DeepSeek LLM.

This module provides autonomous security testing agents that use
DeepSeek to analyze, test, and identify vulnerabilities.
"""

from __future__ import annotations

import os
import time
from typing import Any

from deephunter.agents.agent import BaseAgent
from deephunter.agents.base import AgentResult
from deephunter.llm.base import LLMMessage
from deephunter.llm.deepseek_provider import DeepSeekProvider


def get_deepseek_provider() -> DeepSeekProvider:
    """Get or create DeepSeek provider instance."""
    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        provider = DeepSeekProvider(api_key="sk-test")
    else:
        provider = DeepSeekProvider(api_key=api_key)
    return provider


class SecurityTestAgent(BaseAgent):
    """Base class for security testing agents using DeepSeek.

    Subclasses implement specific testing methodologies like
    JWT analysis, OAuth testing, API fuzzing, etc.
    """

    def __init__(self, name: str | None = None) -> None:
        super().__init__(name)
        self._timeout_seconds = 120.0
        self._max_retries = 2

    def _analyze_with_llm(
        self,
        prompt: str,
        context: dict[str, Any],
        max_tokens: int = 2048,
    ) -> str:
        """Use DeepSeek to analyze and generate security findings."""
        provider = get_deepseek_provider()

        messages = [
            LLMMessage(role="system", content=self.get_system_prompt()),
            LLMMessage(role="user", content=prompt),
        ]

        try:
            response = provider.generate(messages, max_tokens=max_tokens)
            if hasattr(response, 'content'):
                return response.content
            return str(response)
        except Exception as e:
            return f"Analysis failed: {str(e)}"

    def get_system_prompt(self) -> str:
        """Return the system prompt for this agent's methodology."""
        return (
            "You are an expert security researcher analyzing application security. "
            "Analyze the provided data and identify potential vulnerabilities. "
            "Output findings in structured format with:\n"
            "- Vulnerability type\n"
            "- Severity (Critical/High/Medium/Low/Info)\n"
            "- Evidence\n"
            "- Remediation\n"
            "If no issues found, respond with 'No vulnerabilities detected.'"
        )

    def execute(self, context: dict[str, Any] | None) -> AgentResult:
        """Execute security testing against target."""
        start_time = time.time()
        if context is None:
            context = {}

        if hasattr(context, 'shared_data'):
            ctx_data = context.shared_data or {}
        elif isinstance(context, dict):
            ctx_data = context
        else:
            ctx_data = {}

        target = ctx_data.get("target", "unknown")
        task_description = ctx_data.get("task_description", "")

        prompt = self.build_prompt(target, task_description, ctx_data)
        findings = self._analyze_with_llm(prompt, ctx_data)

        execution_time = (time.time() - start_time) * 1000

        success = "Analysis failed" not in findings and findings

        return AgentResult(
            agent_name=self.name,
            success=success,
            data={
                "target": target,
                "task": task_description,
                "findings": findings,
                "agent": self.name,
            },
            error="" if success else findings,
            execution_time_ms=execution_time,
        )

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        """Build analysis prompt from context. Override in subclasses."""
        return f"""Analyze {target} for security issues.

Task: {task_description}

Target: {target}

Provide detailed security findings or state that no issues were found.
"""


class AuthReviewAgent(SecurityTestAgent):
    """Agent for authentication and authorization security testing.

    Tests JWT validation, OAuth flows, OIDC configurations,
    session management, and related authentication mechanisms.
    """

    def __init__(self) -> None:
        super().__init__("auth_review")

    def get_system_prompt(self) -> str:
        return """You are an expert in authentication and authorization security.

Analyze authentication mechanisms for:
- JWT algorithm confusion (alg:none, RS256→HS256)
- Missing signature verification
- Token expiration not enforced
- OAuth 2.0 redirect URI validation bypass
- PKCE downgrade attacks
- OpenID Connect misconfigurations
- Session fixation/hijacking
- Weak session token generation

Output each finding as:
[VULNERABILITY] Type: <type>
Severity: <Critical/High/Medium/Low>
Description: <brief description>
Evidence: <specific evidence from analysis>
Remediation: <recommended fix>

If no issues found, respond: No authentication vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        technologies = context.get("technologies", [])
        scope_entries = context.get("scope_entries", [])

        return f"""Perform authentication security analysis on: {target}

Task: {task_description}

Target: {target}
Discovered Endpoints: {', '.join(str(e) for e in scope_entries[:20])}
Technologies: {', '.join(technologies) if technologies else 'Unknown'}

Analyze for:
1. JWT validation issues (algorithm confusion, missing verification)
2. OAuth 2.0 security (redirect URI, PKCE, token handling)
3. OIDC configuration (issuer validation, ID token checks)
4. Session management weaknesses

Provide specific vulnerability findings with evidence."""


class ApiReviewAgent(SecurityTestAgent):
    """Agent for API security testing (REST, GraphQL, SOAP).

    Tests for injection vulnerabilities, broken authentication,
    rate limiting issues, and API-specific attacks.
    """

    def __init__(self) -> None:
        super().__init__("api_review")

    def get_system_prompt(self) -> str:
        return """You are an expert in API security testing.

Analyze REST and GraphQL APIs for:
- SQL/NoSQL injection in parameters
- Mass assignment vulnerabilities
- Broken authentication endpoints
- Missing rate limiting
- GraphQL introspection abuse
- GraphQL batching attacks (N+1)
- Depth limiting bypass
- Batched query abuse
- API versioning vulnerabilities
- Undocumented endpoints exposure

Output findings as:
[VULNERABILITY] Type: <type>
Severity: <Critical/High/Medium/Low>
Endpoint: <affected endpoint>
Description: <description>
PoC: <proof of concept if applicable>
Remediation: <fix>

If no issues found, respond: No API vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        endpoints = context.get("endpoints", [])
        scope_entries = context.get("scope_entries", [])

        return f"""Perform API security analysis on: {target}

Task: {task_description}

Target: {target}
Known Endpoints: {', '.join(str(e) for e in scope_entries[:30])}
API Endpoints Found: {', '.join(endpoints[:20]) if endpoints else 'None detected'}

Test for:
1. Injection attacks (SQL, NoSQL, command injection)
2. Authentication/authorization bypass
3. Rate limiting and resource exhaustion
4. GraphQL-specific attacks
5. Mass assignment
6. Data exposure through pagination

Provide specific vulnerability findings."""


class AuthorizationReviewAgent(SecurityTestAgent):
    """Agent for testing authorization and access control issues.

    Tests for IDOR, privilege escalation, broken access control,
    and horizontal/vertical privilege boundary violations.
    """

    def __init__(self) -> None:
        super().__init__("authorization_review")

    def get_system_prompt(self) -> str:
        return """You are an expert in authorization and access control security.

Analyze for:
- Insecure Direct Object References (IDOR)
- Horizontal privilege escalation
- Vertical privilege escalation
- Missing function-level access control
- Forced browsing to protected resources
- Role/permission manipulation
- Direct access to admin endpoints
- API endpoint authorization gaps

Output findings as:
[VULNERABILITY] Type: IDOR/Privilege Escalation/Broken Access Control
Severity: <Critical/High/Medium/Low>
Affected Resource: <resource path>
Description: <description>
Impact: <security impact>
Remediation: <fix>

If no issues found, respond: No authorization vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        return f"""Analyze {target} for authorization and access control vulnerabilities.

Task: {task_description}

Target: {target}

Test for:
1. IDOR - Can users access other users' resources by modifying IDs?
2. Privilege escalation - Can lower-privilege users gain higher privileges?
3. Broken access control - Are protected endpoints actually protected?
4. Forced browsing - Can admin endpoints be accessed directly?

Provide specific access control findings."""


class BusinessLogicAgent(SecurityTestAgent):
    """Agent for business logic vulnerability testing.

    Tests for workflow bypasses, race conditions,
    state manipulation, and application-specific logic flaws.
    """

    def __init__(self) -> None:
        super().__init__("business_logic")

    def get_system_prompt(self) -> str:
        return """You are an expert in business logic vulnerability testing.

Analyze for:
- Workflow state transition bypasses
- Race conditions (TOCTOU)
- Price/quantity manipulation
- Parameter tampering
- Insufficient workflow validation
- Trust boundary violations
- Time-of-check to time-of-use (TOCTOU)
- Business rule circumvention

Output findings as:
[VULNERABILITY] Type: <type>
Severity: <Critical/High/Medium/Low>
Description: <description>
Business Impact: <impact on business>
PoC: <proof of concept>
Remediation: <fix>

If no issues found, respond: No business logic vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        return f"""Analyze {target} for business logic vulnerabilities.

Task: {task_description}

Target: {target}

Focus on:
1. Can application state transitions be bypassed?
2. Are there race conditions in critical operations?
3. Can financial/quantity parameters be manipulated?
4. Are business rules properly enforced server-side?

Provide specific business logic findings."""


class CloudReviewAgent(SecurityTestAgent):
    """Agent for cloud infrastructure security testing.

    Tests for SSRF to cloud metadata, misconfigured storage,
    excessive permissions, and cloud-specific attack vectors.
    """

    def __init__(self) -> None:
        super().__init__("cloud_review")

    def get_system_prompt(self) -> str:
        return """You are an expert in cloud security.

Analyze for:
- SSRF to cloud metadata services (AWS 169.254.169.254)
- Publicly exposed storage buckets/containers
- Overly permissive IAM roles
- Missing encryption at rest/transit
- Cloud-specific information disclosure
- Metadata API access via SSRF
- Azure/GCP metadata enumeration

Output findings as:
[VULNERABILITY] Type: <type>
Severity: <Critical/High/Medium/Low>
Cloud Service: <AWS/Azure/GCP>
Description: <description>
Impact: <security impact>
Remediation: <fix>

If no issues found, respond: No cloud security vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        return f"""Analyze {target} for cloud infrastructure vulnerabilities.

Task: {task_description}

Target: {target}

Test for:
1. SSRF to cloud metadata (AWS, Azure, GCP)
2. Publicly accessible storage
3. Excessive IAM permissions
4. Missing encryption
5. Cloud-specific information disclosure

Provide specific cloud security findings."""


class JavaScriptReviewAgent(SecurityTestAgent):
    """Agent for JavaScript and front-end security analysis.

    Analyzes JS files for secrets, client-side vulnerabilities,
    DOM XSS, and insecure dependencies.
    """

    def __init__(self) -> None:
        super().__init__("javascript_review")

    def get_system_prompt(self) -> str:
        return """You are an expert in JavaScript and front-end security.

Analyze JavaScript code for:
- Hardcoded API keys, secrets, tokens
- Client-side authentication bypass
- DOM XSS vulnerabilities
- Insecure localStorage/sessionStorage usage
- CORS misconfigurations
- Sensitive data exposure in JS
- JWT/session stored in client storage
- Dangerous eval() or innerHTML usage
- Insecure third-party scripts

Output findings as:
[VULNERABILITY] Type: <type>
Severity: <Critical/High/Medium/Low>
Location: <file/line if applicable>
Description: <description>
Evidence: <specific finding>
Remediation: <fix>

If no issues found, respond: No JavaScript vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        return f"""Analyze {target} for JavaScript and front-end vulnerabilities.

Task: {task_description}

Target: {target}

Search for:
1. Hardcoded secrets in JavaScript
2. Client-side authentication logic
3. DOM XSS sinks
4. Insecure storage usage
5. Sensitive data exposure

Provide specific JavaScript security findings."""


class InitialReconAgent(SecurityTestAgent):
    """Agent for initial reconnaissance and information gathering.

    Performs passive reconnaissance, enumerates attack surface,
    and gathers intelligence for further testing.
    """

    def __init__(self) -> None:
        super().__init__("initial_recon")

    def get_system_prompt(self) -> str:
        return """You are an expert in reconnaissance and information gathering.

Analyze reconnaissance data for:
- Exposed services and versions
- Misconfigured services
- Information disclosure
- Default credentials indicators
- Enumerated subdomains and their purposes
- Technology fingerprinting
- Potential entry points

Output findings as:
[FINDING] Type: <type>
Description: <description>
Relevance: <security relevance>
Recommendations: <next testing steps>

If nothing notable found, respond: No significant findings from reconnaissance."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        subdomains = context.get("subdomains", [])
        technologies = context.get("technologies", [])
        scope_entries = context.get("scope_entries", [])

        return f"""Analyze reconnaissance data for: {target}

Task: {task_description}

Target: {target}
Subdomains Found: {len(subdomains) if subdomains else 'None'}
Technologies: {', '.join(technologies) if technologies else 'Unknown'}
Scope Entries: {len(scope_entries) if scope_entries else 0}

Analyze this reconnaissance data to identify:
1. Exposed services and potential entry points
2. Technology stack and version information
3. Misconfigurations or information disclosure
4. Default credentials opportunities

Provide reconnaissance summary and prioritized testing recommendations."""


class SSRFTestingAgent(SecurityTestAgent):
    """Agent specialized in Server-Side Request Forgery testing."""

    def __init__(self) -> None:
        super().__init__("ssrf_testing")

    def get_system_prompt(self) -> str:
        return """You are an expert in SSRF (Server-Side Request Forgery) testing.

Analyze for SSRF vulnerabilities:
- URL parameter injection
- Open redirect chaining to SSRF
- Cloud metadata access (169.254.169.254)
- Internal port scanning via SSRF
- Data exfiltration via SSRF
- Blind SSRF with out-of-band detection

Output findings as:
[VULNERABILITY] Type: SSRF
Severity: <Critical/High/Medium/Low>
Vulnerable Parameter: <parameter>
Description: <description>
PoC: <proof of concept>
Impact: <impact>
Remediation: <fix>

If no issues found, respond: No SSRF vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        return f"""Test {target} for Server-Side Request Forgery (SSRF) vulnerabilities.

Task: {task_description}

Target: {target}

Test for:
1. SSRF via URL parameters (url, src, dest, redirect, uri, etc.)
2. Cloud metadata service access attempts
3. Internal port and service enumeration
4. Data exfiltration opportunities
5. SSRF filter bypass techniques

Provide specific SSRF findings with PoC."""


class CommandInjectionAgent(SecurityTestAgent):
    """Agent specialized in command injection testing."""

    def __init__(self) -> None:
        super().__init__("command_injection")

    def get_system_prompt(self) -> str:
        return """You are an expert in command injection and OS command execution testing.

Analyze for command injection:
- Shell metacharacter injection (;, |, &, $)
- Argument injection
- Command chaining
- Blind command injection
- Reverse shell opportunities
- Path traversal for command injection (via include/require)

Output findings as:
[VULNERABILITY] Type: Command Injection
Severity: <Critical/High/Medium/Low>
Vulnerable Input: <input field/parameter>
Payload Used: <specific payload>
Description: <description>
Impact: <impact>
Remediation: <fix>

If no issues found, respond: No command injection vulnerabilities detected."""

    def build_prompt(
        self,
        target: str,
        task_description: str,
        context: dict[str, Any],
    ) -> str:
        return f"""Test {target} for command injection vulnerabilities.

Task: {task_description}

Target: {target}

Test for:
1. OS command injection via shell metacharacters
2. Argument injection vs shell injection
3. Blind command injection with time-based detection
4. Command chaining and piping
5. Path traversal leading to command execution

Provide specific command injection findings with evidence."""


# Registry of all security testing agents
SECURITY_AGENTS: list[type[BaseAgent]] = [
    AuthReviewAgent,
    ApiReviewAgent,
    AuthorizationReviewAgent,
    BusinessLogicAgent,
    CloudReviewAgent,
    JavaScriptReviewAgent,
    InitialReconAgent,
    SSRFTestingAgent,
    CommandInjectionAgent,
]


def register_security_agents() -> dict[str, BaseAgent]:
    """Register all security testing agents."""
    agents = {}
    for agent_cls in SECURITY_AGENTS:
        agent = agent_cls()
        agents[agent.name] = agent
    return agents