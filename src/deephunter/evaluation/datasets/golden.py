"""Golden benchmark datasets — ground truth for core bug classes.

These datasets represent canonical vulnerability scenarios that
every subsystem should handle correctly.
"""

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    DatasetType,
    ExpectedMethodology,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
)


def _make_sqli_entry(name: str, desc: str, techs: list[str], areas: list[str],
                     steps: list[tuple[str, str, str]], hyps: list[str]) -> BenchmarkEntry:
    return BenchmarkEntry(
        name=name,
        description=desc,
        input=BenchmarkInput(
            technologies=techs,
            bug_classes=["sql_injection"],
            attack_surface_areas=areas,
            description=desc,
        ),
        expected=ExpectedOutput(
            planner_steps=[ExpectedStep(phase=p, title=t, description=d) for p, t, d in steps],
            technologies=techs,
            attack_surface=areas,
            reasoning=ExpectedReasoning(hypotheses=hyps, confidence=0.9),
            checklists=["Test all input fields for SQL injection", "Test parameterized queries", "Verify WAF bypass resistance"],
            workflows=["Identify all user input points", "Test with SQL injection payloads", "Analyze error responses", "Verify parameterized queries"],
            knowledge_packs=["mysql", "postgresql"],
        ),
        tags=["sql_injection", "golden", "injection"],
        difficulty="medium",
        cwe_ids=["CWE-89"],
    )


def _make_xss_entry(name: str, desc: str, techs: list[str]) -> BenchmarkEntry:
    return BenchmarkEntry(
        name=name,
        description=desc,
        input=BenchmarkInput(
            technologies=techs,
            bug_classes=["xss"],
            attack_surface_areas=["Input fields", "URL parameters", "Headers"],
            description=desc,
        ),
        expected=ExpectedOutput(
            planner_steps=[
                ExpectedStep(phase="input_validation", title="XSS Testing", description="Test all user inputs for reflected, stored, and DOM-based XSS", priority_score=0.85),
                ExpectedStep(phase="input_validation", title="Context-Aware Payloads", description="Deliver payloads appropriate to each injection context", priority_score=0.80),
                ExpectedStep(phase="input_validation", title="CSP Analysis", description="Review Content-Security-Policy headers for bypass vectors", priority_score=0.70),
            ],
            technologies=techs,
            attack_surface=["Input fields", "URL parameters", "Headers"],
            reasoning=ExpectedReasoning(
                hypotheses=[
                    "User input is reflected without sanitization",
                    "Stored input is rendered without encoding",
                    "DOM manipulation uses untrusted data",
                ],
                confidence=0.85,
            ),
            checklists=["Test all input fields for XSS", "Test URL parameters for reflected XSS", "Review CSP headers", "Test DOM-based XSS vectors"],
            workflows=["Enumerate all user-controlled inputs", "Inject context-aware XSS payloads", "Verify encoding/sanitization", "Review CSP configuration"],
            knowledge_packs=["django", "flask", "express"],
        ),
        tags=["xss", "golden", "injection"],
        difficulty="medium",
        cwe_ids=["CWE-79"],
    )


def _make_auth_entry(name: str, desc: str, techs: list[str], auth: list[str]) -> BenchmarkEntry:
    return BenchmarkEntry(
        name=name,
        description=desc,
        input=BenchmarkInput(
            technologies=techs,
            bug_classes=["auth_bypass", "broken_auth"],
            auth_mechanisms=auth,
            attack_surface_areas=["Login endpoint", "Session management", "Password reset"],
            description=desc,
        ),
        expected=ExpectedOutput(
            planner_steps=[
                ExpectedStep(phase="authentication_analysis", title=f"{a} Analysis", description=f"Test {a} implementation", priority_score=0.90)
                for a in auth
            ] + [
                ExpectedStep(phase="authentication_analysis", title="Session Security Review", description="Test session fixation, cookie flags, and token management", priority_score=0.85),
            ],
            technologies=techs,
            attack_surface=["Login", "Session", "Password reset", "MFA"],
            reasoning=ExpectedReasoning(
                hypotheses=[
                    "Session tokens may be predictable or lack entropy",
                    "Password reset flow may allow token enumeration",
                    "MFA implementation may have bypass vectors",
                ],
                confidence=0.8,
            ),
            knowledge_packs=["jwt", "oauth", "django", "laravel"],
        ),
        tags=["authentication", "golden"],
        difficulty="medium",
        cwe_ids=["CWE-287", "CWE-384"],
    )


GOLDEN_DATASET_SQLI_XSS = BenchmarkDataset(
    name="Golden: SQL Injection & XSS",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical SQL injection and XSS scenarios covering the most common vulnerability patterns.",
    tags=["golden", "sqli", "xss", "injection"],
    entries=[
        _make_sqli_entry(
            "SQLi via Login Form",
            "Classic SQL injection in login form authentication bypass",
            ["PHP", "MySQL", "Apache"],
            ["Login form", "Authentication bypass"],
            [
                ("input_validation", "SQL Injection Testing", "Test login form for SQL injection"),
                ("input_validation", "Auth Bypass Testing", "Test for authentication bypass via SQLi"),
                ("input_validation", "Error-Based SQLi", "Analyze database error messages for injection confirmation"),
            ],
            ["Login form passes unsanitized input to SQL query", "Database errors reveal query structure"],
        ),
        _make_sqli_entry(
            "SQLi via Search Parameter",
            "SQL injection through search functionality",
            ["PHP", "MySQL", "Nginx"],
            ["Search endpoint", "Product search"],
            [
                ("input_validation", "Search SQL Injection", "Test search parameter for SQL injection"),
                ("input_validation", "Blind SQLi", "Test for time-based and boolean-based blind SQL injection"),
                ("input_validation", "Out-of-Band SQLi", "Test for out-of-band SQL injection via DNS/HTTP"),
            ],
            ["Search parameter is concatenated into SQL WHERE clause", "Blind injection may extract data character by character"],
        ),
        _make_xss_entry(
            "Reflected XSS in Search",
            "Reflected cross-site scripting through search functionality",
            ["JavaScript", "React", "Express"],
        ),
        _make_xss_entry(
            "Stored XSS in Comments",
            "Stored cross-site scripting through comment submission",
            ["Python", "Django", "PostgreSQL"],
        ),
    ],
)

GOLDEN_DATASET_AUTH = BenchmarkDataset(
    name="Golden: Authentication & Authorization",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical authentication and authorization scenarios.",
    tags=["golden", "auth", "authorization"],
    entries=[
        _make_auth_entry("JWT Auth Bypass", "JWT authentication with algorithm confusion vulnerability", ["Node.js", "Express"], ["jwt"]),
        _make_auth_entry("OAuth Misconfiguration", "OAuth2 flow with redirect URI validation bypass", ["Python", "FastAPI"], ["oauth2"]),
        BenchmarkEntry(
            name="IDOR in User Profile",
            description="Insecure direct object reference in user profile API",
            input=BenchmarkInput(
                technologies=["Python", "Django"],
                bug_classes=["idor", "privilege_escalation"],
                attack_surface_areas=["User profile API", "User settings endpoint"],
                description="User profile endpoint uses sequential user IDs without authorization checks",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="authorization_analysis", title="IDOR Testing", description="Test user profile endpoint for IDOR by modifying user_id parameter", priority_score=0.90),
                    ExpectedStep(phase="authorization_analysis", title="Horizontal Privilege Escalation", description="Attempt to access other users' profiles by changing IDs", priority_score=0.85),
                    ExpectedStep(phase="authorization_analysis", title="Vertical Privilege Escalation", description="Attempt to access admin-level profiles", priority_score=0.80),
                ],
                technologies=["Python", "Django"],
                attack_surface=["User profile API", "User settings"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "User IDs are sequential integers",
                        "No authorization check on profile endpoint",
                        "API returns sensitive personal information",
                    ],
                    confidence=0.9,
                ),
                knowledge_packs=["django", "rest"],
            ),
            tags=["idor", "authorization", "golden"],
            difficulty="easy",
            cwe_ids=["CWE-639"],
        ),
    ],
)

GOLDEN_DATASET_SSRF = BenchmarkDataset(
    name="Golden: Server-Side Request Forgery",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical SSRF scenarios targeting cloud metadata and internal services.",
    tags=["golden", "ssrf", "cloud"],
    entries=[
        BenchmarkEntry(
            name="SSRF via URL Parameter",
            description="Application fetches user-supplied URLs without validation",
            input=BenchmarkInput(
                technologies=["Python", "Flask"],
                bug_classes=["ssrf"],
                attack_surface_areas=["URL fetch endpoint", "Proxy functionality"],
                cloud_providers=["aws"],
                description="Application accepts a URL parameter and fetches the content server-side",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="SSRF Testing", description="Test URL parameter for server-side request forgery", priority_score=0.95),
                    ExpectedStep(phase="cloud_analysis", title="Cloud Metadata SSRF", description="Test for AWS/GCP/Azure metadata endpoint access", priority_score=0.95),
                    ExpectedStep(phase="input_validation", title="Blind SSRF", description="Test for out-of-band SSRF via Burp Collaborator", priority_score=0.85),
                    ExpectedStep(phase="input_validation", title="Internal Network Scanning", description="Use SSRF to probe internal network services", priority_score=0.80),
                ],
                technologies=["Python", "Flask"],
                attack_surface=["URL parameter", "Metadata service", "Internal network"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "URL parameter is not validated against allowlist",
                        "Redirect following may bypass restrictions",
                        "Cloud metadata endpoint may be accessible internally",
                    ],
                    confidence=0.9,
                ),
                knowledge_packs=["flask", "aws", "gcp", "azure"],
            ),
            tags=["ssrf", "golden", "cloud"],
            difficulty="medium",
            cwe_ids=["CWE-918"],
        ),
    ],
)

GOLDEN_DATASET_LARAVEL = BenchmarkDataset(
    name="Golden: Laravel Framework",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Comprehensive Laravel-specific vulnerability scenarios.",
    tags=["golden", "laravel", "php", "framework"],
    entries=[
        BenchmarkEntry(
            name="Laravel Debug Mode Leak",
            description="Laravel application with APP_DEBUG=true in production",
            input=BenchmarkInput(
                technologies=["PHP", "Laravel", "MySQL", "Nginx"],
                frameworks=["laravel"],
                bug_classes=["info_disclosure"],
                attack_surface_areas=["Debug mode", "Environment configuration", "Error pages"],
                description="Laravel app with debug mode enabled exposes sensitive information",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="fingerprint", title="Laravel Debug Mode Detection", description="Check if APP_DEBUG is enabled by triggering errors", priority_score=0.95),
                    ExpectedStep(phase="fingerprint", title="Environment Variable Extraction", description="Extract database credentials and APP_KEY from error pages", priority_score=0.95),
                ],
                technologies=["PHP", "Laravel", "MySQL"],
                frameworks=["laravel"],
                attack_surface=["Debug mode", "Error pages"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "APP_DEBUG=true reveals stack traces and environment variables",
                        "Database credentials may be exposed in error output",
                        "APP_KEY exposure enables signed cookie manipulation",
                    ],
                    confidence=0.95,
                ),
                knowledge_packs=["laravel"],
            ),
            tags=["laravel", "debug", "golden"],
            difficulty="easy",
            cwe_ids=["CWE-200", "CWE-489"],
        ),
        BenchmarkEntry(
            name="Laravel Mass Assignment",
            description="Mass assignment vulnerability in Eloquent models",
            input=BenchmarkInput(
                technologies=["PHP", "Laravel"],
                frameworks=["laravel"],
                bug_classes=["privilege_escalation"],
                attack_surface_areas=["User creation API", "Profile update endpoint"],
                description="User model has guarded fields allowing mass assignment of admin role",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="Mass Assignment Testing", description="Test all model creation/update endpoints for mass assignment", priority_score=0.90),
                    ExpectedStep(phase="privilege_escalation", title="Privilege Escalation via Mass Assignment", description="Attempt to set role=admin or is_admin=true in POST body", priority_score=0.90),
                ],
                technologies=["PHP", "Laravel"],
                frameworks=["laravel"],
                attack_surface=["User creation", "Profile update"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "User model does not guard role/is_admin fields",
                        "Mass assignment allows setting arbitrary model attributes",
                    ],
                    confidence=0.85,
                ),
                knowledge_packs=["laravel"],
            ),
            tags=["laravel", "mass-assignment", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-915"],
        ),
    ],
)

GOLDEN_DATASET_CLOUD = BenchmarkDataset(
    name="Golden: Cloud Security",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical cloud security scenarios across AWS, Azure, and GCP.",
    tags=["golden", "cloud", "aws", "azure", "gcp"],
    entries=[
        BenchmarkEntry(
            name="AWS S3 Bucket Misconfiguration",
            description="Publicly readable S3 bucket with sensitive data",
            input=BenchmarkInput(
                technologies=["AWS"],
                cloud_providers=["aws"],
                bug_classes=["info_disclosure"],
                attack_surface_areas=["S3 bucket", "Storage"],
                description="AWS S3 bucket allows public read access",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="cloud_analysis", title="S3 Bucket Enumeration", description="Enumerate S3 buckets for public access", priority_score=0.90),
                    ExpectedStep(phase="cloud_analysis", title="S3 Bucket Content Review", description="Review exposed S3 objects for sensitive data", priority_score=0.85),
                ],
                technologies=["AWS S3"],
                attack_surface=["S3 bucket", "Cloud storage"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "S3 bucket policy allows public read",
                        "Bucket contains sensitive backup or configuration files",
                    ],
                    confidence=0.9,
                ),
                knowledge_packs=["aws"],
            ),
            tags=["cloud", "aws", "s3", "golden"],
            difficulty="easy",
            cwe_ids=["CWE-200"],
        ),
        BenchmarkEntry(
            name="AWS IMDS SSRF",
            description="SSRF via cloud metadata service on EC2",
            input=BenchmarkInput(
                technologies=["AWS", "Node.js", "Express"],
                cloud_providers=["aws"],
                bug_classes=["ssrf"],
                attack_surface_areas=["Metadata service", "URL fetch endpoint"],
                description="Application fetches user-supplied URLs and runs on EC2",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="cloud_analysis", title="IMDS SSRF Testing", description="Test for AWS metadata service access via SSRF", priority_score=0.95),
                    ExpectedStep(phase="cloud_analysis", title="IMDSv1 Exploitation", description="Check if IMDSv1 is enabled for easier exploitation", priority_score=0.90),
                ],
                technologies=["AWS EC2", "Node.js", "Express"],
                attack_surface=["Metadata service", "URL parameter"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "EC2 metadata endpoint 169.254.169.254 is accessible internally",
                        "IMDSv1 allows token-less metadata retrieval",
                        "IAM role credentials can be extracted from metadata",
                    ],
                    confidence=0.9,
                ),
                knowledge_packs=["aws", "express"],
            ),
            tags=["cloud", "aws", "ssrf", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-918"],
        ),
    ],
)
