"""Regression benchmark datasets — for detecting quality regressions.

These datasets are run on every CI cycle and must maintain or
improve their scores. A score drop triggers a pipeline failure.
"""

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    DatasetType,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
)


REGRESSION_DATASET_PLANNER = BenchmarkDataset(
    name="Regression: Planner Quality",
    version="1.0.0",
    dataset_type=DatasetType.REGRESSION,
    description="Regression tests for the Investigation Planner. Measures planner step accuracy and coverage.",
    tags=["regression", "planner"],
    entries=[
        BenchmarkEntry(
            name="Planner: Laravel Detection",
            description="Planner should detect Laravel and generate appropriate investigation steps",
            input=BenchmarkInput(
                technologies=["PHP", "Laravel", "MySQL", "Nginx"],
                frameworks=["laravel"],
                attack_surface_areas=["Authentication", "Debug mode", "File upload"],
                auth_mechanisms=["session_cookie"],
                description="Standard Laravel application with authentication and file upload",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="fingerprint", title="Laravel Framework Analysis", description="Review Laravel-specific attack surface", priority_score=0.85),
                    ExpectedStep(phase="authentication_analysis", title="Session Management Analysis", description="Test session handling", priority_score=0.80),
                    ExpectedStep(phase="input_validation", title="Mass Assignment Testing", description="Test model creation for mass assignment", priority_score=0.80),
                    ExpectedStep(phase="file_upload_analysis", title="File Upload Security Analysis", description="Test file upload functionality", priority_score=0.75),
                ],
                technologies=["PHP", "Laravel", "MySQL", "Nginx"],
                frameworks=["laravel"],
                attack_surface=["Authentication", "Debug mode", "File upload"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "Laravel debug mode may be enabled in production",
                        "Eloquent models may allow mass assignment",
                        "Sanctum tokens may be exposed in URLs",
                    ],
                    confidence=0.85,
                ),
                knowledge_packs=["laravel", "nginx", "mysql"],
            ),
            tags=["regression", "planner", "laravel"],
            difficulty="medium",
        ),
        BenchmarkEntry(
            name="Planner: AWS Cloud Detection",
            description="Planner should detect AWS and generate cloud-specific investigation steps",
            input=BenchmarkInput(
                technologies=["AWS", "Node.js", "Express", "MongoDB"],
                frameworks=["express"],
                cloud_providers=["aws"],
                attack_surface_areas=["S3 bucket", "Lambda function", "API Gateway"],
                description="Application deployed on AWS with S3, Lambda, and API Gateway",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="cloud_analysis", title="AWS Security Review", description="Check S3 bucket permissions, IAM roles, and metadata service", priority_score=0.85),
                    ExpectedStep(phase="cloud_analysis", title="S3 Bucket Testing", description="Enumerate S3 buckets for public access", priority_score=0.80),
                ],
                technologies=["AWS", "Node.js", "Express"],
                frameworks=["express"],
                attack_surface=["S3 bucket", "Lambda", "API Gateway"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "S3 buckets may be publicly accessible",
                        "Lambda functions may have excessive IAM permissions",
                        "API Gateway may have missing authentication",
                    ],
                    confidence=0.80,
                ),
                knowledge_packs=["aws", "express", "mongodb"],
            ),
            tags=["regression", "planner", "cloud"],
            difficulty="medium",
        ),
        BenchmarkEntry(
            name="Planner: No Tech Match",
            description="Planner should generate universal steps when no technologies are detected",
            input=BenchmarkInput(
                technologies=[],
                frameworks=[],
                description="No specific technologies detected — universal coverage expected",
            ),
            expected=ExpectedOutput(
                planner_steps=[],  # Universal steps may vary — check that steps are generated
                technologies=[],
                attack_surface=[],
                reasoning=ExpectedReasoning(
                    hypotheses=["No specific technology fingerprint identified"],
                    confidence=0.5,
                ),
                knowledge_packs=["graphql", "rest", "jwt"],
            ),
            tags=["regression", "planner", "universal"],
            difficulty="easy",
        ),
    ],
)

REGRESSION_DATASET_METHODOLOGY = BenchmarkDataset(
    name="Regression: Methodology Coverage",
    version="1.0.0",
    dataset_type=DatasetType.REGRESSION,
    description="Regression tests for Methodology Engine coverage — checks that all key investigation areas are addressed.",
    tags=["regression", "methodology"],
    entries=[
        BenchmarkEntry(
            name="Methodology: SQL Injection Coverage",
            description="Methodology engine should cover SQL injection testing",
            input=BenchmarkInput(
                technologies=["PHP", "MySQL"],
                bug_classes=["sql_injection"],
                attack_surface_areas=["Search", "Login", "API parameters"],
                description="Application with multiple potential SQL injection points",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="SQL Injection Testing", description="Test all input vectors for SQL injection", priority_score=0.95),
                    ExpectedStep(phase="input_validation", title="Blind SQL Injection", description="Test for blind SQL injection", priority_score=0.85),
                    ExpectedStep(phase="input_validation", title="Out-of-Band SQL Injection", description="Test for OOB SQL injection", priority_score=0.75),
                ],
                technologies=["PHP", "MySQL"],
                attack_surface=["Search", "Login", "API parameters"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "Input parameters may be concatenated into SQL queries",
                        "Database errors may be visible in responses",
                    ],
                    confidence=0.85,
                ),
                knowledge_packs=["mysql"],
            ),
            tags=["regression", "methodology", "sqli"],
            difficulty="medium",
        ),
        BenchmarkEntry(
            name="Methodology: SSRF Coverage",
            description="Methodology engine should cover SSRF testing",
            input=BenchmarkInput(
                technologies=["Python", "Flask", "AWS"],
                bug_classes=["ssrf"],
                attack_surface_areas=["URL fetch endpoint", "Metadata service"],
                cloud_providers=["aws"],
                description="Application fetches external URLs runs on AWS EC2",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="SSRF Testing", description="Test for server-side request forgery", priority_score=0.95),
                    ExpectedStep(phase="cloud_analysis", title="Cloud Metadata SSRF", description="Test metadata endpoint access", priority_score=0.95),
                ],
                technologies=["Python", "Flask", "AWS"],
                attack_surface=["URL fetch", "Metadata service"],
                knowledge_packs=["flask", "aws"],
            ),
            tags=["regression", "methodology", "ssrf"],
            difficulty="hard",
        ),
    ],
)

REGRESSION_DATASET_TECH_INTEL = BenchmarkDataset(
    name="Regression: Technology Intelligence",
    version="1.0.0",
    dataset_type=DatasetType.REGRESSION,
    description="Regression tests for Technology Intelligence accuracy.",
    tags=["regression", "tech_intel"],
    entries=[
        BenchmarkEntry(
            name="Tech Intel: Laravel Fingerprint",
            description="Technology Intelligence should detect Laravel from fingerprints",
            input=BenchmarkInput(
                technologies=["PHP"],
                description="Application returns Laravel-specific cookies and headers",
            ),
            expected=ExpectedOutput(
                technologies=["PHP", "Laravel"],
                attack_surface=["Debug mode", "Elixir", "Blade templates"],
                reasoning=ExpectedReasoning(
                    hypotheses=["Laravel session cookie detected", "Laravel debugbar endpoint found"],
                    confidence=0.9,
                ),
                knowledge_packs=["laravel"],
            ),
            tags=["regression", "tech_intel", "laravel"],
            difficulty="easy",
        ),
        BenchmarkEntry(
            name="Tech Intel: AWS Detection",
            description="Technology Intelligence should detect AWS infrastructure",
            input=BenchmarkInput(
                technologies=[],
                cloud_providers=["aws"],
                description="Application headers and behavior indicate AWS deployment",
            ),
            expected=ExpectedOutput(
                technologies=["AWS"],
                attack_surface=["S3 bucket", "EC2 metadata"],
                reasoning=ExpectedReasoning(
                    hypotheses=["x-amz-request-id header detected", "EC2 metadata endpoint is accessible"],
                    confidence=0.85,
                ),
                knowledge_packs=["aws"],
            ),
            tags=["regression", "tech_intel", "aws"],
            difficulty="easy",
        ),
    ],
)
