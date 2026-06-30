"""Cloud Review Expert Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch, DecisionTreeNode, MethodologyPack, PackCategory,
    PackChecklist, PackPlannerRule,
)

PACK = MethodologyPack(
    name="Cloud Review",
    version="1.0.0", category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for reviewing cloud-deployed applications across AWS, Azure, and GCP. Covers metadata service attacks, storage exposure, IAM misconfiguration, container security, and serverless function review.",
    attack_surface_areas=["cloud", "infrastructure", "configuration", "authentication"],
    investigation_priority=80,
    related_packs=["Microservices", "REST API", "Session Management"],

    checklists=[
        PackChecklist(
            objective="Test cloud metadata service access (SSRF to IMDS)",
            description="Test for Server-Side Request Forgery that can access cloud instance metadata service to steal credentials.",
            procedure="1. Test SSRF to AWS: http://169.254.169.254/latest/meta-data/\n2. Test SSRF to AWS IMDSv2: PUT http://169.254.169.254/latest/api/token\n3. Test SSRF to GCP: http://metadata.google.internal/computeMetadata/v1/\n4. Test SSRF to Azure: http://169.254.169.254/metadata/instance\n5. Test with various protocols (file://, gopher://, dict://)\n6. Test via redirect chains\n7. Test headers (Metadata-Flavor: Google for GCP)\n8. Extract IAM role credentials from metadata",
            priority="critical", difficulty="medium",
            required_evidence=["Cloud metadata credentials extracted"],
            expected_result="IMDS SSRF assessed",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE],
            tags=["cloud", "ssrf", "imds", "aws", "azure", "gcp"],
        ),
        PackChecklist(
            objective="Identify cloud provider and exposed storage",
            description="Identify cloud provider from DNS, headers, and check for exposed storage buckets/containers.",
            procedure="1. Check DNS CNAME/NS records for cloud provider\n2. Check HTTP headers (x-amz-request-id for AWS, x-ms- for Azure, x-guploader-uploadid for GCP)\n3. Test common bucket names: company-backup, company-assets, company-public\n4. Test AWS S3: http://{bucket}.s3.amazonaws.com\n5. Test Azure Blob: https://{storage}.blob.core.windows.net/{container}\n6. Test GCP Cloud Storage: https://storage.googleapis.com/{bucket}\n7. Check bucket listing and object access controls",
            priority="high", difficulty="easy",
            required_evidence=["Cloud storage bucket accessible"],
            expected_result="Cloud exposure assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["cloud", "storage", "s3", "blob"],
        ),
        PackChecklist(
            objective="Review IAM/cloud permission configuration",
            description="Identify cloud IAM misconfigurations through exposed endpoints and permissions.",
            procedure="1. Identify IAM roles from metadata or environment variables\n2. Check for overly permissive roles (S3:*, **:FullAccess)\n3. Test for access key leakage in source code, env, configs\n4. Test for unsecured cloud function endpoints\n5. Check for public cloud storage with sensitive data\n6. Review cloud API key permissions\n7. Test for privilege escalation via cloud APIs",
            priority="critical", difficulty="medium",
            required_evidence=["IAM misconfiguration or leaked credentials"],
            expected_result="Cloud IAM security assessed",
            bug_classes=[BugClass.PRIVILEGE_ESCALATION, BugClass.INFO_DISCLOSURE],
            tags=["cloud", "iam", "permissions"],
        ),
        PackChecklist(
            objective="Review container/Docker security",
            description="Review container configuration, Dockerfile, and registry exposure.",
            procedure="1. Check for Dockerfile exposure at /Dockerfile\n2. Check for .docker/config.json with registry credentials\n3. Check container registry URLs in config\n4. Test common container registry endpoints\n5. Check if application runs as root inside container\n6. Review Dockerfile for secrets, base image vulnerabilities\n7. Check for Kubernetes manifest exposure (k8s.yaml, deployment.yaml)\n8. Test K8s API server access",
            priority="high", difficulty="medium",
            required_evidence=["Container/Docker misconfiguration found"],
            expected_result="Container security assessed",
            bug_classes=[BugClass.INFO_DISCLOSURE],
            tags=["cloud", "container", "docker", "kubernetes"],
        ),
        PackChecklist(
            objective="Review serverless function security",
            description="Review cloud serverless function configuration for event injection, timeout abuse, and dependency vulnerabilities.",
            procedure="1. Identify serverless endpoints (AWS Lambda, Azure Functions, GCP Cloud Functions)\n2. Check for event source injection (S3 events, SQS, etc.)\n3. Test function timeouts with long-running operations\n4. Check for dependency vulnerabilities in serverless runtime\n5. Review environment variables for secrets\n6. Test function warm-start behavior\n7. Check function URL endpoints for direct access",
            priority="high", difficulty="hard",
            required_evidence=["Serverless security vulnerability"],
            expected_result="Serverless function security assessed",
            bug_classes=[BugClass.RCE, BugClass.INFO_DISCLOSURE],
            tags=["cloud", "serverless", "lambda"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="cloud-root", question="What cloud attack vector?",
            branches=[
                DecisionTreeBranch(condition="SSRF vulnerability found", conclusion="CRITICAL: 1. AWS IMDS extraction 2. GCP metadata 3. Azure metadata 4. Cloud credential theft"),
                DecisionTreeBranch(condition="Cloud storage URLs found", conclusion="TEST: 1. Bucket listing 2. Object access 3. IAM role extraction from bucket policy"),
                DecisionTreeBranch(condition="Container/Docker detected", conclusion="REVIEW: 1. Dockerfile exposure 2. Registry creds 3. Root execution 4. K8s API access"),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="cloud", description="Prioritize IMDS SSRF testing", priority_modifier=0.25, phase="input_validation"),
        PackPlannerRule(attack_surface="cloud", description="Prioritize cloud storage exposure testing", priority_modifier=0.15, phase="recon"),
    ],
    references=[{"source": "OWASP", "id": "CLOUD", "title": "OWASP Cloud Security"}, {"source": "CWE", "id": "CWE-918", "title": "SSRF"}],
    tags=["cloud", "aws", "azure", "gcp", "infrastructure"],
)
