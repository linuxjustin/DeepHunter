"""Metadata extraction from parsed document content.

Heuristic-based extraction of titles, authors, tags, technologies,
bug classes, cloud providers, frameworks, programming languages,
and operating systems from plain text.
"""

from __future__ import annotations

import re
from typing import Any

from deephunter.core.types import (
    BugClass,
    CloudProvider,
    Framework,
    Technology,
)

# ── Regex helpers ────────────────────────────────────────────────────────────

_RE_TITLE_H1 = re.compile(r"^#\s+(.+)$", re.MULTILINE)
_RE_TITLE_HTML = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)
_RE_AUTHOR_MD = re.compile(
    r"(?:^|\n)(?:author|by|credit):\s*(.+)$", re.IGNORECASE | re.MULTILINE
)
_RE_VERSION = re.compile(
    r"(?:version|v)[:\s]*(\d+\.\d+(?:\.\d+)?(?:-[a-zA-Z0-9]+)?)",
    re.IGNORECASE,
)
_RE_DATE = re.compile(
    r"(?:date|published|created|updated)[:\s]*(\d{4}[-/]\d{1,2}[-/]\d{1,2})",
    re.IGNORECASE,
)


class MetadataExtractor:
    """Extracts structured metadata from plain text content.

    Uses regex patterns and keyword matching to identify technologies,
    bug classes, cloud providers, frameworks, programming languages,
    operating systems, author, version, and date.

    Results are best-effort and should be reviewed by a researcher.
    """

    # ── Technology keyword maps ──────────────────────────────────

    TECHNOLOGY_PATTERNS: dict[Technology, list[str]] = {
        Technology.NODEJS: ["node.js", "nodejs", "express.js", "npm"],
        Technology.REACT: ["react", "reactjs", "react.js", "jsx"],
        Technology.ANGULAR: ["angular", "angularjs", "angular.js"],
        Technology.VUE: ["vue", "vuejs", "vue.js"],
        Technology.DJANGO: ["django", "django rest"],
        Technology.FLASK: ["flask", "flask restful"],
        Technology.SPRING: ["spring", "spring boot", "spring mvc"],
        Technology.ASPNET: ["asp.net", "aspnet", ".net core", "c#", "csharp"],
        Technology.RUBY_ON_RAILS: ["ruby on rails", "rails", "ruby"],
        Technology.LARAVEL: ["laravel", "php artisan"],
        Technology.EXPRESS: ["express", "expressjs"],
        Technology.FASTAPI: ["fastapi", "fast api"],
        Technology.GIN: ["gin", "gin gonic"],
    }

    # ── Bug class keyword maps ───────────────────────────────────

    BUG_CLASS_PATTERNS: dict[BugClass, list[str]] = {
        BugClass.SQL_INJECTION: [
            "sql injection", "sqli", "sql injection", "blind sql",
        ],
        BugClass.XSS: ["xss", "cross-site scripting", "cross site scripting"],
        BugClass.CSRF: ["csrf", "cross-site request forgery", "xsrf"],
        BugClass.SSRF: ["ssrf", "server-side request forgery"],
        BugClass.RCE: ["rce", "remote code execution", "code execution"],
        BugClass.LFI: ["lfi", "local file inclusion", "file inclusion"],
        BugClass.IDOR: ["idor", "insecure direct object reference"],
        BugClass.AUTH_BYPASS: [
            "authentication bypass", "auth bypass", "authz bypass",
        ],
        BugClass.RACE_CONDITION: ["race condition", "toctou"],
        BugClass.DESERIALIZATION: [
            "deserialization", "deserialization attack",
        ],
        BugClass.XXE: ["xxe", "xml external entity"],
        BugClass.SSTI: ["ssti", "server-side template injection"],
        BugClass.OPEN_REDIRECT: ["open redirect", "url redirection"],
        BugClass.PATH_TRAVERSAL: [
            "path traversal", "directory traversal", "../",
        ],
        BugClass.COMMAND_INJECTION: [
            "command injection", "os command injection",
        ],
        BugClass.CORS_MISCONFIG: ["cors", "cross-origin resource sharing"],
        BugClass.HTTP_REQUEST_SMUGGLING: ["request smuggling", "http smuggling"],
    }

    # ── Cloud provider keyword maps ──────────────────────────────

    CLOUD_PATTERNS: dict[CloudProvider, list[str]] = {
        CloudProvider.AWS: ["aws", "amazon web services", "s3", "lambda", "ec2"],
        CloudProvider.AZURE: ["azure", "microsoft azure", "azure ad"],
        CloudProvider.GCP: ["gcp", "google cloud", "gcs", "gke"],
    }

    # ── Framework keyword maps ───────────────────────────────────

    FRAMEWORK_PATTERNS: dict[Framework, list[str]] = {
        Framework.OWASP_ASVS: ["owasp asvs", "asvs", "application security verification"],
        Framework.OWASP_WSTG: ["owasp wstg", "wstg", "web security testing guide"],
        Framework.NIST: ["nist", "nist sp 800", "nist cybersecurity"],
        Framework.MITRE_ATTACK: ["mitre attack", "att&ck", "mitre att&ck"],
        Framework.PCI_DSS: ["pci dss", "pci", "payment card industry"],
    }

    # ── Programming language keyword maps ────────────────────────

    LANGUAGE_PATTERNS: dict[str, list[str]] = {
        "Python": ["python", "django", "flask", "fastapi"],
        "JavaScript": ["javascript", "js", "node.js", "nodejs", "express"],
        "TypeScript": ["typescript", "ts", "angular", "nestjs"],
        "Go": ["golang", "go language", "go ", "gin gonic"],
        "Java": ["java", "spring", "maven", "gradle"],
        "Rust": ["rust", "rustlang", "cargo", "rustc"],
        "Ruby": ["ruby", "rails", "ruby on rails"],
        "PHP": ["php", "laravel", "wordpress"],
        "CSharp": ["c#", "csharp", ".net", "asp.net"],
        "C++": ["c++", "cpp"],
        "C": ["c language", "c programming"],
    }

    # ── Operating system keyword maps ────────────────────────────

    OS_PATTERNS: dict[str, list[str]] = {
        "Linux": ["linux", "ubuntu", "debian", "centos", "red hat", "alpine"],
        "Windows": ["windows", "win server", "iis", "active directory", "ntlm"],
        "macOS": ["macos", "os x", "mac os"],
        "Android": ["android", "adb"],
        "iOS": ["ios", "iphone", "ipad"],
    }

    # ── Tag patterns ─────────────────────────────────────────────

    _TAG_PATTERNS: dict[str, list[str]] = {
        "authentication": ["oauth", "jwt", "session", "login", "sso", "saml"],
        "authorization": ["rbac", "abac", "acl", "permissions", "role"],
        "api-security": ["rest api", "graphql", "api key", "rate limit"],
        "cloud-security": ["aws", "azure", "gcp", "cloud", "s3", "lambda"],
        "container-security": ["docker", "kubernetes", "k8s", "container"],
        "network-security": ["firewall", "waf", "cdn", "dns", "tls"],
    }

    # ── Public API ───────────────────────────────────────────────

    @classmethod
    def extract_technologies(cls, text: str) -> list[Technology]:
        found: set[Technology] = set()
        lower = text.lower()
        for tech, patterns in cls.TECHNOLOGY_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(tech)
                    break
        return sorted(found, key=lambda t: t.value)

    @classmethod
    def extract_bug_classes(cls, text: str) -> list[BugClass]:
        found: set[BugClass] = set()
        lower = text.lower()
        for bc, patterns in cls.BUG_CLASS_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(bc)
                    break
        return sorted(found, key=lambda b: b.value)

    @classmethod
    def extract_cloud_providers(cls, text: str) -> list[CloudProvider]:
        found: set[CloudProvider] = set()
        lower = text.lower()
        for cp, patterns in cls.CLOUD_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(cp)
                    break
        return sorted(found, key=lambda c: c.value)

    @classmethod
    def extract_frameworks(cls, text: str) -> list[Framework]:
        found: set[Framework] = set()
        lower = text.lower()
        for fw, patterns in cls.FRAMEWORK_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(fw)
                    break
        return sorted(found, key=lambda f: f.value)

    @classmethod
    def extract_programming_languages(cls, text: str) -> list[str]:
        found: set[str] = set()
        lower = text.lower()
        for lang, patterns in cls.LANGUAGE_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(lang)
                    break
        return sorted(found)

    @classmethod
    def extract_operating_systems(cls, text: str) -> list[str]:
        found: set[str] = set()
        lower = text.lower()
        for os_name, patterns in cls.OS_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(os_name)
                    break
        return sorted(found)

    @classmethod
    def extract_tags(cls, text: str) -> list[str]:
        found: set[str] = set()
        lower = text.lower()
        for tag, patterns in cls._TAG_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(tag)
                    break
        return sorted(found)

    @classmethod
    def extract_title(cls, text: str) -> str | None:
        """Extract a probable title from document text."""
        m = _RE_TITLE_H1.search(text)
        if m:
            return m.group(1).strip()
        m = _RE_TITLE_HTML.search(text)
        if m:
            return m.group(1).strip()
        lines = [l.strip() for l in text.strip().split("\n") if l.strip()]
        if lines and len(lines[0]) < 200:
            return lines[0]
        return None

    @classmethod
    def extract_author(cls, text: str) -> str | None:
        m = _RE_AUTHOR_MD.search(text)
        if m:
            return m.group(1).strip()
        return None

    @classmethod
    def extract_version(cls, text: str) -> str | None:
        m = _RE_VERSION.search(text)
        if m:
            return m.group(1).strip()
        return None

    @classmethod
    def extract_date(cls, text: str) -> str | None:
        m = _RE_DATE.search(text)
        if m:
            return m.group(1).strip()
        return None

    @classmethod
    def extract_all(cls, text: str) -> dict[str, list[str]]:
        """Run all extractors and return results as string lists.

        Returns:
            Dict with keys ``technologies``, ``bug_classes``,
            ``cloud_providers``, ``frameworks``, ``languages``,
            ``operating_systems``, ``tags``.
        """
        return {
            "technologies": [t.value for t in cls.extract_technologies(text)],
            "bug_classes": [b.value for b in cls.extract_bug_classes(text)],
            "cloud_providers": [c.value for c in cls.extract_cloud_providers(text)],
            "frameworks": [f.value for f in cls.extract_frameworks(text)],
            "languages": cls.extract_programming_languages(text),
            "operating_systems": cls.extract_operating_systems(text),
            "tags": cls.extract_tags(text),
        }
