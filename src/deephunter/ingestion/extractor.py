"""Metadata extraction from parsed document content.

Heuristic-based extraction of titles, authors, tags, and technology
mentions from plain text.
"""

from __future__ import annotations

from deephunter.core.types import (
    BugClass,
    CloudProvider,
    Technology,
)


class MetadataExtractor:
    """Extracts structured metadata from plain text content.

    Uses regex patterns and keyword matching to identify technologies,
    bug classes, cloud providers, and other interesting attributes.
    Results are best-effort and should be reviewed by a researcher.
    """

    # Technology keyword maps
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

    # Bug class keyword maps
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

    # Cloud provider patterns
    CLOUD_PATTERNS: dict[CloudProvider, list[str]] = {
        CloudProvider.AWS: ["aws", "amazon web services", "s3", "lambda", "ec2"],
        CloudProvider.AZURE: ["azure", "microsoft azure", "azure ad"],
        CloudProvider.GCP: ["gcp", "google cloud", "gcs", "gke"],
    }

    @classmethod
    def extract_technologies(cls, text: str) -> list[Technology]:
        """Detect technologies mentioned in the text.

        Args:
            text: The plain text content to scan.

        Returns:
            List of detected technologies (deduplicated).
        """
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
        """Detect bug classes mentioned in the text.

        Args:
            text: The plain text content to scan.

        Returns:
            List of detected bug classes (deduplicated).
        """
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
        """Detect cloud providers mentioned in the text.

        Args:
            text: The plain text content to scan.

        Returns:
            List of detected cloud providers (deduplicated).
        """
        found: set[CloudProvider] = set()
        lower = text.lower()
        for cp, patterns in cls.CLOUD_PATTERNS.items():
            for pattern in patterns:
                if pattern in lower:
                    found.add(cp)
                    break
        return sorted(found, key=lambda c: c.value)

    @classmethod
    def extract_all(cls, text: str) -> dict[str, list[str]]:
        """Run all extractors and return results as string lists.

        Args:
            text: The plain text content to scan.

        Returns:
            Dict with keys 'technologies', 'bug_classes', 'cloud_providers'.
        """
        return {
            "technologies": [t.value for t in cls.extract_technologies(text)],
            "bug_classes": [b.value for b in cls.extract_bug_classes(text)],
            "cloud_providers": [c.value for c in cls.extract_cloud_providers(text)],
        }
