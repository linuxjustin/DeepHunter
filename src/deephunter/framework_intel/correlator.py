"""Framework Correlator — maps technology combinations to framework stacks.

Examples:
  Nginx + PHP + Laravel -> LEMP + Laravel stack
  Nginx + Python + Django -> Django stack
  React + Next.js + Node.js -> Next.js fullstack
"""

from __future__ import annotations

from deephunter.framework_intel.models import FrameworkStack, StackCorrelation


# Known framework stacks and their technology signatures.
_STACK_SIGNATURES: list[tuple[set[str], str, str, list[str], str]] = [
    ({"nginx", "php", "laravel"}, "LEMP + Laravel", "Nginx/PHP/Laravel stack on Linux", ["laravel", "php", "nginx"], "high"),
    ({"apache", "php", "laravel"}, "LAMP + Laravel", "Apache/PHP/Laravel stack", ["laravel", "php", "apache"], "high"),
    ({"nginx", "python", "django"}, "Django Stack", "Nginx/Python/Django stack", ["django", "python", "nginx"], "high"),
    ({"nginx", "node.js", "express"}, "Express Stack", "Nginx/Node.js/Express stack", ["express", "node.js", "nginx"], "high"),
    ({"nginx", "python", "flask"}, "Flask Stack", "Nginx/Python/Flask stack", ["flask", "python", "nginx"], "high"),
    ({"nginx", "python", "fastapi"}, "FastAPI Stack", "Nginx/Python/FastAPI stack", ["fastapi", "python", "nginx"], "high"),
    ({"nginx", "java", "spring"}, "Spring Boot Stack", "Nginx/Java/Spring Boot stack", ["spring", "java", "nginx"], "high"),
    ({"nginx", "node.js", "next.js"}, "Next.js Stack", "Nginx/Node.js/Next.js stack", ["next.js", "node.js", "nginx"], "high"),
    ({"nginx", "ruby", "rails"}, "Rails Stack", "Nginx/Ruby/Rails stack", ["rails", "ruby", "nginx"], "high"),
    ({"nginx", "asp.net", "dotnet"}, "ASP.NET Stack", "Nginx/ASP.NET stack", ["asp.net", "dotnet", "nginx"], "high"),
    ({"iis", "asp.net", "dotnet"}, "IIS + ASP.NET", "IIS/ASP.NET stack on Windows", ["asp.net", "dotnet", "iis"], "high"),
    ({"nginx", "php", "wordpress"}, "WordPress Stack", "Nginx/PHP/WordPress stack", ["wordpress", "php", "nginx"], "high"),
    ({"apache", "php", "wordpress"}, "LAMP + WordPress", "Apache/PHP/WordPress stack", ["wordpress", "php", "apache"], "high"),
    ({"nginx", "php", "drupal"}, "Drupal Stack", "Nginx/PHP/Drupal stack", ["drupal", "php", "nginx"], "high"),
    ({"nginx", "php", "magento"}, "Magento Stack", "Nginx/PHP/Magento stack", ["magento", "php", "nginx"], "high"),
    ({"nginx", "python"}, "Python Web Stack", "Nginx/Python web application", ["python", "nginx"], "medium"),
    ({"nginx", "php"}, "PHP Web Stack", "Nginx/PHP web application", ["php", "nginx"], "medium"),
    ({"node.js", "express"}, "Express API", "Node.js Express API", ["express", "node.js"], "medium"),
    ({"python", "flask"}, "Flask Application", "Python Flask application", ["flask", "python"], "medium"),
    ({"python", "fastapi"}, "FastAPI Application", "Python FastAPI application", ["fastapi", "python"], "medium"),
    ({"react", "next.js"}, "Next.js Frontend", "React with Next.js framework", ["next.js", "react"], "medium"),
    ({"python", "django"}, "Django Application", "Python Django application", ["django", "python"], "medium"),
    ({"php", "laravel"}, "Laravel Application", "PHP Laravel application", ["laravel", "php"], "medium"),
    ({"java", "spring"}, "Spring Boot Application", "Java Spring Boot application", ["spring", "java"], "medium"),
    ({"ruby", "rails"}, "Rails Application", "Ruby on Rails application", ["rails", "ruby"], "medium"),
    ({"php", "wordpress"}, "WordPress Site", "PHP WordPress site", ["wordpress", "php"], "medium"),
    ({"php", "drupal"}, "Drupal Site", "PHP Drupal site", ["drupal", "php"], "medium"),
    ({"asp.net"}, "ASP.NET Application", "ASP.NET web application", ["asp.net"], "medium"),
    ({"cloudflare", "nginx", "laravel"}, "Cloudflare + Laravel", "Laravel behind Cloudflare CDN", ["laravel", "cloudflare", "nginx"], "high"),
    ({"cloudflare", "nginx", "wordpress"}, "Cloudflare + WordPress", "WordPress behind Cloudflare", ["wordpress", "cloudflare"], "high"),
    # ── Standalone frameworks / CMSes (bare-minimum detection) ──
    ({"laravel"}, "Laravel Application (standalone)", "PHP Laravel application", ["laravel"], "low"),
    ({"django"}, "Django Application (standalone)", "Python Django application", ["django"], "low"),
    ({"wordpress"}, "WordPress Site (standalone)", "PHP WordPress site", ["wordpress"], "low"),
    ({"drupal"}, "Drupal Site (standalone)", "PHP Drupal site", ["drupal"], "low"),
    ({"magento"}, "Magento Site (standalone)", "PHP Magento site", ["magento"], "low"),
    ({"flask"}, "Flask Application (standalone)", "Python Flask application", ["flask"], "low"),
    ({"fastapi"}, "FastAPI Application (standalone)", "Python FastAPI application", ["fastapi"], "low"),
    ({"express"}, "Express Application (standalone)", "Node.js Express application", ["express"], "low"),
    ({"rails"}, "Rails Application (standalone)", "Ruby on Rails application", ["rails"], "low"),
    ({"next.js"}, "Next.js Application (standalone)", "React Next.js application", ["next.js"], "low"),
    ({"spring"}, "Spring Boot Application (standalone)", "Java Spring Boot application", ["spring"], "low"),
    ({"asp.net"}, "ASP.NET Application (standalone)", "ASP.NET web application", ["asp.net"], "low"),
]


class FrameworkCorrelator:
    """Correlates detected technologies into framework stacks."""

    def __init__(self) -> None:
        self._signatures = _STACK_SIGNATURES

    def correlate(self, detected_technologies: list[str]) -> StackCorrelation:
        """Correlate detected technologies into known framework stacks.

        Args:
            detected_technologies: List of technology names detected by httpx or
                other fingerprinting tools.

        Returns:
            StackCorrelation with matched stacks and unmatched technologies.
        """
        tech_set = {t.lower().strip() for t in detected_technologies}
        found_stacks: list[FrameworkStack] = []
        matched_techs: set[str] = set()

        for sig, name, desc, techs, conf in self._signatures:
            if sig.issubset(tech_set):
                stack = FrameworkStack(
                    name=name,
                    description=desc,
                    technologies=techs,
                    confidence=conf,
                    tags=list(sig),
                )
                found_stacks.append(stack)
                matched_techs.update(sig)

        unmatched = sorted(tech_set - matched_techs)

        return StackCorrelation(
            source_technologies=detected_technologies,
            stacks=found_stacks,
            unmatched_technologies=unmatched,
        )

    def add_custom_signature(
        self,
        required_techs: set[str],
        stack_name: str,
        stack_description: str = "",
        technologies: list[str] | None = None,
        confidence: str = "medium",
    ) -> None:
        self._signatures.append((
            required_techs,
            stack_name,
            stack_description,
            technologies or list(required_techs),
            confidence,
        ))

    def list_known_stacks(self) -> list[str]:
        return sorted({s[1] for s in self._signatures})
