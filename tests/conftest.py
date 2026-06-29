"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.core.config import DeepHunterConfig
from deephunter.core.types import (
    BugClass,
    Confidence,
    SourceType,
    Technology,
)
from deephunter.knowledge.models import SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore


@pytest.fixture
def sample_config() -> DeepHunterConfig:
    return DeepHunterConfig.default()


@pytest.fixture
def sample_config_path(tmp_path: Path) -> Path:
    path = tmp_path / "config.yaml"
    cfg = DeepHunterConfig.default()
    cfg.save(str(path))
    return path


@pytest.fixture
def empty_store(tmp_path: Path) -> KnowledgeStore:
    return KnowledgeStore(str(tmp_path / "store.db"))


@pytest.fixture
def populated_store(tmp_path: Path) -> KnowledgeStore:
    store = KnowledgeStore(str(tmp_path / "store.db"))

    sko1 = SecurityKnowledgeObject(
        title="JWT Authentication Bypass",
        summary="Common JWT attacks including alg confusion and key confusion.",
        source="https://example.com/jwt",
        source_type=SourceType.OWASP,
        bug_classes=[BugClass.AUTH_BYPASS],
        technology=[Technology.NODEJS],
        tags=["jwt", "authentication"],
        raw_content="JWT (JSON Web Tokens) are commonly used for authentication...",
        confidence=Confidence.HIGH,
    )

    sko2 = SecurityKnowledgeObject(
        title="SQL Injection in REST APIs",
        summary="SQL injection techniques specific to REST API endpoints.",
        source="https://example.com/sqli",
        source_type=SourceType.PAYLOADS_ALL_THE_THINGS,
        bug_classes=[BugClass.SQL_INJECTION],
        technology=[Technology.DJANGO],
        tags=["sqli"],
        raw_content="SQL injection remains a critical vulnerability...",
        confidence=Confidence.MEDIUM,
    )

    sko3 = SecurityKnowledgeObject(
        title="XSS Prevention Cheat Sheet",
        summary="Cross-site scripting prevention techniques and bypasses.",
        source="https://example.com/xss",
        source_type=SourceType.OWASP,
        bug_classes=[BugClass.XSS],
        technology=[Technology.REACT],
        tags=["xss"],
        raw_content="Cross-site scripting (XSS) vulnerabilities allow attackers...",
        confidence=Confidence.HIGH,
    )

    store.add_batch([sko1, sko2, sko3])
    return store


@pytest.fixture
def sample_markdown() -> str:
    return """# SQL Injection Testing

## Introduction

SQL injection is a code injection technique that exploits vulnerabilities in an application's software.

## Techniques

- **Classic SQLi**: `' OR '1'='1`
- **Blind SQLi**: Time-based and boolean-based
- **Union-based**: Using UNION to extract data

## Prevention

Use parameterized queries and input validation.
"""


@pytest.fixture
def sample_html() -> str:
    return """<!DOCTYPE html>
<html>
<head><title>XSS Testing Guide</title></head>
<body>
<h1>Cross-Site Scripting</h1>
<p>XSS allows attackers to inject malicious scripts.</p>
<h2>Types</h2>
<ul>
<li>Reflected XSS</li>
<li>Stored XSS</li>
<li>DOM-based XSS</li>
</ul>
</body>
</html>
"""


@pytest.fixture
def sample_json() -> str:
    return """
{
    "title": "SSRF Bypass Techniques",
    "severity": "high",
    "techniques": ["internal", "cloud", "protocol"],
    "references": ["https://example.com/ssrf"]
}
"""


@pytest.fixture
def sample_yaml() -> str:
    return """
title: Race Condition Testing
severity: medium
id: RACE-001
description: >
  Race conditions occur when multiple processes access shared resources.
tags:
  - race-condition
  - concurrency
"""


