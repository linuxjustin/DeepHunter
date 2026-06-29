"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path
from typing import Generator

import pytest
import yaml

from deephunter.core.config import DeepHunterConfig
from deephunter.core.types import (
    BugClass,
    Confidence,
    DocumentType,
    SourceType,
    Technology,
    TestingIdea,
)
from deephunter.knowledge.models import SKOBuilder, SecurityKnowledgeObject
from deephunter.knowledge.store import KnowledgeStore
from deephunter.parsers.base import ParserRegistry


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
def empty_store() -> KnowledgeStore:
    return KnowledgeStore()


@pytest.fixture
def populated_store() -> KnowledgeStore:
    store = KnowledgeStore()

    sko1 = (
        SKOBuilder()
        .title("JWT Authentication Bypass")
        .summary("Common JWT attacks including alg confusion and key confusion.")
        .source("https://example.com/jwt")
        .source_type(SourceType.OWASP)
        .add_bug_class(BugClass.AUTH_BYPASS)
        .add_technology(Technology.NODEJS)
        .add_tag("jwt")
        .add_tag("authentication")
        .raw_content("JWT (JSON Web Tokens) are commonly used for authentication...")
        .confidence(Confidence.HIGH)
        .build()
    )

    sko2 = (
        SKOBuilder()
        .title("SQL Injection in REST APIs")
        .summary("SQL injection techniques specific to REST API endpoints.")
        .source("https://example.com/sqli")
        .source_type(SourceType.PAYLOADS_ALL_THE_THINGS)
        .add_bug_class(BugClass.SQL_INJECTION)
        .add_technology(Technology.DJANGO)
        .add_tag("sqli")
        .raw_content("SQL injection remains a critical vulnerability...")
        .confidence(Confidence.MEDIUM)
        .build()
    )

    sko3 = (
        SKOBuilder()
        .title("XSS Prevention Cheat Sheet")
        .summary("Cross-site scripting prevention techniques and bypasses.")
        .source("https://example.com/xss")
        .source_type(SourceType.OWASP)
        .add_bug_class(BugClass.XSS)
        .add_technology(Technology.REACT)
        .add_tag("xss")
        .raw_content("Cross-site scripting (XSS) vulnerabilities allow attackers...")
        .confidence(Confidence.HIGH)
        .build()
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


@pytest.fixture
def clear_parser_registry() -> Generator:
    ParserRegistry.clear()
    yield
    ParserRegistry.clear()