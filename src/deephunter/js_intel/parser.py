"""JavaScript source parser — extracts structured intelligence from JS text.

Uses regex-based static analysis (not AST parsing) for speed and resilience
against minified, bundled, or syntax-invalid JavaScript.

Design goals:
- Fast — suitable for millions of artifacts
- Resilient — works on truncated, bundled, or transpiled output
- Extensible — add new patterns to ``patterns.py``
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from deephunter.js_intel import patterns as p
from deephunter.js_intel.models import (
    JSAnalysisResult,
    JSAuthObs,
    JSBundle,
    JSConfigObs,
    JSCookieUsage,
    JSEndpointRef,
    JSFrameworkObs,
    JSModule,
    JSRoute,
    JSSecretObs,
    JSTokenStorage,
    ModuleType,
)
from deephunter.recon.models import EndpointCategory, HttpMethod


class JSParser:
    """Regex-based JavaScript content parser.

    Produces structured observations from raw JavaScript source text.
    Thread-safe and stateless — all state is returned in the result.
    """

    def parse(self, content: str, source_url: str = "") -> JSAnalysisResult:
        """Parse JavaScript source and extract structured intelligence.

        Args:
            content: Raw JavaScript source text.
            source_url: Origin URL of the JavaScript file.

        Returns:
            JSAnalysisResult with all extracted observations.
        """
        content_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        content_size = len(content.encode("utf-8"))

        result = JSAnalysisResult(
            source_url=source_url,
            content_hash=content_hash,
            content_size=content_size,
            original_source_url=source_url,
        )

        self._detect_bundle_info(content, result)
        self._extract_modules(content, source_url, result)
        self._extract_api_endpoints(content, source_url, result)
        self._extract_graphql(content, source_url, result)
        self._extract_routes(content, source_url, result)
        self._extract_auth(content, source_url, result)
        self._extract_config(content, source_url, result)
        self._extract_frameworks(content, result)
        self._extract_build_tools(content, result)
        self._extract_third_party(content, result)
        self._extract_websockets(content, source_url, result)
        self._extract_secrets(content, source_url, result)
        self._detect_source_map(content, result)

        return result

    # ── Bundle detection ─────────────────────────────────────────────

    @staticmethod
    def _detect_bundle_info(content: str, result: JSAnalysisResult) -> None:
        is_minified = bool(p.MINIFIED_HEURISTIC_SHORT_LINES.search(content))
        if not is_minified:
            break_count = len(p.MINIFIED_HEURISTIC_MANY_BREAKS.findall(content))
            line_count = content.count("\n") + 1
            if line_count > 1:
                avg_line_len = len(content) / line_count
                is_minified = avg_line_len > 200

        result.is_bundle = is_minified

        result.bundle = JSBundle(
            url=result.source_url,
            size=result.content_size,
            content_hash=result.content_hash,
            is_minified=is_minified,
        )

    # ── Module extraction ────────────────────────────────────────────

    @staticmethod
    def _extract_modules(content: str, source_url: str, result: JSAnalysisResult) -> None:
        seen_modules: set[str] = set()

        for match in p.ESM_IMPORT.finditer(content):
            raw = match.group(0)
            path = match.group("path")
            if not path or path in seen_modules:
                continue
            seen_modules.add(path)
            line_no = content[: match.start()].count("\n") + 1
            is_rel = path.startswith(".") or path.startswith("/")
            is_default = bool(match.group("default"))
            module_type = ModuleType.ESM if not is_default else ModuleType.ESM
            result.modules.append(JSModule(
                name=path,
                module_type=module_type,
                is_relative=is_rel,
                line_number=line_no,
                context=raw[:120],
                source_url=source_url,
            ))

        for match in p.DYNAMIC_IMPORT.finditer(content):
            path = match.group("path")
            if not path or path in seen_modules:
                continue
            seen_modules.add(path)
            line_no = content[: match.start()].count("\n") + 1
            is_rel = path.startswith(".") or path.startswith("/")
            result.modules.append(JSModule(
                name=path,
                module_type=ModuleType.DYNAMIC,
                is_relative=is_rel,
                line_number=line_no,
                context=match.group(0)[:120],
                source_url=source_url,
            ))

        for match in p.REQUIRE.finditer(content):
            path = match.group("path")
            if not path or path in seen_modules:
                continue
            seen_modules.add(path)
            line_no = content[: match.start()].count("\n") + 1
            is_rel = path.startswith(".") or path.startswith("/")
            result.modules.append(JSModule(
                name=path,
                module_type=ModuleType.COMMONJS,
                is_relative=is_rel,
                line_number=line_no,
                context=match.group(0)[:120],
                source_url=source_url,
            ))

        for match in p.DEFINE_REQUIRE.finditer(content):
            deps_str = match.group("deps") or ""
            deps = re.findall(r"""['"]([^'"]+)['"]""", deps_str)
            for dep in deps:
                if dep in seen_modules:
                    continue
                seen_modules.add(dep)
                line_no = content[: match.start()].count("\n") + 1
                is_rel = dep.startswith(".") or dep.startswith("/")
                result.modules.append(JSModule(
                    name=dep,
                    module_type=ModuleType.AMD,
                    is_relative=is_rel,
                    line_number=line_no,
                    context=match.group(0)[:120],
                    source_url=source_url,
                ))

        result.bundle.module_count = len(result.modules) if result.bundle else 0

    # ── API endpoint extraction ──────────────────────────────────────

    @staticmethod
    def _extract_api_endpoints(content: str, source_url: str, result: JSAnalysisResult) -> None:
        seen_urls: set[str] = set()

        def _add_endpoint(
            url: str,
            methods: list[HttpMethod] | None = None,
            match_obj: re.Match | None = None,
            cat: EndpointCategory = EndpointCategory.API,
        ) -> None:
            if not url or url in seen_urls:
                return
            seen_urls.add(url)
            line_no = 0
            ctx = ""
            if match_obj:
                line_no = content[: match_obj.start()].count("\n") + 1
                ctx = match_obj.group(0)[:120]
            result.api_endpoints.append(JSEndpointRef(
                url=url,
                methods=methods or [HttpMethod.GET],
                category=cat,
                source_url=source_url,
                line_number=line_no,
                context=ctx,
            ))

        for match in p.FETCH_CALL.finditer(content):
            url = match.group("url")
            _add_endpoint(url, [HttpMethod.GET], match)

        for match in p.AXIOS_CALL.finditer(content):
            method_str = match.group("method").upper()
            url = match.group("url")
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET
            _add_endpoint(url, [method], match)

        for match in p.JQUERY_AJAX.finditer(content):
            url = match.group("url") or match.group("url2") or ""
            _add_endpoint(url, [HttpMethod.GET], match)

        for match in p.XHR_OPEN.finditer(content):
            method_str = match.group("method")
            url = match.group("url")
            try:
                method = HttpMethod(method_str)
            except ValueError:
                method = HttpMethod.GET
            _add_endpoint(url, [method], match)

        for match in p.SUPERAGENT.finditer(content):
            url = match.group("url")
            _add_endpoint(url, [HttpMethod.GET], match)

        for match in p.GOT_FETCH.finditer(content):
            url = match.group("url")
            _add_endpoint(url, [HttpMethod.GET], match)

        for match in p.KY_FETCH.finditer(content):
            url = match.group("url")
            _add_endpoint(url, [HttpMethod.GET], match)

        for match in p.GENERIC_API_URL.finditer(content):
            url = match.group("url")
            if url not in seen_urls and not any(
                _is_known_library_path(url) for _ in [None]
            ):
                _add_endpoint(url, [HttpMethod.GET], match)

    # ── GraphQL extraction ───────────────────────────────────────────

    @staticmethod
    def _extract_graphql(content: str, source_url: str, result: JSAnalysisResult) -> None:
        seen_gql_urls: set[str] = set()

        for match in p.GRAPHQL_ENDPOINT.finditer(content):
            url = match.group("url")
            if url in seen_gql_urls:
                continue
            seen_gql_urls.add(url)
            line_no = content[: match.start()].count("\n") + 1
            result.graphql_endpoints.append(JSEndpointRef(
                url=url,
                methods=[HttpMethod.POST, HttpMethod.GET],
                category=EndpointCategory.GRAPHQL,
                is_graphql=True,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.GRAPHQL_OPERATION.finditer(content):
            op_name = match.group("name")
            line_no = content[: match.start()].count("\n") + 1
            if result.graphql_endpoints:
                result.graphql_endpoints[-1].graphql_operation = op_name

    # ── Route extraction ─────────────────────────────────────────────

    @staticmethod
    def _extract_routes(content: str, source_url: str, result: JSAnalysisResult) -> None:
        seen_paths: set[str] = set()

        for match in p.REACT_ROUTER_PATH.finditer(content):
            path = match.group("path")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            line_no = content[: match.start()].count("\n") + 1
            is_dynamic = ":" in path or "{" in path
            result.routes.append(JSRoute(
                path=path,
                is_dynamic=is_dynamic,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.VUE_ROUTER_PATH.finditer(content):
            path = match.group("path")
            if not path or path in seen_paths:
                continue
            seen_paths.add(path)
            line_no = content[: match.start()].count("\n") + 1
            is_dynamic = ":" in path or "{" in path
            result.routes.append(JSRoute(
                path=path,
                is_dynamic=is_dynamic,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        # Attach components to routes
        for route in result.routes:
            for match in p.REACT_ROUTER_COMPONENT.finditer(content):
                comp = match.group("component")
                if comp and not route.component:
                    route.component = comp
                    break

    # ── Authentication extraction ────────────────────────────────────

    @staticmethod
    def _extract_auth(content: str, source_url: str, result: JSAnalysisResult) -> None:
        for match in p.SESSION_STORAGE.finditer(content):
            key = match.group("key")
            line_no = content[: match.start()].count("\n") + 1
            result.token_storage.append(JSTokenStorage(
                storage_type="sessionStorage",
                key=key,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))
            result.auth_observations.append(JSAuthObs(
                mechanism="token_storage",
                location="sessionStorage",
                identifier=key,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.LOCAL_STORAGE.finditer(content):
            key = match.group("key")
            line_no = content[: match.start()].count("\n") + 1
            result.token_storage.append(JSTokenStorage(
                storage_type="localStorage",
                key=key,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))
            result.auth_observations.append(JSAuthObs(
                mechanism="token_storage",
                location="localStorage",
                identifier=key,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.COOKIE_ACCESS.finditer(content):
            value = match.group("value") or ""
            line_no = content[: match.start()].count("\n") + 1
            result.auth_observations.append(JSAuthObs(
                mechanism="cookie",
                location="document.cookie",
                identifier=value[:60],
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.JWT_PATTERN.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.auth_observations.append(JSAuthObs(
                mechanism="jwt",
                location="inline",
                identifier=match.group(0)[:60],
                value_preview=match.group(0)[:40],
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.JWT_REFERENCE.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.auth_observations.append(JSAuthObs(
                mechanism="jwt",
                location="variable",
                identifier=match.group("value")[:60],
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.AUTH_HEADER.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.auth_observations.append(JSAuthObs(
                mechanism="auth_header",
                location="header",
                identifier=match.group(0),
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.CSRF_TOKEN.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.auth_observations.append(JSAuthObs(
                mechanism="csrf",
                location="header_or_body",
                identifier=match.group(0),
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.OAUTH_PATTERN.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.auth_observations.append(JSAuthObs(
                mechanism="oauth",
                location="config",
                identifier=match.group("value") or "",
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

    # ── Config & feature flags ───────────────────────────────────────

    @staticmethod
    def _extract_config(content: str, source_url: str, result: JSAnalysisResult) -> None:
        seen_config_keys: set[str] = set()

        for match in p.CONFIG_VALUE.finditer(content):
            key = match.group("key")
            value = match.group("value")
            if key in seen_config_keys:
                continue
            seen_config_keys.add(key)
            line_no = content[: match.start()].count("\n") + 1
            category = "env_var"
            if key.startswith("FEATURE_") or key.startswith("VITE_FEATURE_"):
                category = "feature_flag"
                result.feature_flags.append(JSConfigObs(
                    key=key, value=value, category=category,
                    line_number=line_no, context=match.group(0)[:120], source_url=source_url,
                ))
            result.config_values.append(JSConfigObs(
                key=key, value=value, category=category,
                line_number=line_no, context=match.group(0)[:120], source_url=source_url,
            ))

        for match in p.FEATURE_FLAG.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.feature_flags.append(JSConfigObs(
                key=match.group(0)[:60],
                value=match.group(0),
                category="feature_flag",
                line_number=line_no,
                context=match.group(0)[:120],
                source_url=source_url,
            ))

        for match in p.ENVIRONMENT_CHECK.finditer(content):
            line_no = content[: match.start()].count("\n") + 1
            result.config_values.append(JSConfigObs(
                key=match.group(0),
                value="true",
                category="env_check",
                line_number=line_no,
                context=match.group(0)[:120],
                source_url=source_url,
            ))

    # ── Framework detection ──────────────────────────────────────────

    @staticmethod
    def _extract_frameworks(content: str, result: JSAnalysisResult) -> None:
        for framework_name, pattern_str, confidence in p.FRAMEWORK_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            match = pattern.search(content)
            if match:
                result.framework_observations.append(JSFrameworkObs(
                    framework=framework_name,
                    evidence=match.group(0)[:80],
                    confidence=confidence,
                    source_url=result.source_url,
                ))
                if framework_name not in result.detected_frameworks:
                    result.detected_frameworks.append(framework_name)

    # ── Build tool detection ─────────────────────────────────────────

    @staticmethod
    def _extract_build_tools(content: str, result: JSAnalysisResult) -> None:
        for tool_name, pattern_str, confidence in p.BUILD_TOOL_PATTERNS:
            pattern = re.compile(pattern_str, re.IGNORECASE)
            if pattern.search(content):
                if tool_name not in result.build_tool_hints:
                    result.build_tool_hints.append(tool_name)
                if result.bundle:
                    result.bundle.build_tool = tool_name

    # ── Third-party libraries ────────────────────────────────────────

    @staticmethod
    def _extract_third_party(content: str, result: JSAnalysisResult) -> None:
        for match in p.THIRD_PARTY_PATH.finditer(content):
            url = match.group(0).strip("'\"")
            if url not in result.third_party_libraries:
                result.third_party_libraries.append(url)

        # Extract library names from import paths
        for mod in result.modules:
            if not mod.is_relative and mod.name not in result.third_party_libraries:
                lib_name = mod.name.split("/")[0]
                if lib_name and lib_name not in result.third_party_libraries:
                    result.third_party_libraries.append(lib_name)

    # ── WebSocket & SSE extraction ───────────────────────────────────

    @staticmethod
    def _extract_websockets(content: str, source_url: str, result: JSAnalysisResult) -> None:
        for match in p.WEBSOCKET.finditer(content):
            url = match.group("url")
            line_no = content[: match.start()].count("\n") + 1
            result.api_endpoints.append(JSEndpointRef(
                url=url,
                methods=[HttpMethod.GET],
                category=EndpointCategory.WEBSOCKET,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

        for match in p.EVENT_SOURCE.finditer(content):
            url = match.group("url")
            line_no = content[: match.start()].count("\n") + 1
            result.api_endpoints.append(JSEndpointRef(
                url=url,
                methods=[HttpMethod.GET],
                category=EndpointCategory.WEBSOCKET,
                source_url=source_url,
                line_number=line_no,
                context=match.group(0)[:120],
            ))

    # ── Secret extraction ────────────────────────────────────────────

    @staticmethod
    def _extract_secrets(content: str, source_url: str, result: JSAnalysisResult) -> None:
        for match in p.API_KEY_PATTERN.finditer(content):
            value = match.group("value")
            line_no = content[: match.start()].count("\n") + 1
            entropy = _estimate_entropy(value)
            result.secret_observations.append(JSSecretObs(
                secret_type="api_key",
                value_preview=value[:20],
                line_number=line_no,
                context=match.group(0)[:120],
                source_url=source_url,
                entropy=entropy,
            ))

        for match in p.PASSWORD_PATTERN.finditer(content):
            value = match.group("value")
            line_no = content[: match.start()].count("\n") + 1
            result.secret_observations.append(JSSecretObs(
                secret_type="password",
                value_preview=value[:20],
                line_number=line_no,
                context=match.group(0)[:120],
                source_url=source_url,
            ))

    # ── Source map detection ─────────────────────────────────────────

    @staticmethod
    def _detect_source_map(content: str, result: JSAnalysisResult) -> None:
        if p.SOURCE_MAP_COMMENT.search(content) or p.SOURCE_MAP_HEADER.search(content):
            result.has_source_map = True
            if result.bundle:
                result.bundle.has_source_map_comment = True


def _is_known_library_path(path: str) -> bool:
    """Check if a URL path is from a known CDN or library."""
    known_prefixes = [
        "https://cdn.",
        "https://unpkg.",
        "https://cdnjs.",
        "https://fonts.",
        "https://code.jquery.com",
    ]
    return any(path.lower().startswith(pfx) for pfx in known_prefixes)


def _estimate_entropy(value: str) -> float:
    """Simple entropy estimation for a string."""
    if not value:
        return 0.0
    from math import log2

    freq: dict[str, int] = {}
    for ch in value:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * log2(c / n) for c in freq.values())
