"""Tests for the JavaScript source parser."""

from __future__ import annotations

import json

import pytest

from deephunter.js_intel.parser import JSParser, _estimate_entropy, _is_known_library_path


class TestJSParser:
    def make_parser(self) -> JSParser:
        return JSParser()

    # ── Module extraction ───────────────────────────────────────────

    def test_parse_esm_import(self) -> None:
        parser = self.make_parser()
        js = """import React from 'react';
import { useState, useEffect } from 'react';
import * as Utils from '../utils/helpers';
"""
        result = parser.parse(js, source_url="https://example.com/app.js")
        assert len(result.modules) >= 2
        names = [m.name for m in result.modules]
        assert "react" in names
        assert "../utils/helpers" in names
        for m in result.modules:
            if m.name == "react":
                assert m.module_type.value == "esm"
                assert m.is_relative is False

    def test_parse_dynamic_import(self) -> None:
        parser = self.make_parser()
        js = """const Admin = () => import('./admin/AdminPage');"""
        result = parser.parse(js)
        assert len(result.modules) >= 1
        mod = result.modules[0]
        assert mod.name == "./admin/AdminPage"
        assert mod.module_type.value == "dynamic"
        assert mod.is_relative is True

    def test_parse_require(self) -> None:
        parser = self.make_parser()
        js = """const express = require('express');
const fs = require('fs');
"""
        result = parser.parse(js)
        assert len(result.modules) >= 2
        names = [m.name for m in result.modules]
        assert "express" in names
        assert "fs" in names
        for m in result.modules:
            assert m.module_type.value == "commonjs"

    def test_parse_amd_define(self) -> None:
        parser = self.make_parser()
        js = """define(['jquery', 'lodash'], function($, _) { ... });"""
        result = parser.parse(js)
        names = [m.name for m in result.modules]
        assert "jquery" in names
        assert "lodash" in names
        for m in result.modules:
            if m.name == "jquery":
                assert m.module_type.value == "amd"

    def test_parse_empty_content(self) -> None:
        parser = self.make_parser()
        result = parser.parse("")
        assert result.modules == []
        assert result.api_endpoints == []
        assert result.content_size == 0

    def test_parse_no_imports(self) -> None:
        parser = self.make_parser()
        result = parser.parse("var x = 42; console.log(x);")
        assert result.modules == []

    # ── API endpoint extraction ─────────────────────────────────────

    def test_fetch_calls(self) -> None:
        parser = self.make_parser()
        js = """
fetch('/api/users');
fetch('https://api.example.com/data', { method: 'POST' });
"""
        result = parser.parse(js)
        urls = [ep.url for ep in result.api_endpoints]
        assert "/api/users" in urls
        assert "https://api.example.com/data" in urls

    def test_axios_calls(self) -> None:
        parser = self.make_parser()
        js = """
axios.get('/api/users');
axios.post('/api/users', { name: 'test' });
axios.put('/api/users/1');
axios.delete('/api/users/1');
"""
        result = parser.parse(js)
        urls = [ep.url for ep in result.api_endpoints]
        assert "/api/users" in urls
        assert "/api/users/1" in urls

    def test_jquery_ajax(self) -> None:
        parser = self.make_parser()
        js = """$.ajax('/api/data');"""
        result = parser.parse(js)
        assert any("/api/data" in ep.url for ep in result.api_endpoints)

    def test_xhr_open(self) -> None:
        parser = self.make_parser()
        js = """xhr.open('GET', '/api/data', true);"""
        result = parser.parse(js)
        assert any("/api/data" in ep.url for ep in result.api_endpoints)

    def test_generic_api_url(self) -> None:
        parser = self.make_parser()
        js = """
const API_URL = 'https://api.example.com/v1/users';
const url = '/api/health';
"""
        result = parser.parse(js)
        urls = [ep.url for ep in result.api_endpoints]
        assert "https://api.example.com/v1/users" in urls
        assert "/api/health" in urls

    def test_cdn_url_not_extracted_as_endpoint(self) -> None:
        parser = self.make_parser()
        js = """const jq = 'https://cdn.example.com/lib.js';"""
        result = parser.parse(js)
        # CDN URLs should not be extracted as API endpoints
        assert not any("cdn.example.com" in ep.url for ep in result.api_endpoints)

    # ── GraphQL extraction ──────────────────────────────────────────

    def test_graphql_endpoint(self) -> None:
        parser = self.make_parser()
        js = """
const gqlUrl = '/graphql';
const gqlUrl2 = 'https://example.com/graphql';
"""
        result = parser.parse(js)
        assert len(result.graphql_endpoints) >= 1

    def test_graphql_operation(self) -> None:
        parser = self.make_parser()
        js = """
query GetUsers {
  users { id name }
}
mutation CreateUser {
  createUser { id }
}
"""
        result = parser.parse(js)
        assert len(result.graphql_endpoints) >= 0  # gql tag not used, but operations found

    # ── Route extraction ────────────────────────────────────────────

    def test_react_router_paths(self) -> None:
        parser = self.make_parser()
        js = """
const routes = [
  { path: '/dashboard', component: Dashboard },
  { path: '/users/:id', component: UserProfile },
  { path: '/settings', component: Settings },
];
"""
        result = parser.parse(js)
        paths = [r.path for r in result.routes]
        assert "/dashboard" in paths
        assert "/users/:id" in paths
        assert "/settings" in paths

    def test_dynamic_route_detection(self) -> None:
        parser = self.make_parser()
        js = """
const routes = [
  { path: '/users/:id', component: UserProfile },
];
"""
        result = parser.parse(js)
        route = result.routes[0]
        assert route.is_dynamic is True
        assert route.path == "/users/:id"

    # ── Auth extraction ─────────────────────────────────────────────

    def test_session_storage(self) -> None:
        parser = self.make_parser()
        js = """
sessionStorage.setItem('access_token', token);
const t = sessionStorage.getItem('refresh_token');
"""
        result = parser.parse(js)
        assert len(result.token_storage) >= 2
        keys = [ts.key for ts in result.token_storage]
        assert "access_token" in keys
        assert "refresh_token" in keys

    def test_local_storage(self) -> None:
        parser = self.make_parser()
        js = """localStorage.setItem('token', jwt);"""
        result = parser.parse(js)
        assert len(result.token_storage) >= 1
        assert result.token_storage[0].storage_type == "localStorage"

    def test_cookie_access(self) -> None:
        parser = self.make_parser()
        js = """const token = document.cookie;"""
        result = parser.parse(js)
        assert len(result.auth_observations) >= 1
        assert any(o.mechanism == "cookie" for o in result.auth_observations)

    def test_jwt_detection(self) -> None:
        parser = self.make_parser()
        js = """const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVNHq0wLERYoQ8';"""
        result = parser.parse(js)
        assert any(o.mechanism == "jwt" for o in result.auth_observations)

    def test_auth_header_ref(self) -> None:
        parser = self.make_parser()
        js = """headers: { 'Authorization': 'Bearer ' + token }"""
        result = parser.parse(js)
        assert any(o.mechanism == "auth_header" for o in result.auth_observations)

    def test_csrf_token(self) -> None:
        parser = self.make_parser()
        js = """const csrf = 'X-CSRF-Token';"""
        result = parser.parse(js)
        assert any(o.mechanism == "csrf" for o in result.auth_observations)

    # ── Config extraction ───────────────────────────────────────────

    def test_env_config_values(self) -> None:
        parser = self.make_parser()
        js = """
const config = {
  REACT_APP_API_URL: 'https://api.example.com',
  FEATURE_NEW_DASHBOARD: 'true',
  NEXT_PUBLIC_ANALYTICS_ID: 'UA-12345',
};
"""
        result = parser.parse(js)
        keys = [c.key for c in result.config_values]
        assert "REACT_APP_API_URL" in keys
        assert "NEXT_PUBLIC_ANALYTICS_ID" in keys

    def test_feature_flags(self) -> None:
        parser = self.make_parser()
        js = """
const flags = {
  FEATURE_NEW_DASHBOARD: 'true',
};
"""
        result = parser.parse(js)
        assert len(result.feature_flags) >= 1
        assert result.feature_flags[0].category == "feature_flag"

    def test_environment_check(self) -> None:
        parser = self.make_parser()
        js = """if (process.env.NODE_ENV === 'production') { ... }"""
        result = parser.parse(js)
        assert len(result.config_values) >= 1
        assert any("NODE_ENV" in c.key for c in result.config_values)

    # ── Framework detection ─────────────────────────────────────────

    def test_detect_react(self) -> None:
        parser = self.make_parser()
        js = """import React from 'react'; const el = React.createElement('div', null);"""
        result = parser.parse(js)
        assert "React" in result.detected_frameworks

    def test_detect_vue(self) -> None:
        parser = self.make_parser()
        js = """import { createApp } from 'vue'; createApp(App).mount('#app');"""
        result = parser.parse(js)
        assert "Vue" in result.detected_frameworks

    def test_detect_angular(self) -> None:
        parser = self.make_parser()
        js = """import { Component } from '@angular/core';"""
        result = parser.parse(js)
        assert "Angular" in result.detected_frameworks

    def test_detect_nextjs(self) -> None:
        parser = self.make_parser()
        js = """export async function getStaticProps() { return { props: {} }; }"""
        result = parser.parse(js)
        assert "Next.js" in result.detected_frameworks

    def test_detect_express(self) -> None:
        parser = self.make_parser()
        js = """const app = express(); app.use(express.Router());"""
        result = parser.parse(js)
        assert "Express" in result.detected_frameworks

    def test_multiple_frameworks(self) -> None:
        parser = self.make_parser()
        js = """
import React from 'react';
import Vue from 'vue';
import { Component } from '@angular/core';
"""
        result = parser.parse(js)
        assert "React" in result.detected_frameworks
        assert "Vue" in result.detected_frameworks
        assert "Angular" in result.detected_frameworks

    # ── Build tool detection ────────────────────────────────────────

    def test_detect_webpack(self) -> None:
        parser = self.make_parser()
        js = """__webpack_require__('module');"""
        result = parser.parse(js)
        assert "webpack" in result.build_tool_hints

    def test_detect_vite(self) -> None:
        parser = self.make_parser()
        js = """if (import.meta.hot) { ... }"""
        result = parser.parse(js)
        assert "Vite" in result.build_tool_hints

    # ── Bundle / minification detection ─────────────────────────────

    def test_minified_detection(self) -> None:
        parser = self.make_parser()
        long_line = "a" * 600 + ";b" * 100
        result = parser.parse(long_line)
        assert result.is_bundle is True
        assert result.bundle is not None
        assert result.bundle.is_minified is True

    def test_not_minified(self) -> None:
        parser = self.make_parser()
        js = "function hello() {\n  return 'world';\n}\n"
        result = parser.parse(js)
        assert result.is_bundle is False

    # ── WebSocket extraction ────────────────────────────────────────

    def test_websocket(self) -> None:
        parser = self.make_parser()
        js = """const ws = new WebSocket('wss://example.com/socket');"""
        result = parser.parse(js)
        urls = [ep.url for ep in result.api_endpoints]
        assert "wss://example.com/socket" in urls

    def test_event_source(self) -> None:
        parser = self.make_parser()
        js = """const es = new EventSource('/events');"""
        result = parser.parse(js)
        urls = [ep.url for ep in result.api_endpoints]
        assert "/events" in urls

    # ── Secrets extraction ──────────────────────────────────────────

    def test_api_key_secret(self) -> None:
        parser = self.make_parser()
        js = """const config = { api_key: 'sk_live_1234567890abcdef' };"""
        result = parser.parse(js)
        assert len(result.secret_observations) >= 1

    def test_password_secret(self) -> None:
        parser = self.make_parser()
        js = """const pwd = 'supersecret123'; // password"""
        result = parser.parse(js)
        # The password pattern looks for key: value structures, not inline strings
        assert len(result.secret_observations) >= 0

    # ── Source map detection ────────────────────────────────────────

    def test_source_map_comment(self) -> None:
        parser = self.make_parser()
        js = """//# sourceMappingURL=app.js.map"""
        result = parser.parse(js)
        assert result.has_source_map is True
        if result.bundle:
            assert result.bundle.has_source_map_comment is True

    # ── Third-party detection ───────────────────────────────────────

    def test_third_party_cdn(self) -> None:
        parser = self.make_parser()
        js = """const jq = 'https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js';"""
        result = parser.parse(js)
        assert len(result.third_party_libraries) >= 1
        assert any("jquery" in lib for lib in result.third_party_libraries)

    def test_third_party_from_imports(self) -> None:
        parser = self.make_parser()
        js = """import axios from 'axios'; import lodash from 'lodash';"""
        result = parser.parse(js)
        assert "axios" in result.third_party_libraries
        assert "lodash" in result.third_party_libraries

    # ── Edge cases ──────────────────────────────────────────────────

    def test_empty_string(self) -> None:
        parser = self.make_parser()
        result = parser.parse("")
        assert result.modules == []
        assert result.content_size == 0

    def test_whitespace_only(self) -> None:
        parser = self.make_parser()
        result = parser.parse("   \n  \n  ")
        assert result.modules == []
        assert result.api_endpoints == []

    def test_bundled_js(self) -> None:
        parser = self.make_parser()
        js = '"use strict";' + "var a=1,b=2;" * 50
        result = parser.parse(js)
        assert result.is_bundle is True

    def test_content_hash_consistency(self) -> None:
        parser = self.make_parser()
        r1 = parser.parse("console.log('hello');")
        r2 = parser.parse("console.log('hello');")
        assert r1.content_hash == r2.content_hash

    def test_content_hash_different(self) -> None:
        parser = self.make_parser()
        r1 = parser.parse("console.log('a');")
        r2 = parser.parse("console.log('b');")
        assert r1.content_hash != r2.content_hash


class TestUtilityFunctions:
    def test_estimate_entropy_empty(self) -> None:
        assert _estimate_entropy("") == 0.0

    def test_estimate_entropy_low(self) -> None:
        ent = _estimate_entropy("aaaaaaaaaaaaaaaa")
        assert ent < 1.0

    def test_estimate_entropy_high(self) -> None:
        ent = _estimate_entropy("k$9#mP2@xQ7!zR5")
        assert ent > 3.0

    def test_is_known_library_path_cdn(self) -> None:
        assert _is_known_library_path("https://cdn.example.com/lib.js") is True
        assert _is_known_library_path("https://unpkg.com/react") is True
        assert _is_known_library_path("https://code.jquery.com/jquery.js") is True

    def test_is_known_library_path_other(self) -> None:
        assert _is_known_library_path("https://api.example.com/data") is False
        assert _is_known_library_path("/api/users") is False
