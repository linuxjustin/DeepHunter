"""Tests for the JavaScript Intelligence Tool Adapter."""

from __future__ import annotations

import pytest

from deephunter.js_intel.adapter import JavaScriptIntelAdapter
from deephunter.recon.models import ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import ToolCategory


class TestJavaScriptIntelAdapter:
    def make_adapter(self) -> JavaScriptIntelAdapter:
        return JavaScriptIntelAdapter()

    def test_name(self) -> None:
        adapter = self.make_adapter()
        assert adapter.name == "js_intel_adapter"
        assert adapter.category == ToolCategory.js_analysis

    def test_metadata(self) -> None:
        adapter = self.make_adapter()
        assert adapter.metadata.version == "1.0.0"
        assert "javascript" in adapter.metadata.tags
        assert adapter.metadata.category == ToolCategory.js_analysis

    def test_execute_raises(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        with pytest.raises(NotImplementedError, match="import-only"):
            adapter.execute(ctx)

    def test_parse_output_string(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        result = adapter.parse_output("var x = 1;", ctx)
        assert result == "var x = 1;"

    def test_parse_output_bytes(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        result = adapter.parse_output(b"var x = 2;", ctx)
        assert result == "var x = 2;"

    def test_parse_output_none(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        assert adapter.parse_output(None, ctx) == ""

    def test_parse_output_empty(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        assert adapter.parse_output("", ctx) == ""

    def test_normalize_with_content(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext(args={"source_url": "https://example.com/app.js"})
        result = adapter.normalize("import React from 'react'; fetch('/api/data');", ctx)
        assert isinstance(result, PluginResult)
        assert result.success is True
        assert len(result.js_files) == 1
        assert len(result.js_endpoints) >= 1
        assert len(result.technologies) >= 1

    def test_normalize_with_host_id(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext(args={
            "source_url": "https://example.com/app.js",
            "host_id": "host-1",
        })
        result = adapter.normalize("fetch('/api/users');", ctx)
        assert result.js_files[0].host_id == "host-1"

    def test_normalize_empty(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        result = adapter.normalize("", ctx)
        assert result.success is True
        assert result.js_files == []

    def test_normalize_import_only(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        result = adapter.normalize("   \n  \n  ", ctx)
        assert result.success is True

    def test_normalize_framework_detection(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext(args={"source_url": "https://example.com/app.js"})
        result = adapter.normalize("import React from 'react'; import Vue from 'vue';", ctx)
        tech_names = [t.name for t in result.technologies]
        assert "React" in tech_names
        assert "Vue" in tech_names

    def test_normalize_application_creation(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext(args={"source_url": "https://example.com/app.js"})
        result = adapter.normalize("import React from 'react';", ctx)
        assert len(result.applications) >= 1

    def test_build_command(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext()
        cmd = adapter.build_command(ctx)
        assert "js_intel_adapter" in cmd
        assert "import-only" in cmd

    def test_endpoints_have_source(self) -> None:
        adapter = self.make_adapter()
        ctx = ExecutionContext(args={"source_url": "https://example.com/app.js"})
        result = adapter.normalize("fetch('/api/data');", ctx)
        for ep in result.js_endpoints:
            assert ep.source == ReconSourceType.JAVASCRIPT_ANALYSIS

    def test_dependency_injection(self) -> None:
        from deephunter.js_intel.engine import JSAnalysisEngine

        engine = JSAnalysisEngine()
        adapter = JavaScriptIntelAdapter(engine=engine)
        ctx = ExecutionContext(args={"source_url": "https://example.com/app.js"})
        result = adapter.normalize("var x = 1;", ctx)
        assert result.success is True
