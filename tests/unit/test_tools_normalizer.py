"""Tests for tools/normalizer.py."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from deephunter.recon.plugin import PluginResult
from deephunter.tools.context import ExecutionContext
from deephunter.tools.exceptions import PluginParseError
from deephunter.tools.models import ToolMetadata
from deephunter.tools.normalizer import (
    ImportPipeline,
    build_default_pipeline,
    parse_csv,
    parse_json,
    parse_ndjson,
    parse_path,
    parse_txt,
    parse_yaml,
)


class TestParseJson:
    def test_parse_object(self) -> None:
        result = parse_json('{"name": "test", "count": 3}', {})
        assert result["name"] == "test"
        assert result["count"] == 3

    def test_parse_array(self) -> None:
        result = parse_json('[1, 2, 3]', {})
        assert result == [1, 2, 3]

    def test_empty_object(self) -> None:
        assert parse_json("{}", {}) == {}

    def test_invalid_raises(self) -> None:
        with pytest.raises(PluginParseError):
            parse_json("not valid json", {})

    def test_nested(self) -> None:
        result = parse_json('{"a": {"b": [1, 2]}}', {})
        assert result["a"]["b"] == [1, 2]


class TestParseYaml:
    def test_parse_simple(self) -> None:
        result = parse_yaml("name: test\nversion: 1", {})
        assert result["name"] == "test"
        assert result["version"] == 1

    def test_parse_list(self) -> None:
        result = parse_yaml("- a\n- b\n- c", {})
        assert result == ["a", "b", "c"]

    def test_invalid_raises(self) -> None:
        with pytest.raises(PluginParseError):
            parse_yaml(": invalid yaml", {})

    def test_multi_document(self) -> None:
        result = parse_yaml("a: 1\n---\nb: 2", {})
        assert isinstance(result, list)
        assert result[0]["a"] == 1
        assert result[1]["b"] == 2

    def test_empty(self) -> None:
        assert parse_yaml("", {}) is None

    def test_nested_yaml(self) -> None:
        result = parse_yaml("parent:\n  child:\n    key: value", {})
        assert result["parent"]["child"]["key"] == "value"


class TestParseCsv:
    def test_simple_csv(self) -> None:
        result = parse_csv("name,age\nAlice,30\nBob,25", {})
        assert len(result) == 2
        assert result[0]["name"] == "Alice"
        assert result[1]["age"] == "25"

    def test_single_column(self) -> None:
        result = parse_csv("host\nhost1\nhost2", {})
        assert len(result) == 2

    def test_empty_returns_empty(self) -> None:
        result = parse_csv("", {})
        assert result == []

    def test_with_headers_only(self) -> None:
        result = parse_csv("a,b,c", {})
        assert result == []

    def test_irregular_rows(self) -> None:
        result = parse_csv("a,b\n1,2,3\n4", {})
        assert len(result) == 2


class TestParseTxt:
    def test_simple_lines(self) -> None:
        result = parse_txt("host1\nhost2\nhost3", {})
        assert result == ["host1", "host2", "host3"]

    def test_empty_string(self) -> None:
        assert parse_txt("", {}) == []

    def test_trailing_newline(self) -> None:
        result = parse_txt("line1\nline2\n", {})
        assert result == ["line1", "line2"]

    def test_blank_lines_removed(self) -> None:
        result = parse_txt("a\n\n\nb\n", {})
        assert result == ["a", "b"]

    def test_whitespace_lines_removed(self) -> None:
        result = parse_txt("a\n   \n\t\nb", {})
        assert result == ["a", "b"]

    def test_single_line(self) -> None:
        result = parse_txt("only_line", {})
        assert result == ["only_line"]


class TestParseNdjson:
    def test_multiple_lines(self) -> None:
        data = '{"id": 1}\n{"id": 2}\n{"id": 3}'
        result = parse_ndjson(data, {})
        assert len(result) == 3
        assert result[0]["id"] == 1

    def test_mixed_valid_invalid(self) -> None:
        data = '{"ok": true}\nnot json\n{"also": "ok"}'
        result = parse_ndjson(data, {})
        assert len(result) == 3
        assert result[0]["ok"] is True
        assert result[1]["raw"] == "not json"

    def test_empty(self) -> None:
        assert parse_ndjson("", {}) == []

    def test_trailing_newline(self) -> None:
        result = parse_ndjson('{"a": 1}\n', {})
        assert len(result) == 1

    def test_blank_lines_skipped(self) -> None:
        result = parse_ndjson('{"a": 1}\n\n{"b": 2}', {})
        assert len(result) == 2


class TestImportPipeline:
    def test_default_format_detection(self) -> None:
        assert ImportPipeline._detect_format('{"a": 1}') == "json"
        assert ImportPipeline._detect_format("[1, 2]") == "json"
        assert ImportPipeline._detect_format("name: val") == "yaml"
        assert ImportPipeline._detect_format("a,b\n1,2") == "csv"
        assert ImportPipeline._detect_format("hello world") in ("txt", "ndjson")
        assert ImportPipeline._detect_format("") == "txt"

    def test_roundtrip_json(self) -> None:
        pipeline = build_default_pipeline()
        result = pipeline.run('{"hosts": ["a", "b"]}', fmt="json")
        assert isinstance(result, PluginResult)

    def test_parse_with_fmt(self) -> None:
        pipeline = build_default_pipeline()
        parsed = pipeline.parse("[1, 2, 3]", fmt="json")
        assert parsed == [1, 2, 3]

    def test_parse_auto_detect(self) -> None:
        pipeline = build_default_pipeline()
        parsed = pipeline.parse('{"key": "val"}')
        assert parsed["key"] == "val"

    def test_parse_none(self) -> None:
        pipeline = build_default_pipeline()
        assert pipeline.parse(None) == {}

    def test_parse_bytes(self) -> None:
        pipeline = build_default_pipeline()
        parsed = pipeline.parse(b'{"key": "val"}')
        assert parsed["key"] == "val"

    def test_unknown_format_raises(self) -> None:
        pipeline = ImportPipeline()
        with pytest.raises(PluginParseError):
            pipeline.parse("data", fmt="unknown")

    def test_register_parser(self) -> None:
        pipeline = ImportPipeline()
        calls: list[str] = []
        def my_parser(raw: str, kwargs: dict[str, Any]) -> Any:
            calls.append(raw)
            return {"parsed": raw}
        pipeline.register_parser("custom", my_parser)
        result = pipeline.parse("hello", fmt="custom")
        assert result["parsed"] == "hello"
        assert len(calls) == 1

    def test_register_normalizer(self) -> None:
        pipeline = build_default_pipeline()
        def my_norm(parsed: Any, ctx: dict[str, Any]) -> PluginResult:
            pr = PluginResult()
            pr.hosts = parsed.get("hosts", [])
            return pr
        pipeline.register_normalizer(my_norm)
        result = pipeline.run('{"hosts": ["a.com"]}', fmt="json")
        assert len(result.hosts) == 1

    def test_normalize_default(self) -> None:
        pipeline = build_default_pipeline()
        result = pipeline.normalize({})
        assert isinstance(result, PluginResult)

    def test_none_parse_output(self) -> None:
        pipeline = build_default_pipeline()
        parsed = pipeline.parse(None, fmt="json")
        assert parsed == {}

    def test_parse_with_context(self) -> None:
        pipeline = build_default_pipeline()
        ctx = ExecutionContext(target="example.com")
        result = pipeline.run('{"target": "example.com"}', context=ctx)
        assert isinstance(result, PluginResult)


class TestParsePath:
    def test_json_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.json"
        f.write_text('{"a": 1}')
        result = parse_path(f)
        assert result["a"] == 1

    def test_yaml_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.yaml"
        f.write_text("key: value")
        result = parse_path(f)
        assert result["key"] == "value"

    def test_txt_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.txt"
        f.write_text("line1\nline2")
        result = parse_path(f)
        assert isinstance(result, list)
        assert result[0] == "line1"

    def test_csv_file(self, tmp_path: Path) -> None:
        f = tmp_path / "data.csv"
        f.write_text("name\nAlice\nBob")
        result = parse_path(f)
        assert len(result) == 2

    def test_explicit_format(self, tmp_path: Path) -> None:
        f = tmp_path / "data.unknown"
        f.write_text('{"a": 1}')
        result = parse_path(f, fmt="json")
        assert result["a"] == 1

    def test_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            parse_path("/nonexistent/path/file.txt")
