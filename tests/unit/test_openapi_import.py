"""Tests for OpenAPI import."""

from __future__ import annotations

import tempfile
import yaml

from deephunter.integrations.openapi import OpenAPIImporter, OpenAPISpec


class TestOpenAPIImporter:
    def test_load_spec_from_yaml(self) -> None:
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "responses": {"200": {"description": "Success"}},
                    }
                }
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(spec_data, f)
            f.flush()
            importer = OpenAPIImporter()
            spec = importer.load_spec(f.name)
            assert spec.openapi == "3.0.0"
            assert spec.info_title == "Test API"

    def test_parse_operations(self) -> None:
        spec_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test", "version": "1.0.0"},
            "paths": {
                "/items/{id}": {
                    "get": {
                        "operationId": "getItem",
                        "summary": "Get item",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                    },
                    "post": {
                        "operationId": "createItem",
                        "summary": "Create item",
                    },
                }
            },
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(spec_data, f)
            f.flush()
            importer = OpenAPIImporter()
            importer.load_spec(f.name)
            assert len(importer.operations) == 2
            get_op = next(op for op in importer.operations if op.method == "GET")
            assert get_op.operation_id == "getItem"
            assert len(get_op.parameters) == 1


class TestOpenAPISpecModel:
    def test_spec_model(self) -> None:
        spec = OpenAPISpec(
            openapi="3.0.0",
            info_title="Test",
            info_version="1.0.0",
        )
        assert spec.openapi == "3.0.0"