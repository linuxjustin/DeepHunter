"""Tests for Burp Suite integration."""

from __future__ import annotations

from deephunter.integrations.burp import (
    BurpImporter,
    BurpHttpExchange,
    convert_burp_exchange_to_recon,
)


class TestBurpModels:
    def test_burp_exchange(self) -> None:
        exchange = BurpHttpExchange(
            url="https://api.example.com/login",
            method="POST",
            host="api.example.com",
            port=443,
            response_status=200,
        )
        assert exchange.url == "https://api.example.com/login"
        assert exchange.method == "POST"


class TestBurpImporter:
    def test_import_auto_detect(self) -> None:
        importer = BurpImporter()
        assert importer.state_parser is not None
        assert importer.har_parser is not None
        assert importer.report_parser is not None


class TestConvertBurpExchange:
    def test_convert_basic_exchange(self) -> None:
        exchange = BurpHttpExchange(
            url="https://example.com/api/users",
            method="GET",
            host="example.com",
            port=443,
            response_status=200,
            response_headers=[("Content-Type", "application/json")],
        )
        result = convert_burp_exchange_to_recon(exchange)
        assert result["host"] is not None
        assert result["endpoint"] is not None