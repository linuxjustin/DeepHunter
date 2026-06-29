"""Tests for the CLI interface."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from deephunter.cli.main import cli
from deephunter.knowledge.models import SKOBuilder
from deephunter.knowledge.store import KnowledgeStore


class TestCLI:
    def setup_method(self) -> None:
        self.runner = CliRunner()

    def test_init_creates_config(self, tmp_path: Path) -> None:
        config_path = tmp_path / "test_config.yaml"
        result = self.runner.invoke(
            cli,
            ["init", str(config_path)],
        )
        assert result.exit_code == 0
        assert config_path.exists()
        assert "Default configuration written" in result.output

    def test_init_with_default_name(self) -> None:
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "DeepHunter" in result.output

    def test_help_output(self) -> None:
        result = self.runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "ingest" in result.output
        assert "list-skos" in result.output
        assert "get-sko" in result.output
        assert "search" in result.output
        assert "hypothesize" in result.output
        assert "stats" in result.output
        assert "init" in result.output

    def test_stats_empty(self) -> None:
        result = self.runner.invoke(cli, ["stats"])
        assert result.exit_code == 0
        assert "Total SKOs: 0" in result.output

    def test_list_skos_empty(self) -> None:
        result = self.runner.invoke(cli, ["list-skos"])
        assert result.exit_code == 0
        assert "No SKOs found" in result.output

    def test_get_sko_not_found(self) -> None:
        result = self.runner.invoke(cli, ["get-sko", "nonexistent"])
        assert result.exit_code == 0
        assert "not found" in result.output

    def test_search_empty(self) -> None:
        result = self.runner.invoke(cli, ["search", "test"])
        assert result.exit_code == 0
        assert "No SKOs indexed" in result.output or "Ingest documents" in result.output

    def test_hypothesize_empty(self) -> None:
        result = self.runner.invoke(cli, ["hypothesize", "test context"])
        assert result.exit_code == 0
        assert "No knowledge ingested" in result.output

    def test_ingest_no_dirs(self) -> None:
        result = self.runner.invoke(cli, ["ingest"])
        assert result.exit_code == 0