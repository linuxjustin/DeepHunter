"""Tests for utility modules."""

from __future__ import annotations

import logging
from pathlib import Path

from deephunter.utils.files import ensure_dir, file_extension, list_files, read_text_file, write_text_file
from deephunter.utils.logging import get_logger, setup_logging


class TestLogging:
    def test_get_logger(self) -> None:
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)
        assert logger.name == "test.module"

    def test_setup_logging(self) -> None:
        setup_logging(level="DEBUG")
        logger = get_logger("test.setup")
        assert logger.getEffectiveLevel() == logging.DEBUG

    def test_setup_logging_with_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        setup_logging(level="INFO", log_file=str(log_file))
        logger = get_logger("test.file")
        logger.info("Hello from test")
        assert log_file.exists()
        content = log_file.read_text()
        assert "Hello from test" in content


class TestFiles:
    def test_ensure_dir(self, tmp_path: Path) -> None:
        path = tmp_path / "a" / "b" / "c"
        result = ensure_dir(str(path))
        assert result.exists()
        assert result.is_dir()

    def test_list_files(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.md").write_text("b")
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "c.txt").write_text("c")

        files = list_files(str(tmp_path), extensions=[".txt"], recursive=True)
        assert len(files) == 2

        files = list_files(str(tmp_path), extensions=[".txt"], recursive=False)
        assert len(files) == 1

    def test_list_files_nonexistent(self) -> None:
        files = list_files("/nonexistent/directory")
        assert files == []

    def test_list_files_all(self, tmp_path: Path) -> None:
        (tmp_path / "a.txt").write_text("a")
        (tmp_path / "b.md").write_text("b")
        files = list_files(str(tmp_path), recursive=False)
        assert len(files) == 2

    def test_read_text_file(self, tmp_path: Path) -> None:
        path = tmp_path / "test.txt"
        path.write_text("hello world")
        content = read_text_file(str(path))
        assert content == "hello world"

    def test_read_text_file_not_found(self) -> None:
        import pytest
        with pytest.raises(FileNotFoundError):
            read_text_file("/nonexistent/file.txt")

    def test_write_text_file(self, tmp_path: Path) -> None:
        path = tmp_path / "sub" / "out.txt"
        result = write_text_file(str(path), "test content")
        assert result.exists()
        assert result.read_text() == "test content"

    def test_file_extension(self) -> None:
        assert file_extension("test.md") == "md"
        assert file_extension("test.html") == "html"
        assert file_extension("/path/to/file.YAML") == "yaml"
        assert file_extension("noext") == ""