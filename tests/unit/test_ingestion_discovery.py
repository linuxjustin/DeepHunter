"""Tests for FileDiscoverer."""

from __future__ import annotations

from pathlib import Path

import pytest

from deephunter.ingestion.discovery import FileDiscoverer


class TestFileDiscoverer:
    def test_single_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.md"
        f.write_text("hello")
        d = FileDiscoverer()
        files = d.discover(f)
        assert len(files) == 1
        assert files[0] == f.resolve()

    def test_single_file_not_found(self) -> None:
        d = FileDiscoverer()
        with pytest.raises(FileNotFoundError):
            d.discover("/nonexistent/file.md")

    def test_directory_non_recursive(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("a")
        (tmp_path / "b.md").write_text("b")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "c.md").write_text("c")

        d = FileDiscoverer()
        files = d.discover(tmp_path, recursive=False)
        assert len(files) == 2
        assert all(f.suffix == ".md" for f in files)

    def test_directory_recursive(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("a")
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "b.md").write_text("b")
        (sub / "c.txt").write_text("c")

        d = FileDiscoverer()
        files = d.discover(tmp_path, recursive=True)
        assert len(files) == 3

    def test_extension_filter(self, tmp_path: Path) -> None:
        (tmp_path / "a.md").write_text("a")
        (tmp_path / "b.txt").write_text("b")
        (tmp_path / "c.html").write_text("c")

        d = FileDiscoverer(supported_extensions={".md", ".html"})
        files = d.discover(tmp_path, recursive=False)
        assert len(files) == 2
        assert {f.suffix for f in files} == {".md", ".html"}

    def test_max_file_size(self, tmp_path: Path) -> None:
        f = tmp_path / "large.md"
        f.write_text("x" * 1000)

        d = FileDiscoverer(max_file_size_bytes=500)
        files = d.discover(tmp_path, recursive=False)
        assert len(files) == 0

        d2 = FileDiscoverer(max_file_size_bytes=2000)
        files2 = d2.discover(tmp_path, recursive=False)
        assert len(files2) == 1

    def test_empty_directory(self, tmp_path: Path) -> None:
        d = FileDiscoverer()
        files = d.discover(tmp_path, recursive=True)
        assert files == []

    def test_path_is_resolved(self, tmp_path: Path) -> None:
        f = tmp_path / "test.md"
        f.write_text("hello")
        d = FileDiscoverer()

        import os
        original_dir = os.getcwd()
        try:
            os.chdir(tmp_path)
            files = d.discover("test.md")
            assert files[0].is_absolute()
        finally:
            os.chdir(original_dir)
