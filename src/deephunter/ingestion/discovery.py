"""File discovery for the ingestion pipeline.

Discovers documents by scanning directories (recursively or not),
accepting single file paths, and filtering by supported extensions.
"""

from __future__ import annotations

from pathlib import Path

from deephunter.utils.logging import get_logger

logger = get_logger(__name__)


class FileDiscoverer:
    """Discovers files for ingestion.

    Supports single files, directories, and recursive directory
    scanning with extension filtering.
    """

    def __init__(
        self,
        supported_extensions: set[str] | None = None,
        max_file_size_bytes: int | None = None,
    ) -> None:
        self._extensions = supported_extensions or set()
        self._max_size = max_file_size_bytes

    def discover(self, path: str | Path, recursive: bool = True) -> list[Path]:
        """Discover files at the given path.

        Args:
            path: A file path or directory path.
            recursive: Whether to scan subdirectories (ignored for single files).

        Returns:
            Sorted list of discovered file paths.

        Raises:
            FileNotFoundError: If ``path`` does not exist.
        """
        p = Path(path).resolve()
        if not p.exists():
            raise FileNotFoundError(f"Path does not exist: {p}")

        if p.is_file():
            return self._filter([p])

        return self._filter(self._scan_dir(p, recursive=recursive))

    def _scan_dir(self, directory: Path, recursive: bool) -> list[Path]:
        pattern = "**/*" if recursive else "*"
        return sorted(p for p in directory.glob(pattern) if p.is_file())

    def _filter(self, files: list[Path]) -> list[Path]:
        result: list[Path] = []
        for f in files:
            if self._extensions and f.suffix.lower() not in self._extensions:
                continue
            if self._max_size is not None:
                try:
                    if f.stat().st_size > self._max_size:
                        logger.debug("Skipping oversized file: %s", f)
                        continue
                except OSError:
                    continue
            result.append(f)
        return result
