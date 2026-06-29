"""File system utility functions."""

from __future__ import annotations

from pathlib import Path


def ensure_dir(path: str | Path) -> Path:
    """Ensure a directory exists, creating it if necessary.

    Args:
        path: Directory path.

    Returns:
        The resolved Path object.
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p.resolve()


def list_files(
    directory: str | Path,
    extensions: list[str] | None = None,
    recursive: bool = True,
) -> list[Path]:
    """List files in a directory, optionally filtering by extension.

    Args:
        directory: Root directory to search.
        extensions: Optional list of extensions (e.g. ``['.md', '.html']``).
        recursive: Whether to search subdirectories.

    Returns:
        Sorted list of matching file paths.
    """
    base = Path(directory)
    if not base.exists():
        return []

    pattern = "**/*" if recursive else "*"
    files = [p for p in base.glob(pattern) if p.is_file()]

    if extensions:
        ext_set = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensions}
        files = [p for p in files if p.suffix.lower() in ext_set]

    return sorted(files)


def read_text_file(path: str | Path) -> str:
    """Read a text file, returning its contents as a string.

    Args:
        path: File path.

    Returns:
        File contents.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"File not found: {p}")
    return p.read_text(encoding="utf-8")


def write_text_file(path: str | Path, content: str) -> Path:
    """Write text content to a file, creating parent directories as needed.

    Args:
        path: Destination path.
        content: Text content to write.

    Returns:
        The resolved Path object.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p.resolve()


def file_extension(path: str | Path) -> str:
    """Get the lowercase file extension without leading dot.

    Args:
        path: File path.

    Returns:
        Extension string (e.g. ``'md'``, ``'html'``).
    """
    return Path(path).suffix.lower().lstrip(".")
