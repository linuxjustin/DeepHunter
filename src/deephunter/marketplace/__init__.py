"""Plugin marketplace infrastructure for DeepHunter.

Provides metadata models, versioning, validation, installation,
and update management for the plugin ecosystem.
"""

from __future__ import annotations

import hashlib
import re
import zipfile
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

import yaml
from pydantic import BaseModel, Field, field_validator


class PluginCategory(str, Enum):
    """Categories of plugins."""

    RECON = "recon"
    INTELLIGENCE = "intelligence"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    INTEGRATION = "integration"
    VISUALIZATION = "visualization"
    AUTOMATION = "automation"
    OTHER = "other"


class PluginStatus(str, Enum):
    """Status of a plugin in the marketplace."""

    DRAFT = "draft"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    REMOVED = "removed"


class Version(BaseModel):
    """Semantic version with comparison."""

    major: int = 0
    minor: int = 0
    patch: int = 0
    prerelease: str = ""

    def __str__(self) -> str:
        v = f"{self.major}.{self.minor}.{self.patch}"
        if self.prerelease:
            v += f"-{self.prerelease}"
        return v

    def __lt__(self, other: Version) -> bool:
        if (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch):
            return True
        if self.prerelease and not other.prerelease:
            return True
        return False

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return False
        return str(self) == str(other)


class PluginMetadata(BaseModel):
    """Metadata for a marketplace plugin."""

    id: str = Field(default_factory=lambda: f"plg-{uuid4().hex[:12]}")
    name: str = Field(description="Plugin name (unique identifier)")
    version: str = Field(description="Current version (semver)")
    display_name: str = Field(description="Human-readable name")
    description: str = Field(default="")
    author: str = Field(description="Author name or organization")
    author_email: str = ""
    homepage: str = ""
    repository: str = ""
    license: str = "MIT"
    category: PluginCategory = PluginCategory.OTHER
    tags: list[str] = Field(default_factory=list)
    status: PluginStatus = Field(default=PluginStatus.DRAFT)

    min_platform_version: str = Field(default="1.0.0", description="Minimum DeepHunter platform version")
    max_platform_version: str = Field(default="2.0.0", description="Maximum DeepHunter platform version")

    dependencies: dict[str, str] = Field(default_factory=dict, description="Plugin dependencies with version constraints")

    download_url: str = ""
    checksum_sha256: str = ""
    file_size: int = 0

    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    published_at: datetime | None = None

    downloads: int = 0
    rating: float = 0.0
    reviews_count: int = 0

    hidden: bool = False
    featured: bool = False
    verified: bool = False

    changelog: str = ""
    readme: str = ""

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        if not re.match(r"^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$", v):
            raise ValueError("Version must be valid semver")
        return v


class PluginRelease(BaseModel):
    """A single release of a plugin."""

    version: str
    release_date: datetime = Field(default_factory=lambda: datetime.now(UTC))
    changelog: str = ""
    download_url: str = ""
    checksum_sha256: str = ""
    file_size: int = 0
    platform_version: str = ""
    assets: list[dict[str, Any]] = Field(default_factory=list)


class PluginValidationResult(BaseModel):
    """Result of plugin validation."""

    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class PluginManifest(BaseModel):
    """The plugin.yml manifest file structure."""

    name: str
    version: str
    display_name: str
    description: str = ""
    author: str = ""
    license: str = "MIT"
    category: str = "other"
    entry_point: str = ""
    requirements: list[str] = Field(default_factory=list)


class PluginValidator:
    """Validates plugin packages before installation."""

    REQUIRED_FILES = ["plugin.yml", "README.md"]

    def validate_package(self, package_path: str | Path) -> PluginValidationResult:
        """Validate a plugin package (.whl or .tar.gz or directory)."""
        errors = []
        warnings = []
        metadata: dict[str, Any] = {}

        p = Path(package_path)

        if p.is_dir():
            if not self._validate_directory(p, errors, warnings):
                return PluginValidationResult(valid=False, errors=errors, warnings=warnings)
        elif p.suffix == ".whl":
            if not self._validate_wheel(p, errors, warnings):
                return PluginValidationResult(valid=False, errors=errors, warnings=warnings)
        elif p.suffix in (".tar.gz", ".tgz"):
            if not self._validate_tarball(p, errors, warnings):
                return PluginValidationResult(valid=False, errors=errors, warnings=warnings)
        else:
            errors.append(f"Unsupported package format: {p.suffix}")
            return PluginValidationResult(valid=False, errors=errors, warnings=warnings)

        return PluginValidationResult(valid=len(errors) == 0, errors=errors, warnings=warnings, metadata=metadata)

    def _validate_directory(self, dir_path: Path, errors: list[str], warnings: list[str]) -> bool:
        for req_file in self.REQUIRED_FILES:
            if not (dir_path / req_file).exists():
                errors.append(f"Missing required file: {req_file}")

        manifest_file = dir_path / "plugin.yml"
        if manifest_file.exists():
            try:
                with open(manifest_file) as f:
                    manifest = yaml.safe_load(f)
                if not manifest:
                    errors.append("plugin.yml is empty")
                else:
                    if "name" not in manifest:
                        errors.append("plugin.yml missing 'name' field")
                    if "version" not in manifest:
                        errors.append("plugin.yml missing 'version' field")
                    if "entry_point" not in manifest:
                        warnings.append("plugin.yml missing 'entry_point' field")
            except yaml.YAMLError as exc:
                errors.append(f"Invalid YAML in plugin.yml: {exc}")

        return len(errors) == 0

    def _validate_wheel(self, wheel_path: Path, errors: list[str], warnings: list[str]) -> bool:
        try:
            with zipfile.ZipFile(wheel_path) as zf:
                namelist = zf.namelist()
                for req_file in self.REQUIRED_FILES:
                    matching = [n for n in namelist if n.endswith(req_file)]
                    if not matching:
                        errors.append(f"Missing required file in wheel: {req_file}")

                plugin_yml = [n for n in namelist if n.endswith("plugin.yml")]
                if plugin_yml:
                    try:
                        manifest = yaml.safe_load(zf.read(plugin_yml[0]).decode())
                        if manifest and "name" in manifest:
                            metadata = {"name": manifest["name"], "version": manifest.get("version", "unknown")}
                    except Exception:
                        pass
        except zipfile.BadZipFile:
            errors.append("Invalid wheel file: not a valid ZIP archive")
            return False

        return len(errors) == 0

    def _validate_tarball(self, tar_path: Path, errors: list[str], warnings: list[str]) -> bool:
        import tarfile

        try:
            with tarfile.open(tar_path) as tf:
                members = tf.getnames()
                for req_file in self.REQUIRED_FILES:
                    matching = [m for m in members if m.endswith(req_file)]
                    if not matching:
                        errors.append(f"Missing required file in tarball: {req_file}")
        except tarfile.TarError:
            errors.append(f"Invalid tarball: not a valid tar archive")
            return False

        return len(errors) == 0

    @staticmethod
    def compute_checksum(file_path: str | Path) -> str:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()


class PluginRegistry:
    """Local registry of installed plugins."""

    def __init__(self, registry_path: str | Path | None = None) -> None:
        self._registry_path = Path(registry_path) if registry_path else Path.home() / ".deephunter" / "plugins" / "registry.json"
        self._plugins: dict[str, PluginMetadata] = {}
        self._load_registry()

    def _load_registry(self) -> None:
        if self._registry_path.exists():
            import json

            with open(self._registry_path) as f:
                data = json.load(f)
            for plugin_data in data.get("plugins", []):
                try:
                    plugin = PluginMetadata(**plugin_data)
                    self._plugins[plugin.name] = plugin
                except Exception:
                    continue

    def _save_registry(self) -> None:
        import json

        self._registry_path.parent.mkdir(parents=True, exist_ok=True)
        data = {"plugins": [p.model_dump() for p in self._plugins.values()]}
        with open(self._registry_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

    def register(self, metadata: PluginMetadata) -> None:
        self._plugins[metadata.name] = metadata
        self._save_registry()

    def unregister(self, name: str) -> bool:
        if name in self._plugins:
            del self._plugins[name]
            self._save_registry()
            return True
        return False

    def get(self, name: str) -> PluginMetadata | None:
        return self._plugins.get(name)

    def list_all(self) -> list[PluginMetadata]:
        return list(self._plugins.values())

    def list_by_category(self, category: PluginCategory) -> list[PluginMetadata]:
        return [p for p in self._plugins.values() if p.category == category]

    def search(self, query: str) -> list[PluginMetadata]:
        q = query.lower()
        return [p for p in self._plugins.values() if q in p.name.lower() or q in p.display_name.lower() or q in p.description.lower()]


class PluginInstaller:
    """Handles plugin installation and updates."""

    def __init__(self, plugins_dir: str | Path | None = None) -> None:
        self._plugins_dir = Path(plugins_dir) if plugins_dir else Path.home() / ".deephunter" / "plugins" / "installed"
        self._plugins_dir.mkdir(parents=True, exist_ok=True)
        self._validator = PluginValidator()
        self._registry = PluginRegistry()

    def install(self, package_path: str | Path, metadata: PluginMetadata) -> tuple[bool, str]:
        validation = self._validator.validate_package(package_path)
        if not validation.valid:
            return False, f"Validation failed: {', '.join(validation.errors)}"

        plugin_dir = self._plugins_dir / metadata.name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        p = Path(package_path)
        if p.is_dir():
            import shutil

            for item in p.iterdir():
                dest = plugin_dir / item.name
                if item.is_dir():
                    shutil.copytree(item, dest, dirs_exist_ok=True)
                else:
                    shutil.copy2(item, dest)
        else:
            import shutil

            shutil.unpack_archive(package_path, plugin_dir)

        metadata.download_url = str(package_path)
        metadata.checksum_sha256 = self._validator.compute_checksum(package_path)
        metadata.status = PluginStatus.PUBLISHED
        self._registry.register(metadata)

        return True, f"Successfully installed {metadata.name} v{metadata.version}"

    def uninstall(self, name: str) -> bool:
        plugin_dir = self._plugins_dir / name
        if plugin_dir.exists():
            import shutil

            shutil.rmtree(plugin_dir)
        return self._registry.unregister(name)

    def update_available(self, name: str, new_version: str) -> bool:
        current = self._registry.get(name)
        if not current:
            return False
        return Version(str(new_version)) > Version(str(current.version))