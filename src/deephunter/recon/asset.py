"""Asset Inventory — manages discovered assets (domains, subdomains, IPs, cloud resources)."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import AssetCreatedEvent, ReconEventBus
from deephunter.recon.models import Asset, ReconSourceType


class AssetInventory:
    """Inventory of all discovered assets.

    Assets are the top-level entities that scope entries resolve to:
    domains, subdomains, IP addresses, CIDR ranges, cloud resources.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._assets: dict[str, Asset] = {}

    # ── CRUD ──────────────────────────────────────────────────────

    def add(self, asset: Asset) -> None:
        if asset.id in self._assets:
            raise ValueError(f"Asset '{asset.id}' already exists")
        self._assets[asset.id] = asset
        self._event_bus.emit(
            AssetCreatedEvent(
                entity_id=asset.id,
                description=f"Asset {asset.identifier} ({asset.asset_type})",
                asset_type=asset.asset_type,
                identifier=asset.identifier,
            )
        )

    def get(self, asset_id: str) -> Asset | None:
        return self._assets.get(asset_id)

    def update(self, asset: Asset) -> None:
        if asset.id not in self._assets:
            raise ValueError(f"Asset '{asset.id}' not found")
        self._assets[asset.id] = asset

    def remove(self, asset_id: str) -> bool:
        if asset_id in self._assets:
            del self._assets[asset_id]
            return True
        return False

    def find(self, identifier: str) -> Asset | None:
        for asset in self._assets.values():
            if asset.identifier == identifier:
                return asset
        return None

    def find_by_program(self, program_id: str) -> list[Asset]:
        return [a for a in self._assets.values() if a.program_id == program_id]

    def find_by_type(self, asset_type: str) -> list[Asset]:
        return [a for a in self._assets.values() if a.asset_type == asset_type]

    def find_by_source(self, source: ReconSourceType) -> list[Asset]:
        return [a for a in self._assets.values() if a.source == source]

    def list_all(self) -> list[Asset]:
        return list(self._assets.values())

    # ── Bulk ──────────────────────────────────────────────────────

    def add_batch(self, assets: list[Asset]) -> None:
        for asset in assets:
            if asset.id not in self._assets:
                self._assets[asset.id] = asset

    def clear(self) -> None:
        self._assets.clear()

    @property
    def count(self) -> int:
        return len(self._assets)

    def __len__(self) -> int:
        return len(self._assets)
