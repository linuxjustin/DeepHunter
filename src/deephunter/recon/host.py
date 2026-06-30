"""Host Registry — manages discovered hosts with IP, port, protocol, and DNS records."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import (
    DNSRecordObservedEvent,
    HostDiscoveredEvent,
    ReconEventBus,
)
from deephunter.recon.models import DNSRecord, Host, HostStatus, Protocol, ReconSourceType


class HostRegistry:
    """Registry of all discovered hosts.

    A host is a (hostname, IP, port, protocol) tuple with associated
    DNS records and metadata.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._hosts: dict[str, Host] = {}

    # ── CRUD ──────────────────────────────────────────────────────

    def add(self, host: Host) -> None:
        if host.id in self._hosts:
            raise ValueError(f"Host '{host.id}' already exists")
        self._hosts[host.id] = host
        self._event_bus.emit(
            HostDiscoveredEvent(
                entity_id=host.id,
                description=f"Host {host.hostname}:{host.port} ({host.ip})",
                hostname=host.hostname,
                ip=host.ip,
                port=host.port,
            )
        )

    def get(self, host_id: str) -> Host | None:
        return self._hosts.get(host_id)

    def update(self, host: Host) -> None:
        if host.id not in self._hosts:
            raise ValueError(f"Host '{host.id}' not found")
        self._hosts[host.id] = host

    def remove(self, host_id: str) -> bool:
        if host_id in self._hosts:
            del self._hosts[host_id]
            return True
        return False

    def find_by_hostname(self, hostname: str) -> list[Host]:
        return [h for h in self._hosts.values() if h.hostname == hostname]

    def find_by_ip(self, ip: str) -> list[Host]:
        return [h for h in self._hosts.values() if h.ip == ip]

    def find_by_port(self, port: int) -> list[Host]:
        return [h for h in self._hosts.values() if h.port == port]

    def find_by_protocol(self, protocol: Protocol) -> list[Host]:
        return [h for h in self._hosts.values() if h.protocol == protocol]

    def find_by_asset(self, asset_id: str) -> list[Host]:
        return [h for h in self._hosts.values() if h.asset_id == asset_id]

    def find_active(self) -> list[Host]:
        return [h for h in self._hosts.values() if h.status == HostStatus.ACTIVE]

    def list_all(self) -> list[Host]:
        return list(self._hosts.values())

    # ── DNS ───────────────────────────────────────────────────────

    def add_dns_record(self, host_id: str, record: DNSRecord) -> None:
        host = self._hosts.get(host_id)
        if host is None:
            raise ValueError(f"Host '{host_id}' not found")
        record.host_id = host_id
        host.dns_records.append(record)
        self._event_bus.emit(
            DNSRecordObservedEvent(
                session_id="",
                entity_id=record.id,
                description=f"DNS {record.record_type}: {record.value}",
                record_type=record.record_type.value,
                value=record.value,
            )
        )

    def get_dns_records(self, host_id: str) -> list[DNSRecord]:
        host = self._hosts.get(host_id)
        if host is None:
            return []
        return host.dns_records

    def find_dns_by_type(self, host_id: str, record_type: str) -> list[DNSRecord]:
        host = self._hosts.get(host_id)
        if host is None:
            return []
        return [r for r in host.dns_records if r.record_type.value == record_type]

    # ── Bulk ──────────────────────────────────────────────────────

    def add_batch(self, hosts: list[Host]) -> None:
        for host in hosts:
            if host.id not in self._hosts:
                self._hosts[host.id] = host

    def clear(self) -> None:
        self._hosts.clear()

    @property
    def count(self) -> int:
        return len(self._hosts)

    def __len__(self) -> int:
        return len(self._hosts)
