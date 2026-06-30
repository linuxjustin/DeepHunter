"""Authentication & Authorization Intelligence — observed auth mechanisms and patterns."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import AuthObservedEvent, ReconEventBus
from deephunter.recon.models import AuthMechanism, AuthObservation, AuthType, ReconSourceType


class AuthIntelligence:
    """Manages authentication and authorization observations.

    Represents *observed* mechanisms — never infers vulnerabilities.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._mechanisms: dict[str, AuthMechanism] = {}
        self._observations: dict[str, AuthObservation] = {}

    # ── Mechanisms ───────────────────────────────────────────────

    def add_mechanism(self, mechanism: AuthMechanism) -> None:
        if mechanism.id in self._mechanisms:
            raise ValueError(f"AuthMechanism '{mechanism.id}' already exists")
        self._mechanisms[mechanism.id] = mechanism
        self._event_bus.emit(
            AuthObservedEvent(
                entity_id=mechanism.id,
                description=f"Auth {mechanism.auth_type.value} at {mechanism.url}",
                auth_type=mechanism.auth_type.value,
                url=mechanism.url,
            )
        )

    def get_mechanism(self, mech_id: str) -> AuthMechanism | None:
        return self._mechanisms.get(mech_id)

    def find_by_type(self, auth_type: AuthType) -> list[AuthMechanism]:
        return [m for m in self._mechanisms.values() if m.auth_type == auth_type]

    def find_by_host(self, host_id: str) -> list[AuthMechanism]:
        return [m for m in self._mechanisms.values() if m.host_id == host_id]

    def list_mechanisms(self) -> list[AuthMechanism]:
        return list(self._mechanisms.values())

    # ── Observations ─────────────────────────────────────────────

    def add_observation(self, observation: AuthObservation) -> None:
        if observation.id in self._observations:
            raise ValueError(f"AuthObservation '{observation.id}' already exists")
        self._observations[observation.id] = observation

    def list_observations(self) -> list[AuthObservation]:
        return list(self._observations.values())

    # ── Summary ──────────────────────────────────────────────────

    def get_auth_types_summary(self) -> dict[AuthType, int]:
        summary: dict[AuthType, int] = {}
        for m in self._mechanisms.values():
            summary[m.auth_type] = summary.get(m.auth_type, 0) + 1
        return summary

    def clear(self) -> None:
        self._mechanisms.clear()
        self._observations.clear()

    @property
    def mechanism_count(self) -> int:
        return len(self._mechanisms)

    @property
    def observation_count(self) -> int:
        return len(self._observations)
