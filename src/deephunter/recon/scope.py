"""Scope Manager — organizes programs and scope entries."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import ReconEventBus, ScopeLoadedEvent
from deephunter.recon.models import Program, Scope


class ScopeManager:
    """Manages programs and scope entries.

    Provides program CRUD, scope containment checks, and wildcard matching.
    """

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._programs: dict[str, Program] = {}
        self._scopes: dict[str, Scope] = {}

    # ── Programs ─────────────────────────────────────────────────

    def add_program(self, program: Program) -> None:
        if program.id in self._programs:
            raise ValueError(f"Program '{program.id}' already exists")
        self._programs[program.id] = program

    def get_program(self, program_id: str) -> Program | None:
        return self._programs.get(program_id)

    def update_program(self, program: Program) -> None:
        if program.id not in self._programs:
            raise ValueError(f"Program '{program.id}' not found")
        program.updated_at = program.updated_at  # keep existing
        self._programs[program.id] = program

    def remove_program(self, program_id: str) -> bool:
        if program_id in self._programs:
            del self._programs[program_id]
            to_remove = [s.id for s in self._scopes.values() if s.program_id == program_id]
            for sid in to_remove:
                del self._scopes[sid]
            return True
        return False

    def list_programs(self) -> list[Program]:
        return list(self._programs.values())

    # ── Scopes ───────────────────────────────────────────────────

    def add_scope(self, scope: Scope) -> None:
        if scope.id in self._scopes:
            raise ValueError(f"Scope '{scope.id}' already exists")
        self._scopes[scope.id] = scope
        self._event_bus.emit(
            ScopeLoadedEvent(
                session_id=scope.program_id,
                entity_id=scope.id,
                description=f"Scope {scope.target} ({scope.scope_type})",
            )
        )

    def get_scope(self, scope_id: str) -> Scope | None:
        return self._scopes.get(scope_id)

    def remove_scope(self, scope_id: str) -> bool:
        if scope_id in self._scopes:
            del self._scopes[scope_id]
            return True
        return False

    def list_scopes(self, program_id: str | None = None) -> list[Scope]:
        if program_id is None:
            return list(self._scopes.values())
        return [s for s in self._scopes.values() if s.program_id == program_id]

    def list_in_scope(self) -> list[Scope]:
        return [s for s in self._scopes.values() if s.in_scope]

    def list_out_of_scope(self) -> list[Scope]:
        return [s for s in self._scopes.values() if not s.in_scope]

    # ── Matchers ─────────────────────────────────────────────────

    def is_in_scope(self, hostname: str) -> bool:
        for scope in self.list_in_scope():
            if self._match_scope(scope, hostname):
                return True
        return False

    def is_out_of_scope(self, hostname: str) -> bool:
        for scope in self.list_out_of_scope():
            if self._match_scope(scope, hostname):
                return True
        return False

    @staticmethod
    def _match_scope(scope: Scope, hostname: str) -> bool:
        target = scope.target.lower()
        hostname = hostname.lower()
        if scope.scope_type == "exact":
            return hostname == target
        if scope.scope_type == "wildcard":
            if target.startswith("*."):
                return hostname.endswith(target[1:]) or hostname == target[2:]
            return hostname == target
        return hostname == target

    # ── Bulk ─────────────────────────────────────────────────────

    def load_scopes(self, scopes: list[Scope]) -> None:
        for scope in scopes:
            self._scopes[scope.id] = scope

    def clear(self) -> None:
        self._programs.clear()
        self._scopes.clear()

    @property
    def program_count(self) -> int:
        return len(self._programs)

    @property
    def scope_count(self) -> int:
        return len(self._scopes)
