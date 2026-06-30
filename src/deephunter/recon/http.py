"""HTTP Intelligence — manages HTTP probe observations, headers, and cookies."""

from __future__ import annotations

from typing import Any

from deephunter.recon.events import HTTPObservedEvent, ReconEventBus
from deephunter.recon.models import (
    HTTPHeader,
    HTTPObservation,
    SecurityHeader,
    SecurityHeaderName,
    Cookie,
    Host,
)


# ── Security header analysis ────────────────────────────────────────────────

_SECURITY_HEADER_RECOMMENDATIONS: dict[str, str] = {
    SecurityHeaderName.STRICT_TRANSPORT_SECURITY.value: "Add Strict-Transport-Security with a long max-age (e.g. 31536000) and includeSubDomains.",
    SecurityHeaderName.CONTENT_SECURITY_POLICY.value: "Add Content-Security-Policy to control resource loading and mitigate XSS.",
    SecurityHeaderName.X_FRAME_OPTIONS.value: "Add X-Frame-Options: DENY or SAMEORIGIN to prevent clickjacking.",
    SecurityHeaderName.X_CONTENT_TYPE_OPTIONS.value: "Add X-Content-Type-Options: nosniff to prevent MIME sniffing.",
    SecurityHeaderName.REFERRER_POLICY.value: "Add Referrer-Policy: strict-origin-when-cross-origin or similar.",
    SecurityHeaderName.PERMISSIONS_POLICY.value: "Add Permissions-Policy to restrict browser features.",
    SecurityHeaderName.CROSS_ORIGIN_OPENER_POLICY.value: "Add Cross-Origin-Opener-Policy: same-origin for isolation.",
    SecurityHeaderName.CROSS_ORIGIN_EMBEDDER_POLICY.value: "Add Cross-Origin-Embedder-Policy: require-corp for isolation.",
    SecurityHeaderName.CROSS_ORIGIN_RESOURCE_POLICY.value: "Add Cross-Origin-Resource-Policy: same-origin.",
}

_SECURE_VALUES: dict[str, list[str]] = {
    SecurityHeaderName.STRICT_TRANSPORT_SECURITY.value: ["max-age="],
    SecurityHeaderName.X_FRAME_OPTIONS.value: ["DENY", "SAMEORIGIN"],
    SecurityHeaderName.X_CONTENT_TYPE_OPTIONS.value: ["nosniff"],
    SecurityHeaderName.REFERRER_POLICY.value: [
        "no-referrer", "same-origin", "strict-origin",
        "strict-origin-when-cross-origin",
    ],
}


def analyze_security_headers(headers: list[HTTPHeader]) -> list[SecurityHeader]:
    """Analyze response headers for security-relevant headers.

    Returns a list of ``SecurityHeader`` objects with presence, secure
    status, and recommendations.
    """
    header_map = {h.name.lower(): h.value for h in headers}
    results: list[SecurityHeader] = []
    observed_names = set()

    for sh_name in SecurityHeaderName:
        lower = sh_name.value
        value = header_map.get(lower, "")
        present = lower in header_map
        observed_names.add(lower)

        # Determine if the header is securely configured
        secure = False
        if present and sh_name.value in _SECURE_VALUES:
            for pattern in _SECURE_VALUES[sh_name.value]:
                if pattern.lower() in value.lower():
                    secure = True
                    break

        results.append(SecurityHeader(
            name=sh_name,
            value=value,
            present=present,
            secure=secure,
            recommendation="" if (present and secure) else _SECURITY_HEADER_RECOMMENDATIONS.get(sh_name.value, ""),
        ))

    return results


def classify_security_headers(headers: list[HTTPHeader]) -> list[HTTPHeader]:
    """Tag headers that are security-relevant."""
    sec_names = {h.value for h in SecurityHeaderName}
    result: list[HTTPHeader] = []
    for h in headers:
        result.append(HTTPHeader(
            name=h.name,
            value=h.value,
            security_relevant=h.name.lower() in sec_names,
        ))
    return result


def find_missing_security_headers(headers: list[SecurityHeader]) -> list[SecurityHeader]:
    """Return security headers that are missing or insecure."""
    return [h for h in headers if not h.present or not h.secure]


# ── HTTP Intelligence Manager ──────────────────────────────────────────────


class HTTPIntelligence:
    """Manages HTTP probe observations and header analysis."""

    def __init__(self, event_bus: ReconEventBus | None = None) -> None:
        self._event_bus = event_bus or ReconEventBus()
        self._observations: dict[str, HTTPObservation] = {}

    def add_observation(self, observation: HTTPObservation) -> None:
        if observation.id in self._observations:
            raise ValueError(f"HTTP observation '{observation.id}' already exists")
        observation.headers = classify_security_headers(observation.headers)
        observation.security_headers = analyze_security_headers(observation.headers)
        self._observations[observation.id] = observation
        self._event_bus.emit(
            HTTPObservedEvent(
                entity_id=observation.id,
                description=f"{observation.method} {observation.url} -> {observation.status_code}",
                url=observation.url,
                status_code=observation.status_code,
            )
        )

    def get_observation(self, obs_id: str) -> HTTPObservation | None:
        return self._observations.get(obs_id)

    def find_by_host(self, host_id: str) -> list[HTTPObservation]:
        return [o for o in self._observations.values() if o.host_id == host_id]

    def find_by_status(self, status_code: int) -> list[HTTPObservation]:
        return [o for o in self._observations.values() if o.status_code == status_code]

    def find_by_content_type(self, content_type: str) -> list[HTTPObservation]:
        return [o for o in self._observations.values() if content_type in o.content_type]

    def find_missing_security_headers(self) -> list[tuple[HTTPObservation, list[SecurityHeader]]]:
        results: list[tuple[HTTPObservation, list[SecurityHeader]]] = []
        for obs in self._observations.values():
            missing = find_missing_security_headers(obs.security_headers)
            if missing:
                results.append((obs, missing))
        return results

    def list_all(self) -> list[HTTPObservation]:
        return list(self._observations.values())

    def clear(self) -> None:
        self._observations.clear()

    @property
    def count(self) -> int:
        return len(self._observations)
