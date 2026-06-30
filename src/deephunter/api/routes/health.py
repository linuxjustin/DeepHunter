"""Health check and observability endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
async def health_check() -> dict:
    """Basic health check endpoint."""
    return {"status": "healthy", "timestamp": datetime.now(UTC).isoformat()}


@router.get("/health/ready")
async def readiness_check() -> dict:
    """Readiness probe for Kubernetes."""
    return {"status": "ready", "timestamp": datetime.now(UTC).isoformat()}


@router.get("/health/live")
async def liveness_check() -> dict:
    """Liveness probe for Kubernetes."""
    return {"status": "alive", "timestamp": datetime.now(UTC).isoformat()}


@router.get("/version")
async def version_info() -> dict:
    """Return version information."""
    return {
        "version": "1.0.0",
        "api_version": "v1",
        "build_date": "2026-01-01",
    }