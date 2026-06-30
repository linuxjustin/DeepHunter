"""FastAPI application factory for DeepHunter API.

Creates and configures the FastAPI application with all routers,
middleware, and observability hooks.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from deephunter.workspace.manager import WorkspaceManager


_workspace_manager: WorkspaceManager | None = None


class _AuthRateLimitMiddleware(BaseHTTPMiddleware):
    """Authentication and rate limiting middleware.

    Reads DEEPHUNTER_API__API_KEYS (comma-separated) and
    DEEPHUNTER_API__RATE_LIMIT_PER_MINUTE from environment.
    Excluded paths: health, docs, version.
    Auth is disabled when no API keys are configured.
    """

    _initialized = False
    _allowed_keys: list[str] = []
    _excluded_paths: frozenset[str] = frozenset()
    _rate_limit: int = 60
    _rate_store: dict[str, tuple[int, float]] = defaultdict(lambda: (0, 0.0))
    _rate_lock = None

    @classmethod
    def _load_config(cls) -> None:
        if cls._initialized:
            return
        cls._initialized = True
        import threading
        cls._rate_lock = threading.Lock()

        api_keys_env = os.environ.get("DEEPHUNTER_API__API_KEYS", "")
        cls._allowed_keys = [k.strip() for k in api_keys_env.split(",") if k.strip()]

        excluded = os.environ.get(
            "DEEPHUNTER_API__EXCLUDED_PATHS",
            "/health,/health/ready,/health/live,/version,/docs,/redoc,/openapi.json",
        )
        cls._excluded_paths = frozenset(excluded.split(","))

        cls._rate_limit = int(os.environ.get("DEEPHUNTER_API__RATE_LIMIT_PER_MINUTE", "60") or "0")

    async def dispatch(self, request: Request, call_next):
        self._load_config()
        path = request.url.path

        if path not in self._excluded_paths and self._allowed_keys:
            provided = request.headers.get("x-api-key", "")
            if not provided or provided not in self._allowed_keys:
                return JSONResponse(status_code=403, content={"detail": "Invalid or missing API key"})

        if self._rate_limit > 0 and path not in self._excluded_paths:
            client_ip = request.client.host if request.client else "unknown"
            current_time = time.monotonic()
            if self._rate_lock:
                with self._rate_lock:
                    count, window_start = self._rate_store[client_ip]
                    elapsed = current_time - window_start
                    if elapsed > 60.0:
                        self._rate_store[client_ip] = (1, current_time)
                    else:
                        if count >= self._rate_limit:
                            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded"})
                        self._rate_store[client_ip] = (count + 1, window_start)

        return await call_next(request)


def _get_cors_origins() -> list[str]:
    """Get CORS allowed origins from environment or defaults."""
    env_origins = os.environ.get("DEEPHUNTER_API__ALLOWED_ORIGINS", "")
    if env_origins:
        return [o.strip() for o in env_origins.split(",") if o.strip()]
    return ["http://localhost:3000", "http://localhost:8000"]


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


def create_app(title: str = "DeepHunter API", version: str = "1.0.0", root_path: str = "") -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=title,
        version=version,
        root_path=root_path,
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=_get_cors_origins(),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.add_middleware(_AuthRateLimitMiddleware)

    from deephunter.api.routes.health import router as health
    from deephunter.api.routes.projects import router as projects
    from deephunter.api.routes.targets import router as targets
    from deephunter.api.routes.reports import router as reports
    from deephunter.api.routes.conversations import router as conversations
    from deephunter.api.routes.evidence import router as evidence
    from deephunter.api.routes.workspace import router as workspace
    from deephunter.api.routes.notebook import router as notebook
    from deephunter.api.routes.tasks import router as tasks
    from deephunter.api.routes.search import router as search
    from deephunter.api.routes.dashboard import router as dashboard
    from deephunter.api.routes.timeline import router as timeline

    app.include_router(health, prefix="/api/v1", tags=["health"])
    app.include_router(projects, prefix="/api/v1", tags=["projects"])
    app.include_router(targets, prefix="/api/v1", tags=["targets"])
    app.include_router(reports, prefix="/api/v1", tags=["reports"])
    app.include_router(conversations, prefix="/api/v1", tags=["conversations"])
    app.include_router(evidence, prefix="/api/v1", tags=["evidence"])
    app.include_router(workspace, prefix="/api/v1", tags=["workspace"])
    app.include_router(notebook, prefix="/api/v1", tags=["notebook"])
    app.include_router(tasks, prefix="/api/v1", tags=["tasks"])
    app.include_router(search, prefix="/api/v1", tags=["search"])
    app.include_router(dashboard, prefix="/api/v1", tags=["dashboard"])
    app.include_router(timeline, prefix="/api/v1", tags=["timeline"])

    return app


def get_workspace_manager() -> WorkspaceManager:
    global _workspace_manager
    if _workspace_manager is None:
        workspace_dir = Path.home() / ".deephunter" / "workspaces"
        _workspace_manager = WorkspaceManager(workspace_dir)
    return _workspace_manager