"""FastAPI application factory for DeepHunter API.

Creates and configures the FastAPI application with all routers,
middleware, and observability hooks.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from deephunter.workspace.manager import WorkspaceManager


_workspace_manager: WorkspaceManager | None = None
_api_root_path: str = ""


def get_workspace_manager() -> WorkspaceManager:
    global _workspace_manager
    if _workspace_manager is None:
        workspace_dir = Path.home() / ".deephunter" / "workspaces"
        _workspace_manager = WorkspaceManager(workspace_dir)
    return _workspace_manager


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


def create_app(title: str = "DeepHunter API", version: str = "1.0.0", root_path: str = "") -> FastAPI:
    """Create and configure the FastAPI application."""
    global _api_root_path
    _api_root_path = root_path

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
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from deephunter.api.routes import health, projects, targets, reports, conversations, evidence, workspace

    app.include_router(health.router, prefix="/api/v1", tags=["health"])
    app.include_router(projects.router, prefix="/api/v1", tags=["projects"])
    app.include_router(targets.router, prefix="/api/v1", tags=["targets"])
    app.include_router(reports.router, prefix="/api/v1", tags=["reports"])
    app.include_router(conversations.router, prefix="/api/v1", tags=["conversations"])
    app.include_router(evidence.router, prefix="/api/v1", tags=["evidence"])
    app.include_router(workspace.router, prefix="/api/v1", tags=["workspace"])

    return app


def create_ws_app() -> FastAPI:
    return create_app("DeepHunter WebSocket Events", "1.0.0")