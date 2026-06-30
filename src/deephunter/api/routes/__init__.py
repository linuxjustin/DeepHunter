"""API routes package."""

from deephunter.api.routes.health import router as health
from deephunter.api.routes.projects import router as projects
from deephunter.api.routes.targets import router as targets
from deephunter.api.routes.reports import router as reports
from deephunter.api.routes.conversations import router as conversations
from deephunter.api.routes.evidence import router as evidence
from deephunter.api.routes.workspace import router as workspace

__all__ = ["health", "projects", "targets", "reports", "conversations", "evidence", "workspace"]