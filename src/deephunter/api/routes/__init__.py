"""API routes package."""

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

__all__ = ["health", "projects", "targets", "reports", "conversations", "evidence", "workspace", "notebook", "tasks", "search", "dashboard", "timeline"]