"""Bug bounty production workflows — 11 end-to-end pipelines."""

from deephunter.agents.workflows.initial_recon import InitialReconWorkflow
from deephunter.agents.workflows.attack_surface import AttackSurfaceWorkflow
from deephunter.agents.workflows.tech_profiling import TechnologyProfilingWorkflow
from deephunter.agents.workflows.auth_review import AuthReviewWorkflow
from deephunter.agents.workflows.authorization_review import AuthorizationReviewWorkflow
from deephunter.agents.workflows.business_logic import BusinessLogicWorkflow
from deephunter.agents.workflows.api_review import APIReviewWorkflow
from deephunter.agents.workflows.js_review import JavaScriptReviewWorkflow
from deephunter.agents.workflows.cloud_review import CloudReviewWorkflow
from deephunter.agents.workflows.finding_prep import FindingPreparationWorkflow
from deephunter.agents.workflows.report_gen import ReportGenerationWorkflow

__all__ = [
    "InitialReconWorkflow",
    "AttackSurfaceWorkflow",
    "TechnologyProfilingWorkflow",
    "AuthReviewWorkflow",
    "AuthorizationReviewWorkflow",
    "BusinessLogicWorkflow",
    "APIReviewWorkflow",
    "JavaScriptReviewWorkflow",
    "CloudReviewWorkflow",
    "FindingPreparationWorkflow",
    "ReportGenerationWorkflow",
]
