"""Report management and export API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel

from deephunter.workspace.manager import WorkspaceManager
from deephunter.workspace.models import ReportFormat

router = APIRouter()


class CreateReportRequest(BaseModel):
    target_id: str
    title: str
    format: str = "markdown"
    content: str = ""
    findings_count: int = 0
    severity_counts: dict[str, int] = {}


class ReportListResponse(BaseModel):
    id: str
    title: str
    format: str
    target_id: str
    findings_count: int
    generated_at: str


class ReportCreateResponse(BaseModel):
    id: str
    title: str
    format: str


class ReportDetailResponse(BaseModel):
    id: str
    title: str
    format: str
    content: str
    target_id: str
    findings_count: int
    severity_counts: dict[str, int]
    generated_by: str
    generated_at: str


class DeleteResponse(BaseModel):
    status: str
    id: str


@router.get("/reports", response_model=list[ReportListResponse])
async def list_reports(target_id: str | None = None) -> list[ReportListResponse]:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    reports = manager.current_workspace.state.reports
    if target_id:
        reports = [r for r in reports if r.target_id == target_id]
    return [ReportListResponse(id=r.id, title=r.title, format=r.format.value, target_id=r.target_id, findings_count=r.findings_count, generated_at=r.generated_at.isoformat()) for r in reports]


@router.post("/reports", response_model=ReportCreateResponse)
async def create_report(req: CreateReportRequest) -> ReportCreateResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        manager.create_workspace("Default")
    report = manager.create_report(
        target_id=req.target_id,
        title=req.title,
        format=ReportFormat(req.format),
        content=req.content,
        findings_count=req.findings_count,
        severity_counts=req.severity_counts,
    )
    manager.save_workspace()
    return ReportCreateResponse(id=report.id, title=report.title, format=report.format.value)


@router.get("/reports/{report_id}", response_model=ReportDetailResponse)
async def get_report(report_id: str) -> ReportDetailResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    for report in manager.current_workspace.state.reports:
        if report.id == report_id:
            return ReportDetailResponse(id=report.id, title=report.title, format=report.format.value, content=report.content, target_id=report.target_id, findings_count=report.findings_count, severity_counts=report.severity_counts, generated_by=report.generated_by, generated_at=report.generated_at.isoformat())
    raise HTTPException(status_code=404, detail="Report not found")


@router.get("/reports/{report_id}/export", response_class=PlainTextResponse)
async def export_report(report_id: str, format: str = "markdown") -> str:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    for report in manager.current_workspace.state.reports:
        if report.id == report_id:
            if format == "html":
                return _convert_to_html(report.content, report.title)
            elif format == "json":
                import json
                return json.dumps({"title": report.title, "content": report.content, "findings_count": report.findings_count, "severity_counts": report.severity_counts}, indent=2)
            elif format == "sarif":
                return _convert_to_sarif(report)
            return report.content
    raise HTTPException(status_code=404, detail="Report not found")


@router.delete("/reports/{report_id}", response_model=DeleteResponse)
async def delete_report(report_id: str) -> DeleteResponse:
    manager = WorkspaceManager()
    if manager.current_workspace is None:
        raise HTTPException(status_code=400, detail="No workspace loaded")
    initial_len = len(manager.current_workspace.state.reports)
    manager.current_workspace.state.reports = [r for r in manager.current_workspace.state.reports if r.id != report_id]
    if len(manager.current_workspace.state.reports) == initial_len:
        raise HTTPException(status_code=404, detail="Report not found")
    manager.save_workspace()
    return DeleteResponse(status="deleted", id=report_id)


def _convert_to_html(content: str, title: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head><title>{title}</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; }}
h1 {{ color: #1a1a1a; border-bottom: 2px solid #6366f1; padding-bottom: 0.5rem; }}
h2 {{ color: #374151; margin-top: 2rem; }}
.finding {{ background: #f9fafb; border-left: 4px solid #6366f1; padding: 1rem; margin: 1rem 0; }}
.high {{ border-color: #ef4444; }}
.medium {{ border-color: #f59e0b; }}
.low {{ border-color: #22c55e; }}
</style>
</head>
<body>
<h1>{title}</h1>
{content}
</body>
</html>"""


def _convert_to_sarif(report) -> str:
    import json
    rules = []
    for i, line in enumerate(report.content.split("\n")):
        if line.startswith("## "):
            finding_title = line[3:].strip()
            rules.append({"id": f"F{i}", "name": finding_title.replace(" ", "_"), "shortDescription": {"text": finding_title}})

    results = []
    for i, rule in enumerate(rules):
        results.append({"ruleId": rule["id"], "level": "warning", "message": {"text": rule["shortDescription"]["text"]}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "report"}, "region": {"startLine": i + 1}}}]})

    sarif = {"version": "2.1.0", "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "runs": [{"tool": {"driver": {"name": "DeepHunter", "version": "1.0.0", "rules": rules}}, "results": results}]}
    return json.dumps(sarif, indent=2)
