"""CI/CD integration — GitHub Actions quality gates."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

from deephunter.evaluation.models import (
    BenchmarkSuiteResult,
    CICheckResult,
    CIComparison,
)
from deephunter.evaluation.reporter import JSONReporter, MarkdownReporter

_DEFAULT_ARTIFACTS = "/tmp/opencode/evaluation/ci"


class CIIntegration:
    """Integrates evaluation with CI/CD pipelines (GitHub Actions)."""

    def __init__(self, artifacts_dir: str = _DEFAULT_ARTIFACTS) -> None:
        self._artifacts_dir = Path(artifacts_dir)
        self._json_reporter = JSONReporter()
        self._md_reporter = MarkdownReporter()

    def _ensure_dir(self) -> Path:
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)
        return self._artifacts_dir

    def run_quality_gate(
        self, result: BenchmarkSuiteResult, threshold: float = 0.7
    ) -> CICheckResult:
        passed = result.overall_score >= threshold
        summary_parts: list[str] = [
            f"Quality gate {'PASSED' if passed else 'FAILED'}",
            f"Score: {result.overall_score:.1%} (threshold: {threshold:.1%})",
            f"Pass rate: {result.pass_rate():.1%}",
            f"Passed: {result.passed}/{result.total_entries} | Failed: {result.failed}",
            f"Duration: {result.duration_ms:.1f} ms",
        ]

        report_path = str(self._ensure_dir() / f"quality_gate_{result.dataset_id}.json")

        return CICheckResult(
            passed=passed,
            score=result.overall_score,
            threshold=threshold,
            summary=" | ".join(summary_parts),
            report_path=report_path,
        )

    def compare_with_previous(
        self,
        result: BenchmarkSuiteResult,
        previous_run_path: str | None = None,
    ) -> CIComparison:
        prev = self.load_previous_result(previous_run_path)
        if prev is None:
            return CIComparison(
                current_run_id=result.id,
                passed_quality_gate=True,
            )

        regressions: list[str] = []
        improvements: list[str] = []

        prev_by_id = {r.entry_id: r for r in prev.results}
        for curr in result.results:
            p = prev_by_id.get(curr.entry_id)
            if p is None:
                continue
            if p.passed and not curr.passed:
                regressions.append(curr.entry_name or curr.entry_id)
            elif not p.passed and curr.passed:
                improvements.append(curr.entry_name or curr.entry_id)

        return CIComparison(
            previous_run_id=prev.id,
            current_run_id=result.id,
            previous_score=prev.overall_score,
            current_score=result.overall_score,
            score_change=round(result.overall_score - prev.overall_score, 4),
            regressions=regressions,
            improvements=improvements,
            passed_quality_gate=result.overall_score >= prev.overall_score,
        )

    def load_previous_result(
        self, path: str | None = None
    ) -> BenchmarkSuiteResult | None:
        if path is not None:
            p = Path(path)
            if p.exists():
                raw = p.read_text(encoding="utf-8")
                return BenchmarkSuiteResult.model_validate_json(raw)

        auto_path = self._artifacts_dir / "latest_result.json"
        if auto_path.exists():
            try:
                raw = auto_path.read_text(encoding="utf-8")
                return BenchmarkSuiteResult.model_validate_json(raw)
            except Exception:
                return None
        return None

    def save_current_result(self, result: BenchmarkSuiteResult) -> str:
        dest = self._ensure_dir() / "latest_result.json"
        dest.write_text(
            self._json_reporter.generate(result), encoding="utf-8"
        )
        return str(dest)

    def should_fail_pipeline(
        self, check: CICheckResult, fail_on_regression: bool = True
    ) -> bool:
        return not check.passed or (fail_on_regression and check.regressions_detected > 0)

    def generate_ci_summary(
        self, result: BenchmarkSuiteResult, check: CICheckResult
    ) -> str:
        lines: list[str] = [
            "## DeepHunter Evaluation Summary",
            "",
            f"**Suite:** {result.suite_name}",
            f"**Provider:** {result.provider or 'N/A'}",
            f"**Timestamp:** {datetime.now(UTC).isoformat()}",
            "",
            "### Quality Gate",
            "",
            f"- **Status:** {'✅ PASSED' if check.passed else '❌ FAILED'}",
            f"- **Score:** {result.overall_score:.1%} (threshold: {check.threshold:.1%})",
            "",
            "### Results",
            "",
            "| Metric | Value |",
            "|:---|---:|",
            f"| Overall Score | {result.overall_score:.1%} |",
            f"| Pass Rate | {result.pass_rate():.1%} |",
            f"| Passed | {result.passed} |",
            f"| Failed | {result.failed} |",
            f"| Total | {result.total_entries} |",
            f"| Duration | {result.duration_ms:.1f} ms |",
            "",
        ]

        if result.results:
            lines.append("### Entry Details")
            lines.append("")
            lines.append("| Entry | Status | Score | Duration |")
            lines.append("|:---|:---:|:---:|:---:|")
            for er in result.results:
                status = "✅" if er.passed else "❌"
                lines.append(
                    f"| {er.entry_name or er.entry_id} | {status} | "
                    f"{er.metrics.overall_score():.1%} | {er.duration_ms:.1f} ms |"
                )

        return "\n".join(lines)

    @staticmethod
    def detect_ci_environment() -> str:
        if os.environ.get("GITHUB_ACTIONS") == "true":
            return "github_actions"
        if os.environ.get("GITLAB_CI") == "true":
            return "gitlab_ci"
        if os.environ.get("JENKINS_URL"):
            return "jenkins"
        if os.environ.get("CIRCLECI") == "true":
            return "circleci"
        return "local"

    @staticmethod
    def get_ci_variable(name: str, default: str = "") -> str:
        return os.environ.get(name, default)

    def write_step_summary(self, result: BenchmarkSuiteResult, check: CICheckResult) -> str | None:
        env = self.detect_ci_environment()
        if env == "github_actions":
            summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
            if summary_path:
                content = self.generate_ci_summary(result, check)
                Path(summary_path).write_text(content, encoding="utf-8")
                return summary_path
        return None
