"""Report generation — HTML, Markdown, JSON, CSV."""

from __future__ import annotations

import csv
import json
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from io import StringIO
from pathlib import Path
from typing import Any

from deephunter.evaluation.models import (
    BenchmarkSuiteResult,
    Leaderboard,
    RegressionReport,
    Scorecard,
    TrendReport,
)


class BaseReporter(ABC):
    """Abstract base for all report generators."""

    @abstractmethod
    def generate(self, data: Any) -> str:
        ...


class JSONReporter(BaseReporter):
    """Generates JSON reports."""

    def generate(self, data: Any) -> str:
        obj = data.model_dump() if hasattr(data, "model_dump") else data
        return json.dumps(obj, indent=2, default=str)


class MarkdownReporter(BaseReporter):
    """Generates Markdown reports for benchmark results."""

    def generate(self, data: Any) -> str:
        if isinstance(data, Scorecard):
            return self.generate_scorecard(data)
        if isinstance(data, BenchmarkSuiteResult):
            return self.generate_suite(data)
        if isinstance(data, TrendReport):
            return self.generate_trend(data)
        if isinstance(data, RegressionReport):
            return self.generate_regression(data)
        if isinstance(data, Leaderboard):
            return self.generate_leaderboard(data)
        return str(data)

    def generate_scorecard(self, scorecard: Scorecard) -> str:
        lines: list[str] = []
        lines.append(f"# Scorecard: {scorecard.name or 'Evaluation'}")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|:---|---:|")
        lines.append(f"| Overall Score | {scorecard.overall_score:.1%} |")
        lines.append(f"| Pass Rate | {scorecard.pass_rate:.1%} |")
        lines.append(f"| Passed / Failed | {scorecard.passed} / {scorecard.failed} |")
        lines.append(f"| Total Tests | {scorecard.total_tests} |")
        lines.append(f"| Duration | {scorecard.duration_ms:.1f} ms |")
        lines.append("")
        if scorecard.category_scores:
            lines.append("## Category Scores")
            lines.append("")
            lines.append("| Category | Score | Status |")
            lines.append("|:---:|:---:|:---:|")
            for cat, sc in sorted(scorecard.category_scores.items()):
                compliant = scorecard.threshold_compliance.get(cat, False)
                status = "✅ Pass" if compliant else "❌ Fail"
                lines.append(f"| {cat} | {sc:.1%} | {status} |")
        return "\n".join(lines)

    def generate_suite(self, result: BenchmarkSuiteResult) -> str:
        lines: list[str] = []
        lines.append(f"# Suite: {result.suite_name}")
        lines.append("")
        lines.append(f"- **Overall Score:** {result.overall_score:.1%}")
        lines.append(f"- **Pass Rate:** {result.pass_rate():.1%}")
        lines.append(f"- **Passed:** {result.passed} / **Failed:** {result.failed}")
        lines.append(f"- **Duration:** {result.duration_ms:.1f} ms")
        lines.append(f"- **Provider:** {result.provider or 'N/A'}")
        lines.append("")
        lines.append("## Results")
        lines.append("")
        lines.append("| Entry | Status | Score | Duration |")
        lines.append("|:---|---:|:---:|:---:|")
        for er in result.results:
            status = "✅" if er.passed else "❌"
            lines.append(
                f"| {er.entry_name or er.entry_id} | {status} | "
                f"{er.metrics.overall_score():.1%} | {er.duration_ms:.1f} ms |"
            )
        return "\n".join(lines)

    def generate_trend(self, trend: TrendReport) -> str:
        lines: list[str] = []
        lines.append(f"# Trend: {trend.name}")
        lines.append("")
        lines.append(f"- **Score Delta:** {trend.score_delta:+.1%}")
        lines.append(f"- **Pass Rate Delta:** {trend.pass_rate_delta:+.1%}")
        if trend.regression_detected:
            lines.append("- **⚠ Regression Detected**")
        if trend.regressed_metrics:
            lines.append(f"- **Regressed Metrics:** {', '.join(trend.regressed_metrics)}")
        lines.append("")
        lines.append("| Timestamp | Score | Pass Rate |")
        lines.append("|:---|:---:|:---:|")
        for pt in trend.points:
            lines.append(f"| {pt.timestamp} | {pt.overall_score:.1%} | {pt.pass_rate:.1%} |")
        return "\n".join(lines)

    def generate_regression(self, regression: RegressionReport) -> str:
        lines: list[str] = []
        lines.append(f"# Regression Report: {regression.suite_name}")
        lines.append("")
        lines.append("| Metric | Previous | Current | Delta |")
        lines.append("|:---|---:|---:|---:|")
        lines.append(
            f"| Score | {regression.previous_score:.1%} | {regression.current_score:.1%} | "
            f"{regression.score_delta:+.1%} |"
        )
        lines.append(
            f"| Pass Rate | {regression.previous_pass_rate:.1%} | "
            f"{regression.current_pass_rate:.1%} | {regression.pass_rate_delta:+.1%} |"
        )
        if regression.metric_deltas:
            for name, delta in regression.metric_deltas.items():
                lines.append(f"| {name} | — | — | {delta:+.1%} |")
        lines.append("")
        if regression.regressed:
            lines.append("## ⚠ Regressions Detected")
            if regression.new_failures:
                for nf in regression.new_failures:
                    lines.append(f"- {nf}")
        if regression.fixed_tests:
            lines.append("## ✅ Fixed Tests")
            for ft in regression.fixed_tests:
                lines.append(f"- {ft}")
        return "\n".join(lines)

    def generate_leaderboard(self, board: Leaderboard) -> str:
        lines: list[str] = []
        lines.append(f"# Leaderboard: {board.name}")
        lines.append("")
        lines.append(f"**Category:** {board.category.value}")
        lines.append("")
        lines.append("| Rank | Name | Score | Pass Rate | Latency | Provider |")
        lines.append("|:---:|:---|:---:|:---:|:---:|:---|")
        for entry in board.entries:
            lines.append(
                f"| {entry.rank} | {entry.name} | {entry.score:.1%} | "
                f"{entry.pass_rate:.1%} | {entry.avg_latency_ms:.1f} ms | "
                f"{entry.provider or 'N/A'} |"
            )
        return "\n".join(lines)


class HTMLReporter(BaseReporter):
    """Generates HTML reports with inline CSS for benchmark results."""

    _CSS = """
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto,
                         Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 960px; margin: 40px auto; padding: 0 24px;
            background: #f1f5f9; color: #1e293b; line-height: 1.6;
        }
        h1 { border-bottom: 3px solid #3b82f6; padding-bottom: 12px; }
        h2 { color: #334155; margin-top: 32px; }
        .grid {
            display: grid; grid-template-columns: repeat(3, 1fr);
            gap: 16px; margin: 24px 0;
        }
        .card {
            background: #fff; border-radius: 12px; padding: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,.08); text-align: center;
        }
        .card-label { font-size: 13px; color: #64748b; text-transform: uppercase;
                      letter-spacing: .05em; }
        .card-value { font-size: 32px; font-weight: 700; margin-top: 4px; }
        .progress-group { margin-bottom: 16px; }
        .progress-label {
            display: flex; justify-content: space-between; margin-bottom: 4px;
            font-size: 14px;
        }
        .progress-label span:first-child { font-weight: 600; }
        .bar-bg {
            background: #e2e8f0; border-radius: 8px; height: 22px;
            overflow: hidden;
        }
        .bar-fill {
            height: 100%; border-radius: 8px;
            transition: width .6s ease;
        }
        table {
            width: 100%; border-collapse: collapse; background: #fff;
            border-radius: 12px; overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,.08); margin: 16px 0;
        }
        th {
            background: #3b82f6; color: #fff; padding: 12px 16px;
            text-align: left; font-weight: 600;
        }
        td { padding: 10px 16px; border-bottom: 1px solid #e2e8f0; }
        tr:last-child td { border-bottom: none; }
        tr:nth-child(even) { background: #f8fafc; }
        .pass { color: #16a34a; font-weight: 600; }
        .fail { color: #dc2626; font-weight: 600; }
        .footer { margin-top: 32px; font-size: 13px; color: #94a3b8;
                  text-align: center; }
        .status-dot {
            display: inline-block; width: 10px; height: 10px;
            border-radius: 50%; margin-right: 6px;
        }
    """

    def generate(self, data: Any) -> str:
        if isinstance(data, Scorecard):
            return self.generate_scorecard(data)
        if isinstance(data, BenchmarkSuiteResult):
            return self.generate_suite(data)
        if isinstance(data, Leaderboard):
            return self.generate_leaderboard(data)
        return f"<pre>{data!s}</pre>"

    def _wrap(self, title: str, body: str) -> str:
        ts = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>{title}</title><style>{self._CSS}</style></head>
<body>{body}<div class="footer">Generated {ts}</div>
</body></html>"""

    def _bar(self, pct: float) -> str:
        p = int(pct * 100)
        color = "#22c55e" if pct >= 0.7 else "#eab308" if pct >= 0.4 else "#ef4444"
        return (
            '<div class="progress-group"><div class="progress-label">'
            f'<span>&nbsp;</span><span>{p}%</span></div>'
            f'<div class="bar-bg"><div class="bar-fill" '
            f'style="width:{p}%;background:{color}">'
            '</div></div></div>'
        )

    def generate_scorecard(self, scorecard: Scorecard) -> str:
        colors = {
            "overall": "#3b82f6",
            "pass": "#16a34a" if scorecard.pass_rate >= 0.7 else "#dc2626",
        }

        total_span = f'<span style="font-size:16px;color:#94a3b8"> / {scorecard.total_tests}</span>'
        cards = f"""<div class="grid">
<div class="card"><div class="card-label">Overall Score</div>
<div class="card-value" style="color:{colors['overall']}">{scorecard.overall_score:.1%}</div></div>
<div class="card"><div class="card-label">Pass Rate</div>
<div class="card-value" style="color:{colors['pass']}">{scorecard.pass_rate:.1%}</div></div>
<div class="card"><div class="card-label">Tests</div>
<div class="card-value">{scorecard.passed}{total_span}</div></div>
</div>"""

        bars = ""
        for cat, sc in sorted(scorecard.category_scores.items()):
            p = int(sc * 100)
            c = "#22c55e" if sc >= 0.7 else "#eab308" if sc >= 0.4 else "#ef4444"
            compliant = scorecard.threshold_compliance.get(cat, False)
            dot_bg = "#22c55e" if compliant else "#ef4444"
            dot = f'<span class="status-dot" style="background:{dot_bg}"></span>'
            bars += (
                '<div class="progress-group"><div class="progress-label">'
                f'<span>{dot}{cat}</span><span>{p}%</span></div>'
                f'<div class="bar-bg"><div class="bar-fill" '
                f'style="width:{p}%;background:{c}"></div></div></div>'
            )

        body = f"""<h1>Scorecard: {scorecard.name or 'Evaluation'}</h1>
{cards}
<h2>Category Scores</h2>
{bars}
<div class="card" style="text-align:left;margin-top:16px">
<p><strong>Duration:</strong> {scorecard.duration_ms:.1f} ms &middot;
<strong>Passed:</strong> {scorecard.passed} &middot;
<strong>Failed:</strong> {scorecard.failed}</p>
</div>"""
        return self._wrap(f"Scorecard: {scorecard.name}", body)

    def generate_suite(self, result: BenchmarkSuiteResult) -> str:
        pct = result.pass_rate()
        pass_color = "#16a34a" if pct >= 0.7 else "#dc2626"

        cards = f"""<div class="grid">
<div class="card"><div class="card-label">Score</div>
<div class="card-value" style="color:#3b82f6">{result.overall_score:.1%}</div></div>
<div class="card"><div class="card-label">Pass Rate</div>
<div class="card-value" style="color:{pass_color}">{pct:.1%}</div></div>
<div class="card"><div class="card-label">Duration</div>
<div class="card-value" style="font-size:24px">{result.duration_ms:.0f} ms</div></div>
</div>"""

        rows = ""
        for er in result.results:
            status_cls = "pass" if er.passed else "fail"
            icon = "&#10003;" if er.passed else "&#10007;"
            rows += f"""<tr><td>{er.entry_name or er.entry_id}</td>
<td class="{status_cls}">{icon} {'Pass' if er.passed else 'Fail'}</td>
<td>{er.metrics.overall_score():.1%}</td>
<td>{er.duration_ms:.1f} ms</td>
<td>{len(er.errors)}</td></tr>"""

        body = f"""<h1>Suite: {result.suite_name}</h1>
<p><strong>Provider:</strong> {result.provider or 'N/A'} &middot;
<strong>Dataset:</strong> {result.dataset_id} &middot;
<strong>Entries:</strong> {result.total_entries}</p>
{cards}
<h2>Entry Results</h2>
<table><thead><tr><th>Entry</th><th>Status</th><th>Score</th><th>Duration</th><th>Errors</th></tr></thead>
<tbody>{rows}</tbody></table>"""
        return self._wrap(f"Suite: {result.suite_name}", body)

    def generate_leaderboard(self, board: Leaderboard) -> str:
        ranked = sorted(board.entries, key=lambda e: -e.score)
        rows = ""
        for i, entry in enumerate(ranked, 1):
            rows += f"""<tr><td>{i}</td><td>{entry.name}</td>
<td>{entry.score:.1%}</td>
<td class="{'pass' if entry.pass_rate >= 0.7 else 'fail'}">{entry.pass_rate:.1%}</td>
<td>{entry.avg_latency_ms:.1f} ms</td>
<td>{entry.provider or 'N/A'}</td></tr>"""

        headers = (
            "<th>#</th><th>Name</th><th>Score</th>"
            "<th>Pass Rate</th><th>Latency</th><th>Provider</th>"
        )
        body = f"""<h1>Leaderboard: {board.name}</h1>
<p><strong>Category:</strong> {board.category.value} &middot;
<strong>Ranked:</strong> {board.total_ranked}</p>
<table><thead><tr>{headers}</tr></thead>
<tbody>{rows}</tbody></table>"""
        return self._wrap(f"Leaderboard: {board.name}", body)


class CSVReporter(BaseReporter):
    """Generates CSV reports for benchmark results."""

    def generate(self, data: Any) -> str:
        if isinstance(data, list) and all(isinstance(x, BenchmarkSuiteResult) for x in data):
            return self.generate_metrics(data)
        if isinstance(data, Leaderboard):
            return self.generate_leaderboard(data)
        return str(data)

    def generate_metrics(self, results: list[BenchmarkSuiteResult]) -> str:
        buf = StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "name", "overall_score", "pass_rate", "passed",
            "failed", "total", "duration_ms", "provider",
        ])
        for r in results:
            writer.writerow([
                r.suite_name,
                round(r.overall_score, 4),
                round(r.pass_rate(), 4),
                r.passed,
                r.failed,
                r.total_entries,
                round(r.duration_ms, 2),
                r.provider,
            ])
        return buf.getvalue()

    def generate_leaderboard(self, board: Leaderboard) -> str:
        buf = StringIO()
        writer = csv.writer(buf)
        writer.writerow([
            "rank", "name", "score", "pass_rate",
            "avg_latency_ms", "provider", "entries_evaluated",
        ])
        for entry in sorted(board.entries, key=lambda e: e.rank):
            writer.writerow([
                entry.rank,
                entry.name,
                round(entry.score, 4),
                round(entry.pass_rate, 4),
                round(entry.avg_latency_ms, 2),
                entry.provider,
                entry.entries_evaluated,
            ])
        return buf.getvalue()


class ReportWriter:
    """Convenience wrapper that generates all report formats on disk."""

    def __init__(self, output_dir: str = "/tmp/opencode/evaluation/reports") -> None:
        self._output_dir = Path(output_dir)
        self._json_reporter = JSONReporter()
        self._md_reporter = MarkdownReporter()
        self._html_reporter = HTMLReporter()
        self._csv_reporter = CSVReporter()

    def _ensure_dir(self) -> Path:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        return self._output_dir

    def _write(self, stem: str, suffix: str, content: str) -> str:
        path = self._ensure_dir() / f"{stem}{suffix}"
        path.write_text(content, encoding="utf-8")
        return str(path)

    def write_all(self, result: BenchmarkSuiteResult) -> dict[str, str]:
        name = result.suite_name or "suite"
        return {
            "json": self._write(name, ".json", self._json_reporter.generate(result)),
            "md": self._write(name, ".md", self._md_reporter.generate(result)),
            "html": self._write(name, ".html", self._html_reporter.generate(result)),
        }

    def write_scorecard(self, scorecard: Scorecard) -> dict[str, str]:
        stem = f"scorecard_{scorecard.name.replace(' ', '_')}" if scorecard.name else "scorecard"
        return {
            "json": self._write(stem, ".json", self._json_reporter.generate(scorecard)),
            "md": self._write(stem, ".md", self._md_reporter.generate(scorecard)),
            "html": self._write(stem, ".html", self._html_reporter.generate(scorecard)),
        }

    def write_trend(self, trend: TrendReport) -> dict[str, str]:
        stem = f"trend_{trend.name.replace(' ', '_')}" if trend.name else "trend"
        return {
            "json": self._write(stem, ".json", self._json_reporter.generate(trend)),
            "md": self._write(stem, ".md", self._md_reporter.generate(trend)),
        }

    def write_regression(self, regression: RegressionReport) -> dict[str, str]:
        stem = (
            f"regression_{regression.suite_name.replace(' ', '_')}"
            if regression.suite_name else "regression"
        )
        return {
            "json": self._write(stem, ".json", self._json_reporter.generate(regression)),
            "md": self._write(stem, ".md", self._md_reporter.generate(regression)),
        }

    def write_leaderboard(self, board: Leaderboard) -> dict[str, str]:
        stem = f"leaderboard_{board.category.value}"
        return {
            "json": self._write(stem, ".json", self._json_reporter.generate(board)),
            "md": self._write(stem, ".md", self._md_reporter.generate(board)),
            "html": self._write(stem, ".html", self._html_reporter.generate(board)),
            "csv": self._write(stem, ".csv", self._csv_reporter.generate(board)),
        }
