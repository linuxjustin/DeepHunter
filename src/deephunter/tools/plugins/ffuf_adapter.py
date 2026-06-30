from __future__ import annotations

from typing import Any

from deephunter.recon.models import Endpoint, EndpointCategory, HttpMethod, Parameter, ParamLocation, ParamType, ReconSourceType
from deephunter.recon.plugin import PluginResult
from deephunter.tools.base import BaseToolPlugin
from deephunter.tools.context import ExecutionContext
from deephunter.tools.models import PluginHealth, ToolCategory, ToolMetadata
from deephunter.tools.normalizer import parse_ndjson


class FfufAdapter(BaseToolPlugin):
    metadata = ToolMetadata(
        name="ffuf",
        description="Web fuzzer via ffuf — discovers paths, parameters, and virtual hosts by fuzzing",
        version="1.0.0",
        category=ToolCategory.fuzzing,
        tags=["fuzzer", "discovery", "content", "ffuf"],
        supported_formats=["ndjson"],
        requires_network=True,
        requires_installation=True,
        timeout_default=300.0,
        retry_default=0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        import shlex
        import subprocess

        url = context.args.get("url", context.target)
        wordlist = context.args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        cmd = f"ffuf -u {shlex.quote(url)} -w {shlex.quote(wordlist)} -json"
        try:
            proc = subprocess.run(
                shlex.split(cmd),
                capture_output=True,
                text=True,
                timeout=context.get_plugin_timeout(),
                env=context.env,
            )
            return proc.stdout
        except subprocess.TimeoutExpired:
            return None

    def parse_output(self, raw: str | bytes | None, context: ExecutionContext) -> list[dict[str, Any]]:
        if not raw:
            return []
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        results = parse_ndjson(raw, {})
        return results

    def normalize(self, parsed: list[dict[str, Any]], context: ExecutionContext) -> PluginResult:
        result = PluginResult()
        seen_urls: set[str] = set()

        for entry in parsed:
            url = entry.get("url", "") or ""
            if not url or url in seen_urls:
                continue
            seen_urls.add(url)

            status = int(entry.get("status", 0) or 0)
            content_length = int(entry.get("length", 0) or 0)
            content_words = int(entry.get("words", 0) or 0)
            content_lines = int(entry.get("lines", 0) or 0)
            content_type = entry.get("content_type", "") or entry.get("content-type", "") or ""
            redirect = entry.get("redirectlocation", "") or entry.get("redirect_location", "") or ""
            input_data = entry.get("input", {}) or {}

            params: list[Parameter] = []
            if input_data and isinstance(input_data, dict):
                for k, v in input_data.items():
                    params.append(Parameter(
                        name=str(k),
                        location=ParamLocation.QUERY,
                        param_type=ParamType.STRING,
                        observed_values=[str(v)],
                        source=ReconSourceType.URL_COLLECTION,
                    ))

            category = EndpointCategory.UNKNOWN
            if status in (200, 201, 204):
                if url.endswith("/"):
                    category = EndpointCategory.API
            if redirect:
                category = EndpointCategory.UNKNOWN
            if content_type and "json" in content_type:
                category = EndpointCategory.API

            endpoint = Endpoint(
                path=url,
                method=HttpMethod.GET,
                category=category,
                parameters=params,
                status_code=status or None,
                content_length=content_length or None,
                source=ReconSourceType.URL_COLLECTION,
                metadata={
                    "tool": "ffuf",
                    "words": content_words,
                    "lines": content_lines,
                    "content_type": content_type,
                    "redirect": redirect,
                    "input": input_data,
                },
            )
            result.endpoints.append(endpoint)

        result.success = True
        return result

    def health(self, context: ExecutionContext) -> PluginHealth:
        import shutil
        found = shutil.which("ffuf") is not None
        return PluginHealth(
            healthy=found,
            installed=found,
            executable_found=found,
            errors=[] if found else ["ffuf not found on PATH"],
        )

    def build_command(self, context: ExecutionContext) -> str:
        url = context.args.get("url", context.target)
        wordlist = context.args.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
        return f"ffuf -u {url} -w {wordlist} -json"
