# Tool Integration SDK & Plugin Framework

## Overview

The Tool Integration SDK enables third-party security tools (subdomain enums,
port scanners, URL discoverers, technology detectors, etc.) to be wrapped as
plugins and executed within DeepHunter through a consistent lifecycle.

```
Plugin Lifecycle:
  validate_context → prepare → execute → parse_output → normalize → import_results → cleanup
```

## Architecture

```
src/deephunter/tools/
├── __init__.py      # Public exports
├── base.py          # BaseToolPlugin ABC
├── models.py        # ToolMetadata, ExecutionReport, ToolStatus, ToolParameter, PluginHealth
├── config.py        # ToolPluginConfig
├── context.py       # ExecutionContext
├── events.py        # ToolEventBus + typed lifecycle events
├── registry.py      # ToolPluginRegistry + auto-discovery
├── executor.py      # ToolExecutor (subprocess, retry, timeout)
├── normalizer.py    # ImportPipeline + format parsers
├── reporter.py      # build_report, report_summary
├── exceptions.py    # Typed exception hierarchy
└── plugins/        
    └── subfinder_plugin.py  # Example built-in plugin
```

## Quick Start

### 1. Define a Plugin

```python
from deephunter.tools import BaseToolPlugin, ExecutionContext, ToolMetadata, ToolCategory
from deephunter.recon.plugin import PluginResult

class MyToolPlugin(BaseToolPlugin):
    metadata = ToolMetadata(
        name="my_tool",
        description="Scans for X",
        version="1.0.0",
        category=ToolCategory.port_scan,
        requires_network=False,
        timeout_default=60.0,
    )

    def execute(self, context: ExecutionContext) -> str | bytes | None:
        # Run the external tool (subprocess, API call, etc.)
        return "output data"

    def parse_output(self, raw, context):
        # Convert raw output to structured data
        return {"items": raw.strip().splitlines()}

    def normalize(self, parsed, context):
        # Convert structured data to deephunter domain models
        result = PluginResult()
        for hostname in parsed.get("items", []):
            result.hosts.append({"hostname": hostname, "ip": ""})
        return result
```

### 2. Register and Execute

```python
from deephunter.tools import ToolPluginRegistry, ToolExecutor, ExecutionContext

registry = ToolPluginRegistry()
registry.register(MyToolPlugin())

executor = ToolExecutor()
plugin = registry.get("my_tool")
ctx = ExecutionContext(plugin_name="my_tool", args={"target": "example.com"})

report = executor.execute(plugin, ctx)
print(report.status, report.duration_ms)
```

### 3. Auto-Discovery

Plugins can be auto-discovered via:
- **Entry points** (group `deephunter.tool_plugins`)
- **Plugin directories** (default `~/.deephunter/plugins/`)
- **Built-in plugins** (`deephunter.tools.plugins`)

```python
registry = ToolPluginRegistry(event_bus=ToolEventBus())
count = registry.discover()
print(f"Discovered {count} plugins")
```

## BaseToolPlugin API

| Method | Purpose |
|--------|---------|
| `validate_context(context) -> bool` | Validate execution context before running |
| `prepare(context) -> None` | Set up working directory, temp files |
| `execute(context) -> str\|bytes\|None` | Run the external tool |
| `parse_output(raw, context) -> Any` | Parse raw tool output |
| `normalize(parsed, context) -> PluginResult` | Convert to domain models |
| `import_results(result, context) -> dict` | Register results (counts per entity type) |
| `cleanup(context) -> None` | Tear down temp files |
| `health(context) -> PluginHealth` | Check if tool is installed/healthy |
| `build_command(context) -> str` | Return the command string for display |

## Execution Lifecycle

The `ToolExecutor.execute()` method orchestrates the full lifecycle:

1. Emit `ToolExecutionStartedEvent`
2. Check cancellation
3. Call `plugin.execute(context)` 
4. Call `plugin.parse_output(raw, context)`
5. Call `plugin.normalize(parsed, context)` → `PluginResult`
6. Emit `ToolImportStartedEvent`
7. Call `plugin.import_results(result, context)`
8. Emit `ToolImportCompletedEvent`
9. Return `ExecutionReport`

On failure, retries are attempted (configurable via `ToolPluginConfig.default_retries`
or per-plugin via `plugin_retries`).

## Configuration

```python
from deephunter.tools import ToolPluginConfig

cfg = ToolPluginConfig(
    enabled=True,
    default_timeout=120.0,       # seconds
    default_retries=2,
    retry_delay_seconds=2.0,
    plugin_timeouts={"slow_tool": 600.0},
    plugin_retries={"fast_tool": 0},
    enabled_plugins=["subfinder", "nuclei"],
    disabled_plugins=["slow_tool"],
    plugin_dirs=["~/.deephunter/plugins"],
    env_overrides={"PATH": "/opt/tools/bin"},
)
```

Set via environment variables:

```bash
export DEEPHUNTER_TOOL_PLUGINS__ENABLED=false
export DEEPHUNTER_TOOL_PLUGINS__DEFAULT_TIMEOUT=300
```

## Output Parsing (ImportPipeline)

The `ImportPipeline` converts raw tool output into structured data:

```python
from deephunter.tools import ImportPipeline, build_default_pipeline

pipeline = build_default_pipeline()

# Auto-detect format
parsed = pipeline.parse('{"hosts": ["a", "b"]}')
parsed = pipeline.parse("host1\nhost2\n", fmt="txt")
parsed = pipeline.parse("name,port\nnginx,80", fmt="csv")
```

Supported formats: `json`, `yaml`, `csv`, `txt`, `ndjson`

## Events

| Event | When |
|-------|------|
| `ToolExecutionStartedEvent` | Before plugin.execute() |
| `ToolExecutionCompletedEvent` | After successful execution |
| `ToolExecutionFailedEvent` | On execution failure |
| `ToolImportStartedEvent` | Before plugin.import_results() |
| `ToolImportCompletedEvent` | After import |
| `ToolPluginDiscoveredEvent` | During auto-discovery |
| `ToolPluginRegisteredEvent` | When plugin is registered |

## Reports

```python
from deephunter.tools import build_report, report_summary

report = build_report(
    tool_name="subfinder",
    plugin_name="subfinder",
    status=ToolStatus.success,
    command="subfinder -d example.com -silent",
    stdout="...",
    exit_code=0,
    duration_ms=1520.3,
)

summary = report_summary([report])
# {'total': 1, 'succeeded': 1, 'total_duration_ms': 1520.3, ...}
```

## Built-in Plugin Example

```python
from deephunter.tools.plugins.subfinder_plugin import SubfinderPlugin

plugin = SubfinderPlugin()
ctx = ExecutionContext(target="example.com")
result = plugin.normalize(["sub.a.com", "sub.b.com"], ctx)
# 2 hosts added to PluginResult
```

## Exception Hierarchy

```
DeepHunterError
  └── ToolPluginError
        ├── PluginNotFoundError
        ├── PluginRegistrationError
        ├── PluginValidationError
        ├── PluginExecutionError
        ├── PluginTimeoutError
        ├── PluginNotInstalledError
        ├── PluginImportError
        ├── PluginParseError
        ├── PluginNormalizeError
        ├── PluginConfigError
        └── PluginDiscoveryError
```

## Creating Entry Point Plugins

In your package's `pyproject.toml`:

```toml
[project.entry-points."deephunter.tool_plugins"]
my_tool = "my_package.plugins:MyToolPlugin"
```
