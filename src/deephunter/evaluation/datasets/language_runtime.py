"""Language runtime benchmark datasets — PHP, Node.js, Python.

Tests the investigation planner's ability to correctly identify vulnerabilities
specific to each language runtime environment.
"""

from deephunter.evaluation.models import (
    BenchmarkDataset,
    BenchmarkEntry,
    BenchmarkInput,
    DatasetType,
    ExpectedOutput,
    ExpectedReasoning,
    ExpectedStep,
)

PHP_DATASET = BenchmarkDataset(
    id="php-runtime",
    name="PHP Runtime Security",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical PHP runtime vulnerability scenarios — deserialization, command injection, LFI/RFI, type juggling, and SSRF.",
    tags=["golden", "php", "runtime", "command-injection", "deserialization"],
    entries=[
        BenchmarkEntry(
            name="PHP Object Injection",
            description="unserialize() on user-controlled input allows PHP object injection",
            input=BenchmarkInput(
                technologies=["PHP"],
                frameworks=["Laravel", "Symfony"],
                bug_classes=["deserialization"],
                attack_surface_areas=["API endpoints", "Session data", "Cached data"],
                description="PHP application unpickles user-controlled serialized data",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="PHP Deserialization Testing", description="Identify unserialize() calls with user-controlled input", priority_score=0.95),
                    ExpectedStep(phase="exploitation", title="PHP Object Injection PoC", description="Craft serialized object with malicious __reduce__ for RCE", priority_score=0.90),
                ],
                technologies=["PHP"],
                frameworks=["Laravel", "Symfony"],
                attack_surface=["Deserialization", "Object injection"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "unserialize() is called on user-controlled data",
                        "PHP magic methods (__destruct, __wakeup) enable gadget chain attacks",
                        "RCE is achievable via PHP object injection",
                    ],
                    confidence=0.90,
                ),
                knowledge_packs=["php"],
            ),
            tags=["php", "deserialization", "rce", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-502", "CWE-94"],
        ),
        BenchmarkEntry(
            name="PHP Command Injection",
            description="User input reaches exec()/shell_exec() without sanitization",
            input=BenchmarkInput(
                technologies=["PHP"],
                frameworks=["Custom PHP"],
                bug_classes=["command_injection"],
                attack_surface_areas=["System utilities", "Admin functions", "File processing"],
                description="PHP application executes shell commands with user-supplied arguments",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="Command Injection Detection", description="Identify exec, shell_exec, system, passthru, popen calls with user input", priority_score=0.99),
                    ExpectedStep(phase="exploitation", title="Command Injection Exploitation", description="Test with ; whoami, | whoami, $(whoami) for RCE", priority_score=0.99),
                ],
                technologies=["PHP"],
                frameworks=["Custom PHP"],
                attack_surface=["Command execution", "OS interaction"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "User input reaches shell execution functions without escaping",
                        "Shell metacharacters (;, |, &, $()) allow command chaining",
                        "RCE is achievable via command injection",
                    ],
                    confidence=0.95,
                ),
                knowledge_packs=["php"],
            ),
            tags=["php", "command-injection", "rce", "golden"],
            difficulty="easy",
            cwe_ids=["CWE-78"],
        ),
        BenchmarkEntry(
            name="PHP LFI to RCE via PHP Wrappers",
            description="Local file inclusion combined with PHP wrappers achieves RCE",
            input=BenchmarkInput(
                technologies=["PHP"],
                frameworks=["Custom PHP"],
                bug_classes=["path_traversal"],
                attack_surface_areas=["File inclusion", "Template loading", "Image processing"],
                description="PHP application includes files based on user-supplied paths without validation",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="LFI Detection", description="Identify include/require with user-controlled paths", priority_score=0.95),
                    ExpectedStep(phase="exploitation", title="LFI to RCE via Wrappers", description="Use php://filter, phar://, or zip:// to achieve RCE", priority_score=0.90),
                ],
                technologies=["PHP"],
                frameworks=["Custom PHP"],
                attack_surface=["File inclusion", "Path traversal"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "LFI via include($user_input) without validation",
                        "PHP wrappers (php://, phar://, zip://) can achieve RCE",
                        "Log poisoning or upload + LFI enables full compromise",
                    ],
                    confidence=0.85,
                ),
                knowledge_packs=["php"],
            ),
            tags=["php", "lfi", "rce", "path-traversal", "golden"],
            difficulty="hard",
            cwe_ids=["CWE-22", "CWE-94"],
        ),
    ],
)


NODEJS_DATASET = BenchmarkDataset(
    id="nodejs-runtime",
    name="Node.js Runtime Security",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical Node.js runtime vulnerability scenarios — prototype pollution, command injection, path traversal, SSRF, and ReDoS.",
    tags=["golden", "nodejs", "javascript", "prototype-pollution", "command-injection"],
    entries=[
        BenchmarkEntry(
            name="Node.js Prototype Pollution",
            description="JSON body parsing allows __proto__/constructor.prototype pollution",
            input=BenchmarkInput(
                technologies=["Node.js"],
                frameworks=["Express", "NestJS"],
                bug_classes=["prototype_pollution"],
                attack_surface_areas=["JSON API endpoints", "Configuration merging", "Deep clone utilities"],
                description="Node.js application merges JSON body into objects without prototype chain sanitization",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="Prototype Pollution Detection", description="Send __proto__ and constructor.prototype in JSON body", priority_score=0.99),
                    ExpectedStep(phase="privilege_escalation", title="Prototype Pollution Exploitation", description="Pollute hasOwnProperty or isAdmin to escalate privileges", priority_score=0.90),
                ],
                technologies=["Node.js"],
                frameworks=["Express"],
                attack_surface=["JSON parsing", "Object merge"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "JSON.parse() or Object.assign/merge without __proto__ filtering",
                        "Prototype pollution affects all objects globally",
                        "Privilege escalation achievable via polluted properties",
                    ],
                    confidence=0.95,
                ),
                knowledge_packs=["nodejs"],
            ),
            tags=["nodejs", "prototype-pollution", "auth-bypass", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-1321", "CWE-287"],
        ),
        BenchmarkEntry(
            name="Node.js Command Injection",
            description="child_process.exec/spawn with user input allows OS command execution",
            input=BenchmarkInput(
                technologies=["Node.js"],
                frameworks=["Express"],
                bug_classes=["command_injection"],
                attack_surface_areas=["System utilities", "File processing", "Admin functions"],
                description="Node.js application executes shell commands with user-supplied arguments",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="Command Injection Detection", description="Identify child_process.exec, spawn, execSync with user input", priority_score=0.99),
                    ExpectedStep(phase="exploitation", title="Command Injection Exploitation", description="Test shell metacharacters (; | & $()) for RCE", priority_score=0.99),
                ],
                technologies=["Node.js"],
                frameworks=["Express"],
                attack_surface=["Command execution", "OS interaction"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "child_process functions receive user input without shell=False",
                        "Shell=True or string interpolation enables command injection",
                        "RCE achievable via command injection",
                    ],
                    confidence=0.95,
                ),
                knowledge_packs=["nodejs"],
            ),
            tags=["nodejs", "command-injection", "rce", "golden"],
            difficulty="easy",
            cwe_ids=["CWE-78", "CWE-94"],
        ),
        BenchmarkEntry(
            name="Node.js SSRF",
            description="User-controlled URL passed to fetch/axios enables SSRF",
            input=BenchmarkInput(
                technologies=["Node.js"],
                frameworks=["Express", "NestJS"],
                bug_classes=["ssrf"],
                attack_surface_areas=["Webhook callbacks", "URL preview", "Image fetch"],
                description="Node.js application fetches user-supplied URLs for processing",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="SSRF Detection", description="Identify fetch/axios calls with user-controlled URL parameters", priority_score=0.95),
                    ExpectedStep(phase="exploitation", title="SSRF Cloud Metadata", description="Access 169.254.169.254 for cloud credentials", priority_score=0.90),
                ],
                technologies=["Node.js"],
                frameworks=["Express"],
                attack_surface=["URL fetching", "External requests"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "User input controls URL in HTTP client calls",
                        "Cloud metadata service (169.254.169.254) reachable",
                        "Internal services and credentials accessible via SSRF",
                    ],
                    confidence=0.85,
                ),
                knowledge_packs=["nodejs"],
            ),
            tags=["nodejs", "ssrf", "cloud", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-918"],
        ),
    ],
)


PYTHON_DATASET = BenchmarkDataset(
    id="python-runtime",
    name="Python Runtime Security",
    version="1.0.0",
    dataset_type=DatasetType.GOLDEN,
    description="Canonical Python runtime vulnerability scenarios — pickle/YAML deserialization RCE, SSTI, command injection, and SQL injection.",
    tags=["golden", "python", "django", "flask", "fastapi", "deserialization", "ssti"],
    entries=[
        BenchmarkEntry(
            name="Python YAML Deserialization RCE",
            description="yaml.unsafe_load() on user input allows arbitrary code execution",
            input=BenchmarkInput(
                technologies=["Python"],
                frameworks=["Django", "Flask", "FastAPI"],
                bug_classes=["deserialization"],
                attack_surface_areas=["Configuration import", "Data import", "YAML API endpoints"],
                description="Python application deserializes YAML from user input",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="YAML Deserialization Testing", description="Identify yaml.unsafe_load/unsafe_load_all calls with user input", priority_score=0.99),
                    ExpectedStep(phase="exploitation", title="YAML RCE Exploitation", description="Use !!python/object/apply to execute arbitrary code", priority_score=0.99),
                ],
                technologies=["Python"],
                frameworks=["Flask"],
                attack_surface=["YAML parsing", "Data deserialization"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "yaml.unsafe_load() is called on user-controlled data",
                        "Python object serialization via !!python/object/apply enables RCE",
                        "Full server compromise achievable via YAML deserialization",
                    ],
                    confidence=0.95,
                ),
                knowledge_packs=["python"],
            ),
            tags=["python", "yaml", "deserialization", "rce", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-502", "CWE-94"],
        ),
        BenchmarkEntry(
            name="Python SSTI via Jinja2",
            description="User input in render_template_string or template config achieves RCE",
            input=BenchmarkInput(
                technologies=["Python"],
                frameworks=["Flask", "Jinja2"],
                bug_classes=["ssti"],
                attack_surface_areas=["Template rendering", "Email templates", "Dynamic content"],
                description="Flask application renders user-controlled template content",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="SSTI Detection", description="Identify render_template_string and template name injection", priority_score=0.99),
                    ExpectedStep(phase="exploitation", title="Jinja2 SSTI Exploitation", description="Use {{ config.items() }} or payload chain for RCE", priority_score=0.99),
                ],
                technologies=["Python"],
                frameworks=["Flask"],
                attack_surface=["Template rendering", "XSS"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "User input reaches Jinja2 template rendering without escaping",
                        "SSTI payloads can access config, globals, and achieve RCE",
                        "{{''.__class__.__mro__[1].__subclasses__()}} enables code execution",
                    ],
                    confidence=0.95,
                ),
                knowledge_packs=["python", "flask"],
            ),
            tags=["python", "ssti", "rce", "jinja2", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-94", "CWE-79"],
        ),
        BenchmarkEntry(
            name="Python SQLAlchemy SQL Injection",
            description="Raw SQL via text() or .format() in queries allows SQL injection",
            input=BenchmarkInput(
                technologies=["Python"],
                frameworks=["Flask", "Django"],
                bug_classes=["sql_injection"],
                attack_surface_areas=["Search endpoints", "User lookup", "Filter operations"],
                description="Python application uses raw SQL with string interpolation instead of parameterized queries",
            ),
            expected=ExpectedOutput(
                planner_steps=[
                    ExpectedStep(phase="input_validation", title="SQL Injection Detection", description="Identify text() raw SQL and .format() string interpolation", priority_score=0.95),
                    ExpectedStep(phase="exploitation", title="SQL Injection Exploitation", description="Use UNION, boolean-based, or time-based blind SQLi", priority_score=0.90),
                ],
                technologies=["Python"],
                frameworks=["Flask"],
                attack_surface=["Database queries", "Search/filter"],
                reasoning=ExpectedReasoning(
                    hypotheses=[
                        "Raw SQL via text() or .format() with user input",
                        "SQL injection enables database read/write, potentially RCE",
                        "ORM bypass is possible with raw SQL",
                    ],
                    confidence=0.90,
                ),
                knowledge_packs=["python"],
            ),
            tags=["python", "sqli", "sqlalchemy", "golden"],
            difficulty="medium",
            cwe_ids=["CWE-89"],
        ),
    ],
)


def get_runtime_datasets() -> list[BenchmarkDataset]:
    return [PHP_DATASET, NODEJS_DATASET, PYTHON_DATASET]


def get_runtime_dataset(name: str) -> BenchmarkDataset | None:
    for ds in get_runtime_datasets():
        if ds.name == name or ds.id == name:
            return ds
    return None
