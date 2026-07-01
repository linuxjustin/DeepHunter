# DeepHunter Roadmap

## Overview

This roadmap tracks planned improvements to the DeepHunter platform, prioritized by impact on real bug bounty engagement workflows.

---

## v0.3 — Investigation Quality (Current)

**Goal**: Make DeepHunter actually run full investigations end-to-end.

### In Progress
- [ ] `investigate status` CLI command — check session progress without resuming
- [ ] `build_graph` handler — create attack surface observations from scope entries
- [ ] Variable substitution for workflow prompt templates (`{{ variable }}` support)
- [ ] `state.in_scope` crash fix — every investigation crashed on first run

### Planned
- [ ] Connect `recon` CLI to investigation workflow — import nmap, subfinder, nuclei results
- [ ] Connect `scan` CLI to investigation workflow — actual attack surface enumeration
- [ ] `investigate report` subcommand — real report generation from investigation state
- [ ] Evidence-to-SKO feedback loop — completed findings update knowledge store

---

## v0.4 — Tool Integrations

**Goal**: Make every tool integration actually execute and produce structured output.

### Planned
- [ ] Burp Suite import → active scan integration
- [ ] SQLMap integration for SQL injection testing
- [ ] FFUF/Gobuster integration for directory fuzzing
- [ ] GraphQL introspection + testing plugin
- [ ] Cloud provider API integrations (AWS, GCP, Azure)

---

## v0.5 — Planner Quality

**Goal**: Make investigation plans genuinely useful for professional researchers.

### Planned
- [ ] Context-aware priority scoring (reward from hypotheses, not hardcoded)
- [ ] Evidence linking — steps reference `hypothesis_ids` and `observation_ids`
- [ ] Step rationale — every step explains WHY it was selected
- [ ] Adaptive prioritization — findings adjust subsequent step priorities
- [ ] Conditional report step — only added when findings exist

---

## v0.6 — AI & Provider Quality

**Goal**: Make AI assistance reliable and cost-efficient.

### Planned
- [ ] Router passes `tools` to providers — tool calling through router
- [ ] Execution fallback — try next provider when one fails
- [ ] Context overflow check — validate prompt fits model context
- [ ] Claude tool arguments fix — pass dict not `str(dict)`
- [ ] Gemini streaming — yield tool call chunks correctly
- [ ] Cost-based model selection — simple tasks use cheap models
- [ ] Token usage tracking and budget alerts

---

## v0.7 — Evaluation Framework

**Goal**: Measure and improve investigation quality over time.

### Planned
- [ ] End-to-end benchmark runner — actually execute investigations against known targets
- [ ] False positive rate tracking in evaluation metrics
- [ ] True positive rate tracking in evaluation metrics
- [ ] Report quality scoring
- [ ] Planner accuracy benchmarks
- [ ] Provider comparison benchmarks (latency, cost, accuracy)

---

## v0.8 — Knowledge Excellence

**Goal**: Make knowledge packs the best in the industry.

### Planned
- [ ] `version_specific_notes` populated for Django, Laravel, Spring Boot, Express
- [ ] Auth0 dedicated pack (Management API v1 vs v2 distinction)
- [ ] Missing packs: Laravel, ASP.NET Core, Spring Framework
- [ ] Missing coverage: HTTP Request Smuggling, WebSocket security, MFA bypass
- [ ] CVE date tracking — when was each CVE added to the pack?

---

## v0.9 — Documentation

**Goal**: A new researcher can go from zero to full investigation in under 30 minutes.

### Planned
- [ ] Quick-start guide: full end-to-end investigation walkthrough
- [ ] Custom workflow creation guide with YAML schema reference
- [ ] Knowledge pack creation guide with examples
- [ ] Troubleshooting guide for common issues
- [ ] Architecture-in-practice doc showing how all modules connect

---

## v1.0 — Production Release

**Goal**: Professional bug bounty hunters trust DeepHunter as their primary tool.

### Criteria
- [ ] All 2421 tests passing
- [ ] 0 known crash bugs in standard workflows
- [ ] Real investigation capability (not just planning)
- [ ] Professional report output (directly submittable)
- [ ] < 30 min install-to-first-finding for OWASP Juice Shop
- [ ] Documentation complete for all CLI commands
- [ ] Evaluation framework measuring real investigation quality

---

## Backlog (Unprioritized)

### High Priority
- Parallel step execution for independent workflow steps
- Interactive investigation mode with researcher input
- Workflow step timeout enforcement
- Checkpoint recovery from mid-step crash
- Workspace backup/restore
- Investigation comparison (diff two sessions)

### Medium Priority
- Multi-user workspace collaboration
- HackerOne/Bugcrowd API integration for scope sync
- Custom nuclei template support
- `investigate run --dry-run` to preview steps
- `investigate run --parallel` for independent steps
- Language-specific output (non-English)
- One-click report export (PDF, HTML, DOCX)

### Lower Priority
- GraphQL schema versioning and diff detection
- K8s-specific attack paths (kubectl proxy, RBAC enumeration)
- Mobile application security packs (iOS, Android)
- WebAssembly security coverage
- Service mesh security (Istio, Linkerd)
- Serverless-specific coverage (Azure Functions, Google Cloud Functions)

---

*Last updated: 2026-07-01*