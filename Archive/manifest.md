# Claude Security Approval - Document Manifest

## Status: APPROVED

**Approval Date:** 2026-01-15
**Final Cycle:** 3
**Approved By:** PALADIN, CRBRS Security Lead

---

## Root Documents (Approved Artifacts)

| Document | Owner | Purpose |
|----------|-------|---------|
| `security-approval.md` | PALADIN/CRBRS | Formal security approval, residual risk assessment, conditions |
| `architecture-recommendation.md` | Axiom | Deployment architecture, configuration specs, implementation guide |
| `manifest.md` | - | This document index |
| `_loop-prompt.md` | - | Original research loop prompt |

---

## Working Directories

### `axiom/` - Research Team Documents

| Document | Purpose |
|----------|---------|
| `research.md` | Current security research and findings |
| `configurations.md` | Deployment configuration analysis |
| `archive/` | Historical versions from previous cycles |

### `crbrs/` - Security Team Documents

| Document | Purpose |
|----------|---------|
| `review.md` | Current security review and verdict |
| `findings.md` | Itemized findings tracker |
| `archive/` | Historical versions from previous cycles |

---

## Scope

This approval covers Claude Code deployment for development teams with:

- **Deployment Model:** AWS-only (Linux EC2 instances in VPC) - NO local installations
- **Codebase Access:** Read/write to internal repositories (non-classified)
- **OS-level Access:** File system, terminal, development tools (sandboxed)
- **API Provider:** Amazon Bedrock via VPC Private Endpoints
- **Developer Access:** AWS SSM Session Manager (no SSH to instances)
- **Cloud Services:** GitLab, Jira/Confluence, package registries (allowlisted)

### Supported Use Cases
- Code generation and completion
- Code review and debugging
- Test generation
- Documentation generation
- Refactoring assistance
- Git operations (with PR workflow)

### Out of Scope
- Classified/restricted data access
- Production system access
- Customer data environments
- Financial transaction systems
- Healthcare/PII systems (without additional controls)

---

## Key Security Controls Summary

| Control Category | Implementation |
|-----------------|----------------|
| Isolation | bubblewrap (Linux) / seatbelt (macOS) sandboxing |
| Policy Enforcement | managed-settings.json (non-overridable) |
| DLP | TruffleHog + LLM Guard + egress DLP |
| Prompt Injection | Lakera Guard + output validation + behavioral monitoring |
| Audit | Kinesis → S3 Object Lock (COMPLIANCE mode) |
| Network | DNS Firewall + Network Firewall (explicit allowlist) |
| Code Integrity | PR-only workflow with human review |
| Session | 8hr max, 30min idle, full recording |

---

## Residual Risk Summary

| Category | Risk Level |
|----------|------------|
| Data Exposure | LOW |
| Prompt Injection | LOW |
| Audit Tampering | VERY LOW |
| Network Exfiltration | LOW |
| Code Integrity | VERY LOW |
| Session Hijacking | LOW |
| **Overall** | **LOW** |

---

## Conditions of Approval

### Before Production
1. Deploy Lakera Guard (commercial)
2. Configure S3 Object Lock in COMPLIANCE mode
3. Enable full session recording
4. Subscribe to Anthropic security advisories
5. Complete developer training

### Within 30 Days
1. Configure company-specific entity patterns
2. Deploy monitoring dashboard
3. Conduct IR tabletop exercise
4. Review detection thresholds

### Ongoing
- Monthly threshold review (first 90 days)
- Quarterly log recovery testing
- Annual security reassessment

---

## Research Cycle History

| Cycle | Date | Axiom Status | CRBRS Status | Outcome |
|-------|------|--------------|--------------|---------|
| 1 | 2026-01-15 | Complete | ITERATE | 2C/4H identified |
| 2 | 2026-01-15 | Complete | APPROVED | All C/H remediated |
| 3 | 2026-01-15 | Complete | APPROVED | AWS-only + command analysis |

---

## Contact Information

| Role | Team | Responsibility |
|------|------|----------------|
| Security Lead | CRBRS (PALADIN) | Approval authority, policy decisions |
| Research Lead | Axiom (Thesis) | Architecture recommendations |
| Implementation | Cloud Operations | Infrastructure deployment |
| Training | Security Awareness | Developer enablement |

---

## Document Control

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-01-15 | Initial approval |

**Review Cycle:** Quarterly or upon significant architecture change
