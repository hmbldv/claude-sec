# Claude Code Enterprise Security Approval

**Document Type:** Formal Security Approval
**Classification:** Internal
**Version:** 1.0
**Date:** 2026-01-15

---

## Formal Approval Statement

The CRBRS Security Team hereby approves the deployment of Claude Code in the enterprise environment, subject to the conditions outlined in this document.

This approval covers:
- **Primary:** Claude Code CLI for development teams
- **Secondary:** Claude Desktop with OS access (same controls apply)
- **Infrastructure:** AWS-based deployment via Amazon Bedrock
- **Use Cases:** Codebase access, OS-level operations, developer workflows

---

## Executive Summary

After comprehensive security review spanning 2 cycles, the proposed Claude Code architecture has demonstrated adequate security controls to mitigate identified risks to acceptable levels.

**Review Summary:**
| Finding Type | Initial | Final | Resolution |
|--------------|---------|-------|------------|
| Critical | 2 | 0 | Remediated |
| High | 4 | 0 | Remediated |
| Medium | 6 | 6 | Accepted with controls |
| Low | 3 | 3 | Accepted |

**Overall Residual Risk:** LOW

---

## Approved Architecture

The following architecture is approved for production deployment:

### Deployment Model
- **API Provider:** Amazon Bedrock (Claude models)
- **Client:** Claude Code CLI with enterprise sandboxing
- **Authentication:** OIDC federation via IAM Identity Center
- **Network:** VPC Private Endpoints (no public internet exposure)

### Security Control Stack

| Layer | Control | Purpose |
|-------|---------|---------|
| 1 | OS Sandboxing | Filesystem/network isolation |
| 2 | managed-settings.json | Enterprise policy enforcement |
| 3 | PreToolUse Hooks | DLP, prompt injection detection, audit |
| 4 | LLM Guard Proxy | PII masking, final DLP scan |
| 5 | Route 53 DNS Firewall | Domain allowlisting |
| 6 | AWS Network Firewall | Layer 7 egress filtering |
| 7 | VPC Private Endpoint | Private API connectivity |
| 8 | S3 Object Lock | Immutable audit logging |

---

## Residual Risk Assessment

| Risk Category | Residual Risk | Justification |
|---------------|---------------|---------------|
| Data Exposure | LOW | Multi-layer DLP with verified secret scanning |
| Prompt Injection | LOW | Lakera Guard + behavioral monitoring + autonomy limits |
| Audit Tampering | VERY LOW | S3 Object Lock in COMPLIANCE mode |
| Network Exfiltration | LOW | Explicit domain allowlist at DNS and network layers |
| Code Integrity | VERY LOW | PR-only workflow with mandatory human review |
| Session Hijacking | LOW | 8hr timeout, re-auth requirements, full recording |
| Supply Chain (MCP) | LOW | Deny-by-default with strict allowlist |

**Residual Risk Statement:** The combination of native Claude Code security features (sandboxing, permissions) with enterprise controls (DLP, network filtering, audit logging) reduces risk to levels acceptable for internal development use.

---

## Accepted Medium Findings

The following Medium severity findings are accepted with documented compensating controls:

| ID | Finding | Compensating Control | Risk Acceptance |
|----|---------|---------------------|-----------------|
| MED-01 | Credential management | 1-hour lifetime, JIT access | Acceptable |
| MED-02 | IR plan gaps | Runbook documented, tabletop scheduled | Acceptable |
| MED-03 | Vulnerability mgmt | SLAs defined, advisories subscribed | Acceptable |
| MED-04 | MCP server risk | Deny-by-default, approved allowlist | Acceptable |
| MED-05 | Backup/recovery | Config in Git, logs replicated | Acceptable |
| MED-06 | Training gaps | Required before access granted | Acceptable |

---

## Conditions of Approval

### Mandatory Requirements (Before Production)

These requirements MUST be implemented before Claude Code is deployed to production:

1. **Lakera Guard Deployment**
   - Commercial version required for production
   - Dev/test may use LLM Guard (open-source)
   - Detection threshold: block on medium+ confidence

2. **S3 Object Lock Configuration**
   - COMPLIANCE mode (not Governance)
   - 7-year retention period
   - CloudWatch alerts on modification attempts

3. **Session Recording**
   - Full recording required (not sampling)
   - Recordings stored in separate S3 bucket with Object Lock
   - Kill switch accessible to security team

4. **Security Advisories**
   - Subscribe to Anthropic security notifications
   - Security team distribution list must receive alerts

5. **Developer Training**
   - Training module must be completed before access
   - Annual recertification required

### Recommended Actions (Within 30 Days)

1. Configure LLM Guard with company-specific entity patterns
2. Deploy egress monitoring dashboard
3. Conduct IR tabletop exercise
4. Review and tune detection thresholds
5. Document exception/bypass procedures

### Ongoing Requirements

1. **Monthly:** Detection threshold review (first 90 days)
2. **Quarterly:** Log recovery testing
3. **Weekly:** Blocked domain review (first 30 days)
4. **Annually:** Full security reassessment

---

## Monitoring and Review

### Key Metrics
- Prompt injection attempts blocked
- DLP violations detected
- Egress blocks triggered
- Session anomalies flagged
- Audit log integrity status

### Periodic Review
- **90-day review:** Evaluate effectiveness, tune thresholds
- **Annual review:** Full security reassessment with updated threat model

### Incident Triggers
The following events require immediate security team notification:
- Any Critical/High finding in Claude Code CVE
- Prompt injection detection with high confidence
- Audit log tampering attempt
- Credential compromise suspected
- Anomalous behavior pattern detected

---

## Scope Limitations

### In Scope
- Development teams using Claude Code for code generation, review, debugging
- Access to internal codebases (non-classified)
- OS-level operations within sandboxed environment
- Git operations with PR workflow

### Out of Scope
- Access to classified/restricted data
- Production system access
- Customer data environments
- Financial transaction systems
- Healthcare/PII systems (without additional controls)

### Future Considerations
- Extension to additional use cases requires separate security review
- Access to higher data classification levels requires additional controls
- Integration with additional MCP servers requires individual approval

---

## Approval Authority

This approval is issued under the authority of the CRBRS Security Team.

**Approved By:**

```
╔════════════════════════════════════════════════════════════════╗
║                                                                 ║
║    PALADIN                                                      ║
║    CRBRS Security Lead                                          ║
║                                                                 ║
║    Date: 2026-01-15                                            ║
║                                                                 ║
║    Approval Status: APPROVED                                   ║
║                                                                 ║
╚════════════════════════════════════════════════════════════════╝
```

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-15 | PALADIN | Initial approval |

**Review Cycle:** Annual or upon significant architecture change

**Distribution:** Security Team, Engineering Leadership, Compliance Team
