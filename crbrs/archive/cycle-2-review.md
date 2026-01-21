# CRBRS Security Review: Claude Code Enterprise Deployment

**Cycle:** 2
**Status:** Review Complete - APPROVED
**Review Date:** 2026-01-15
**Lead:** PALADIN | **Coordinator:** NEXUS

---

## Review Summary

Axiom has addressed all Critical and High findings from Cycle 1 with comprehensive, defense-in-depth solutions. The proposed architecture now meets enterprise security requirements.

**Finding Status:**
| Severity | Cycle 1 | Cycle 2 | Status |
|----------|---------|---------|--------|
| Critical | 2 | 0 | REMEDIATED |
| High | 4 | 0 | REMEDIATED |
| Medium | 6 | 6 | ACCEPTED WITH CONTROLS |
| Low | 3 | 3 | ACCEPTED |

---

## Critical Finding Review

### CRIT-01: DLP Integration - REMEDIATED

**Original Finding:** No DLP scanning of prompts before API transmission.

**Proposed Remediation:**
1. Layer 1: TruffleHog/Gitleaks PreToolUse hook for secret scanning
2. Layer 2: LLM Guard proxy for PII detection and sanitization
3. Layer 3: Egress DLP at corporate proxy

**CRBRS Assessment:** ACCEPTABLE

The multi-layer approach addresses the finding comprehensively:
- TruffleHog's verification feature eliminates false positives
- LLM Guard provides NER-based PII detection
- Defense-in-depth ensures coverage gaps are mitigated

**Conditions:**
- Implement TruffleHog in "verified-only" mode to prevent false positive workflow disruption
- Configure LLM Guard with company-specific entity patterns within 30 days of deployment
- Document bypass procedure for legitimate security research use cases

---

### CRIT-02: Prompt Injection Defense - REMEDIATED

**Original Finding:** No detection or prevention of prompt injection attacks.

**Proposed Remediation:**
1. Layer 1: Lakera Guard input guardrails
2. Layer 2: Output guardrails with command validation
3. Layer 3: Behavioral monitoring via SIEM
4. Layer 4: Autonomy reduction (ask permissions for writes/bash)

**CRBRS Assessment:** ACCEPTABLE

The layered guardrail approach aligns with OWASP LLM Security recommendations:
- Input validation catches known attack patterns
- Output validation prevents execution of injected commands
- Behavioral monitoring detects novel attacks
- Autonomy reduction limits blast radius

**Conditions:**
- Deploy Lakera Guard (commercial) rather than open-source alternatives for production
  - Rationale: <50ms latency, better detection rates, ongoing threat intelligence updates
- Set initial detection threshold to "block on medium+ confidence" with logging for all
- Review and tune thresholds monthly for first 90 days

**Open Question Response:**
- **Lakera vs LLM Guard:** Recommend Lakera Guard for production; LLM Guard acceptable for dev/test
- **Prompt injection thresholds:** Block on medium+ confidence; log all detections

---

## High Finding Review

### HIGH-01: Audit Log Integrity - REMEDIATED

**Original Finding:** Local audit logs could be tampered with.

**Proposed Remediation:**
- Real-time streaming to Kinesis Firehose
- S3 Object Lock in COMPLIANCE mode (7-year retention)
- CloudTrail monitoring of configuration changes
- Cryptographic hash chain verification

**CRBRS Assessment:** ACCEPTABLE

The architecture provides tamper-evident, immutable logging:
- COMPLIANCE mode prevents even admin deletion
- Real-time streaming eliminates local tampering window
- CloudTrail provides meta-audit of the audit system

**Conditions:**
- Set Kinesis buffering interval to 60 seconds maximum
- Configure CloudWatch alarm for any Object Lock modification attempts
- Test log recovery procedure quarterly

---

### HIGH-02: Network Egress Controls - REMEDIATED

**Original Finding:** Insufficient egress filtering.

**Proposed Remediation:**
- Route 53 DNS Firewall with explicit allowlist
- AWS Network Firewall with Layer 7 domain filtering
- DoH blocking to prevent DNS bypass
- Traffic anomaly detection via VPC Flow Logs

**CRBRS Assessment:** ACCEPTABLE

The egress architecture implements zero-trust networking:
- DNS-level filtering catches domain resolution attempts
- Network Firewall validates actual TLS connections
- DoH blocking closes bypass vector
- Anomaly detection provides defense against unknown vectors

**Conditions:**
- Implement allowlist as specified (api.anthropic.com, *.amazonaws.com only)
- Add monitoring dashboard for egress blocks within 14 days
- Review blocked domains weekly for first 30 days to identify legitimate use cases

---

### HIGH-03: Code Commit Review Enforcement - REMEDIATED

**Original Finding:** Claude could push code directly without review.

**Proposed Remediation:**
- Block `git push` in managed-settings.json deny list
- Require PR workflow for all code changes
- Server-side pre-push hooks for enforcement
- Branch protection rules on main/protected branches

**CRBRS Assessment:** ACCEPTABLE

The PR-only workflow ensures human review:
- managed-settings.json provides client-side enforcement
- Server-side hooks provide defense-in-depth
- Branch protection provides final enforcement layer

**Conditions:**
- Configure `git push` to "ask" (not "deny") to allow pushing to feature branches
- Require at least 1 human reviewer for all PRs from Claude sessions
- Enable "dismiss stale reviews" on branch protection

---

### HIGH-04: Session Management - REMEDIATED

**Original Finding:** No session timeout or isolation.

**Proposed Remediation:**
- 8-hour maximum session duration
- 30-minute idle timeout
- Re-authentication for sensitive operations
- Single concurrent session per user
- Session recording via SSM

**CRBRS Assessment:** ACCEPTABLE

The session management policy appropriately limits exposure:
- 8-hour limit aligns with typical workday
- Idle timeout reduces abandoned session risk
- Re-auth for sensitive ops prevents credential theft abuse
- Recording provides forensic capability

**Conditions:**
- Session recording is REQUIRED (not optional) for compliance
- Store session recordings in separate S3 bucket with Object Lock
- Implement session kill switch accessible to security team

**Open Question Response:**
- **Session recording:** Full recording required, not sampling

---

## Medium Finding Review

All Medium findings have acceptable compensating controls or risk acceptance rationale.

### MED-01: AWS Credential Management - ACCEPTED

**Control:** 1-hour credential lifetime, IAM Identity Center, documented break-glass

**Risk Acceptance:** Short-lived credentials with JIT access adequately mitigate risk.

### MED-02: Incident Response Plan - ACCEPTED

**Control:** Claude-specific IR runbook with kill switch documented

**Risk Acceptance:** IR runbook meets minimum viable requirements. Recommend tabletop exercise within 60 days.

### MED-03: Vulnerability Management - ACCEPTED

**Control:** Patch SLAs defined, security notification subscription

**Risk Acceptance:** Standard vulnerability management applies. Subscribe to Anthropic advisories immediately.

### MED-04: MCP Server Risk - ACCEPTED

**Control:** Deny-by-default policy, allowlist with approval required

**Risk Acceptance:** Strict allowlist adequately mitigates supply chain risk. Current allowlist (hive-postgres, metabase) approved.

### MED-05: Backup and Recovery - ACCEPTED

**Control:** Config in Git, audit logs replicated, RTO/RPO defined

**Risk Acceptance:** Stateless service with configuration management meets DR requirements.

### MED-06: Developer Training - ACCEPTED

**Control:** Training module with completion requirement

**Risk Acceptance:** Training requirement before access mitigates human factor risk.

**Open Question Response:**
- **MCP server isolation:** Container-level isolation acceptable for approved servers; VM-level for untested servers

---

## Low Finding Review

All Low findings accepted with recommendations:
- LOW-01: Monitoring dashboard recommended within 30 days
- LOW-02: AWS Budgets alerts should be configured
- LOW-03: Runbooks should be developed during pilot phase

---

## Positive Findings (Unchanged from Cycle 1)

The following controls continue to meet security requirements:
1. OS-level sandboxing (bubblewrap/seatbelt)
2. managed-settings.json hierarchy
3. VPC Private Endpoints
4. OIDC federation
5. Defense-in-depth architecture

---

## Residual Risk Assessment

| Risk Category | Residual Risk | Justification |
|---------------|---------------|---------------|
| Data Exposure | LOW | Multi-layer DLP with secret scanning |
| Prompt Injection | LOW | Layered guardrails + behavioral monitoring |
| Audit Tampering | VERY LOW | S3 Object Lock COMPLIANCE mode |
| Network Exfiltration | LOW | DNS + Network Firewall allowlisting |
| Code Integrity | VERY LOW | PR-only workflow with human review |
| Session Hijacking | LOW | Timeout + re-auth + recording |

**Overall Residual Risk: LOW**

The proposed architecture implements multiple overlapping controls that reduce risk to acceptable levels for enterprise deployment.

---

## Conditions of Approval

### Mandatory (Before Production)
1. Deploy Lakera Guard (commercial) for prompt injection defense
2. Configure S3 Object Lock in COMPLIANCE mode (not Governance)
3. Enable full session recording (not sampling)
4. Subscribe to Anthropic security advisories
5. Complete developer training module

### Recommended (Within 30 Days)
1. Configure LLM Guard with company-specific entity patterns
2. Deploy egress monitoring dashboard
3. Conduct IR tabletop exercise
4. Review and tune detection thresholds

### Ongoing
1. Monthly threshold review for first 90 days
2. Quarterly log recovery testing
3. Weekly blocked domain review for first 30 days

---

## Verdict

**CRBRS REVIEW - CYCLE 2 - APPROVED**

The Claude Code enterprise deployment architecture is approved for production implementation, subject to the conditions outlined above.

**Approval Summary:**
- Critical Findings: 0 (remediated)
- High Findings: 0 (remediated)
- Medium Findings: 6 (accepted with compensating controls)
- Low Findings: 3 (accepted)
- Residual Risk: LOW

---

**Approved: PALADIN, CRBRS Security Lead**
**Date: 2026-01-15**

---

**CRBRS REVIEW - CYCLE 2 - APPROVED**
