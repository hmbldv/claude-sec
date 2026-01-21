# CRBRS Security Review: Claude Code Enterprise Deployment

**Cycle:** 4
**Status:** Review Complete - APPROVED
**Review Date:** 2026-01-15
**Lead:** PALADIN | **Coordinator:** NEXUS

---

## Review Summary

Axiom has expanded the security scope to address critical operational considerations:

- **MCP Server Security** - Comprehensive framework for external data access
- **Docker/Container Security** - Container isolation with escape prevention
- **Shell Security (HISTCONTROL)** - Defense against audit evasion techniques
- **Security Domain Coverage** - NIST CSF 2.0 + Cyber AI Profile alignment

**Finding Status:**

| Severity | Previous (C3) | New (C4) | Status |
|----------|---------------|----------|--------|
| Critical | 0 | 0 | Maintained |
| High | 0 | 0 | Maintained |
| Medium | 6 | 8 | +2 new accepted |
| Low | 3 | 5 | +2 new accepted |
| **New Issues** | - | 0 | - |

**Verdict: APPROVED**

---

## MCP SERVER SECURITY REVIEW

### Assessment: APPROVED with Conditions

#### Option A vs Option B Decision

**CRBRS Decision:** Use **Option A (Exclusive managed-mcp.json)** for production deployments.

| Factor | Option A (Exclusive) | Option B (Policy) |
|--------|---------------------|-------------------|
| Control Level | HIGH | MEDIUM |
| Flexibility | LOW | HIGH |
| Shadow Server Risk | ELIMINATED | Mitigated |
| Audit Complexity | LOW | HIGH |
| Enterprise Fit | Preferred | Acceptable |

**Rationale:**
- Eliminates "shadow MCP server" risk entirely
- Pre-approved servers can be hardened and audited
- Credential injection via Vault/SSM prevents plaintext exposure
- Users cannot add arbitrary data connections

**Exception Process:** New MCP server requests require:
1. Business justification submitted to security
2. Security review of server code/configuration
3. Addition to managed-mcp.json via change control
4. Audit logging verification

#### Database Access Decision

**CRBRS Decision:** Read-only database access APPROVED with restrictions.

| Access Type | Decision | Conditions |
|-------------|----------|------------|
| Read-only (SELECT) | APPROVED | Query logging, rate limiting |
| Write (INSERT/UPDATE/DELETE) | DENIED | No exceptions |
| Schema modification | DENIED | No exceptions |
| Stored procedure execution | ASK | Case-by-case approval |

**Required Controls:**
1. **Query Logging:** All SQL statements logged with full context
2. **Rate Limiting:** Max 100 queries/minute, 10,000/hour
3. **Row Limits:** No query returns >10,000 rows without approval
4. **Column Masking:** PII columns masked at database level
5. **Read-Only User:** Database credentials must have read-only grants

**Data Classification Requirements:**

| Classification | MCP Access | Conditions |
|----------------|-----------|------------|
| Public | ALLOWED | Standard logging |
| Internal | ALLOWED | Enhanced logging, rate limiting |
| Confidential | RESTRICTED | Approval required, full audit |
| Restricted | DENIED | No MCP access |

#### MCP Audit Requirements: APPROVED

The proposed audit schema is acceptable:
- Session ID, user, timestamp
- MCP server and tool invoked
- Full parameter logging (with sensitive value masking)
- Result size/row count
- Latency metrics

**Additional Requirement:** MCP audit logs must flow to same Kinesis → S3 Object Lock pipeline as other Claude Code audit data.

---

## DOCKER/CONTAINER SECURITY REVIEW

### Assessment: APPROVED with Conditions

#### Docker Requirement Decision

**CRBRS Decision:** Docker access APPROVED with strict restrictions.

**Rationale:** Development workflows legitimately require:
- Running tests in containerized environments
- Building container images
- Local development matching production

#### Docker Permission Model: APPROVED

| Category | Decision | Rationale |
|----------|----------|-----------|
| **Deny privileged mode** | APPROVED | Prevents container escape |
| **Deny host mounts** | APPROVED | Prevents data access |
| **Deny host network** | APPROVED | Prevents network bypass |
| **Allow read-only ops** | APPROVED | Safe inspection |
| **Ask for run/exec** | APPROVED | Human approval required |

#### Additional Docker Controls Required

1. **Registry Restriction:**
```json
{
  "permissions": {
    "deny": [
      "Bash(docker:pull:docker.io/*)",
      "Bash(docker:pull:gcr.io/*)",
      "Bash(docker:pull:ghcr.io/*)"
    ],
    "allow": [
      "Bash(docker:pull:${ECR_REGISTRY}/*)"
    ]
  }
}
```

2. **Resource Limits:** All Claude-initiated containers must have:
   - `--memory=2g`
   - `--cpus=2`
   - `--pids-limit=100`

3. **Network Isolation:** Require `--network=claude-isolated` for all containers

4. **No Volume Mounts Outside Project:**
```json
{
  "deny": [
    "Bash(docker:run:*:-v:/*)",
    "Bash(docker:run:*:--mount:*)"
  ],
  "allow": [
    "Bash(docker:run:*:-v:${PROJECT_DIR}/*)"
  ]
}
```

#### DevContainer Mode: CONDITIONAL

**CRBRS Decision:** DevContainer mode acceptable ONLY with:
- `disableBypassPermissionsMode: "disable"` enforced
- Network firewall rules applied to DevContainer host
- No credential passthrough from host

**DENIED:** `--dangerously-skip-permissions` under all circumstances.

---

## SHELL SECURITY (HISTCONTROL) REVIEW

### Assessment: APPROVED

#### HISTCONTROL Deny Rules: APPROVED

All proposed deny rules for history evasion are approved:
- `unset HISTFILE/HISTSIZE/HISTFILESIZE`
- `export HISTCONTROL=*`
- `history -c/-d`
- History file deletion/truncation

**CRBRS Position:** These rules provide defense at the Claude Code permission layer.

#### Defense in Depth Requirements: APPROVED

| Layer | Control | Status |
|-------|---------|--------|
| **Layer 1: Claude Code** | managed-settings.json deny rules | APPROVED |
| **Layer 2: OS Profile** | `/etc/profile.d/history-security.sh` | REQUIRED |
| **Layer 3: Filesystem** | `chattr +a` on history files | RECOMMENDED |
| **Layer 4: Kernel** | auditd execve monitoring | REQUIRED |
| **Layer 5: Syslog** | Real-time command forwarding | RECOMMENDED |

**Minimum Requirement:** Layers 1, 2, and 4 are MANDATORY.

#### Audit Tampering Protection: APPROVED

Additional deny rules for audit tampering are approved:
- `auditctl -D/-e 0`
- `service/systemctl stop auditd`
- `/var/log/audit/*` deletion

**CRBRS Note:** The EC2 instance should have auditd configured as a system service with automatic restart and alerting on stop attempts.

---

## SECURITY DOMAIN COVERAGE REVIEW

### NIST CSF 2.0 Alignment: APPROVED

Axiom's coverage audit demonstrates comprehensive alignment with CSF 2.0 core functions.

#### Gaps Identified - Required Remediation

| Gap | Priority | CRBRS Decision |
|-----|----------|----------------|
| **Developer Training** | HIGH | MANDATORY condition of approval |
| **IR Playbook** | HIGH | MANDATORY within 30 days |
| **Role Definition** | MEDIUM | Document before production |
| **Communication Plan** | MEDIUM | Document before production |
| **Reasoning Traces** | LOW | Deferred to Phase 2 |

### Developer Training Requirement

**CRBRS Decision:** MANDATORY condition of approval.

Training must cover:
1. Claude Code security controls and rationale
2. Prohibited operations (what NOT to ask Claude to do)
3. MCP server usage policies
4. Incident reporting procedures
5. Social engineering awareness (prompt injection)

**Format:** Annual certification with acknowledgment.

### Incident Response Playbook Scenarios

**CRBRS Decision:** The following scenarios MUST be covered:

| Scenario | Response Actions |
|----------|------------------|
| **Suspected data exfiltration** | Session kill, instance isolation, log preservation |
| **Prompt injection detected** | Session kill, alert SOC, review conversation |
| **Unauthorized command attempt** | Log review, user notification, escalation |
| **Anomalous API patterns** | Rate limiting, session review, SOC alert |
| **Container escape attempt** | Instance termination, forensic snapshot |
| **MCP server compromise** | Credential rotation, server disable, audit |

**Timeline:** Playbook must be completed within 30 days of production deployment.

---

## UPDATED CONDITIONS OF APPROVAL

### Mandatory (Before Production)

All previous conditions remain, plus:

1. **MCP Server Policy**
   - Use managed-mcp.json (Option A) for all deployments
   - No user-added MCP servers permitted
   - Change control process for new servers

2. **Docker Restrictions**
   - Registry restricted to approved ECR
   - Resource limits enforced
   - Network isolation required
   - No privileged mode under any circumstances

3. **Shell Security**
   - Deploy `/etc/profile.d/history-security.sh`
   - Configure auditd with execve monitoring
   - History file protection (chattr +a recommended)

4. **Developer Training**
   - Complete security training before access
   - Annual recertification required

5. **Database Access (if MCP enabled)**
   - Read-only grants only
   - Query logging mandatory
   - Rate limiting configured

### Mandatory (Within 30 Days)

1. **IR Playbook**
   - Claude-specific scenarios documented
   - Tabletop exercise completed
   - SOC integration verified

2. **Role Documentation**
   - Claude operator vs user vs admin defined
   - Access provisioning process documented

3. **Communication Plan**
   - Escalation procedures defined
   - Notification templates created

### Recommended (Within 90 Days)

1. Syslog forwarding for real-time command logging
2. Extended thinking trace logging for audit
3. Automated anomaly detection tuning

---

## NEW FINDINGS (Cycle 4)

### MED-07: MCP Server Governance Gap
**Severity:** MEDIUM
**Status:** ACCEPTED with compensating control

**Finding:** MCP servers can expose arbitrary datasets to Claude.

**Compensating Control:** Option A (managed-mcp.json) eliminates user-added servers. All servers pre-approved via change control.

### MED-08: Docker Escape Potential
**Severity:** MEDIUM
**Status:** ACCEPTED with compensating control

**Finding:** Docker access creates potential container escape vectors.

**Compensating Control:** Comprehensive deny list for privileged flags, host mounts, and network modes. Human approval required for all docker run/exec.

### LOW-04: HISTCONTROL Bypass at OS Level
**Severity:** LOW
**Status:** ACCEPTED with compensating control

**Finding:** Claude Code deny rules can be bypassed if OS history settings not hardened.

**Compensating Control:** Mandatory `/etc/profile.d/history-security.sh` deployment + auditd monitoring.

### LOW-05: DevContainer Credential Risk
**Severity:** LOW
**Status:** ACCEPTED with compensating control

**Finding:** DevContainers may have credential access if not properly isolated.

**Compensating Control:** `disableBypassPermissionsMode: "disable"` mandatory. Credential passthrough prohibited.

---

## RESIDUAL RISK ASSESSMENT (Updated)

| Risk Category | C3 | C4 | Change | Justification |
|---------------|----|----|--------|---------------|
| Data Exposure | LOW | LOW | - | MCP controls + DLP |
| Prompt Injection | LOW | LOW | - | Lakera Guard unchanged |
| Audit Tampering | VERY LOW | VERY LOW | - | S3 Object Lock + auditd |
| Network Exfiltration | VERY LOW | VERY LOW | - | Network controls unchanged |
| Code Integrity | VERY LOW | VERY LOW | - | PR workflow unchanged |
| Session Hijacking | VERY LOW | VERY LOW | - | SSM unchanged |
| Command Injection | LOW | LOW | - | Deny patterns expanded |
| **MCP Data Access** | N/A | LOW | NEW | managed-mcp.json + audit |
| **Container Escape** | N/A | LOW | NEW | Docker restrictions |
| **Audit Evasion** | N/A | VERY LOW | NEW | Multi-layer defense |

**Overall Residual Risk: LOW** (Maintained)

---

## VERDICT

**CRBRS REVIEW - CYCLE 4 - APPROVED**

The expanded security scope has been thoroughly addressed:

1. **MCP Security:** Option A (exclusive control) eliminates shadow server risk
2. **Docker Security:** Comprehensive restrictions prevent escape vectors
3. **Shell Security:** Multi-layer HISTCONTROL defense approved
4. **Domain Coverage:** NIST CSF 2.0 alignment verified, gaps documented

**Summary of Cycle 4 Approvals:**
- MCP managed-mcp.json exclusive control: APPROVED
- Read-only database access via MCP: APPROVED with conditions
- Docker with restrictions: APPROVED
- HISTCONTROL deny rules + auditd: APPROVED
- Developer training requirement: APPROVED (mandatory)
- IR playbook requirement: APPROVED (30-day deadline)

---

**Approved: PALADIN, CRBRS Security Lead**
**Date: 2026-01-15**

---

**CRBRS REVIEW - CYCLE 4 - APPROVED**
