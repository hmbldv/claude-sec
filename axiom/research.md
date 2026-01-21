# Axiom Research: Claude Code Enterprise Security

**Cycle:** 4
**Status:** Ready for Security Review
**Last Updated:** 2026-01-15
**Lead:** Thesis | **Coordinator:** Proof

---

## Executive Summary

This cycle addresses expanded security considerations beyond the core architecture:

1. **MCP Server Security** - Model Context Protocol server integration with external datasets
2. **Docker/Container Security** - Container isolation and security controls
3. **Shell Security** - HISTCONTROL and bash audit evasion mitigations
4. **Security Domain Coverage** - NIST CSF 2.0 alignment and completeness audit

All prior architectural decisions from Cycle 3 remain in effect:
- AWS-only deployment (mandatory)
- Command restriction analysis with conditional allows
- Cloud service integration (GitLab, Jira, package registries)

---

## TABLE OF CONTENTS

1. [Architecture Summary (Unchanged)](#architecture-summary)
2. [MCP Server Security (NEW)](#mcp-server-security)
3. [Docker/Container Security (NEW)](#dockercontainer-security)
4. [Shell Security - HISTCONTROL (NEW)](#shell-security---histcontrol)
5. [Security Domain Coverage Audit (NEW)](#security-domain-coverage-audit)
6. [Updated Managed-Settings.json](#updated-managed-settingsjson)
7. [Comprehensive Security Controls Matrix](#comprehensive-security-controls-matrix)
8. [Open Questions for CRBRS](#open-questions-for-crbrs)

---

## ARCHITECTURE SUMMARY

### Core Architecture (Unchanged from Cycle 3)

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                            AWS ACCOUNT                                          │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │                         CLAUDE CODE VPC                                   │ │
│  │  ┌─────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    PRIVATE SUBNET                                    │ │ │
│  │  │  ┌───────────────────────────────────────────────────────────────┐ │ │ │
│  │  │  │           EC2: CLAUDE CODE INSTANCE (Linux)                   │ │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │ │ │ │
│  │  │  │  │ Claude Code │  │ bubblewrap  │  │ managed-settings   │   │ │ │ │
│  │  │  │  │ CLI         │  │ sandbox     │  │ .json              │   │ │ │ │
│  │  │  │  └─────────────┘  └─────────────┘  └────────────────────┘   │ │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │ │ │ │
│  │  │  │  │ MCP Servers │  │ Docker      │  │ auditd + syslog    │   │ │ │ │
│  │  │  │  │ (managed)   │  │ (isolated)  │  │                    │   │ │ │ │
│  │  │  │  └─────────────┘  └─────────────┘  └────────────────────┘   │ │ │ │
│  │  │  │  Access: AWS SSM Session Manager                            │ │ │ │
│  │  │  └───────────────────────────────────────────────────────────────┘ │ │ │
│  │  └──────────────────────────────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    NETWORK CONTROLS                                  │ │ │
│  │  │  Route 53 DNS Firewall ──► AWS Network Firewall ──► NAT Gateway    │ │ │
│  │  └──────────────────────────────────────────────────────────────────────┘ │ │
│  │  ┌──────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    VPC ENDPOINTS (PrivateLink)                       │ │ │
│  │  │  Bedrock Runtime │ SSM │ S3 │ CloudWatch │ RDS/DynamoDB (if needed)│ │ │
│  │  └──────────────────────────────────────────────────────────────────────┘ │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## MCP SERVER SECURITY

### What is MCP?

The Model Context Protocol (MCP) allows Claude Code to connect to external data sources and tools:
- **Databases** (PostgreSQL, MySQL, DynamoDB)
- **APIs** (REST, GraphQL endpoints)
- **File systems** (beyond sandbox)
- **Third-party services** (Slack, GitHub, Jira)

### Security Risks

| Risk | Severity | Description |
|------|----------|-------------|
| **Unauthorized Data Access** | CRITICAL | MCP servers can expose databases, file systems, and APIs to Claude |
| **Shadow MCP Servers** | HIGH | Unapproved servers deployed without governance bypass security |
| **Credential Exposure** | HIGH | API keys in plaintext config files |
| **Data Exfiltration** | HIGH | Claude can read from sources and potentially leak via prompts |
| **Authentication Gaps** | HIGH | Research shows 2000+ public MCP servers lack authentication |
| **Privilege Escalation** | MEDIUM | MCP tools may have broader access than intended |

### Industry Research Findings

> **Knostic Research (July 2025):** Scanning of nearly 2,000 MCP servers found ALL verified servers lacked any form of authentication. Anyone could access tool listings and potentially exfiltrate data.

> **June 2025 MCP Spec Update:** OAuth Resource Server classification addresses token theft but implementation remains inconsistent.

### Enterprise MCP Security Requirements

| Requirement | Implementation |
|-------------|----------------|
| **Centralized Authentication** | SSO integration with enterprise IdP (Okta, Entra ID) |
| **Role-Based Access Control** | User/team/org level permissions per MCP server |
| **Comprehensive Audit** | Log all MCP tool invocations with full context |
| **Credential Management** | Encrypted storage, automatic rotation |
| **Approval Workflow** | New MCP servers require security review |

### MCP Configuration Architecture

Claude Code supports two control models for MCP servers:

#### Option A: Exclusive Control (Recommended for High Security)

Use `managed-mcp.json` to deploy a fixed set of MCP servers users cannot modify:

```json
// /etc/claude-code/managed-mcp.json (Linux)
{
  "mcpServers": {
    "postgres-readonly": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "POSTGRESQL_URL": "postgresql://readonly:${VAULT_TOKEN}@db.internal:5432/app?sslmode=require"
      }
    },
    "internal-api": {
      "command": "node",
      "args": ["/opt/mcp-servers/internal-api/index.js"],
      "env": {
        "API_ENDPOINT": "https://api.internal.company.com",
        "AUTH_METHOD": "iam-role"
      }
    }
  }
}
```

**Key Properties:**
- Users CANNOT add MCP servers via `claude mcp add`
- All servers pre-approved and hardened
- Credentials injected via Vault/SSM Parameter Store

#### Option B: Policy-Based Control

Allow user-added servers with strict allowlist/denylist:

```json
// managed-settings.json
{
  "mcp": {
    "defaultPolicy": "deny",
    "allowlist": [
      { "name": "internal-*" },
      { "url": "https://mcp.company.com/*" }
    ],
    "denylist": [
      { "name": "*" },
      { "command": "npx" },
      { "url": "http://*" }
    ]
  }
}
```

**Precedence:** Denylist ALWAYS wins over allowlist.

### MCP Server Categories and Recommendations

| Category | Risk Level | Recommendation |
|----------|-----------|----------------|
| **Database (Read-Only)** | MEDIUM | Allow with audit logging |
| **Database (Write)** | HIGH | Deny or require explicit approval per operation |
| **Internal APIs** | MEDIUM | Allow with authentication, audit |
| **External APIs** | HIGH | Case-by-case approval |
| **File System** | CRITICAL | Deny external; restrict to project directory |
| **Cloud Providers** | HIGH | IAM role-based, scoped permissions |

### MCP Audit Requirements

Every MCP tool invocation must log:

```json
{
  "timestamp": "2026-01-15T10:30:00Z",
  "session_id": "sess_abc123",
  "user": "developer@company.com",
  "mcp_server": "postgres-readonly",
  "tool": "query",
  "parameters": {
    "sql": "SELECT * FROM users WHERE id = 123"
  },
  "result_rows": 1,
  "result_bytes": 256,
  "latency_ms": 45
}
```

### Dataset Access Controls

When Claude accesses datasets via MCP:

| Control | Implementation |
|---------|----------------|
| **Data Classification** | Tag datasets by sensitivity (Public/Internal/Confidential/Restricted) |
| **Query Filtering** | Prevent SELECT * on sensitive tables |
| **Row-Level Security** | Database enforces user context |
| **Column Masking** | Mask PII/sensitive columns |
| **Query Audit** | Log all queries with full SQL |
| **Rate Limiting** | Prevent bulk data extraction |
| **Read-Only Default** | No INSERT/UPDATE/DELETE without explicit approval |

---

## DOCKER/CONTAINER SECURITY

### Docker Access Scenarios

Claude Code may need Docker access for:
- Running test environments
- Building container images
- Executing isolated commands
- Development container workflows

### Security Risks

| Risk | Severity | Description |
|------|----------|-------------|
| **Container Escape** | CRITICAL | Breakout to host system |
| **Privileged Mode** | CRITICAL | Full host access if enabled |
| **Host Filesystem Access** | HIGH | Volume mounts expose host data |
| **Network Namespace** | HIGH | Container could access internal networks |
| **Image Supply Chain** | HIGH | Malicious base images |
| **Credential in Images** | HIGH | Secrets baked into layers |
| **Resource Exhaustion** | MEDIUM | DoS via container resource abuse |

### Docker Permission Model

```json
{
  "permissions": {
    "deny": [
      "--- DOCKER PRIVILEGED/ESCAPE VECTORS ---",
      "Bash(docker:run:--privileged:*)",
      "Bash(docker:run:-v:/:/host:*)",
      "Bash(docker:run:--pid=host:*)",
      "Bash(docker:run:--network=host:*)",
      "Bash(docker:run:--cap-add=SYS_ADMIN:*)",
      "Bash(docker:run:--cap-add=ALL:*)",
      "Bash(docker:run:--security-opt=apparmor=unconfined:*)",
      "Bash(docker:run:--security-opt=seccomp=unconfined:*)",

      "--- DOCKER DANGEROUS OPERATIONS ---",
      "Bash(docker:rm:-f:*)",
      "Bash(docker:system:prune:*)",
      "Bash(docker:volume:rm:*)",
      "Bash(docker:network:rm:*)",

      "--- DOCKER HOST MOUNTS ---",
      "Bash(docker:run:*:-v:/etc/*)",
      "Bash(docker:run:*:-v:/var/*)",
      "Bash(docker:run:*:-v:/root/*)",
      "Bash(docker:run:*:-v:/home/*)",
      "Bash(docker:run:*:--mount:type=bind,source=/*)"
    ],

    "allow": [
      "--- DOCKER READ-ONLY OPERATIONS ---",
      "Bash(docker:ps:*)",
      "Bash(docker:images:*)",
      "Bash(docker:logs:*)",
      "Bash(docker:inspect:*)",
      "Bash(docker:stats:*)"
    ],

    "ask": [
      "--- DOCKER REQUIRES APPROVAL ---",
      "Bash(docker:build:*)",
      "Bash(docker:run:*)",
      "Bash(docker:exec:*)",
      "Bash(docker:pull:*)",
      "Bash(docker:push:*)",
      "Bash(docker:compose:*)"
    ]
  }
}
```

### DevContainer Security

Claude Code's official DevContainer provides isolation but has known limitations:

> **Warning:** While the devcontainer provides substantial protections, when executed with `--dangerously-skip-permissions`, devcontainers don't prevent a malicious project from exfiltrating anything accessible in the devcontainer including Claude Code credentials.

**Enterprise Recommendation:**
- NEVER use `--dangerously-skip-permissions` in production
- Use `managed-settings.json` to disable this mode entirely

```json
{
  "permissions": {
    "disableBypassPermissionsMode": "disable"
  }
}
```

### Container Network Isolation

If Docker is enabled, enforce network restrictions:

```bash
# Create isolated Docker network
docker network create --internal claude-isolated

# All Claude-initiated containers must use isolated network
docker run --network=claude-isolated ...
```

**Alternative:** Use AWS Fargate for container workloads with VPC-level network controls.

### Container Image Security

| Control | Implementation |
|---------|----------------|
| **Registry Allowlist** | Only pull from approved registries |
| **Image Scanning** | Trivy/Snyk scan before use |
| **Base Image Policy** | Only approved base images |
| **No Build from URL** | Block `docker build` with remote context |
| **Read-Only Root** | Force `--read-only` flag |

```json
{
  "permissions": {
    "deny": [
      "Bash(docker:build:http://*)",
      "Bash(docker:build:https://*)",
      "Bash(docker:pull:*:*)",
      "Bash(docker:run:*:*:*)"
    ],
    "allow": [
      "Bash(docker:pull:ecr.aws/approved-registry/*)",
      "Bash(docker:run:--read-only:*:ecr.aws/approved-registry/*)"
    ]
  }
}
```

---

## SHELL SECURITY - HISTCONTROL

### The HISTCONTROL Threat

HISTCONTROL is a bash environment variable that controls command history logging. Adversaries exploit it to evade detection.

**MITRE ATT&CK Reference:** [T1562.003 - Impair Command History Logging](https://attack.mitre.org/techniques/T1562/003/)

### Attack Techniques

| Technique | Command | Impact |
|-----------|---------|--------|
| **Disable History File** | `unset HISTFILE` | No commands logged |
| **Zero History Size** | `export HISTFILESIZE=0` | History truncated |
| **Ignore Spaces** | `export HISTCONTROL=ignorespace` | ` rm evidence` not logged |
| **Ignore All** | `export HISTCONTROL=ignoreboth` | Duplicates and spaces hidden |
| **Redirect History** | `export HISTFILE=/dev/null` | Commands sent to void |
| **Delete History** | `rm ~/.bash_history` | Evidence destruction |

### Real-World APT Examples

| Actor | Technique |
|-------|-----------|
| **APT38** | Prepended spaces to all terminal commands |
| **BPFDoor** | Set `HISTFILE=/dev/null` |
| **Medusa Group** | Deleted PowerShell history via `Remove-Item` |

### Hardening Measures

#### 1. Lock History Variables (System-Wide)

Add to `/etc/profile.d/history-security.sh`:

```bash
#!/bin/bash
# Enterprise History Security Configuration

# Force history recording
export HISTFILE="$HOME/.bash_history"
export HISTFILESIZE=10000
export HISTSIZE=10000
export HISTCONTROL=""
export HISTIGNORE=""
export HISTTIMEFORMAT="%F %T "

# Make variables read-only (cannot be modified by user)
readonly HISTFILE
readonly HISTFILESIZE
readonly HISTSIZE
readonly HISTCONTROL
readonly HISTIGNORE
readonly HISTTIMEFORMAT

# Append immediately rather than on session close
shopt -s histappend
export PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
```

#### 2. Append-Only History File

```bash
# Make history file append-only (even user cannot delete)
chattr +a /home/*/.bash_history
```

**Note:** Only root can remove the append-only attribute.

#### 3. Stream to Syslog (Defense in Depth)

Configure bash to forward commands to syslog in real-time:

```bash
# /etc/profile.d/bash-audit.sh
function log_command {
    declare COMMAND
    COMMAND=$(fc -ln -0)
    logger -p local1.notice -t bash -i -- "${USER}:$(tty):${COMMAND}"
}
trap log_command DEBUG
```

#### 4. Use auditd (Kernel-Level)

auditd provides tamper-resistant logging at the kernel level:

```bash
# /etc/audit/rules.d/claude-audit.rules

# Monitor execve system calls (all command execution)
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution

# Monitor history file modifications
-w /home -p wa -k history_modification
-w /root/.bash_history -p wa -k root_history

# Monitor attempts to modify audit configuration
-w /etc/audit/ -p wa -k audit_config
-w /var/log/audit/ -p wa -k audit_logs
```

#### 5. Detect HISTCONTROL Manipulation

Monitor for suspicious environment variable changes:

```bash
# auditd rule to detect HISTCONTROL modification
-w /etc/environment -p wa -k env_modification
-w /etc/profile -p wa -k profile_modification
-w /etc/profile.d/ -p wa -k profiled_modification
```

### Detection Rules

| Detection | Method |
|-----------|--------|
| Missing history | Alert if session has commands but no history entries |
| HISTCONTROL changes | auditd rule on environment modification |
| History deletion | File integrity monitoring on .bash_history |
| Suspicious patterns | Correlate commands vs logged history |

### Claude Code Integration

Add HISTCONTROL protections to managed-settings.json:

```json
{
  "permissions": {
    "deny": [
      "--- HISTORY EVASION ---",
      "Bash(unset:HISTFILE)",
      "Bash(unset:HISTSIZE)",
      "Bash(unset:HISTFILESIZE)",
      "Bash(export:HISTFILE=*)",
      "Bash(export:HISTSIZE=0)",
      "Bash(export:HISTFILESIZE=0)",
      "Bash(export:HISTCONTROL=*)",
      "Bash(export:HISTIGNORE=*)",
      "Bash(set:+o:history)",
      "Bash(shopt:-u:histappend)",
      "Bash(history:-c)",
      "Bash(history:-d:*)",
      "Bash(rm:*/.bash_history)",
      "Bash(rm:*/.zsh_history)",
      "Bash(truncate:*/.bash_history)",
      "Bash(>:*/.bash_history)",
      "Bash(cat:/dev/null:>:*/.bash_history)"
    ]
  }
}
```

---

## SECURITY DOMAIN COVERAGE AUDIT

### NIST CSF 2.0 + Cyber AI Profile Alignment

The NIST Cybersecurity Framework 2.0 with the December 2025 Cyber AI Profile provides comprehensive security domain coverage. Below is our alignment assessment.

### CSF Core Functions Coverage

#### GOVERN (GV)

| Subcategory | Coverage | Implementation |
|-------------|----------|----------------|
| GV.OC Organizational Context | ✅ | AWS-only deployment mandate |
| GV.RM Risk Management | ✅ | Residual risk assessment per cycle |
| GV.SC Supply Chain | ✅ | Artifact proxy, package scanning |
| GV.PO Policy | ✅ | managed-settings.json enforcement |
| GV.RR Roles/Responsibilities | ⚠️ | Add: Define Claude operator vs user roles |

#### IDENTIFY (ID)

| Subcategory | Coverage | Implementation |
|-------------|----------|----------------|
| ID.AM Asset Management | ✅ | EC2 instance inventory, MCP server registry |
| ID.RA Risk Assessment | ✅ | Finding severity classification |
| ID.IM Improvement | ✅ | Iterative review cycles |

#### PROTECT (PR)

| Subcategory | Coverage | Implementation |
|-------------|----------|----------------|
| PR.AA Identity/Access | ✅ | IAM Identity Center, SSM, MFA |
| PR.AT Awareness/Training | ⚠️ | Add: Developer security training requirement |
| PR.DS Data Security | ✅ | DLP, encryption, network controls |
| PR.PS Platform Security | ✅ | bubblewrap sandbox, managed-settings |
| PR.IR Resilience | ✅ | Ephemeral instances, backup/recovery |

#### DETECT (DE)

| Subcategory | Coverage | Implementation |
|-------------|----------|----------------|
| DE.CM Continuous Monitoring | ✅ | CloudWatch, Kinesis, SIEM |
| DE.AE Adverse Event Analysis | ✅ | Lakera Guard, anomaly detection |

#### RESPOND (RS)

| Subcategory | Coverage | Implementation |
|-------------|----------|----------------|
| RS.MA Incident Management | ⚠️ | Add: Claude-specific IR playbook |
| RS.AN Incident Analysis | ✅ | Audit log correlation, session replay |
| RS.MI Mitigation | ✅ | Instance termination, session kill |
| RS.CO Communication | ⚠️ | Add: Notification procedures |

#### RECOVER (RC)

| Subcategory | Coverage | Implementation |
|-------------|----------|----------------|
| RC.RP Recovery Planning | ✅ | AMI snapshots, infrastructure as code |
| RC.CO Communications | ⚠️ | Add: Post-incident communication plan |

### Cyber AI Profile Specific Considerations

| AI-Specific Domain | Coverage | Implementation |
|--------------------|----------|----------------|
| **Model Integrity** | ✅ | Bedrock managed models, no custom weights |
| **Prompt Injection Defense** | ✅ | Lakera Guard, input validation |
| **Output Validation** | ✅ | DLP on outputs, Lakera output scanning |
| **AI Explainability** | ⚠️ | Add: Log reasoning traces for audit |
| **AI Bias/Fairness** | N/A | Not applicable to code generation |
| **AI Supply Chain** | ✅ | Bedrock-only model access |

### Coverage Gaps Identified

| Gap | Priority | Proposed Remediation |
|-----|----------|---------------------|
| **Developer Training** | HIGH | Mandatory security training before Claude access |
| **IR Playbook** | HIGH | Create Claude-specific incident response procedures |
| **Role Definition** | MEDIUM | Document Claude operator vs user vs admin roles |
| **Communication Plan** | MEDIUM | Define escalation and notification procedures |
| **Reasoning Traces** | LOW | Enable extended thinking logging for audit |

---

## COMPREHENSIVE SECURITY CONTROLS MATRIX

### Security Domains Checklist

| Domain | Status | Key Controls |
|--------|--------|--------------|
| **Access Control** | ✅ | IAM Identity Center, SSM, MFA, session management |
| **Audit & Accountability** | ✅ | Kinesis, S3 Object Lock, CloudTrail, auditd |
| **Configuration Management** | ✅ | managed-settings.json, managed-mcp.json, IaC |
| **Contingency Planning** | ✅ | Ephemeral instances, AMI backups, multi-AZ |
| **Identification & Authentication** | ✅ | SSO, MFA, IAM roles, no long-term credentials |
| **Incident Response** | ⚠️ | Add: Claude-specific IR playbook |
| **Maintenance** | ✅ | Automated patching, instance rotation |
| **Media Protection** | ✅ | EBS encryption, no persistent local data |
| **Physical Protection** | ✅ | AWS data center controls (inherited) |
| **Personnel Security** | ⚠️ | Add: Developer training requirement |
| **Risk Assessment** | ✅ | CRBRS review cycles, finding tracking |
| **Security Assessment** | ✅ | Iterative approval process |
| **System/Communications Protection** | ✅ | VPC isolation, Network Firewall, DNS Firewall |
| **System/Information Integrity** | ✅ | DLP, prompt injection defense, sandbox |
| **Supply Chain** | ✅ | Artifact proxy, package scanning, lockfiles |
| **Privacy** | ✅ | No PII processing, data minimization |
| **MCP/Extension Security** | ✅ | managed-mcp.json, allowlists, audit |
| **Container Security** | ✅ | Docker restrictions, no privileged mode |
| **Shell Security** | ✅ | HISTCONTROL hardening, auditd |

---

## UPDATED MANAGED-SETTINGS.JSON

Complete configuration incorporating all security controls:

```json
{
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": 1,
    "HTTPS_PROXY": "http://llm-guard-proxy.internal:8080",
    "NO_PROXY": "169.254.169.254,localhost"
  },

  "cleanupPeriodDays": 1,

  "session": {
    "maxDurationMinutes": 480,
    "idleTimeoutMinutes": 30,
    "requireReauthForSensitiveOps": true,
    "maxConcurrentSessions": 1
  },

  "permissions": {
    "disableBypassPermissionsMode": "disable",
    "defaultMode": "default",

    "deny": [
      "### FILE ACCESS RESTRICTIONS ###",
      "Read(**/.env)",
      "Read(**/.env.*)",
      "Read(**/*.pem)",
      "Read(**/*.key)",
      "Read(**/*.p12)",
      "Read(**/*.pfx)",
      "Read(**/credentials*)",
      "Read(**/secrets*)",
      "Read(**/.aws/*)",
      "Read(**/.ssh/*)",
      "Read(**/.gnupg/*)",

      "### PRIVILEGE ESCALATION ###",
      "Bash(sudo:*)",
      "Bash(su:*)",
      "Bash(chmod:777:*)",
      "Bash(chmod:666:*)",
      "Bash(chmod:-R:777:*)",
      "Bash(chown:-R:*:*:/*)",
      "Bash(setcap:*)",
      "Bash(chroot:*)",

      "### COVERT CHANNELS ###",
      "Bash(nc:*)",
      "Bash(ncat:*)",
      "Bash(netcat:*)",
      "Bash(socat:*)",
      "Bash(nmap:*)",
      "Bash(masscan:*)",

      "### DESTRUCTIVE COMMANDS ###",
      "Bash(rm:-rf:/*)",
      "Bash(rm:-rf:~/*)",
      "Bash(rm:-rf:.:*)",
      "Bash(rm:-rf:../*)",
      "Bash(mkfs:*)",
      "Bash(dd:if=*:of=/dev/*)",
      "Bash(shred:*)",
      "Bash(wipefs:*)",

      "### DATA EXFILTRATION (curl) ###",
      "Bash(curl:-o:*)",
      "Bash(curl:--output:*)",
      "Bash(curl:-O:*)",
      "Bash(curl:*:|:sh)",
      "Bash(curl:*:|:bash)",
      "Bash(curl:-X:POST:*)",
      "Bash(curl:--data:*)",
      "Bash(curl:-d:*)",
      "Bash(curl:-F:*)",
      "Bash(curl:--upload-file:*)",

      "### DATA EXFILTRATION (wget) ###",
      "Bash(wget:-r:*)",
      "Bash(wget:--recursive:*)",
      "Bash(wget:-b:*)",
      "Bash(wget:--background:*)",
      "Bash(wget:--post-data:*)",
      "Bash(wget:--post-file:*)",
      "Bash(wget:*:|:sh)",
      "Bash(wget:*:|:bash)",

      "### SSH TUNNELING ###",
      "Bash(ssh:-D:*)",
      "Bash(ssh:-R:*)",
      "Bash(ssh:-L:*)",
      "Bash(ssh:-w:*)",
      "Bash(ssh:-N:*)",

      "### BULK FILE TRANSFER ###",
      "Bash(scp:*)",
      "Bash(rsync:*)",
      "Bash(ftp:*)",
      "Bash(sftp:*)",

      "### GIT DANGEROUS ###",
      "Bash(git:push:--force:*)",
      "Bash(git:push:-f:*)",
      "Bash(git:commit:--no-verify:*)",

      "### DOCKER ESCAPE VECTORS ###",
      "Bash(docker:run:--privileged:*)",
      "Bash(docker:run:-v:/:/host:*)",
      "Bash(docker:run:--pid=host:*)",
      "Bash(docker:run:--network=host:*)",
      "Bash(docker:run:--cap-add=SYS_ADMIN:*)",
      "Bash(docker:run:--cap-add=ALL:*)",
      "Bash(docker:run:--security-opt=apparmor=unconfined:*)",
      "Bash(docker:run:--security-opt=seccomp=unconfined:*)",
      "Bash(docker:run:*:-v:/etc/*)",
      "Bash(docker:run:*:-v:/var/*)",
      "Bash(docker:run:*:-v:/root/*)",
      "Bash(docker:run:*:-v:/home/*)",

      "### HISTORY EVASION (HISTCONTROL) ###",
      "Bash(unset:HISTFILE)",
      "Bash(unset:HISTSIZE)",
      "Bash(unset:HISTFILESIZE)",
      "Bash(export:HISTFILE=*)",
      "Bash(export:HISTSIZE=0)",
      "Bash(export:HISTFILESIZE=0)",
      "Bash(export:HISTCONTROL=*)",
      "Bash(export:HISTIGNORE=*)",
      "Bash(set:+o:history)",
      "Bash(shopt:-u:histappend)",
      "Bash(history:-c)",
      "Bash(history:-d:*)",
      "Bash(rm:*/.bash_history)",
      "Bash(rm:*/.zsh_history)",
      "Bash(truncate:*history*)",

      "### AUDIT TAMPERING ###",
      "Bash(auditctl:-D)",
      "Bash(auditctl:-e:0)",
      "Bash(service:auditd:stop)",
      "Bash(systemctl:stop:auditd)",
      "Bash(rm:/var/log/audit/*)",
      "Bash(truncate:/var/log/*)"
    ],

    "allow": [
      "### FILE OPERATIONS ###",
      "Read(*)",
      "Glob(*)",
      "Grep(*)",

      "### GIT (READ) ###",
      "Bash(git:status:*)",
      "Bash(git:diff:*)",
      "Bash(git:log:*)",
      "Bash(git:branch:*)",
      "Bash(git:show:*)",
      "Bash(git:blame:*)",

      "### GIT (WRITE - LOCAL) ###",
      "Bash(git:checkout:*)",
      "Bash(git:add:*)",
      "Bash(git:commit:*)",
      "Bash(git:stash:*)",

      "### BUILD TOOLS ###",
      "Bash(npm:*)",
      "Bash(npx:*)",
      "Bash(node:*)",
      "Bash(yarn:*)",
      "Bash(pnpm:*)",
      "Bash(python:*)",
      "Bash(python3:*)",
      "Bash(pip:*)",
      "Bash(pip3:*)",
      "Bash(pytest:*)",
      "Bash(poetry:*)",
      "Bash(make:*)",
      "Bash(cargo:*)",
      "Bash(go:*)",
      "Bash(gradle:*)",
      "Bash(mvn:*)",
      "Bash(dotnet:*)",

      "### SAFE CURL (READ-ONLY) ###",
      "Bash(curl:-I:*)",
      "Bash(curl:--head:*)",
      "Bash(curl:-s:https://registry.npmjs.org/*)",
      "Bash(curl:-s:https://pypi.org/*)",
      "Bash(curl:-s:https://api.github.com/*)",

      "### SAFE WGET ###",
      "Bash(wget:--spider:*)",
      "Bash(wget:-q:--spider:*)",

      "### SYSTEM INFO ###",
      "Bash(ls:*)",
      "Bash(pwd)",
      "Bash(whoami)",
      "Bash(id)",
      "Bash(uname:*)",
      "Bash(env)",
      "Bash(printenv:*)",
      "Bash(which:*)",
      "Bash(type:*)",
      "Bash(file:*)",
      "Bash(wc:*)",
      "Bash(sort:*)",
      "Bash(uniq:*)",
      "Bash(head:*)",
      "Bash(tail:*)",
      "Bash(cat:*)",
      "Bash(tree:*)",
      "Bash(find:*)",
      "Bash(grep:*)",
      "Bash(awk:*)",
      "Bash(sed:*)",
      "Bash(jq:*)",
      "Bash(yq:*)",

      "### DOCKER (READ-ONLY) ###",
      "Bash(docker:ps:*)",
      "Bash(docker:images:*)",
      "Bash(docker:logs:*)",
      "Bash(docker:inspect:*)",
      "Bash(docker:stats:*)"
    ],

    "ask": [
      "### FILE WRITES ###",
      "Write(*)",
      "Edit(*)",

      "### GIT (REMOTE) ###",
      "Bash(git:push:*)",
      "Bash(git:pull:*)",
      "Bash(git:fetch:*)",
      "Bash(git:clone:*)",
      "Bash(git:reset:--hard:*)",
      "Bash(git:rebase:*)",

      "### NETWORK ###",
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(ssh:*)",

      "### INFRASTRUCTURE ###",
      "Bash(docker:build:*)",
      "Bash(docker:run:*)",
      "Bash(docker:exec:*)",
      "Bash(docker:pull:*)",
      "Bash(docker:push:*)",
      "Bash(docker:compose:*)",
      "Bash(kubectl:*)",
      "Bash(aws:*)",
      "Bash(terraform:*)",
      "Bash(ansible:*)",

      "### FILE PERMISSIONS ###",
      "Bash(chmod:*)",
      "Bash(chown:*)",

      "### PROCESS MANAGEMENT ###",
      "Bash(kill:*)",
      "Bash(pkill:*)"
    ]
  },

  "mcp": {
    "defaultPolicy": "deny",
    "allowlist": [],
    "denylist": [
      { "name": "*" }
    ]
  },

  "hooks": {
    "PreToolUse": [
      {
        "name": "dlp-scanner",
        "command": "/opt/security/dlp-scan.sh"
      },
      {
        "name": "lakera-guard",
        "command": "/opt/security/lakera-check.sh"
      },
      {
        "name": "audit-logger",
        "command": "/opt/security/audit-log.sh"
      }
    ]
  }
}
```

---

## OPEN QUESTIONS FOR CRBRS

### New Questions (Cycle 4)

1. **MCP Server Policy:** Should we use Option A (exclusive managed-mcp.json) or Option B (policy-based allowlist)? What dataset sensitivity classifications require which approach?

2. **Database Read Access:** Is read-only database access via MCP acceptable for development workflows? What query restrictions should apply?

3. **Docker Requirement:** Do development workflows require Docker access? If yes, which restrictions are sufficient to prevent escape?

4. **HISTCONTROL Enforcement:** Is the combination of managed-settings.json deny rules + auditd + syslog sufficient for shell audit requirements?

5. **Training Requirement:** Should developer security training be a mandatory condition before Claude Code access?

6. **IR Playbook:** What Claude-specific scenarios should the incident response playbook cover?

### Carryover (Answered in Cycle 3)

- curl/wget conditional allow: APPROVED
- SSH with no tunneling: APPROVED
- Package registry access: APPROVED with proxy recommendation
- GitLab.com allowlist: APPROVED for non-sensitive projects

---

**AXIOM COMPLETE - CYCLE 4 READY FOR SECURITY REVIEW**
