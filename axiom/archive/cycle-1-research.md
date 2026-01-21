# Axiom Research: Claude Code Enterprise Security

**Cycle:** 1
**Status:** Ready for Security Review
**Last Updated:** 2026-01-15
**Lead:** Thesis | **Coordinator:** Proof

---

## Executive Summary

This research evaluates secure deployment options for Claude Code in a high-security enterprise environment. Key findings:

1. **No true self-hosting** - Claude models cannot be self-hosted; all deployments require API connectivity to Anthropic or cloud provider (Bedrock/Vertex)
2. **Multiple deployment tiers** - Direct Anthropic API, AWS Bedrock, or Google Vertex AI each offer different security tradeoffs
3. **OS-level sandboxing available** - Claude Code's bubblewrap (Linux) and seatbelt (macOS) isolation provides filesystem and network boundaries
4. **Enterprise policy enforcement** - `managed-settings.json` enables organization-wide, non-overridable security policies
5. **Claude for Enterprise recommended** - SSO, SCIM, audit logs, and compliance certifications address enterprise requirements

---

## 1. Deployment Model Analysis

### 1.1 Claude for Enterprise (Direct Anthropic API)

**Overview:** Anthropic's enterprise offering with full security feature set.

**Security Features:**
- SSO via SAML 2.0 and OIDC
- SCIM for automated user provisioning (prefix groups with "anthropic-")
- Comprehensive audit logging (released Sept-Oct 2025)
- Role-based access control (Primary Owner, Admin, Member)
- Compliance API for programmatic usage monitoring
- SOC 2 Type II certified (SOC 3 report publicly available)
- No training on customer data by default

**Encryption:**
- TLS 1.2+ in transit
- AES-256 at rest

**Legal Requirement:** Enterprise contract required for full feature access.

**Sources:**
- [Anthropic Enterprise Plan](https://www.anthropic.com/enterprise)
- [Claude for Enterprise Announcement](https://www.anthropic.com/news/claude-for-enterprise)

### 1.2 AWS Bedrock

**Overview:** Claude models accessed through AWS infrastructure with native AWS security controls.

**Security Features:**
- IAM-based authentication and authorization
- VPC Private Endpoints via AWS PrivateLink (traffic never traverses public internet)
- CloudTrail integration for comprehensive audit logging
- Fine-grained IAM policies per model/action
- Cost tracking via AWS Cost Explorer
- Supports AWS Commercial and GovCloud (US)

**Recommended Authentication:**
- Direct IAM OIDC federation (Microsoft Entra ID, Okta)
- Temporary credentials with user attribution
- Avoid long-lived IAM access/secret keys

**Best Practice:** Dedicated AWS account for Claude Code to simplify cost tracking and access control.

**Sources:**
- [AWS Bedrock Private Access](https://aws.amazon.com/blogs/machine-learning/use-aws-privatelink-to-set-up-private-access-to-amazon-bedrock/)
- [Guidance for Claude Code with Amazon Bedrock](https://aws.amazon.com/solutions/guidance/claude-code-with-amazon-bedrock/)

### 1.3 Google Vertex AI

**Overview:** Claude models via Google Cloud infrastructure.

**Security Features:**
- Google Cloud IAM role-based access
- Cloud Audit Logs integration
- VPC Service Controls support

### 1.4 Self-Hosting Assessment

**Finding: Not possible for Claude models.**

Anthropic does not offer on-premise deployment of Claude models. All options require API connectivity:

| Option | Model Location | Client Location |
|--------|---------------|-----------------|
| Anthropic API | Anthropic cloud | Customer premises |
| AWS Bedrock | AWS infrastructure | Customer premises |
| Vertex AI | Google Cloud | Customer premises |

**Alternative for Air-Gapped Environments:**
Open-source models (Llama, Qwen, DeepSeek, Mistral) can be truly self-hosted but are 6-12 months behind Claude capability.

**Sources:**
- [Claude Code Self-Hosted LLM Feature Request](https://github.com/anthropics/claude-code/issues/7178)
- [Self-Hosting AI Models Analysis](https://steipete.me/posts/2025/self-hosting-ai-models)

---

## 2. Claude Code Security Controls

### 2.1 Sandboxing Architecture

**Released:** October 20, 2025

**Technology:**
- **Linux:** bubblewrap container isolation
- **macOS:** Seatbelt sandbox profiles

**Two-Boundary Isolation Model:**

| Boundary | Protection | Configuration |
|----------|------------|---------------|
| **Filesystem** | Prevents access to sensitive system files | Write: deny-all + explicit allows; Read: allow-all + explicit denies |
| **Network** | Prevents data exfiltration/malware download | All traffic routed through controlled proxies |

**Key Characteristics:**
- All child processes inherit sandbox restrictions
- Even `npm install` postinstall scripts are sandboxed
- 84% reduction in permission prompts (Anthropic internal testing)
- Open-sourced for community adoption

**Configuration:**
```bash
# Enable via slash command
/sandbox

# Modes available:
# - Auto-allow: Commands run in sandbox without prompts
# - Regular: Standard permission flow, but sandboxed
```

**Network Implementation:**
- Linux: Unix domain sockets via socat; network namespace removed from bubblewrap
- macOS: Seatbelt allows only specific localhost proxy ports

**Sources:**
- [Claude Code Sandboxing Documentation](https://code.claude.com/docs/en/sandboxing)
- [Anthropic Engineering: Claude Code Sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)

### 2.2 Permission System

**Hierarchy (Highest to Lowest Priority):**
1. Enterprise managed policies (`managed-settings.json`) - Cannot be overridden
2. Command line arguments
3. Local project settings (`.claude/settings.local.json`)
4. Shared project settings (`.claude/settings.json`)

**Permission Arrays:**
- `deny` - Block tools/commands (enforced first)
- `allow` - Permit tools/commands
- `ask` - Prompt user each time

**Pattern Syntax:**
```json
{
  "permissions": {
    "deny": [
      "Read(**/.env)",
      "Bash(sudo:*)",
      "Bash(curl:*)",
      "Bash(wget:*)"
    ],
    "allow": [
      "Bash(npm:*)",
      "Bash(git:*)"
    ]
  }
}
```

**Permission Modes:**
| Mode | Behavior | Risk Level |
|------|----------|------------|
| `default` | Prompt on first tool use | Low |
| `acceptEdits` | Auto-accept file edits | Medium |
| `plan` | Read-only, no execution | Minimal |
| `bypassPermissions` | Auto-accept all | **Critical** |

**Enterprise Setting:**
```json
{
  "permissions": {
    "disableBypassPermissionsMode": "disable"
  }
}
```

**Sources:**
- [Claude Code Settings Documentation](https://code.claude.com/docs/en/settings)
- [Claude Code Permissions Guide](https://www.eesel.ai/blog/claude-code-permissions)

### 2.3 Hooks for Security Enforcement

**PreToolUse Hooks:**
- Execute before any tool call
- Can block, log, or modify operations
- Support chaining for multiple security checks

**Enterprise Use Cases:**
- Audit logging all tool invocations
- Rate limiting
- Authorization checks
- Input sanitization
- SOX/SOC2 compliance trails

**Example Audit Hook:**
```bash
echo "$(date): Tool ${CLAUDE_TOOL_NAME} executed by ${USER}" >> /var/log/claude-audit.log
```

**Integration Points:**
- Local file logging
- OpenTelemetry (OTel) collector for enterprise SIEM

**Sources:**
- [Claude Code Hooks Guide](https://code.claude.com/docs/en/hooks-guide)
- [Hooks Implementation Guide](https://medium.com/@richardhightower/claude-code-hooks-implementation-guide-audit-system-03763748700f)

---

## 3. Recommended Architecture

### 3.1 Proposed Deployment: AWS Bedrock + Claude for Enterprise

**Rationale:** Combines AWS infrastructure controls with Anthropic enterprise features.

**Architecture Overview:**
```
┌─────────────────────────────────────────────────────────────┐
│                    Corporate Network                         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Developer Workstation                    │   │
│  │  ┌─────────────────────────────────────────────┐    │   │
│  │  │           Claude Code (Sandboxed)            │    │   │
│  │  │  • bubblewrap/seatbelt isolation            │    │   │
│  │  │  • managed-settings.json enforced           │    │   │
│  │  │  • PreToolUse audit hooks                   │    │   │
│  │  └─────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                  │
│                           ▼                                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 Corporate Proxy                       │   │
│  │  • Egress filtering                                  │   │
│  │  • SSL inspection (optional)                         │   │
│  │  • DLP scanning                                      │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      AWS Account                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Private VPC                        │   │
│  │  ┌───────────────┐    ┌───────────────────────┐     │   │
│  │  │ VPC Endpoint  │───▶│   Amazon Bedrock      │     │   │
│  │  │ (PrivateLink) │    │   (Claude Models)     │     │   │
│  │  └───────────────┘    └───────────────────────┘     │   │
│  │         │                        │                   │   │
│  │         ▼                        ▼                   │   │
│  │  ┌───────────────┐    ┌───────────────────────┐     │   │
│  │  │  CloudTrail   │    │    IAM + OIDC         │     │   │
│  │  │  (Audit Logs) │    │  (Federation)         │     │   │
│  │  └───────────────┘    └───────────────────────┘     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Defense-in-Depth Layers

| Layer | Control | Purpose |
|-------|---------|---------|
| 1 | OS Sandboxing | Filesystem/network isolation |
| 2 | managed-settings.json | Enterprise policy enforcement |
| 3 | PreToolUse Hooks | Audit logging, command filtering |
| 4 | Corporate Proxy | Egress control, DLP |
| 5 | VPC Private Endpoint | No public internet exposure |
| 6 | IAM + OIDC | Identity federation, temporary creds |
| 7 | CloudTrail | Comprehensive API audit trail |

### 3.3 Alternative: Isolated VM Approach

For maximum isolation, deploy Claude Code in dedicated VMs:

**Configuration:**
- Linux VM (Ubuntu/RHEL) with CIS hardening
- No persistent storage of sensitive data
- Ephemeral: destroy and recreate per session or daily
- Codebase access via read-only mounts or git clone
- All commits require review in primary environment

**Tradeoffs:**
| Pro | Con |
|-----|-----|
| Maximum isolation | Developer friction |
| Easy to audit/monitor | Performance overhead |
| No data persistence risk | Setup complexity |

---

## 4. Proposed Security Controls

### 4.1 Enterprise managed-settings.json

```json
{
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": 1,
    "HTTPS_PROXY": "http://proxy.corp.local:8080"
  },
  "cleanupPeriodDays": 1,
  "permissions": {
    "disableBypassPermissionsMode": "disable",
    "defaultMode": "default",
    "deny": [
      "Read(**/.env)",
      "Read(**/*.pem)",
      "Read(**/*.key)",
      "Read(**/credentials*)",
      "Read(**/secrets*)",
      "Read(**/.aws/*)",
      "Read(**/.ssh/*)",
      "Bash(sudo:*)",
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(nc:*)",
      "Bash(ncat:*)",
      "Bash(ssh:*)",
      "Bash(scp:*)",
      "Bash(rsync:*)",
      "Bash(chmod:777:*)",
      "Bash(rm:-rf:/*)"
    ],
    "allow": [
      "Bash(git:*)",
      "Bash(npm:*)",
      "Bash(npx:*)",
      "Bash(node:*)",
      "Bash(python:*)",
      "Bash(pip:*)",
      "Bash(pytest:*)",
      "Bash(make:*)",
      "Bash(cargo:*)",
      "Bash(go:*)"
    ],
    "ask": [
      "Bash(docker:*)",
      "Bash(kubectl:*)",
      "Bash(aws:*)"
    ]
  }
}
```

### 4.2 Audit Hook Implementation

```bash
#!/bin/bash
# /etc/claude-code/hooks/pretool-audit.sh

LOG_FILE="/var/log/claude-code/audit.log"
TOOL_NAME="${CLAUDE_TOOL_NAME}"
TOOL_INPUT="${CLAUDE_TOOL_INPUT}"
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
USER_ID=$(whoami)
SESSION_ID="${CLAUDE_SESSION_ID:-unknown}"

# Log to local file
echo "{\"timestamp\":\"${TIMESTAMP}\",\"user\":\"${USER_ID}\",\"session\":\"${SESSION_ID}\",\"tool\":\"${TOOL_NAME}\",\"input\":\"${TOOL_INPUT}\"}" >> "$LOG_FILE"

# Optional: Send to SIEM via syslog
logger -p local0.info -t claude-code "tool=${TOOL_NAME} user=${USER_ID} session=${SESSION_ID}"

exit 0  # Allow execution to proceed
```

### 4.3 IAM Policy for Bedrock

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowClaudeInvocation",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ],
      "Resource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
      ],
      "Condition": {
        "StringEquals": {
          "aws:PrincipalTag/Department": "Engineering"
        }
      }
    },
    {
      "Sid": "DenyOtherModels",
      "Effect": "Deny",
      "Action": "bedrock:InvokeModel*",
      "NotResource": [
        "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
      ]
    }
  ]
}
```

---

## 5. Legal/Contractual Requirements

| Requirement | Details |
|-------------|---------|
| Claude for Enterprise Contract | Required for SSO, SCIM, audit logs, compliance API |
| Data Processing Agreement | Standard with Enterprise contract |
| SOC 2 Type II Report | Available under NDA |
| BAA for HIPAA | Available for Enterprise customers |
| AWS Bedrock Terms | Additional AWS agreement if using Bedrock |

---

## 6. Open Questions for CRBRS Review

1. **Data residency:** Is US-based model hosting acceptable, or is regional deployment required?
2. **Code classification:** What data classification levels will Claude Code access?
3. **Network segmentation:** Can developer workstations reach AWS/Anthropic endpoints directly, or must all traffic proxy?
4. **Session recording:** Is screen/session recording required for compliance?
5. **Incident response:** What is the expected response time for Claude-related security events?
6. **Model access scope:** Should access be limited to specific Claude model versions?

---

## 7. Next Steps

Pending CRBRS security review of:
- Proposed architecture
- Managed-settings.json configuration
- Audit logging approach
- Compensating controls

---

**AXIOM COMPLETE - CYCLE 1 READY FOR SECURITY REVIEW**
