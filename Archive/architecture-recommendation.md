# Claude Code Enterprise Architecture Recommendation

**Document Type:** Architecture Specification
**Version:** 1.0
**Date:** 2026-01-15
**Author:** Axiom Research Team (Scribe)

---

## Recommended Deployment Model

### Primary Recommendation: AWS Bedrock + Enterprise Controls

After evaluating multiple deployment options, we recommend:

| Component | Recommendation | Rationale |
|-----------|---------------|-----------|
| API Provider | Amazon Bedrock | AWS-native security, VPC endpoints, IAM integration |
| Contract | Claude for Enterprise | SSO, SCIM, audit logs, compliance certifications |
| Client | Claude Code CLI | Best developer experience with enterprise sandboxing |
| Authentication | OIDC via IAM Identity Center | Temporary credentials, user attribution |

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                         CORPORATE NETWORK                                     │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                    DEVELOPER WORKSTATION                              │   │
│  │                                                                       │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │                  CLAUDE CODE (SANDBOXED)                        │  │   │
│  │  │                                                                 │  │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│  │   │
│  │  │  │ bubblewrap  │  │ managed-    │  │  Session Controls       ││  │   │
│  │  │  │ /seatbelt   │  │ settings    │  │  • 8hr max duration     ││  │   │
│  │  │  │ isolation   │  │ .json       │  │  • 30min idle timeout   ││  │   │
│  │  │  └─────────────┘  └─────────────┘  │  • Re-auth sensitive ops││  │   │
│  │  │                                     └─────────────────────────┘│  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                                   │                                   │   │
│  │                                   ▼                                   │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │                   PRETOOLUSE HOOKS                              │  │   │
│  │  │                                                                 │  │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│  │   │
│  │  │  │ TruffleHog  │  │ Lakera      │  │  Audit Logger           ││  │   │
│  │  │  │ + Gitleaks  │  │ Guard       │  │  → Kinesis Firehose     ││  │   │
│  │  │  │ (secrets)   │  │ (injection) │  │  → S3 Object Lock       ││  │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘│  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
│                                      ▼                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                      LLM GUARD PROXY                                  │   │
│  │                                                                       │   │
│  │  • PII Detection (NER-based)     • Request/Response Logging         │   │
│  │  • Data Masking/Redaction        • Company-specific Patterns        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                      │                                       │
└──────────────────────────────────────┼───────────────────────────────────────┘
                                       │
                                       ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│                            AWS ACCOUNT                                        │
│                                                                               │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                        CLAUDE VPC                                     │   │
│  │                                                                       │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │                ROUTE 53 DNS FIREWALL                            │  │   │
│  │  │                                                                 │  │   │
│  │  │  ALLOW:  api.anthropic.com, *.amazonaws.com                    │  │   │
│  │  │  BLOCK:  *.pastebin.com, *.ngrok.io, DoH endpoints, ALL OTHER  │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                                   │                                   │   │
│  │                                   ▼                                   │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │                AWS NETWORK FIREWALL                             │  │   │
│  │  │                                                                 │  │   │
│  │  │  Layer 7 TLS SNI filtering:                                    │  │   │
│  │  │  PASS:  api.anthropic.com, *.amazonaws.com                     │  │   │
│  │  │  DROP:  ALL OTHER                                              │  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  │                                   │                                   │   │
│  │                                   ▼                                   │   │
│  │  ┌───────────────────┐      ┌──────────────────────────────────┐    │   │
│  │  │   VPC ENDPOINT    │─────▶│        AMAZON BEDROCK            │    │   │
│  │  │   (PrivateLink)   │      │        (Claude Models)           │    │   │
│  │  │   No Public IP    │      │        via Private Network       │    │   │
│  │  └───────────────────┘      └──────────────────────────────────┘    │   │
│  │                                                                       │   │
│  │  ┌────────────────────────────────────────────────────────────────┐  │   │
│  │  │                   AUDIT INFRASTRUCTURE                          │  │   │
│  │  │                                                                 │  │   │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│  │   │
│  │  │  │ Kinesis     │  │ S3 Bucket   │  │  CloudTrail +           ││  │   │
│  │  │  │ Firehose    │──│ Object Lock │  │  CloudWatch Alerts      ││  │   │
│  │  │  │ (real-time) │  │ COMPLIANCE  │  │  (meta-audit)           ││  │   │
│  │  │  └─────────────┘  └─────────────┘  └─────────────────────────┘│  │   │
│  │  └────────────────────────────────────────────────────────────────┘  │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Configuration Specifications

### 1. managed-settings.json (Enterprise)

Deploy to system-wide location (protected with admin privileges):
- **Linux:** `/etc/claude-code/managed-settings.json`
- **macOS:** `/Library/Application Support/ClaudeCode/managed-settings.json`
- **Windows:** `C:\ProgramData\ClaudeCode\managed-settings.json`

```json
{
  "env": {
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": 1,
    "HTTPS_PROXY": "http://llm-guard-proxy.internal:8080"
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
      "Bash(sudo:*)",
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(nc:*)",
      "Bash(ncat:*)",
      "Bash(netcat:*)",
      "Bash(ssh:*)",
      "Bash(scp:*)",
      "Bash(rsync:*)",
      "Bash(chmod:777:*)",
      "Bash(rm:-rf:/*)",
      "Bash(git:commit:--no-verify:*)",
      "Bash(git:rebase:*)",
      "Bash(git:reset:--hard:*)"
    ],
    "allow": [
      "Read(*)",
      "Glob(*)",
      "Grep(*)",
      "Bash(git:status:*)",
      "Bash(git:diff:*)",
      "Bash(git:log:*)",
      "Bash(git:branch:*)",
      "Bash(git:checkout:*)",
      "Bash(git:add:*)",
      "Bash(git:commit:*)",
      "Bash(npm:*)",
      "Bash(npx:*)",
      "Bash(node:*)",
      "Bash(python:*)",
      "Bash(pip:*)",
      "Bash(pytest:*)",
      "Bash(make:*)",
      "Bash(cargo:*)",
      "Bash(go:*)",
      "Bash(gradle:*)",
      "Bash(mvn:*)"
    ],
    "ask": [
      "Write(*)",
      "Edit(*)",
      "Bash(git:push:*)",
      "Bash(docker:*)",
      "Bash(kubectl:*)",
      "Bash(aws:*)",
      "Bash(terraform:*)"
    ]
  },
  "mcp": {
    "defaultPolicy": "deny",
    "allowlist": []
  }
}
```

### 2. PreToolUse Hook Configuration

**Hook Directory:** `/etc/claude-code/hooks/`

**hooks.json:**
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "name": "secret-scanner",
        "command": "/etc/claude-code/hooks/secret-scan.sh",
        "timeout": 5000
      },
      {
        "name": "prompt-injection-guard",
        "command": "/etc/claude-code/hooks/lakera-guard.sh",
        "timeout": 3000
      },
      {
        "name": "audit-logger",
        "command": "/etc/claude-code/hooks/audit-log.sh",
        "timeout": 2000
      }
    ]
  }
}
```

### 3. AWS Infrastructure (Terraform)

**Key Resources:**

```hcl
# VPC Endpoint for Bedrock
resource "aws_vpc_endpoint" "bedrock" {
  vpc_id             = aws_vpc.claude.id
  service_name       = "com.amazonaws.${var.region}.bedrock-runtime"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = aws_subnet.private[*].id
  security_group_ids = [aws_security_group.bedrock_endpoint.id]
  private_dns_enabled = true
}

# DNS Firewall Rule Group
resource "aws_route53_resolver_firewall_rule_group" "claude" {
  name = "claude-dns-firewall"
  # Rules as specified in research
}

# Network Firewall
resource "aws_networkfirewall_firewall" "claude" {
  name                = "claude-egress-firewall"
  firewall_policy_arn = aws_networkfirewall_firewall_policy.claude.arn
  vpc_id              = aws_vpc.claude.id
  # Subnets and rules as specified
}

# Audit Log Bucket with Object Lock
resource "aws_s3_bucket" "audit_logs" {
  bucket              = "company-claude-audit-logs"
  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "audit" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    default_retention {
      mode  = "COMPLIANCE"
      years = 7
    }
  }
}
```

---

## Compensating Controls Implementation

### DLP Controls

| Control | Tool | Configuration |
|---------|------|---------------|
| Secret Scanning | TruffleHog | `--only-verified` flag |
| PII Detection | LLM Guard | Custom entity patterns |
| Egress DLP | Corporate Proxy | Standard DLP rules |

### Prompt Injection Defense

| Layer | Tool | Threshold |
|-------|------|-----------|
| Input Guardrail | Lakera Guard | Block medium+ |
| Output Validation | Custom hook | Command allowlist |
| Behavioral Monitor | SIEM | Anomaly detection |

### Audit & Compliance

| Requirement | Implementation |
|-------------|---------------|
| Log Integrity | S3 Object Lock COMPLIANCE |
| Real-time Streaming | Kinesis Firehose (60s buffer) |
| Meta-audit | CloudTrail on S3/Kinesis |
| Retention | 7 years (immutable) |

---

## Implementation Roadmap

### Phase 1: Foundation (Week 1-2)

| Task | Owner | Dependencies |
|------|-------|--------------|
| Sign Claude for Enterprise contract | Legal | - |
| Provision AWS account | Cloud Ops | - |
| Deploy VPC with endpoints | Cloud Ops | AWS account |
| Configure DNS Firewall | Network | VPC |
| Configure Network Firewall | Network | VPC |

### Phase 2: Security Controls (Week 2-3)

| Task | Owner | Dependencies |
|------|-------|--------------|
| Deploy managed-settings.json | Security | - |
| Configure PreToolUse hooks | Security | - |
| Deploy LLM Guard proxy | Security | - |
| Set up Kinesis + S3 audit | Security | AWS account |
| Configure Lakera Guard | Security | Contract |

### Phase 3: Pilot (Week 3-4)

| Task | Owner | Dependencies |
|------|-------|--------------|
| Developer training | Security | Training module |
| Pilot with 5-10 developers | Engineering | All controls |
| Tune detection thresholds | Security | Pilot feedback |
| Document procedures | Security | Pilot learnings |

### Phase 4: Production (Week 5+)

| Task | Owner | Dependencies |
|------|-------|--------------|
| Full rollout | Engineering | Pilot success |
| Monitoring dashboard | Security | Production data |
| IR tabletop exercise | Security | Full rollout |
| First threshold review | Security | 30 days ops |

---

## Legal/Contractual Requirements Checklist

| Requirement | Status | Action |
|-------------|--------|--------|
| Claude for Enterprise contract | Required | Contact Anthropic sales |
| Data Processing Agreement | Included | Part of Enterprise contract |
| SOC 2 Type II report | Request | Available under NDA |
| BAA (if HIPAA applicable) | Optional | Request if needed |
| AWS Bedrock terms | Required | Standard AWS agreement |
| Lakera Guard contract | Required | Contact Lakera sales |

---

## Support and Escalation

### Operational Support
- **L1:** IT Help Desk (basic troubleshooting)
- **L2:** Cloud Operations (infrastructure issues)
- **L3:** Security Team (security events)

### Security Escalation
- **Detection Alert:** Security Operations
- **Incident:** Security Lead (PALADIN)
- **Breach:** Executive Leadership + Legal

### Vendor Support
- **Anthropic:** Enterprise support channel
- **AWS:** Business/Enterprise support
- **Lakera:** Customer success contact

---

## Document Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-15 | Axiom (Scribe) | Initial architecture |

**Next Review:** Quarterly or upon significant change
