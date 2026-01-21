# Axiom Research: Claude Code Enterprise Security

**Cycle:** 2
**Status:** Ready for Security Review
**Last Updated:** 2026-01-15
**Lead:** Thesis | **Coordinator:** Proof

---

## Executive Summary

This research addresses all Critical and High findings from CRBRS Cycle 1 review. Key updates:

1. **DLP Integration (CRIT-01)** - Proposed LLM Guard + secret scanning layer
2. **Prompt Injection Defense (CRIT-02)** - Layered guardrails with behavioral monitoring
3. **Audit Log Integrity (HIGH-01)** - S3 Object Lock with real-time streaming
4. **Network Egress Controls (HIGH-02)** - AWS Network Firewall + DNS Firewall
5. **Code Commit Review (HIGH-03)** - PR-only workflow with blocked direct push
6. **Session Management (HIGH-04)** - 8-hour max sessions with re-auth requirements

---

## CRITICAL FINDING REMEDIATIONS

### CRIT-01: Data Loss Prevention (DLP) Integration

**Finding:** No DLP scanning of prompts before transmission to Claude API.

**Proposed Solution:** Multi-layer DLP approach

#### Layer 1: Pre-Prompt Secret Scanning

Deploy TruffleHog + Gitleaks as PreToolUse hook to scan all file reads and prompt content.

**Implementation:**
```bash
#!/bin/bash
# /etc/claude-code/hooks/pretool-dlp.sh

TOOL_NAME="${CLAUDE_TOOL_NAME}"
TOOL_INPUT="${CLAUDE_TOOL_INPUT}"

# For file read operations, scan content
if [[ "$TOOL_NAME" == "Read" || "$TOOL_NAME" == "Grep" ]]; then
    # Extract file path from input
    FILE_PATH=$(echo "$TOOL_INPUT" | jq -r '.file_path // .path // empty')

    if [[ -n "$FILE_PATH" && -f "$FILE_PATH" ]]; then
        # Run TruffleHog scan
        SECRETS=$(trufflehog filesystem "$FILE_PATH" --json --only-verified 2>/dev/null)

        if [[ -n "$SECRETS" ]]; then
            echo "BLOCKED: Verified secrets detected in $FILE_PATH" >&2
            echo "$SECRETS" >> /var/log/claude-code/dlp-blocks.log
            exit 1  # Block the tool execution
        fi
    fi
fi

exit 0  # Allow execution
```

**Rationale:**
- TruffleHog detects 700+ credential types with verification
- Verification eliminates false positives (only blocks confirmed active secrets)
- Executes before file content reaches Claude context

#### Layer 2: LLM-Aware DLP Gateway

Deploy Lakera Guard or LLM Guard as middleware proxy.

**Architecture:**
```
Claude Code → PreToolUse Hook (TruffleHog) → LLM Guard Proxy → AWS Bedrock
                                                    ↓
                                              PII/Secret Detection
                                              Prompt Sanitization
                                              Audit Logging
```

**Lakera Guard Capabilities:**
- Real-time prompt scanning (<50ms latency)
- PII detection using NER models
- Custom entity recognition for company-specific patterns
- Data masking/redaction before API transmission

**Configuration Example (LLM Guard):**
```python
# llm_guard_config.py
from llm_guard import scan_prompt
from llm_guard.input_scanners import (
    Anonymize,
    Secrets,
    TokenLimit
)

scanners = [
    Anonymize(pii_types=["EMAIL", "PHONE", "SSN", "CREDIT_CARD"]),
    Secrets(),
    TokenLimit(limit=100000)
]

def sanitize_prompt(prompt: str) -> tuple[str, dict]:
    sanitized, results, valid = scan_prompt(scanners, prompt)
    return sanitized, results
```

#### Layer 3: Egress DLP at Proxy

Corporate proxy performs final DLP scan on all HTTPS traffic.

**Controls:**
- Pattern matching for remaining sensitive patterns
- Data classification labeling
- Anomaly detection on payload sizes

**Sources:**
- [Lakera Data Loss Prevention](https://www.lakera.ai/data-loss-prevention)
- [LLM Guard Documentation](https://github.com/laiyer-ai/llm-guard)
- [TruffleHog Secret Scanner](https://github.com/trufflesecurity/trufflehog)

---

### CRIT-02: Prompt Injection Defense

**Finding:** No detection or prevention of prompt injection attacks.

**Proposed Solution:** Multi-layer defense with behavioral monitoring

#### Layer 1: Input Guardrails

Deploy Lakera Guard for real-time prompt injection detection.

**Capabilities:**
- Direct prompt injection detection
- Indirect prompt injection (embedded in documents)
- Jailbreak attempt detection
- Adversarial input detection

**Integration:**
```python
# PreToolUse hook integration
import requests

def check_prompt_injection(content: str) -> bool:
    response = requests.post(
        "https://api.lakera.ai/v1/guard",
        headers={"Authorization": f"Bearer {LAKERA_API_KEY}"},
        json={"prompt": content}
    )
    result = response.json()

    if result.get("flagged"):
        log_security_event("prompt_injection_blocked", result)
        return False  # Block
    return True  # Allow
```

#### Layer 2: Output Guardrails

Validate Claude outputs before execution.

**Checks:**
- Command validation against allowlist
- Parameter sanitization
- Anomaly scoring on tool usage patterns

**Implementation:**
```json
{
  "output_guardrails": {
    "enabled": true,
    "validators": [
      {
        "type": "command_allowlist",
        "action": "block_if_not_match"
      },
      {
        "type": "parameter_sanitizer",
        "patterns": ["../", "~", "$HOME", "|", ";", "`"]
      },
      {
        "type": "anomaly_scorer",
        "threshold": 0.8,
        "baseline_window": "7d"
      }
    ]
  }
}
```

#### Layer 3: Behavioral Monitoring

Deploy SIEM integration for anomaly detection.

**Monitored Behaviors:**
| Behavior | Baseline | Alert Threshold |
|----------|----------|-----------------|
| Tool calls per minute | 5-10 | >30 |
| File reads per session | 50-100 | >500 |
| Unique directories accessed | 3-5 | >20 |
| Network requests | API only | Any non-API |
| Error rate | <5% | >20% |

**SOAR Integration:**
- Auto-block on high-confidence detections
- Alert for human review on medium confidence
- Log all for forensic analysis

#### Layer 4: Autonomy Reduction

Restrict Claude's autonomous capabilities for sensitive operations.

**Policy:**
```json
{
  "permissions": {
    "ask": [
      "Bash(*)",
      "Write(*)",
      "Edit(*)"
    ],
    "allow": [
      "Read(*)",
      "Glob(*)",
      "Grep(*)"
    ]
  }
}
```

**Rationale:** "Reducing autonomy is sometimes the cleanest mitigation" - OWASP LLM Security

**Sources:**
- [OWASP LLM01:2025 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [Lakera Prompt Injection Guide](https://www.lakera.ai/blog/guide-to-prompt-injection)
- [Prompt Injection Defenses Repository](https://github.com/tldrsec/prompt-injection-defenses)

---

## HIGH FINDING REMEDIATIONS

### HIGH-01: Audit Log Integrity

**Finding:** Local audit logs can be tampered with.

**Proposed Solution:** Immutable, tamper-evident logging architecture

#### Architecture
```
Claude Code → PreToolUse Hook → Kinesis Data Firehose → S3 (Object Lock)
                    ↓                                          ↓
              CloudWatch Logs ←─────────────────────────→ SIEM Integration
                    ↓
              Real-time Alerts
```

#### Implementation Components

**1. S3 Bucket with Object Lock (Compliance Mode)**
```terraform
resource "aws_s3_bucket" "claude_audit_logs" {
  bucket = "company-claude-audit-logs"

  object_lock_enabled = true
}

resource "aws_s3_bucket_object_lock_configuration" "audit_lock" {
  bucket = aws_s3_bucket.claude_audit_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      years = 7
    }
  }
}
```

**2. Kinesis Firehose for Real-Time Streaming**
```terraform
resource "aws_kinesis_firehose_delivery_stream" "claude_logs" {
  name        = "claude-audit-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.claude_audit_logs.arn

    buffering_size     = 1   # MB
    buffering_interval = 60  # seconds

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = "/aws/firehose/claude-audit"
      log_stream_name = "delivery"
    }
  }
}
```

**3. PreToolUse Hook with Streaming**
```bash
#!/bin/bash
# Stream logs to Kinesis (not local file)

LOG_ENTRY=$(jq -n \
    --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg user "$USER" \
    --arg tool "$CLAUDE_TOOL_NAME" \
    --arg input "$CLAUDE_TOOL_INPUT" \
    --arg session "$CLAUDE_SESSION_ID" \
    '{timestamp: $ts, user: $user, tool: $tool, input: $input, session: $session}')

# Stream to Kinesis (via AWS CLI or SDK)
aws firehose put-record \
    --delivery-stream-name claude-audit-stream \
    --record "Data=${LOG_ENTRY}"

exit 0
```

**4. Tamper Detection**
- CloudTrail monitors Object Lock configuration changes
- CloudWatch alarm on any retention modification attempts
- Cryptographic hash chain for log sequence verification

**Compliance:**
- PCI DSS Requirement 10
- SOX audit requirements
- HIPAA Security Rule
- ISO 27001 A.12.4.1

**Sources:**
- [AWS S3 Object Lock Documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock-managing.html)
- [Tamper-Proof Logging Guide](https://pwnsentinel.org/2025/07/18/tamper-proof-logging/)

---

### HIGH-02: Network Egress Controls

**Finding:** Insufficient egress filtering allows potential data exfiltration.

**Proposed Solution:** Multi-layer egress defense with explicit allowlisting

#### Architecture
```
Claude Code (Sandboxed)
        ↓
   Sandbox Proxy (localhost)
        ↓
   Route 53 DNS Firewall (DNS filtering)
        ↓
   AWS Network Firewall (Layer 7 filtering)
        ↓
   NAT Gateway
        ↓
   Allowed Destinations Only:
   • api.anthropic.com
   • bedrock-runtime.*.amazonaws.com
   • sts.amazonaws.com
```

#### Implementation Components

**1. Route 53 Resolver DNS Firewall**
```terraform
resource "aws_route53_resolver_firewall_domain_list" "allowed" {
  name    = "claude-allowed-domains"
  domains = [
    "api.anthropic.com",
    "*.amazonaws.com"
  ]
}

resource "aws_route53_resolver_firewall_domain_list" "blocked" {
  name    = "claude-blocked-domains"
  domains = [
    "*.pastebin.com",
    "*.ngrok.io",
    "*.requestbin.com",
    "*.webhook.site"
  ]
}

resource "aws_route53_resolver_firewall_rule_group" "claude" {
  name = "claude-dns-firewall"

  rule {
    name                 = "allow-claude-domains"
    action               = "ALLOW"
    firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.allowed.id
    priority             = 100
  }

  rule {
    name                 = "block-exfil-domains"
    action               = "BLOCK"
    block_response       = "NXDOMAIN"
    firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.blocked.id
    priority             = 200
  }

  rule {
    name                 = "block-all-other"
    action               = "BLOCK"
    block_response       = "NXDOMAIN"
    firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.all_domains.id
    priority             = 300
  }
}
```

**2. AWS Network Firewall (Layer 7)**
```terraform
resource "aws_networkfirewall_rule_group" "claude_egress" {
  capacity = 100
  name     = "claude-egress-rules"
  type     = "STATEFUL"

  rule_group {
    stateful_rule_options {
      rule_order = "STRICT_ORDER"
    }

    rules_source {
      rules_string = <<EOF
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"api.anthropic.com"; endswith; msg:"Allow Anthropic API"; sid:1; rev:1;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:".amazonaws.com"; endswith; msg:"Allow AWS Services"; sid:2; rev:1;)
drop tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Block all other TLS"; sid:3; rev:1;)
drop ip $HOME_NET any -> $EXTERNAL_NET any (msg:"Block all other IP"; sid:4; rev:1;)
EOF
    }
  }
}
```

**3. DNS-over-HTTPS (DoH) Blocking**
Block DoH to prevent DNS filtering bypass:
```terraform
resource "aws_networkfirewall_rule_group" "block_doh" {
  capacity = 50
  name     = "block-doh"
  type     = "STATEFUL"

  rule_group {
    rules_source {
      rules_string = <<EOF
drop tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"dns.google"; msg:"Block Google DoH"; sid:100;)
drop tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"cloudflare-dns.com"; msg:"Block Cloudflare DoH"; sid:101;)
drop tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:"dns.quad9.net"; msg:"Block Quad9 DoH"; sid:102;)
EOF
    }
  }
}
```

**4. Traffic Anomaly Detection**
- VPC Flow Logs → CloudWatch Logs Insights
- Alert on unusual payload sizes (>1MB)
- Alert on high request frequency (>100/min)
- Alert on requests to new domains

**Sources:**
- [AWS Network Firewall Egress](https://aws.amazon.com/blogs/networking-and-content-delivery/securing-egress-architectures-with-network-firewall-proxy/)
- [Route 53 DNS Firewall](https://aws.amazon.com/blogs/networking-and-content-delivery/secure-your-amazon-vpc-dns-resolution-with-amazon-route-53-resolver-dns-firewall/)

---

### HIGH-03: Code Commit Review Enforcement

**Finding:** Claude can push code directly without human review.

**Proposed Solution:** PR-only workflow with blocked direct push

#### Policy Changes

**1. Updated managed-settings.json**
```json
{
  "permissions": {
    "deny": [
      "Bash(git:push:*)",
      "Bash(git:commit:--no-verify:*)",
      "Bash(git:rebase:*)",
      "Bash(git:reset:--hard:*)",
      "Bash(git:force-push:*)"
    ],
    "allow": [
      "Bash(git:status:*)",
      "Bash(git:diff:*)",
      "Bash(git:log:*)",
      "Bash(git:branch:*)",
      "Bash(git:checkout:*)",
      "Bash(git:add:*)",
      "Bash(git:commit:*)"
    ],
    "ask": [
      "Bash(git:push:*)"
    ]
  }
}
```

**2. Pre-Push Hook (Server-Side)**
```bash
#!/bin/bash
# .git/hooks/pre-push (or server-side equivalent)

# Require PR for all pushes from Claude Code
if [[ "$GIT_AUTHOR_NAME" == *"Claude"* ]] || [[ -n "$CLAUDE_SESSION_ID" ]]; then
    echo "ERROR: Direct push from Claude Code is blocked."
    echo "Please create a Pull Request for code review."
    exit 1
fi
```

**3. Branch Protection Rules (GitHub/GitLab)**
```yaml
# GitHub branch protection
branches:
  - name: main
    protection:
      required_pull_request_reviews:
        required_approving_review_count: 1
      required_status_checks:
        strict: true
        contexts:
          - "ci/build"
          - "security/secret-scan"
      enforce_admins: true
      restrictions:
        users: []
        teams: []
```

**Workflow:**
1. Claude creates branch and commits locally
2. Claude can `git push` to feature branch (with ask permission)
3. Human creates PR from Claude's branch
4. Human reviews and merges
5. Direct push to main/protected branches blocked

---

### HIGH-04: Session Management

**Finding:** No session timeout or isolation documented.

**Proposed Solution:** Comprehensive session management policy

#### Session Policy

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Max session duration | 8 hours | Limits exposure window |
| Idle timeout | 30 minutes | Reduces abandoned session risk |
| Re-auth for sensitive ops | Required | Prevents credential theft abuse |
| Concurrent sessions | 1 per user | Prevents session confusion |
| Session recording | Enabled | Forensic capability |

#### Implementation

**1. Session Timeout (managed-settings.json)**
```json
{
  "session": {
    "maxDurationMinutes": 480,
    "idleTimeoutMinutes": 30,
    "requireReauthForSensitiveOps": true,
    "maxConcurrentSessions": 1
  }
}
```

**2. Sensitive Operation Re-Authentication**
Operations requiring re-auth:
- Any `Write` or `Edit` to sensitive paths
- Any `Bash` command with elevated permissions
- Any git operations
- Any network requests to non-API endpoints

**3. Session Recording (AWS Configuration)**
For VM-based deployment, SSM Session Manager provides built-in recording:
```terraform
resource "aws_ssm_document" "session_preferences" {
  name            = "SSM-SessionManagerRunShell"
  document_type   = "Session"
  document_format = "JSON"

  content = jsonencode({
    schemaVersion = "1.0"
    description   = "Claude Code session preferences"
    sessionType   = "Standard_Stream"
    inputs = {
      s3BucketName        = aws_s3_bucket.session_logs.id
      s3KeyPrefix         = "claude-sessions/"
      cloudWatchLogGroupName = "/aws/ssm/claude-sessions"
      cloudWatchEncryptionEnabled = true
    }
  })
}
```

**4. Session Isolation**
- Each session gets unique identifier
- Session context isolated in memory
- No cross-session data sharing
- Session cleanup on termination

---

## MEDIUM FINDING REMEDIATIONS

### MED-01: AWS Credential Management

**Proposed Controls:**
```json
{
  "credential_policy": {
    "max_lifetime_hours": 1,
    "rotation": "automatic",
    "source": "IAM Identity Center",
    "break_glass": {
      "procedure": "security-team-approval",
      "max_duration_hours": 4,
      "audit_required": true
    }
  }
}
```

### MED-02: Incident Response Plan

**Claude-Specific IR Runbook:**
1. **Detection:** SIEM alert on anomalous behavior
2. **Containment:** Terminate session, revoke credentials
3. **Eradication:** Review all changes made, rollback if needed
4. **Recovery:** Re-provision clean environment
5. **Lessons Learned:** Update guardrails, retrain if needed

**Kill Switch:**
```bash
# Emergency Claude termination
aws ssm send-command \
    --instance-ids $INSTANCE_ID \
    --document-name "AWS-RunShellScript" \
    --parameters commands=["pkill -9 -f claude"]
```

### MED-03: Vulnerability Management

**Policy:**
| Severity | SLA | Action |
|----------|-----|--------|
| Critical | 24 hours | Emergency patch |
| High | 7 days | Priority patch |
| Medium | 30 days | Scheduled patch |
| Low | 90 days | Batch update |

**Notification:** Subscribe to `security@anthropic.com` advisories

### MED-04: MCP Server Risk

**Policy:**
```json
{
  "mcp": {
    "defaultPolicy": "deny",
    "allowlist": [
      "hive-postgres",
      "metabase"
    ],
    "approvalRequired": true,
    "isolationRequired": true
  }
}
```

### MED-05: Backup and Recovery

**Configuration Management:**
- `managed-settings.json` in Git (company infra repo)
- Terraform state in S3 with versioning
- Audit logs replicated to secondary region (us-west-2)

**RTO/RPO:**
| Component | RTO | RPO |
|-----------|-----|-----|
| Claude Code service | 4 hours | N/A (stateless) |
| Audit logs | 1 hour | 0 (real-time) |
| Configuration | 1 hour | 0 (Git) |

### MED-06: Developer Training

**Training Module Outline:**
1. Claude Code security model overview
2. Prompt injection risks and recognition
3. Safe usage practices
4. Reporting suspicious behavior
5. Incident response procedures

**Requirement:** Complete before Claude Code access granted

---

## Updated Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Corporate Network                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                  Developer Workstation                           │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │               Claude Code (Sandboxed)                    │   │   │
│  │  │  • bubblewrap/seatbelt isolation                        │   │   │
│  │  │  • managed-settings.json enforced                       │   │   │
│  │  │  • 8hr max session, 30min idle timeout                  │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  │                          │                                      │   │
│  │                          ▼                                      │   │
│  │  ┌─────────────────────────────────────────────────────────┐   │   │
│  │  │            PreToolUse Hooks (Defense Layer)             │   │   │
│  │  │  1. TruffleHog/Gitleaks (secret scanning)              │   │   │
│  │  │  2. Lakera Guard (prompt injection detection)          │   │   │
│  │  │  3. Audit logging → Kinesis Firehose                   │   │   │
│  │  └─────────────────────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                              │                                          │
│                              ▼                                          │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    LLM Guard Proxy                               │   │
│  │  • PII detection and masking                                    │   │
│  │  • Final DLP scan                                               │   │
│  │  • Request/response logging                                     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                         AWS Account                                      │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                      Claude VPC                                  │   │
│  │  ┌───────────────────────────────────────────────────────┐     │   │
│  │  │            Route 53 DNS Firewall                       │     │   │
│  │  │  • Allowlist: api.anthropic.com, *.amazonaws.com      │     │   │
│  │  │  • Block: All other domains                           │     │   │
│  │  │  • Block: DoH endpoints                               │     │   │
│  │  └───────────────────────────────────────────────────────┘     │   │
│  │                          │                                      │   │
│  │                          ▼                                      │   │
│  │  ┌───────────────────────────────────────────────────────┐     │   │
│  │  │            AWS Network Firewall                        │     │   │
│  │  │  • Layer 7 domain filtering (TLS SNI)                 │     │   │
│  │  │  • Explicit allowlist enforcement                     │     │   │
│  │  │  • Anomaly detection                                  │     │   │
│  │  └───────────────────────────────────────────────────────┘     │   │
│  │                          │                                      │   │
│  │                          ▼                                      │   │
│  │  ┌───────────────┐    ┌───────────────────────────────┐        │   │
│  │  │ VPC Endpoint  │───▶│      Amazon Bedrock           │        │   │
│  │  │ (PrivateLink) │    │      (Claude Models)          │        │   │
│  │  └───────────────┘    └───────────────────────────────┘        │   │
│  │                                                                 │   │
│  │  ┌───────────────────────────────────────────────────────┐     │   │
│  │  │              Audit Infrastructure                      │     │   │
│  │  │  • Kinesis Firehose (real-time streaming)             │     │   │
│  │  │  • S3 with Object Lock (COMPLIANCE mode)              │     │   │
│  │  │  • CloudTrail (API audit)                             │     │   │
│  │  │  • CloudWatch (alerts)                                │     │   │
│  │  └───────────────────────────────────────────────────────┘     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Open Questions for CRBRS Review

1. **Lakera Guard vs LLM Guard:** Commercial (Lakera) offers lower latency and better detection; open-source (LLM Guard) offers more control. Recommendation?

2. **Session recording:** Full recording for compliance, or sampling for cost optimization?

3. **MCP server isolation:** Container-level isolation acceptable, or require VM-level?

4. **Prompt injection detection thresholds:** Block on any detection, or allow low-confidence with logging?

---

**AXIOM COMPLETE - CYCLE 2 READY FOR SECURITY REVIEW**
