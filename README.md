# Claude Code Enterprise Security Framework

A comprehensive security approval framework and architecture for deploying Claude Code in enterprise environments.

## Overview

This repository contains the security assessment, architecture recommendations, and configuration specifications for securely deploying Claude Code (Anthropic's AI coding assistant) in enterprise development teams.

**Status:** APPROVED
**Version:** 2.0
**Last Review:** January 2026

## Key Documents

| Document | Description |
|----------|-------------|
| [manifest.md](manifest.md) | Document index and project overview |
| [security-approval.md](security-approval.md) | Formal security approval with residual risk assessment |
| [architecture-recommendation.md](architecture-recommendation.md) | Complete deployment architecture and implementation guide |

## Scope

This framework covers Claude Code deployment with:

- **Deployment Model:** AWS-only (Linux EC2 instances in VPC)
- **API Provider:** Amazon Bedrock via VPC Private Endpoints
- **Access Method:** AWS SSM Session Manager (no SSH)
- **Sandbox:** bubblewrap containment
- **MCP Servers:** Pre-approved servers via managed-mcp.json

### Supported Use Cases

- Code generation and completion
- Code review and debugging
- Test generation
- Documentation generation
- Git operations (with PR workflow)
- Database queries (read-only via MCP)
- Container operations (restricted)

## Security Controls Summary

| Category | Implementation |
|----------|---------------|
| Isolation | bubblewrap sandbox |
| Policy Enforcement | managed-settings.json |
| MCP Governance | managed-mcp.json |
| DLP | TruffleHog + LLM Guard |
| Prompt Injection | Lakera Guard |
| Audit | Kinesis to S3 Object Lock |
| Network | DNS Firewall + Network Firewall |
| Code Integrity | PR-only workflow |

## Residual Risk

| Category | Risk Level |
|----------|------------|
| Data Exposure | LOW |
| Prompt Injection | LOW |
| Audit Tampering | VERY LOW |
| Network Exfiltration | VERY LOW |
| Code Integrity | VERY LOW |
| **Overall** | **LOW** |

## Repository Structure

```
claude-sec/
├── manifest.md                    # Document index
├── security-approval.md           # Formal approval document
├── architecture-recommendation.md # Implementation architecture
├── raw-vuln-report.md            # Detailed vulnerability analysis
├── comms-vuln-report.md          # Communication-ready report
├── _loop-prompt.md               # Original research prompt
├── axiom/                        # Research team documents
│   ├── research.md
│   ├── configurations.md
│   └── archive/
├── crbrs/                        # Security team documents
│   ├── review.md
│   ├── findings.md
│   └── archive/
└── Archive/                      # Previous versions
```

## Quick Start

1. Review the [manifest.md](manifest.md) for document overview
2. Read [security-approval.md](security-approval.md) for approval conditions
3. Follow [architecture-recommendation.md](architecture-recommendation.md) for implementation

## Key Configuration Files

| File | Location | Purpose |
|------|----------|---------|
| managed-settings.json | /etc/claude-code/ | Permission enforcement |
| managed-mcp.json | /etc/claude-code/ | MCP server control |
| history-security.sh | /etc/profile.d/ | Shell hardening |
| claude-audit.rules | /etc/audit/rules.d/ | auditd configuration |

## Conditions Before Production

- Deploy AWS infrastructure (VPC, endpoints, firewalls)
- Configure managed-settings.json and managed-mcp.json
- Deploy Lakera Guard for prompt injection defense
- Enable S3 Object Lock (COMPLIANCE mode) for audit logs
- Complete developer security training

See [security-approval.md](security-approval.md) for complete checklist.

## License

This security framework is provided as-is for reference. Adapt to your organization's specific requirements and compliance needs.

## Acknowledgments

- **Axiom Research Team** - Security research and architecture design
- **CRBRS Security Team** - Security review and finding analysis
