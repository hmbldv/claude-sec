# Architecture Recommendation: Claude Code Enterprise Deployment

**Document Type:** Implementation Architecture
**Version:** 2.0
**Date:** 2026-01-15
**Author:** Axiom Research Team (Thesis)
**Status:** APPROVED by CRBRS

---

## Executive Summary

This document provides the complete technical architecture for secure enterprise deployment of Claude Code. It covers infrastructure design, security controls, configuration specifications, and operational procedures.

**Architecture Highlights:**
- AWS-only deployment on Linux EC2 instances
- Multi-layer security controls (network, application, audit)
- Comprehensive permission management via managed-settings.json
- MCP server governance via managed-mcp.json
- NIST CSF 2.0 aligned security posture

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Infrastructure Components](#infrastructure-components)
3. [Security Controls](#security-controls)
4. [Configuration Specifications](#configuration-specifications)
5. [MCP Server Configuration](#mcp-server-configuration)
6. [Docker Configuration](#docker-configuration)
7. [Shell Security Configuration](#shell-security-configuration)
8. [Audit Architecture](#audit-architecture)
9. [Network Configuration](#network-configuration)
10. [Implementation Checklist](#implementation-checklist)

---

## Architecture Overview

### High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────────────────────────┐
│                                   AWS ACCOUNT                                        │
│                                                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────────┐ │
│  │                            CLAUDE CODE VPC (10.0.0.0/16)                       │ │
│  │                                                                                │ │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    PRIVATE SUBNET (10.0.1.0/24)                          │ │ │
│  │  │                                                                          │ │ │
│  │  │  ┌────────────────────────────────────────────────────────────────────┐ │ │ │
│  │  │  │                  EC2: CLAUDE CODE INSTANCE                         │ │ │ │
│  │  │  │                                                                    │ │ │ │
│  │  │  │  ┌──────────────────────────────────────────────────────────────┐ │ │ │ │
│  │  │  │  │                    APPLICATION LAYER                         │ │ │ │ │
│  │  │  │  │                                                              │ │ │ │ │
│  │  │  │  │  Claude Code CLI    bubblewrap    managed-settings.json     │ │ │ │ │
│  │  │  │  │  MCP Servers        managed-mcp.json    PreToolUse Hooks    │ │ │ │ │
│  │  │  │  └──────────────────────────────────────────────────────────────┘ │ │ │ │
│  │  │  │                                                                    │ │ │ │
│  │  │  │  ┌──────────────────────────────────────────────────────────────┐ │ │ │ │
│  │  │  │  │                    SECURITY LAYER                            │ │ │ │ │
│  │  │  │  │                                                              │ │ │ │ │
│  │  │  │  │  Lakera Guard       TruffleHog        LLM Guard Proxy       │ │ │ │ │
│  │  │  │  │  auditd             syslog            history-security.sh   │ │ │ │ │
│  │  │  │  └──────────────────────────────────────────────────────────────┘ │ │ │ │
│  │  │  │                                                                    │ │ │ │
│  │  │  │  ┌──────────────────────────────────────────────────────────────┐ │ │ │ │
│  │  │  │  │                    CONTAINER LAYER (Optional)                │ │ │ │ │
│  │  │  │  │                                                              │ │ │ │ │
│  │  │  │  │  Docker (restricted)    claude-isolated network             │ │ │ │ │
│  │  │  │  │  ECR-only registry      Resource limits enforced            │ │ │ │ │
│  │  │  │  └──────────────────────────────────────────────────────────────┘ │ │ │ │
│  │  │  │                                                                    │ │ │ │
│  │  │  │  Instance Type: m5.xlarge | AMI: Amazon Linux 2023               │ │ │ │
│  │  │  │  Access: AWS SSM Session Manager (no SSH)                        │ │ │ │
│  │  │  └────────────────────────────────────────────────────────────────────┘ │ │ │
│  │  │                                                                          │ │ │
│  │  └──────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                        │                                       │ │
│  │  ┌─────────────────────────────────────▼─────────────────────────────────────┐ │ │
│  │  │                         NETWORK CONTROLS                                   │ │ │
│  │  │                                                                            │ │ │
│  │  │  Route 53 DNS Firewall ──► AWS Network Firewall ──► NAT Gateway           │ │ │
│  │  │                                                                            │ │ │
│  │  │  Allowlist: api.anthropic.com, *.amazonaws.com, gitlab.com, etc.          │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────┘ │ │
│  │                                        │                                       │ │
│  │  ┌─────────────────────────────────────▼─────────────────────────────────────┐ │ │
│  │  │                    VPC ENDPOINTS (PrivateLink)                             │ │ │
│  │  │                                                                            │ │ │
│  │  │  Bedrock │ SSM │ SSM Messages │ S3 │ CloudWatch Logs │ Kinesis           │ │ │
│  │  └────────────────────────────────────────────────────────────────────────────┘ │ │
│  └───────────────────────────────────────────────────────────────────────────────┘ │
│                                                                                      │
│  ┌───────────────────────────────────────────────────────────────────────────────┐ │
│  │                            AUDIT INFRASTRUCTURE                                │ │
│  │                                                                                │ │
│  │  Kinesis Firehose ──► S3 Bucket (Object Lock COMPLIANCE) ──► SIEM            │ │
│  │  SSM Session Logs ──► CloudWatch Logs ──► Long-term Retention                │ │
│  │  CloudTrail ──► S3 ──► API Audit Trail                                       │ │
│  │  auditd ──► rsyslog ──► CloudWatch Agent ──► CloudWatch Logs                 │ │
│  └───────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────┘
                                           │
                                           │ AWS SSM Session Manager
                                           ▼
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                               DEVELOPER ACCESS                                        │
│                                                                                       │
│  Developer Workstation (any location)                                                │
│  ├─ No Claude Code installed locally                                                 │
│  ├─ AWS SSM Session Manager via AWS CLI/Console                                      │
│  ├─ IAM Identity Center SSO + MFA                                                    │
│  └─ All sessions recorded and auditable                                              │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Infrastructure Components

### EC2 Instance Specification

| Component | Specification |
|-----------|---------------|
| Instance Type | m5.xlarge (4 vCPU, 16 GB RAM) |
| AMI | Amazon Linux 2023 |
| Storage | 100 GB gp3 EBS (encrypted) |
| IAM Role | claude-code-instance-role |
| Security Group | claude-code-sg (egress only) |
| Subnet | Private subnet (no public IP) |

### Terraform: EC2 Instance

```terraform
resource "aws_instance" "claude_code" {
  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = "m5.xlarge"
  subnet_id              = aws_subnet.private.id
  iam_instance_profile   = aws_iam_instance_profile.claude_code.name
  vpc_security_group_ids = [aws_security_group.claude_code.id]

  root_block_device {
    volume_size = 100
    volume_type = "gp3"
    encrypted   = true
    kms_key_id  = aws_kms_key.claude_code.arn
  }

  metadata_options {
    http_tokens                 = "required"  # IMDSv2 only
    http_put_response_hop_limit = 1
  }

  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    managed_settings = file("${path.module}/managed-settings.json")
    managed_mcp      = file("${path.module}/managed-mcp.json")
  }))

  tags = {
    Name        = "claude-code-instance"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

### IAM Role

```terraform
resource "aws_iam_role" "claude_code" {
  name = "claude-code-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ec2.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.claude_code.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "bedrock" {
  name = "bedrock-invoke"
  role = aws_iam_role.claude_code.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream"
      ]
      Resource = "arn:aws:bedrock:*::foundation-model/anthropic.claude-*"
    }]
  })
}

resource "aws_iam_role_policy" "audit" {
  name = "audit-logging"
  role = aws_iam_role.claude_code.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kinesis:PutRecord",
          "kinesis:PutRecords"
        ]
        Resource = aws_kinesis_firehose_delivery_stream.claude_audit.arn
      },
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.claude_code.arn}:*"
      }
    ]
  })
}
```

---

## Security Controls

### Control Matrix

| Layer | Control | Implementation | Status |
|-------|---------|----------------|--------|
| Network | DNS Firewall | Route 53 Resolver Firewall | Required |
| Network | Egress Control | AWS Network Firewall | Required |
| Network | Private Connectivity | VPC Endpoints | Required |
| Application | Permission Enforcement | managed-settings.json | Required |
| Application | MCP Governance | managed-mcp.json | Required |
| Application | Sandbox | bubblewrap | Required |
| Application | Prompt Injection | Lakera Guard | Required |
| Application | Secret Scanning | TruffleHog | Required |
| Audit | Immutable Logs | S3 Object Lock | Required |
| Audit | API Logging | CloudTrail | Required |
| Audit | Command Logging | auditd | Required |
| Audit | Session Recording | SSM | Required |
| Shell | History Protection | history-security.sh | Required |
| Container | Docker Restrictions | Permission deny list | Required |

---

## Configuration Specifications

### managed-settings.json

Deploy to `/etc/claude-code/managed-settings.json`:

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
      "Bash(su:*)",
      "Bash(chmod:777:*)",
      "Bash(chmod:666:*)",
      "Bash(chmod:-R:777:*)",
      "Bash(chown:-R:*:*:/*)",
      "Bash(setcap:*)",
      "Bash(chroot:*)",

      "Bash(nc:*)",
      "Bash(ncat:*)",
      "Bash(netcat:*)",
      "Bash(socat:*)",
      "Bash(nmap:*)",
      "Bash(masscan:*)",

      "Bash(rm:-rf:/*)",
      "Bash(rm:-rf:~/*)",
      "Bash(rm:-rf:.:*)",
      "Bash(rm:-rf:../*)",
      "Bash(mkfs:*)",
      "Bash(dd:if=*:of=/dev/*)",
      "Bash(shred:*)",
      "Bash(wipefs:*)",

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

      "Bash(wget:-r:*)",
      "Bash(wget:--recursive:*)",
      "Bash(wget:-b:*)",
      "Bash(wget:--background:*)",
      "Bash(wget:--post-data:*)",
      "Bash(wget:--post-file:*)",
      "Bash(wget:*:|:sh)",
      "Bash(wget:*:|:bash)",

      "Bash(ssh:-D:*)",
      "Bash(ssh:-R:*)",
      "Bash(ssh:-L:*)",
      "Bash(ssh:-w:*)",
      "Bash(ssh:-N:*)",

      "Bash(scp:*)",
      "Bash(rsync:*)",
      "Bash(ftp:*)",
      "Bash(sftp:*)",

      "Bash(git:push:--force:*)",
      "Bash(git:push:-f:*)",
      "Bash(git:commit:--no-verify:*)",

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

      "Bash(auditctl:-D)",
      "Bash(auditctl:-e:0)",
      "Bash(service:auditd:stop)",
      "Bash(systemctl:stop:auditd)",
      "Bash(rm:/var/log/audit/*)",
      "Bash(truncate:/var/log/*)"
    ],

    "allow": [
      "Read(*)",
      "Glob(*)",
      "Grep(*)",

      "Bash(git:status:*)",
      "Bash(git:diff:*)",
      "Bash(git:log:*)",
      "Bash(git:branch:*)",
      "Bash(git:show:*)",
      "Bash(git:blame:*)",
      "Bash(git:checkout:*)",
      "Bash(git:add:*)",
      "Bash(git:commit:*)",
      "Bash(git:stash:*)",

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

      "Bash(curl:-I:*)",
      "Bash(curl:--head:*)",
      "Bash(curl:-s:https://registry.npmjs.org/*)",
      "Bash(curl:-s:https://pypi.org/*)",
      "Bash(curl:-s:https://api.github.com/*)",

      "Bash(wget:--spider:*)",
      "Bash(wget:-q:--spider:*)",

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

      "Bash(docker:ps:*)",
      "Bash(docker:images:*)",
      "Bash(docker:logs:*)",
      "Bash(docker:inspect:*)",
      "Bash(docker:stats:*)"
    ],

    "ask": [
      "Write(*)",
      "Edit(*)",

      "Bash(git:push:*)",
      "Bash(git:pull:*)",
      "Bash(git:fetch:*)",
      "Bash(git:clone:*)",
      "Bash(git:reset:--hard:*)",
      "Bash(git:rebase:*)",

      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(ssh:*)",

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

      "Bash(chmod:*)",
      "Bash(chown:*)",

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

## MCP Server Configuration

### managed-mcp.json

Deploy to `/etc/claude-code/managed-mcp.json`:

```json
{
  "mcpServers": {
    "internal-db-readonly": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres"],
      "env": {
        "POSTGRESQL_URL": "${ssm:/claude-code/db-readonly-url}"
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

### Adding New MCP Servers

New MCP servers require:

1. Security review ticket submitted
2. Code review of server implementation
3. Risk assessment update
4. CRBRS approval
5. Addition via managed-mcp.json (change control)
6. Audit logging verification

---

## Docker Configuration

### Network Setup

```bash
# Create isolated network for Claude-initiated containers
docker network create --internal --driver=bridge claude-isolated

# Verify network isolation
docker network inspect claude-isolated
```

### Resource Limits (via wrapper script)

```bash
#!/bin/bash
# /opt/security/docker-wrapper.sh

# Enforce resource limits on all Claude-initiated containers
exec docker "$@" \
  --memory=2g \
  --cpus=2 \
  --pids-limit=100 \
  --network=claude-isolated \
  --read-only
```

---

## Shell Security Configuration

### /etc/profile.d/history-security.sh

```bash
#!/bin/bash
# Enterprise History Security Configuration
# Deploy to /etc/profile.d/history-security.sh

# Force history recording
export HISTFILE="$HOME/.bash_history"
export HISTFILESIZE=10000
export HISTSIZE=10000
export HISTCONTROL=""
export HISTIGNORE=""
export HISTTIMEFORMAT="%F %T "

# Make variables read-only
readonly HISTFILE
readonly HISTFILESIZE
readonly HISTSIZE
readonly HISTCONTROL
readonly HISTIGNORE
readonly HISTTIMEFORMAT

# Append immediately
shopt -s histappend
export PROMPT_COMMAND="history -a; $PROMPT_COMMAND"

# Log to syslog
function log_command {
    declare COMMAND
    COMMAND=$(fc -ln -0)
    logger -p local1.notice -t bash -i -- "${USER}:$(tty):${COMMAND}"
}
trap log_command DEBUG
```

### /etc/audit/rules.d/claude-audit.rules

```bash
# Monitor all command execution
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b32 -S execve -k command_execution

# Monitor history file modifications
-w /home -p wa -k history_modification
-w /root/.bash_history -p wa -k root_history

# Monitor audit configuration changes
-w /etc/audit/ -p wa -k audit_config
-w /var/log/audit/ -p wa -k audit_logs

# Monitor profile modifications
-w /etc/profile -p wa -k profile_modification
-w /etc/profile.d/ -p wa -k profiled_modification
-w /etc/environment -p wa -k env_modification
```

---

## Audit Architecture

### Kinesis to S3 Pipeline

```terraform
resource "aws_kinesis_firehose_delivery_stream" "claude_audit" {
  name        = "claude-code-audit-stream"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose.arn
    bucket_arn = aws_s3_bucket.audit_logs.arn
    prefix     = "claude-code/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"

    buffering_size     = 5
    buffering_interval = 60

    compression_format = "GZIP"
  }
}

resource "aws_s3_bucket" "audit_logs" {
  bucket = "company-claude-code-audit-logs"
}

resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = 365
    }
  }
}
```

---

## Network Configuration

### DNS Firewall

```terraform
resource "aws_route53_resolver_firewall_domain_list" "allowed" {
  name = "claude-allowed-domains"
  domains = [
    "api.anthropic.com",
    "*.amazonaws.com",
    "gitlab.com",
    "*.gitlab.com",
    "*.atlassian.net",
    "*.atlassian.com",
    "*.atl-paas.net",
    "github.com",
    "*.github.com",
    "*.githubusercontent.com",
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "sum.golang.org"
  ]
}

resource "aws_route53_resolver_firewall_rule" "allow" {
  name                    = "allow-approved-domains"
  action                  = "ALLOW"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.allowed.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.claude.id
  priority                = 100
}

resource "aws_route53_resolver_firewall_rule" "block_all" {
  name                    = "block-all-other"
  action                  = "BLOCK"
  block_response          = "NXDOMAIN"
  firewall_domain_list_id = aws_route53_resolver_firewall_domain_list.all.id
  firewall_rule_group_id  = aws_route53_resolver_firewall_rule_group.claude.id
  priority                = 200
}
```

### VPC Endpoints

```terraform
locals {
  vpc_endpoints = [
    "com.amazonaws.${var.region}.bedrock-runtime",
    "com.amazonaws.${var.region}.ssm",
    "com.amazonaws.${var.region}.ssmmessages",
    "com.amazonaws.${var.region}.s3",
    "com.amazonaws.${var.region}.logs",
    "com.amazonaws.${var.region}.kinesis-firehose"
  ]
}

resource "aws_vpc_endpoint" "private" {
  for_each = toset(local.vpc_endpoints)

  vpc_id              = aws_vpc.claude.id
  service_name        = each.value
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.vpc_endpoints.id]
  private_dns_enabled = true
}
```

---

## Implementation Checklist

### Phase 1: Infrastructure (Week 1)

- [ ] Create VPC with private subnets
- [ ] Deploy VPC endpoints
- [ ] Configure DNS Firewall
- [ ] Configure Network Firewall
- [ ] Create IAM roles and policies
- [ ] Deploy EC2 instance with user data
- [ ] Verify SSM connectivity

### Phase 2: Security Controls (Week 2)

- [ ] Deploy managed-settings.json
- [ ] Deploy managed-mcp.json
- [ ] Install and configure Lakera Guard
- [ ] Install and configure TruffleHog
- [ ] Deploy LLM Guard proxy
- [ ] Configure PreToolUse hooks

### Phase 3: Audit Infrastructure (Week 3)

- [ ] Configure Kinesis Firehose
- [ ] Create S3 bucket with Object Lock
- [ ] Enable CloudTrail
- [ ] Configure SSM session logging
- [ ] Deploy auditd configuration
- [ ] Deploy history-security.sh
- [ ] Configure CloudWatch agent

### Phase 4: Validation (Week 4)

- [ ] Test permission enforcement
- [ ] Verify audit log flow
- [ ] Test network controls
- [ ] Conduct security validation
- [ ] Complete developer training
- [ ] Document operational procedures

### Phase 5: Go-Live

- [ ] Final security review
- [ ] Production deployment
- [ ] Monitoring activation
- [ ] On-call procedures enabled

---

## Document Control

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-15 | Initial architecture | Axiom |
| 1.1 | 2026-01-15 | AWS-only, command analysis | Axiom |
| 2.0 | 2026-01-15 | MCP, Docker, HISTCONTROL, NIST | Axiom |

---

**END OF ARCHITECTURE RECOMMENDATION**
