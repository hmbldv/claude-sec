# Axiom: Deployment Configurations Analyzed

**Cycle:** 1
**Last Updated:** 2026-01-15

---

## Configuration Matrix

| Configuration | Security Level | Developer Experience | Implementation Complexity | Recommended For |
|--------------|----------------|---------------------|--------------------------|-----------------|
| **A: Direct Workstation** | Medium | Excellent | Low | Development/POC |
| **B: Dedicated AWS VM** | High | Good | Medium | Production |
| **C: Ephemeral Containers** | Very High | Moderate | High | Sensitive Projects |

---

## Configuration A: Direct Workstation Deployment

### Overview
Claude Code runs directly on developer laptops/workstations with enterprise security controls.

### Architecture
```
Developer Workstation (macOS/Linux)
├── Claude Code (sandboxed)
├── managed-settings.json (enforced)
├── PreToolUse audit hooks
└── Corporate proxy for egress
         │
         ▼
    AWS Bedrock (via PrivateLink)
```

### Security Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| OS Sandboxing | seatbelt (macOS) / bubblewrap (Linux) | Native |
| Policy Enforcement | managed-settings.json | Configured |
| Command Blocklist | deny array in permissions | Configured |
| Audit Logging | PreToolUse hooks → SIEM | Configured |
| Network Egress | Corporate proxy required | Infrastructure |
| Identity | OIDC federation to AWS | Configured |
| Data Classification | Deny patterns for secrets | Configured |

### Pros
- Minimal friction for developers
- Native IDE integration
- Fast iteration cycles
- Lower infrastructure cost

### Cons
- Broader attack surface (full workstation)
- Relies on endpoint security
- Potential for data leakage via clipboard/screenshots
- Harder to audit comprehensively

### Risk Assessment
| Risk | Severity | Mitigation |
|------|----------|------------|
| Secrets in codebase read by Claude | High | Deny patterns for .env, .pem, credentials |
| Command injection via prompts | High | Sandboxing + command blocklist |
| Data exfiltration | Medium | Network sandbox + proxy + DLP |
| Prompt injection from code | Medium | Sandboxing limits blast radius |
| Credential theft | Medium | No access to ~/.ssh, ~/.aws via deny rules |

---

## Configuration B: Dedicated AWS VM

### Overview
Claude Code runs in dedicated EC2 instances within a hardened VPC.

### Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    AWS Account                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │              Claude Code VPC                     │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │        Private Subnet                    │   │   │
│  │  │  ┌─────────────────────────────────┐   │   │   │
│  │  │  │   EC2 (Amazon Linux 2023)       │   │   │   │
│  │  │  │   • CIS Hardened                │   │   │   │
│  │  │  │   • Claude Code + Sandbox       │   │   │   │
│  │  │  │   • No public IP                │   │   │   │
│  │  │  │   • Session Manager access      │   │   │   │
│  │  │  └─────────────────────────────────┘   │   │   │
│  │  │              │                          │   │   │
│  │  │              ▼                          │   │   │
│  │  │  ┌─────────────────────────────────┐   │   │   │
│  │  │  │   VPC Endpoint (Bedrock)        │   │   │   │
│  │  │  └─────────────────────────────────┘   │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
              │
              ▼ (Session Manager / Remote Desktop)
┌─────────────────────────────────────────────────────────┐
│           Developer Workstation                          │
│           (No direct Claude access)                      │
└─────────────────────────────────────────────────────────┘
```

### Security Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| Network Isolation | Private subnet, no IGW | Infrastructure |
| OS Hardening | CIS Amazon Linux 2023 | AMI |
| Access Control | SSM Session Manager only | Infrastructure |
| API Security | VPC Endpoint (no public) | Infrastructure |
| Audit Trail | CloudTrail + VPC Flow Logs | Infrastructure |
| Session Recording | SSM Session Recording to S3 | Infrastructure |
| IAM | OIDC federation, temp creds | Configured |
| Sandboxing | bubblewrap (Linux) | Native |

### Instance Configuration
```yaml
# Terraform example
resource "aws_instance" "claude_code" {
  ami           = "ami-cis-amazon-linux-2023"
  instance_type = "t3.xlarge"

  subnet_id                   = aws_subnet.private.id
  vpc_security_group_ids      = [aws_security_group.claude_code.id]
  iam_instance_profile        = aws_iam_instance_profile.claude_code.name

  metadata_options {
    http_tokens = "required"  # IMDSv2 only
  }

  root_block_device {
    encrypted = true
  }

  tags = {
    Name        = "claude-code-dev"
    Environment = "development"
    DataClass   = "internal"
  }
}
```

### Security Group
```yaml
resource "aws_security_group" "claude_code" {
  name        = "claude-code-sg"
  description = "Claude Code instance security"
  vpc_id      = aws_vpc.claude.id

  # No inbound rules - Session Manager only

  egress {
    description = "HTTPS to VPC endpoints"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [aws_vpc.claude.cidr_block]
  }

  # No other egress - fully isolated
}
```

### Pros
- Strong network isolation
- Comprehensive audit trail (CloudTrail + SSM)
- Session recording for compliance
- No sensitive data on developer workstations
- Easy to destroy/recreate

### Cons
- Higher latency for developers
- Infrastructure cost (EC2 instances)
- Requires VPN/DirectConnect for access
- Learning curve for developers

### Risk Assessment
| Risk | Severity | Mitigation |
|------|----------|------------|
| Secrets exposure | Low | No secrets in VM; git clone only |
| Network exfiltration | Very Low | VPC endpoint only; no IGW |
| Unauthorized access | Low | SSM + OIDC + MFA |
| Persistence attack | Low | Ephemeral instances; daily rebuild |
| Lateral movement | Very Low | Isolated VPC; no other resources |

---

## Configuration C: Ephemeral Container Environment

### Overview
Claude Code runs in short-lived containers that are destroyed after each session.

### Architecture
```
┌─────────────────────────────────────────────────────────┐
│                    AWS Account                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │              ECS Cluster (Fargate)               │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │   Task: Claude Code Session             │   │   │
│  │  │   • Isolated network namespace          │   │   │
│  │  │   • Read-only root filesystem           │   │   │
│  │  │   • No privileged access                │   │   │
│  │  │   • Max 8 hour lifetime                 │   │   │
│  │  │   • Destroyed on disconnect             │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  │              │                                  │   │
│  │              ▼                                  │   │
│  │  ┌─────────────────────────────────────────┐   │   │
│  │  │   CodeCommit / S3 (Code Access)         │   │   │
│  │  │   • Clone on session start              │   │   │
│  │  │   • Push requires approval              │   │   │
│  │  └─────────────────────────────────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### Security Controls

| Control | Implementation | Status |
|---------|---------------|--------|
| Container Isolation | Fargate with gVisor | Infrastructure |
| Ephemeral | Max 8hr TTL, destroy on disconnect | Configured |
| Filesystem | Read-only root; /tmp only writable | Configured |
| Network | Task-level isolation; VPC endpoint only | Infrastructure |
| Code Access | Clone from CodeCommit; push reviewed | Workflow |
| Secrets | None in container; AWS Secrets Manager | Infrastructure |
| Audit | CloudWatch Logs + CloudTrail | Infrastructure |

### Container Security Configuration
```dockerfile
FROM amazonlinux:2023-minimal

# Install Claude Code
RUN curl -fsSL https://claude.ai/install.sh | sh

# Security hardening
RUN chmod 700 /root && \
    rm -rf /var/cache/* && \
    find / -perm /6000 -type f -exec chmod a-s {} \;

# Non-root user
RUN useradd -m -s /bin/bash developer
USER developer
WORKDIR /home/developer/workspace

# Read-only filesystem enforced at runtime
```

### Task Definition
```json
{
  "family": "claude-code-session",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "8192",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/claude-code-execution",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/claude-code-task",
  "containerDefinitions": [
    {
      "name": "claude-code",
      "image": "ACCOUNT.dkr.ecr.REGION.amazonaws.com/claude-code:latest",
      "readonlyRootFilesystem": true,
      "privileged": false,
      "user": "1000:1000",
      "linuxParameters": {
        "capabilities": {
          "drop": ["ALL"]
        }
      },
      "mountPoints": [
        {
          "sourceVolume": "workspace",
          "containerPath": "/home/developer/workspace"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/claude-code",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "session"
        }
      }
    }
  ]
}
```

### Pros
- Maximum isolation (container + network)
- No persistence = no persistent compromise
- Easy to audit (immutable images)
- Scalable per-developer
- Cost-effective (pay per session)

### Cons
- Significant developer friction
- Code changes must be pushed/pulled
- No persistent IDE state
- Complex infrastructure
- Slower iteration cycles

### Risk Assessment
| Risk | Severity | Mitigation |
|------|----------|------------|
| Container escape | Very Low | Fargate + gVisor isolation |
| Data persistence | None | Ephemeral; destroyed on exit |
| Network attack | Very Low | No ingress; VPC endpoint egress only |
| Supply chain | Low | Signed images; ECR scanning |
| Secrets exposure | Very Low | No secrets in container |

---

## Recommendation Matrix

### By Use Case

| Use Case | Recommended Config | Rationale |
|----------|-------------------|-----------|
| General Development | B: Dedicated VM | Balance of security and usability |
| Sensitive Codebases | C: Ephemeral | Maximum isolation |
| POC/Evaluation | A: Workstation | Fastest to implement |
| Regulated Industry | C: Ephemeral | Audit trail + isolation |
| High Velocity Teams | B: Dedicated VM | Good security, less friction |

### By Risk Tolerance

| Risk Tolerance | Recommended Config |
|---------------|-------------------|
| Low (Conservative) | C: Ephemeral Containers |
| Medium | B: Dedicated AWS VM |
| Higher (with compensating controls) | A: Direct Workstation |

---

## Implementation Priority

### Phase 1: Foundation (Week 1-2)
1. Establish Claude for Enterprise contract
2. Configure AWS account with VPC endpoints
3. Deploy managed-settings.json baseline
4. Implement audit logging hooks

### Phase 2: Pilot (Week 3-4)
1. Deploy Configuration B (Dedicated VM) for pilot team
2. Validate security controls
3. Refine managed-settings.json based on feedback
4. Document operational procedures

### Phase 3: Expansion (Week 5+)
1. Evaluate Configuration C for sensitive projects
2. Consider Configuration A for low-risk use cases
3. Automate VM provisioning/deprovisioning
4. Integrate with existing SIEM

---

**Configurations ready for CRBRS security review.**
