# Playbook 06: Cloud Security Posture Review

> Periodic cloud security assessment using SOCPilot to correlate findings from infrastructure scanning, WAF events, SIEM cloud logs, and secrets hygiene — with a prioritised remediation roadmap.

## How to Invoke

| Method | Command |
|---|---|
| Browser UI | Sidebar → **Cloud Posture** → enter cloud environment (e.g. "AWS prod") |
| CLI | `python agent.py --playbook cloud-posture-review "AWS prod account"` |
| API | `POST /playbook` with `{"playbook": "cloud-posture-review", "target": "..."}` |
| Demo | Works in demo mode — shows realistic 4-tool-call scenario (Prowler + Cloudflare + Sentinel + Vault) |

## MCP Servers Required

| Server | Purpose | Required |
|---|---|---|
| `prowler` | Cloud infrastructure scanning | Yes |
| `cloudflare` | WAF and network security status | Recommended |
| `sentinel` or `splunk` | Cloud audit logs (CloudTrail/Activity Log) | Recommended |
| `vault` | Secret management hygiene | Optional |
| `drata` or `vanta` | Compliance framework mapping | Optional |
| `jira` | Remediation tracking | Optional |

## Trigger

Weekly/monthly scheduled review, post-deployment check, or pre-audit preparation.

## Workflow

### Step 1: Infrastructure Scan

**Prompt:**
```
Run a Prowler security assessment against our [AWS/Azure/GCP] environment:
1. Execute CIS Benchmark checks
2. Focus areas: IAM, networking, encryption, logging, storage
3. Summarise: total checks, pass rate, critical/high/medium failures
4. Compare with last scan — what's new, what's regressed?
```

### Step 2: Network Security Review

**Prompt:**
```
Check our network security posture:
1. Cloudflare: Pull WAF event summary for the last 7 days
   - Top blocked attack types
   - Top targeted endpoints
   - Any rate limiting triggers?
   - Zero Trust policy violations?
2. Prowler: Any security groups with 0.0.0.0/0 ingress?
3. Prowler: Any public S3 buckets or storage accounts?
```

### Step 3: Log & Monitor Coverage

**Prompt:**
```
Verify our logging and monitoring coverage:
1. Prowler: Is CloudTrail/Activity Log enabled everywhere?
   - Data event logging?
   - Multi-region?
   - Log file validation?
2. Sentinel: Are cloud logs flowing? Any gaps in the last 7 days?
3. Are GuardDuty/Defender for Cloud findings being ingested?
```

### Step 4: Remediation Planning

**Prompt:**
```
For all critical and high findings:
1. Group by remediation effort (quick wins vs infrastructure changes)
2. Map to compliance frameworks if Drata/Vanta is connected
3. Create Jira tickets for top 5 critical items with:
   - Finding details and affected resources
   - Specific remediation steps (CLI commands where possible)
   - Compliance control mapping
   - Suggested owner (team/role)
```

## Example Session

```
Cloud Engineer: "Monthly AWS posture review. Run the full assessment
                 and compare with last month."

AI: [Runs Prowler CIS checks]
    → 489 checks executed. Pass rate: 93% (up from 91% last month)
    → 34 failures (down from 44):
      - IAM: 8 (was 12) — improved MFA adoption
      - Network: 11 (was 10) — 1 new security group issue
      - Encryption: 7 (was 9) — S3 encryption project working
      - Logging: 5 (was 8) — CloudTrail gaps fixed
      - Storage: 3 (was 5) — public bucket remediation progressing

    REGRESSION ALERT:
    🔴 New: sg-0a1b2c3d allows SSH (22) from 0.0.0.0/0
       Created 2 days ago. Resource: staging-bastion.
       Not present in last scan.

    [Queries Cloudflare]
    → WAF blocked 12,400 requests this week:
      - SQL injection attempts: 4,200 (targeting /api/search)
      - XSS attempts: 3,100
      - Path traversal: 2,800
      - Rate limited: 2,300 (bot scraping /pricing)
    → Zero Trust: 3 policy violations (contractor VPN expired)

    [Queries Sentinel]
    → CloudTrail: Continuous flow, no gaps
    → GuardDuty: 2 low findings (port scan from known scanner)
    → Cost anomaly: 40% spike in Lambda invocations (investigate)

    POSTURE SCORE: 93% (improving)

    QUICK WINS (this week):
    1. Close SSH security group sg-0a1b2c3d (< 5 min)
    2. Renew 3 contractor VPN certificates (< 30 min)
    3. Investigate Lambda cost spike (< 1 hour)

    PROJECTS (ongoing):
    4. Complete S3 encryption for remaining 7 buckets
    5. Enable CloudTrail data events in us-west-2

    Shall I create Jira tickets for these items?
```
