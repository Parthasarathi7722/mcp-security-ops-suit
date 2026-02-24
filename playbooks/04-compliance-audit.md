# Playbook 04: Compliance Audit

> GRC workflow for running compliance checks across cloud, code, and platform controls using SOCPilot's AI-orchestrated MCP tools.

## How to Invoke

| Method | Command |
|---|---|
| Browser UI | Sidebar → **Compliance Audit** → enter environment or framework (e.g. "AWS prod SOC 2") |
| CLI | `python agent.py --playbook compliance-audit "AWS prod SOC 2 readiness"` |
| API | `POST /playbook` with `{"playbook": "compliance-audit", "target": "..."}` |
| Demo | Works in demo mode — shows realistic 4-tool-call scenario (Drata + Prowler + GHAS + Vault Radar) |

## MCP Servers Required

| Server | Purpose | Required |
|---|---|---|
| `prowler` | Cloud security and compliance checks | Yes |
| `drata` or `vanta` | Compliance framework status | Recommended |
| `ghas` | Code security posture | Recommended |
| `vault` | Secret management hygiene | Optional |
| `vault-radar` | Leaked secret detection | Optional |
| `jira` | Remediation ticket creation | Optional |

## Trigger

Scheduled audit, pre-audit preparation, or ad-hoc compliance review.

## Workflow

### Step 1: Cloud Posture Assessment

**Prompt:**
```
Run a compliance check against [FRAMEWORK] (SOC 2 / CIS / PCI-DSS / ISO 27001)
for our AWS environment.

1. Run Prowler checks mapped to [FRAMEWORK]
2. Summarise: total checks, pass rate, critical failures
3. Group failures by category (IAM, Network, Encryption, Logging)
4. For each critical failure, provide the specific remediation step
```

### Step 2: Code Security Posture

**Prompt:**
```
Pull our code security status:
1. GHAS: Open critical/high Dependabot alerts across all repos
2. GHAS: Open code scanning alerts (CodeQL) — critical/high only
3. GHAS: Any unresolved secret scanning alerts?
4. Vault Radar: Any leaked secrets detected in the last 30 days?
5. Summary: How many repos have zero critical findings?
```

### Step 3: Compliance Platform Status

**Prompt:**
```
From Drata/Vanta:
1. Pull overall compliance status for [FRAMEWORK]
2. List all failing controls with owner and due date
3. Any controls overdue for evidence collection?
4. What's our audit readiness percentage?
5. Compare cloud findings (Prowler) with compliance platform gaps —
   are there inconsistencies?
```

### Step 4: Gap Report

**Prompt:**
```
Generate a compliance gap report combining all findings:
1. Executive summary — overall posture score
2. Critical gaps requiring immediate remediation
3. Framework-specific findings mapped to control IDs
4. Remediation priority matrix (impact vs effort)
5. Create Jira tickets for top 10 critical gaps
```

## Example Session

```
GRC Lead: "We have a SOC 2 Type II audit in 6 weeks. Run a full readiness
           check across our AWS environment, code repos, and Vanta status."

AI: [Runs Prowler SOC 2 checks]
    → 342 checks executed. 91% pass rate.
    → 31 failures: 12 IAM, 8 Encryption, 6 Network, 5 Logging
    → Critical: 4 S3 buckets without encryption, 2 IAM users
      without MFA, 1 CloudTrail not logging data events

    [Queries GHAS]
    → 47 repos scanned. 3 repos with critical Dependabot alerts.
    → 12 open CodeQL findings (2 critical SQL injection).
    → 0 unresolved secret scanning alerts.

    [Queries Vault Radar]
    → 2 secrets detected in last 30 days. Both already rotated.

    [Queries Vanta]
    → SOC 2 readiness: 87%
    → 8 controls failing: AC-2.1, AC-6.1, AU-3.1, CM-6.1,
      IA-2.1, SC-8.1, SC-28.1, SI-4.1
    → 3 controls overdue for evidence refresh (>90 days)

    CROSS-REFERENCE:
    → Prowler S3 encryption failures align with Vanta SC-28.1
    → Prowler MFA failures align with Vanta IA-2.1
    → 2 Vanta control failures (AU-3.1, SI-4.1) not flagged
      by Prowler — likely evidence collection gaps, not
      technical failures

    GAP ANALYSIS:
    🔴 Fix before audit (6 items):
       1. Enable S3 encryption on 4 buckets [SC-28.1]
       2. Enforce MFA for 2 IAM users [IA-2.1]
       3. Enable CloudTrail data events [AU-3.1]
       4. Fix 2 critical SQL injection findings [SI-4.1]
       5. Refresh evidence for 3 overdue controls
       6. Remediate critical Dependabot alerts (3 repos)

    🟡 Recommended (5 items):
       7-11. Network, encryption, logging improvements

    Shall I create Jira tickets for the 6 critical items?
```
