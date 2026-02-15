# Playbook 02: Incident Response

> SOC L2/L3 workflow for investigating and responding to security incidents using AI-orchestrated MCP tools.

## MCP Servers Required

| Server | Purpose | Required |
|---|---|---|
| `sentinel` or `splunk` | Log correlation, incident data | Yes |
| `greynoise` | IP reputation, noise vs targeted | Yes |
| `opencti` | Threat actor attribution, IOC context | Recommended |
| `okta` | Identity context, session management | Recommended |
| `vault` | Credential rotation | Recommended |
| `vault-radar` | Secret exposure check | Optional |
| `cloudflare` | WAF blocking, network response | Optional |
| `jira` | Incident ticket management | Yes |
| `slack` | Real-time team communication | Yes |

## Trigger

SIEM alert for suspicious activity — anomalous login, malware detection, data exfiltration indicator, or similar.

## Workflow

### Phase 1: Detection & Triage (0-15 min)

**Prompt:**
```
Sentinel triggered alert [ALERT-ID] for "Suspicious login from unusual location".
1. Pull the full incident details from Sentinel — affected user, source IP,
   timestamp, and any correlated events in the last 24 hours
2. Check GreyNoise for the source IP — is it a known scanner, VPN endpoint,
   or targeted attack?
3. If we have OpenCTI access, check if this IP appears in any threat feeds
```

### Phase 2: Scope Assessment (15-30 min)

**Prompt:**
```
Based on the initial findings:
1. Query Sentinel for all activity from [SOURCE-IP] in the last 7 days —
   what other accounts or systems did it touch?
2. Query Sentinel for all activity by [AFFECTED-USER] in the last 48 hours —
   any unusual patterns, lateral movement, or privilege escalation?
3. Check Okta for [AFFECTED-USER] — recent login history, MFA status,
   active sessions, group memberships
4. Check Vault Radar — has this user exposed any secrets in the last 30 days?
```

### Phase 3: Containment (30-60 min)

**Prompt:**
```
Based on the scope assessment, take containment actions:
1. [If compromised] Okta: Force logout all sessions for [AFFECTED-USER]
2. [If compromised] Vault: Rotate all credentials accessible by [AFFECTED-USER]
3. [If malicious IP] Cloudflare: Add [SOURCE-IP] to WAF block list
4. Create a Jira incident ticket with full timeline:
   - Detection time, source, affected systems
   - All enrichment findings (GreyNoise, OpenCTI, Okta)
   - Containment actions taken
   - Next steps for eradication
```

> **IMPORTANT**: AI should present containment actions for human approval before executing.
> Credential rotation and user session termination require explicit analyst confirmation.

### Phase 4: Communication

**Prompt:**
```
Post an incident update to Slack #security-incidents:
- Incident ID: [JIRA-ID]
- Severity: [P1/P2/P3]
- Status: Contained / Investigating / Resolved
- Summary: One-paragraph description of what happened
- Impact: Systems and users affected
- Actions taken: Containment steps completed
- Next steps: What's still pending
- Incident commander: [NAME]
```

### Phase 5: Post-Incident

**Prompt:**
```
Generate a post-incident summary:
1. Pull the full Sentinel incident timeline
2. List all IOCs identified (IPs, hashes, domains)
3. Map to MITRE ATT&CK — which techniques were used?
4. Check Security Detections — do we have rules covering each technique?
   If not, which Sigma rules should we add?
5. Suggest detection improvements and preventive controls
```

## Severity Classification

```
┌─────────┬──────────────────────────────────────────────────────────┐
│ P1      │ Active data exfiltration, ransomware, or account        │
│ Critical│ compromise with lateral movement. All hands.            │
├─────────┼──────────────────────────────────────────────────────────┤
│ P2      │ Confirmed compromise of single account/system.          │
│ High    │ No evidence of lateral movement yet. IR team engaged.   │
├─────────┼──────────────────────────────────────────────────────────┤
│ P3      │ Suspicious activity requiring investigation.            │
│ Medium  │ No confirmed compromise. Analyst-led investigation.     │
├─────────┼──────────────────────────────────────────────────────────┤
│ P4      │ Low-confidence alert, likely false positive.            │
│ Low     │ Triage and close if benign. Document decision.          │
└─────────┴──────────────────────────────────────────────────────────┘
```

## Example Session

```
Analyst: "Sentinel alert SEC-7721 — impossible travel detected for admin@company.com.
          Login from Nigeria 3 minutes after US login. Run the IR playbook."

AI: [Queries Sentinel] → Full event: admin@company.com logged in from
    US (10:42 UTC) then Nigeria (10:45 UTC). Both successful. Nigeria
    session accessed SharePoint and downloaded 47 files.

    [Queries GreyNoise] → Nigeria IP: 102.88.xx.xx — NOT a known scanner.
    Residential ISP, first seen today. Verdict: suspicious.

    [Queries OpenCTI] → No direct match, but IP range associated with
    BEC (Business Email Compromise) campaigns targeting O365.

    [Queries Okta] → admin@company.com: MFA via push notification
    (possible MFA fatigue attack). Last password change: 6 months ago.
    Member of: Global Admins, Finance-Approvers.

    [Queries Vault Radar] → admin@company.com committed an AWS key
    to internal repo 2 weeks ago (already rotated).

    ASSESSMENT: P1 — Confirmed account compromise via MFA fatigue.
    Attacker accessed SharePoint with admin privileges.

    RECOMMENDED CONTAINMENT:
    ⚠ These actions require your approval:
    1. Okta: Terminate all sessions for admin@company.com
    2. Okta: Force MFA re-enrollment (hardware key)
    3. Vault: Rotate all secrets accessible by this user
    4. Cloudflare: Block 102.88.xx.xx/24

    Shall I proceed?

Analyst: "Yes, execute containment. Post to #security-incidents as P1."

AI: [Executes containment steps]
    [Creates JIRA INC-892 with full timeline]
    [Posts P1 update to Slack #security-incidents]
```
