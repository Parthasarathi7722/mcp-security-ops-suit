# Playbook 05: Secret Leak Response

> Rapid response workflow when a secret (API key, token, password) is detected in source code, logs, or public repositories.

## MCP Servers Required

| Server | Purpose | Required |
|---|---|---|
| `ghas` | Secret scanning alert details | Yes |
| `vault-radar` | Broad secret detection scope | Recommended |
| `vault` | Credential rotation | Yes |
| `sentinel` or `splunk` | Check for secret misuse | Recommended |
| `okta` | Session/identity management | Optional |
| `greynoise` | Check if secret was exploited | Optional |
| `jira` | Incident tracking | Yes |
| `slack` | Immediate notification | Yes |

## Trigger

GitHub secret scanning alert, Vault Radar detection, or manual report of exposed credential.

## Workflow

### Step 1: Assess Exposure (0-5 min)

**Prompt:**
```
Secret scanning alert detected in [REPO]:
1. Pull GHAS secret scanning alert details — type, location, commit, author
2. Check Vault Radar — is this same secret detected anywhere else?
   (other repos, CI logs, Slack messages, documentation)
3. Determine exposure scope:
   - Is the repo public or private?
   - How long has the secret been exposed? (commit timestamp to detection)
   - What access does this secret grant? (service, scope, permissions)
```

### Step 2: Containment (5-15 min)

**Prompt:**
```
⚠ REQUIRES HUMAN APPROVAL before execution:

Based on the exposure assessment:
1. Vault: Rotate the compromised credential immediately
   - Generate new secret
   - Update all dependent services
2. If the secret grants broad access (admin key, root token):
   - Okta: Force logout sessions that used this credential
   - Check for any service accounts using this key
3. GHAS: Resolve the alert as "revoked"
```

### Step 3: Impact Analysis (15-30 min)

**Prompt:**
```
Check if the leaked secret was misused before rotation:
1. Sentinel/Splunk: Query API logs for the affected service
   - Any unusual calls using this credential?
   - Any calls from unexpected IPs or geolocations?
   - Any data access outside normal patterns?
2. GreyNoise: If suspicious IPs found, check reputation
3. Timeline: Secret committed → Secret detected → Secret rotated
   - What could an attacker have done in that window?
```

### Step 4: Document & Prevent

**Prompt:**
```
1. Create a Jira incident ticket with:
   - Secret type and exposure timeline
   - Affected systems and services
   - Containment actions taken
   - Impact analysis results
   - Root cause (why was the secret committed?)
2. Post to Slack #security-incidents
3. Recommend preventive measures:
   - Was push protection enabled? If not, recommend enabling
   - Was pre-commit hook running? If not, recommend adding
   - Should this secret type be a custom pattern in GHAS?
```

## Severity Classification

```
┌─────────┬──────────────────────────────────────────────┐
│ P1      │ Secret in PUBLIC repo or confirmed misuse.   │
│         │ Admin/root level access. Rotate immediately. │
├─────────┼──────────────────────────────────────────────┤
│ P2      │ Secret in private repo with broad access.    │
│         │ No evidence of misuse. Rotate within 1 hour. │
├─────────┼──────────────────────────────────────────────┤
│ P3      │ Secret in private repo with limited scope.   │
│         │ Service-specific key. Rotate within 24 hours.│
├─────────┼──────────────────────────────────────────────┤
│ P4      │ Test/dev credential in private repo.         │
│         │ Non-production. Rotate within 7 days.        │
└─────────┴──────────────────────────────────────────────┘
```

## Example Session

```
DevSecOps: "GHAS alert — AWS access key committed to payments-service repo.
            Run secret leak response."

AI: [Queries GHAS]
    → Secret type: AWS Access Key (AKIA...)
    → Location: payments-service/src/config.py line 23
    → Commit: abc1234 by dev@company.com, 3 days ago
    → Push protection: Was NOT enabled on this repo
    → Repo visibility: Private

    [Queries Vault Radar]
    → Same key found in 2 additional locations:
      - CI log artifact (GitHub Actions run #4521)
      - Internal wiki page (Confluence)
    → Key belongs to service account: payments-svc-prod
    → Permissions: S3 read/write, DynamoDB full access

    EXPOSURE ASSESSMENT:
    - Scope: Production AWS key with S3 + DynamoDB access
    - Duration: 3 days (committed Mon, detected Thu)
    - Repo: Private (limited blast radius)
    - Additional exposure: CI logs + wiki
    - Severity: P2 — private repo, broad access, no confirmed misuse

    ⚠ RECOMMENDED CONTAINMENT (awaiting approval):
    1. Vault: Rotate AWS access key for payments-svc-prod
    2. AWS: Invalidate the old key
    3. Update: payments-service, CI pipeline, wiki page

    Shall I proceed with containment?

DevSecOps: "Yes, rotate it."

AI: [Rotates credential via Vault]
    [Queries Sentinel for CloudTrail logs]
    → AWS API calls from this key in last 3 days:
      - 99.8% from expected CIDR (company VPN)
      - 2 calls from unknown IP 45.33.xx.xx
    [Queries GreyNoise]
    → 45.33.xx.xx: Linode, first seen today, NOT a known scanner
    → SUSPICIOUS — possible credential stuffing attempt

    IMPACT ANALYSIS:
    🟡 2 API calls from suspicious IP detected. Calls were
       S3:ListBuckets — reconnaissance, no data accessed.
       Key was rotated before escalation.

    [Creates Jira SEC-445 with full timeline]
    [Posts to Slack #security-incidents]
    [Recommends: Enable push protection on payments-service repo,
     add pre-commit hook, create custom pattern for internal key format]
```
