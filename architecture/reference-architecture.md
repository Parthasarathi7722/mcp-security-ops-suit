# Reference Architecture

## Full Stack Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SOC ANALYST INTERFACE                               │
│              (Any MCP-Compatible AI Client / Agent)                        │
│                                                                             │
│  "Check the critical Dependabot alert, see if the CVE is being exploited,  │
│   pull threat intel, and create a P1 Jira ticket with remediation steps"   │
└────────────────────────────────────┬────────────────────────────────────────┘
                                     │
                              MCP Protocol Layer
                          (JSON-RPC over stdio/SSE)
                                     │
         ┌───────────────────────────┼───────────────────────────┐
         │                           │                           │
    ┌────▼─────┐              ┌──────▼──────┐             ┌─────▼──────┐
    │  DETECT  │              │ INVESTIGATE │             │  RESPOND   │
    └────┬─────┘              └──────┬──────┘             └─────┬──────┘
         │                           │                          │
    ┌────┴──────────────┐    ┌───────┴──────────────┐   ┌──────┴──────────┐
    │                   │    │                      │   │                 │
    │ ┌───────────────┐ │    │ ┌──────────────────┐ │   │ ┌─────────────┐│
    │ │ GHAS          │ │    │ │ Sentinel/Splunk  │ │   │ │ Jira        ││
    │ │ - Dependabot  │ │    │ │ - KQL/SPL query  │ │   │ │ - Tickets   ││
    │ │ - CodeQL      │ │    │ │ - Incidents      │ │   │ │ - SLA track ││
    │ │ - Secrets     │ │    │ │ - Analytics      │ │   │ │             ││
    │ └───────────────┘ │    │ └──────────────────┘ │   │ └─────────────┘│
    │                   │    │                      │   │                 │
    │ ┌───────────────┐ │    │ ┌──────────────────┐ │   │ ┌─────────────┐│
    │ │ Semgrep       │ │    │ │ GreyNoise        │ │   │ │ Slack       ││
    │ │ - SAST scan   │ │    │ │ - IP reputation  │ │   │ │ - Alerts    ││
    │ │ - 5000+ rules │ │    │ │ - RIOT checks    │ │   │ │ - Updates   ││
    │ └───────────────┘ │    │ │ - Vuln intel     │ │   │ │             ││
    │                   │    │ └──────────────────┘ │   │ └─────────────┘│
    │ ┌───────────────┐ │    │                      │   │                 │
    │ │ Snyk          │ │    │ ┌──────────────────┐ │   │ ┌─────────────┐│
    │ │ - SCA scan    │ │    │ │ OpenCTI          │ │   │ │ Vault       ││
    │ │ - License     │ │    │ │ - IOCs           │ │   │ │ - Rotate    ││
    │ │ - Container   │ │    │ │ - Threat actors  │ │   │ │ - Revoke    ││
    │ └───────────────┘ │    │ │ - MITRE ATT&CK   │ │   │ │             ││
    │                   │    │ └──────────────────┘ │   │ └─────────────┘│
    │ ┌───────────────┐ │    │                      │   │                 │
    │ │ Trivy         │ │    │ ┌──────────────────┐ │   │ ┌─────────────┐│
    │ │ - Container   │ │    │ │ Vault Radar      │ │   │ │ Okta        ││
    │ │ - SBOM        │ │    │ │ - Leaked secrets │ │   │ │ - Disable   ││
    │ └───────────────┘ │    │ │ - Risk scoring   │ │   │ │ - Deprov    ││
    │                   │    │ └──────────────────┘ │   │ └─────────────┘│
    │ ┌───────────────┐ │    │                      │   │                 │
    │ │ Prowler       │ │    │ ┌──────────────────┐ │   │ ┌─────────────┐│
    │ │ - Cloud scan  │ │    │ │ Security         │ │   │ │ Cloudflare  ││
    │ │ - CIS/SOC2    │ │    │ │ Detections       │ │   │ │ - WAF rules ││
    │ │ - Remediation │ │    │ │ - Sigma rules    │ │   │ │ - Zero Trust││
    │ └───────────────┘ │    │ │ - ESCU           │ │   │ └─────────────┘│
    │                   │    │ │ - KQL templates  │ │   │                 │
    │ ┌───────────────┐ │    │ └──────────────────┘ │   │ ┌─────────────┐│
    │ │ StackHawk     │ │    │                      │   │ │ Drata/Vanta ││
    │ │ - DAST scan   │ │    │ ┌──────────────────┐ │   │ │ - Compliance││
    │ │ - API test    │ │    │ │ Datadog          │ │   │ │ - Controls  ││
    │ └───────────────┘ │    │ │ - Metrics        │ │   │ │ - Reports   ││
    │                   │    │ │ - Logs           │ │   │ └─────────────┘│
    └───────────────────┘    │ │ - RCA            │ │   └────────────────┘
                             │ └──────────────────┘ │
                             └──────────────────────┘
```

## Data Flow: Incident Response

```
   Alert Fires                 AI Correlates               AI Responds
   ──────────                  ─────────────               ───────────

┌──────────────┐          ┌───────────────────┐       ┌──────────────────┐
│ Sentinel     │          │                   │       │                  │
│ "Suspicious  │──────▶   │ AI Co-pilot:      │──────▶│ Auto-generated:  │
│  login from  │          │                   │       │                  │
│  unusual IP" │          │ 1. Query Sentinel │       │ - Jira P1 ticket │
└──────────────┘          │    for full event │       │   with timeline  │
                          │                   │       │                  │
                          │ 2. GreyNoise:     │       │ - Slack alert    │
                          │    IP reputation  │       │   to #incidents  │
                          │    → "Known       │       │                  │
                          │    scanner"       │       │ - Okta: disable  │
                          │                   │       │   compromised    │
                          │ 3. OpenCTI:       │       │   user session   │
                          │    Any threat     │       │                  │
                          │    actor matches? │       │ - Vault: rotate  │
                          │                   │       │   affected API   │
                          │ 4. Okta:          │       │   keys           │
                          │    User's recent  │       │                  │
                          │    activity       │       │ - Cloudflare:    │
                          │                   │       │   block IP in    │
                          │ 5. Vault Radar:   │       │   WAF            │
                          │    Any secrets    │       │                  │
                          │    exposed?       │       └──────────────────┘
                          └───────────────────┘
```

## Data Flow: Vulnerability Triage

```
  New Finding              AI Enriches                  AI Prioritises
  ───────────              ───────────                  ──────────────

┌──────────────┐       ┌──────────────────┐       ┌───────────────────────┐
│ GHAS Alert   │       │                  │       │                       │
│ "Critical    │──▶    │ 1. GHAS: full    │──▶    │ AI Analysis:          │
│  CVE in      │       │    alert details │       │                       │
│  lodash"     │       │    + affected    │       │ "CVE-2024-XXXX in     │
└──────────────┘       │    repos         │       │  lodash is critical   │
                       │                  │       │  but NOT reachable    │
                       │ 2. Snyk: is it   │       │  in your code path.   │
                       │    reachable?    │       │  GreyNoise confirms   │
                       │    transitive?   │       │  active exploitation. │
                       │                  │       │  Recommend: upgrade   │
                       │ 3. GreyNoise:    │       │  to 4.17.21 within   │
                       │    active        │       │  48h."                │
                       │    exploitation? │       │                       │
                       │                  │       │ → Creates Jira ticket │
                       │ 4. OpenCTI:      │       │   Priority: P2       │
                       │    threat actor  │       │   SLA: 48 hours      │
                       │    campaigns?    │       │   Assignee: DevTeam   │
                       │                  │       │                       │
                       │ 5. Security      │       │ → Posts to Slack      │
                       │    Detections:   │       │   #vuln-triage        │
                       │    any Sigma     │       │                       │
                       │    rules for     │       └───────────────────────┘
                       │    this CVE?     │
                       └──────────────────┘
```

## Deployment Tiers

### Tier 1: Solo Analyst (Free)

```
┌──────────────────────────────────────────┐
│         MCP Security Co-pilot             │
│                                          │
│  ┌──────┐  ┌────────┐  ┌──────────────┐ │
│  │ GHAS │  │Semgrep │  │ GreyNoise    │ │
│  │(free)│  │ (free) │  │ (community)  │ │
│  └──────┘  └────────┘  └──────────────┘ │
│                                          │
│  ┌──────────────────────────────────────┐│
│  │ Security Detections (Sigma/ESCU)    ││
│  └──────────────────────────────────────┘│
└──────────────────────────────────────────┘
```

### Tier 2: Team SOC

```
┌──────────────────────────────────────────────────────────┐
│                  MCP Security Co-pilot                    │
│                                                          │
│  DETECT          INVESTIGATE        RESPOND              │
│  ┌──────┐        ┌──────────┐       ┌──────┐            │
│  │ GHAS │        │ Sentinel │       │ Jira │            │
│  │Semgrep│       │GreyNoise │       │Slack │            │
│  │ Snyk │        │ Detections│      │Vault │            │
│  │Prowler│       │ Datadog  │       │      │            │
│  └──────┘        └──────────┘       └──────┘            │
└──────────────────────────────────────────────────────────┘
```

### Tier 3: Enterprise

```
┌──────────────────────────────────────────────────────────────────────────┐
│                  AI Security Operations Platform                         │
│           (MCP Co-pilot / Custom Agent via API)                         │
│                                                                          │
│  DETECT            INVESTIGATE          RESPOND          COMPLY          │
│  ┌──────────┐      ┌──────────────┐     ┌───────────┐   ┌────────────┐ │
│  │ GHAS     │      │ Sentinel     │     │ Jira      │   │ Drata      │ │
│  │ Semgrep  │      │ Splunk       │     │ Slack     │   │ Vanta      │ │
│  │ Snyk     │      │ Elastic      │     │ Vault     │   │ Prowler    │ │
│  │ Trivy    │      │ Datadog      │     │ Okta      │   │            │ │
│  │ StackHawk│      │ GreyNoise    │     │ Cloudflare│   │            │ │
│  │ Prowler  │      │ OpenCTI      │     │ GitHub    │   │            │ │
│  │          │      │ Vault Radar  │     │           │   │            │ │
│  │          │      │ VirusTotal   │     │           │   │            │ │
│  │          │      │ Detections   │     │           │   │            │ │
│  └──────────┘      └──────────────┘     └───────────┘   └────────────┘ │
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐│
│  │ MCP Gateway (MintMCP / Cloudflare Portal)                           ││
│  │ - Centralised auth (OAuth 2.1)                                      ││
│  │ - Audit logging to SIEM                                             ││
│  │ - Rate limiting per tool                                             ││
│  │ - Prompt injection detection                                         ││
│  └──────────────────────────────────────────────────────────────────────┘│
└──────────────────────────────────────────────────────────────────────────┘
```

## MCP Protocol: How It Works

```
┌───────────────┐                    ┌───────────────────┐
│   AI Client   │                    │   MCP Server      │
│  (AI Agent)   │                    │   (e.g. Sentinel) │
│               │                    │                   │
│  User asks:   │   ── initialize ──▶│  Declares:        │
│  "Check logs" │                    │  - tools[]        │
│               │   ◀── response ──  │  - resources[]    │
│               │                    │  - prompts[]      │
│  AI decides   │                    │                   │
│  which tool   │   ── tools/call ──▶│  Executes:        │
│  to use       │   { "name":       │  run_kql_query()  │
│               │     "run_kql" }   │                   │
│               │                    │                   │
│  AI formats   │   ◀── result ────  │  Returns:         │
│  response     │   { "content":    │  query results    │
│               │     [...] }       │                   │
└───────────────┘                    └───────────────────┘
```

### Key Concepts

- **Tools**: Actions the AI can invoke (query, scan, create ticket)
- **Resources**: Data the AI can read (findings, logs, configs)
- **Prompts**: Templates for common workflows (incident response, triage)
- **Transport**: stdio (local) or SSE (remote) — stdio for security-sensitive tools
