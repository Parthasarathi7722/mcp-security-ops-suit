# MCP Security Operations Suite

> **Turn AI into your SOC co-pilot.** A curated collection of MCP (Model Context Protocol) server configurations, playbooks, and architecture patterns that connect 30+ security tools into a unified AI-powered security operations platform.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP Version](https://img.shields.io/badge/MCP-2025--11--25-blue)](https://modelcontextprotocol.io)
[![Blog](https://img.shields.io/badge/Blog-Chaos%20to%20Control-orange)](https://chaostocontrol.ghost.io)

---

## The Problem

Your security team runs 10+ tools. Each has its own dashboard, its own alerts, its own query language. An analyst investigating an incident has to:

1. Check Sentinel for log correlation
2. Tab over to GreyNoise for IP reputation
3. Open GHAS for code scanning alerts
4. Switch to Prowler for cloud posture
5. Query Vault Radar for leaked secrets
6. File a Jira ticket manually
7. Post a Slack update
8. Update the compliance tracker

That's not security operations. That's tab-switching with extra steps.

## The Solution

MCP (Model Context Protocol) lets AI agents connect to external tools through a standardised interface. Instead of tab-switching across dashboards, your AI co-pilot queries all your security tools through MCP servers — from a single conversation.

```
┌─────────────────────────────────────────────────────────────┐
│                    AI Security Co-pilot                      │
│          (Any MCP-Compatible AI Client / Agent)              │
└──────────────────────────┬──────────────────────────────────┘
                           │ MCP Protocol (JSON-RPC / stdio)
        ┌──────────────────┼──────────────────────┐
        ▼                  ▼                      ▼
┌──────────────┐  ┌───────────────┐  ┌───────────────────┐
│   DETECT     │  │   INVESTIGATE │  │     RESPOND       │
├──────────────┤  ├───────────────┤  ├───────────────────┤
│ Semgrep      │  │ Sentinel      │  │ Jira/Linear       │
│ Snyk         │  │ Splunk        │  │ Slack/PagerDuty   │
│ Trivy        │  │ Elastic       │  │ Okta              │
│ GHAS         │  │ GreyNoise     │  │ Vault (rotation)  │
│ Prowler      │  │ OpenCTI       │  │ Cloudflare WAF    │
│ StackHawk    │  │ Vault Radar   │  │ GitHub (PRs)      │
│ Burp Suite*  │  │ Datadog       │  │ Drata/Vanta       │
│ Nuclei*      │  │ Detections DB │  │                   │
└──────────────┘  └───────────────┘  └───────────────────┘
```

*\* Community MCP — configs not included yet. See [Contributing](#contributing) to add them.*

## What's in This Repo

```
mcp-security-ops-suite/
├── mcp-configs/                    # Ready-to-use MCP server configurations
│   ├── siem/                       # Splunk, Sentinel, Elastic, Datadog
│   ├── vuln-scanning/              # Semgrep, Snyk, Trivy, GHAS, StackHawk
│   ├── threat-intel/               # GreyNoise, OpenCTI, VirusTotal
│   ├── cloud-security/             # Prowler, Cloudflare
│   ├── secrets/                    # HashiCorp Vault, Vault Radar
│   ├── compliance/                 # Drata, Vanta
│   ├── identity/                   # Okta
│   ├── detection/                  # Security Detections (Sigma/ESCU/KQL)
│   └── ticketing/                  # Jira, Slack
├── playbooks/                      # SOC workflow playbooks
│   ├── 01-vulnerability-triage.md
│   ├── 02-incident-response.md
│   ├── 03-threat-hunting.md
│   ├── 04-compliance-audit.md
│   ├── 05-secret-leak-response.md
│   └── 06-cloud-posture-review.md
├── architecture/
│   └── reference-architecture.md   # Full architecture with data flows
├── scripts/
│   ├── validate-configs.sh         # Validate MCP config syntax
│   └── setup-env.sh                # Environment setup helper
├── mcp_config.json                 # All-in-one MCP server config
└── SECURITY.md                     # Security considerations
```

## Quick Start

### 1. Pick Your Stack

You don't need all 30+ tools. Start with what you already have:

| Already Using | Add These MCPs | Unlock |
|---|---|---|
| GitHub + GHAS | `ghas`, `semgrep`, `snyk` | Unified vuln triage from chat |
| AWS + Prowler | `prowler`, `cloudflare`, `vault` | Cloud posture in natural language |
| Splunk/Sentinel | `sentinel`/`splunk`, `greynoise`, `opencti` | AI-powered threat hunting |
| Jira + Slack | `jira`, `slack`, `ghas` | Auto-ticket from findings |

### 2. Configure MCP Servers

Copy the relevant config blocks from `mcp_config.json` into your AI client:

```json
{
  "mcpServers": {
    "ghas": {
      "command": "npx",
      "args": ["-y", "@anthropic/ghas-mcp-server"],
      "env": {
        "GITHUB_TOKEN": "${GITHUB_TOKEN}"
      }
    },
    "greynoise": {
      "command": "uvx",
      "args": ["greynoise-mcp"],
      "env": {
        "GREYNOISE_API_KEY": "${GREYNOISE_API_KEY}"
      }
    }
  }
}
```

### 3. Run a Playbook

Open your AI client and try:

> "I just got a Dependabot critical alert for CVE-2024-XXXX in our auth service. Check GreyNoise for exploitation activity, pull the GHAS alert details, check if it's in our OpenCTI threat feeds, and draft a Jira ticket with severity and remediation steps."

That single prompt hits 4 MCP servers, correlates data across tools, and produces an actionable ticket — in seconds.

## Use Cases

### 1. Vulnerability Triage (SOC L1/L2)
**MCPs**: GHAS + Semgrep + Snyk + GreyNoise + Jira
**Flow**: New finding → AI enriches with exploit intel → prioritises by reachability → creates ticket with SLA

### 2. Incident Response (SOC L2/L3)
**MCPs**: Sentinel/Splunk + GreyNoise + OpenCTI + Okta + Vault + Slack
**Flow**: Alert fires → AI correlates logs → checks IP reputation → identifies affected users → rotates credentials → posts IR update

### 3. Threat Hunting (Threat Team)
**MCPs**: Security Detections + Sentinel/Splunk + GreyNoise + OpenCTI
**Flow**: Analyst describes TTP → AI finds matching Sigma rules → translates to KQL → runs hunt → enriches IOCs

### 4. Compliance Audit (GRC)
**MCPs**: Prowler + Drata/Vanta + GHAS + Vault
**Flow**: "Show me SOC 2 gaps" → AI pulls cloud findings + code scanning status + secret hygiene → generates gap report

### 5. Secret Leak Response (DevSecOps)
**MCPs**: Vault Radar + GHAS + Vault + Okta + Jira + Slack
**Flow**: Leaked secret detected → AI traces exposure scope → rotates credential → disables compromised sessions → notifies team

### 6. Cloud Security Posture Review (Cloud Team)
**MCPs**: Prowler + Cloudflare + Sentinel + Vault
**Flow**: "How's our AWS posture?" → AI runs checks → correlates with WAF events → identifies drift → suggests remediations

## MCP Server Reference

### SIEM & Monitoring

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **Microsoft Sentinel** | `@dstreefkerk/ms-sentinel` | Azure AD | KQL queries, incident management, analytics rules |
| **Splunk** | Splunk TA for MCP | API token | SPL queries, incident response, JSON-RPC monitoring |
| **Elastic** | Agent Builder MCP | API key | Log queries, trace analysis, security data |
| **Datadog** | `@shelfio/datadog-mcp` | API/App key | Metrics, logs, incident RCA |

### Vulnerability Scanning

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **Semgrep** | `@semgrep/mcp` | API token | Code scanning, 5000+ rules, 30+ languages |
| **Snyk** | Snyk CLI MCP | API token | SCA, container, IaC scanning |
| **Trivy** | `@aquasecurity/trivy` | None | Container/SBOM scanning, vuln DB |
| **GHAS** | `@rajbos/ghas-mcp-server` | GitHub PAT | Dependabot, secret scanning, code scanning alerts |
| **StackHawk** | StackHawk MCP | API key | DAST, API security testing |
| **Burp Suite** | `@swgee/BurpMCP` | Local | Proxy history, manual test results |

### Threat Intelligence

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **GreyNoise** | `greynoise-mcp` | API key | IP reputation, RIOT, vulnerability intel |
| **OpenCTI** | `@spathodea/opencti` | API token | IOCs, threat actors, MITRE ATT&CK |
| **VirusTotal** | Community MCP | API key | File/URL analysis, hash lookups |

### Cloud Security

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **Prowler** | Prowler MCP | AWS creds | CIS/SOC2/PCI checks, remediation guidance |
| **Cloudflare** | Cloudflare Portals | OAuth | WAF rules, Zero Trust, AI firewall |

### Secrets & Identity

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **HashiCorp Vault** | `@hashicorp/vault-mcp-server` | Vault token | Secret retrieval, key management, audit |
| **Vault Radar** | HCP MCP | HCP token | Leaked secret detection, risk scoring |
| **Okta** | Okta MCP | OAuth | User provisioning, group management, access review |

### Compliance & Governance

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **Drata** | Drata MCP | API token | Compliance tests, controls, framework reports |
| **Vanta** | Vanta MCP | OAuth | SOC 2/ISO 27001 status, remediation, risk |

### Detection Engineering

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **Security Detections** | `@MHaggis/security-detections` | None | Sigma, ESCU, Elastic, KQL rule aggregation |

### Ticketing & Notifications

| Tool | MCP Package | Auth | Capabilities |
|---|---|---|---|
| **Jira** | Atlassian Remote MCP | OAuth | Issue creation, sprint management, audit trail |
| **Slack** | Slack MCP | Bot token | Channel posts, thread updates, notifications |

## Security Considerations

> **Read [SECURITY.md](SECURITY.md) before deploying.**

Key points:

- **Never hardcode credentials** — Use environment variables or Vault
- **Use OAuth 2.1** where supported (only ~8% of MCPs do today — push vendors)
- **Least privilege tokens** — Each MCP server gets its own scoped token
- **Audit everything** — MCP calls should hit your SIEM
- **Verify community MCPs** — Inspect source before deploying
- **Prompt injection is real** — MCP data is untrusted input; treat AI output as advisory, not authoritative
- **Network isolation** — Run MCP servers in containers with restricted egress

## Architecture Tiers

### Tier 1: Solo Analyst (Free/Low Cost)
GHAS + Semgrep + GreyNoise (Community) + Security Detections
- **Cost**: $0 (all free tiers)
- **Covers**: Vulnerability triage, basic threat intel, detection rules

### Tier 2: Team SOC (Mid-Market)
Tier 1 + Sentinel/Splunk + Prowler + Vault + Jira + Slack
- **Cost**: Varies by SIEM licensing
- **Covers**: Full incident response, cloud posture, secret management

### Tier 3: Enterprise SOC
Tier 2 + OpenCTI + Drata/Vanta + Okta + Cloudflare + StackHawk + Datadog
- **Cost**: Enterprise licensing
- **Covers**: Compliance automation, identity-aware response, full ASPM

## Contributing

1. Fork the repo
2. Add your MCP config to the appropriate category under `mcp-configs/`
3. Include: tool name, package, auth method, capabilities, and any gotchas
4. Submit a PR with a tested config

## Related Blog Posts

- [MCP Security Operations Suite: Building an AI-Powered SOC](https://chaostocontrol.ghost.io) — Full walkthrough
- [Building a DevSecOps Pipeline with GitHub Actions](https://chaostocontrol.ghost.io) — Pipeline foundations
- [Stop Alerting, Start Blocking: GHAS as a Security Gate](https://chaostocontrol.ghost.io) — GHAS deep dive
- [DefectDojo as Your Security Single Pane of Glass](https://chaostocontrol.ghost.io) — Vulnerability management

## License

MIT — Use it, fork it, make your SOC less miserable.
