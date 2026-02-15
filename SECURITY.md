# Security Considerations

> Connecting AI to security tools is powerful. It's also a risk surface. Read this before deploying.

## Authentication & Credentials

### Do

- **Use OAuth 2.1** where supported (Okta, Cloudflare, Atlassian, Vanta)
- **Store secrets in HashiCorp Vault** and reference them via environment variables
- **Use short-lived tokens** — rotate API keys on a schedule (30-90 days max)
- **Scope tokens to minimum permissions** — read-only where possible
- **Use separate tokens per MCP server** — compromise of one doesn't cascade

### Don't

- Hardcode credentials in `mcp_config.json`
- Use personal access tokens with broad org-level scope
- Share MCP tokens across tools or environments
- Store tokens in `.env` files committed to Git (add `.env` to `.gitignore`)

### Example: Vault-Backed Credentials

```bash
# Pull secrets from Vault at MCP server startup
export GITHUB_TOKEN=$(vault kv get -field=token secret/mcp/github)
export GREYNOISE_API_KEY=$(vault kv get -field=api_key secret/mcp/greynoise)
export SENTINEL_CLIENT_SECRET=$(vault kv get -field=client_secret secret/mcp/sentinel)
```

## Prompt Injection

MCP data is **untrusted input**. Security findings, log entries, and threat intel feeds can contain attacker-controlled content.

### Risks

- A malicious commit message could contain instructions that manipulate AI analysis
- Alert descriptions from external sources might include injection payloads
- Threat intel feeds could contain crafted IOC descriptions

### Mitigations

- **Treat AI output as advisory** — never auto-execute remediation without human review
- **Validate AI-suggested actions** — especially credential rotation, user deprovisioning, WAF rule changes
- **Log all MCP interactions** for audit and replay
- **Use structured output** — ask AI to return JSON, not freeform commands

## Network Isolation

### MCP Server Deployment

```
┌─────────────────────────────────────────────────┐
│ Analyst Workstation                              │
│  ┌─────────────┐     ┌────────────────────────┐ │
│  │ AI Client   │────▶│ MCP Servers            │ │
│  │ (MCP Host) │────▶│ (containers / local)   │ │
│  └─────────────┘     └──────────┬─────────────┘ │
└─────────────────────────────────┼───────────────┘
                                  │ Restricted egress
                                  ▼
                    ┌─────────────────────────┐
                    │ Security Tool APIs      │
                    │ (Sentinel, Splunk, etc.) │
                    └─────────────────────────┘
```

### Recommendations

- Run MCP servers in **Docker containers** with restricted network policies
- Limit egress to **only the APIs each MCP server needs**
- Use **read-only filesystem mounts** where possible
- Set **resource limits** (CPU, memory) to prevent abuse
- Never expose MCP servers to the public internet

## Data Classification

### What MCP Servers Can Access

| Data Type | Risk Level | Mitigation |
|---|---|---|
| Security findings | Medium | Scoped queries, no bulk export |
| Log data (SIEM) | High | Time-bounded queries, no PII exposure |
| Secrets metadata (Vault Radar) | High | Metadata only, never actual secret values |
| User identity data (Okta) | High | Read-only tokens, audit logging |
| Compliance status (Drata/Vanta) | Medium | Read-only API access |
| Cloud posture (Prowler) | Medium | Read-only, scoped to security checks |

### Rules

- Never expose **actual secret values** through MCP — only metadata (location, type, severity)
- Limit SIEM queries to **relevant time windows** — don't bulk-export all logs
- Okta access should be **read-only** unless credential rotation is explicitly required
- All MCP data access should be **logged to your SIEM**

## Audit Trail

### What to Log

```json
{
  "timestamp": "2026-02-15T10:30:00Z",
  "mcp_server": "sentinel",
  "tool_called": "run_kql_query",
  "parameters": {
    "query": "SecurityEvent | where TimeGenerated > ago(1h)",
    "timespan": "PT1H"
  },
  "user": "analyst@company.com",
  "ai_client": "mcp-security-copilot",
  "result_size": "142 records"
}
```

### Implementation

- Configure your AI client to log all MCP tool invocations
- Forward MCP audit logs to your SIEM (Splunk/Sentinel/Elastic)
- Create detection rules for unusual MCP access patterns:
  - Bulk data queries outside business hours
  - Credential rotation without preceding incident
  - Cross-tool correlation suggesting data exfiltration

## MCP Server Verification

Before deploying any MCP server:

1. **Check the source** — Official vendor MCPs are preferred over community
2. **Inspect the code** — Review what APIs the MCP server calls
3. **Check for known vulnerabilities** — Search for CVEs against the MCP package
4. **Test in isolation** — Run in a sandbox first, not production
5. **Pin versions** — Don't use `@latest` in production; pin to audited versions

### Known MCP Ecosystem Risks

- **53% of MCP servers** use static API keys (prefer OAuth 2.1)
- **NeighborJack-style attacks** can target publicly exposed MCP servers
- **Tool poisoning** can manipulate AI behavior through crafted tool descriptions
- Multiple CVEs have been found in popular MCP implementations

## Incident Response for MCP Compromise

If you suspect an MCP server or credential has been compromised:

1. **Revoke the token** used by the compromised MCP server immediately
2. **Check audit logs** for unusual tool invocations in the last 24-72 hours
3. **Rotate all credentials** that the MCP server had access to
4. **Review AI conversation history** for signs of prompt injection
5. **Update the MCP server** to the latest patched version
6. **Notify your security team** and document the incident

## Responsible Disclosure

If you find a security vulnerability in any MCP configuration or playbook in this repo, please:

1. **Do not open a public issue**
2. Email: parthasd9692@gmail.com with details
3. We'll respond within 48 hours and coordinate disclosure
