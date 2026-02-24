#!/usr/bin/env python3
"""
SOCPilot — AI Security Operations Co-pilot

An AI-powered SOC agent that orchestrates security investigations across
your MCP server stack: SIEM, vulnerability scanning, threat intelligence,
cloud security, secrets management, compliance, and ticketing.

Designed to run inside a private subnet. All MCP tool calls stay on your
network; only the AI inference request leaves the boundary.

Usage:
    python agent.py                                               # Interactive CLI
    python agent.py "triage CVE-2024-50623 in payments-api"      # Direct query
    python agent.py --playbook vuln-triage "CVE-2024-50623 in payments-api"
    python agent.py --playbook incident-response "alert SEC-7721"
    python agent.py --playbook threat-hunting "Cl0p ransomware TTPs"
    python agent.py --list-playbooks
    python agent.py --verbose "hunt for T1190 exploitation in our environment"
    python agent.py --output report.md --playbook compliance-audit "AWS prod"

Environment variables (see .env.example):
    AI_API_KEY    Required. Inference API key.
    AI_MODEL      Optional. Override the default inference model.
    AI_BASE_URL   Optional. Point to a self-hosted or proxy endpoint.
    MCP_MODE      mock (default) | live
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic as _sdk   # Anthropic inference SDK

from config import cfg


# ─────────────────────────────────────────────────────────────────────────────
# INTERNAL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _make_anthropic_client() -> _sdk.AsyncAnthropic:
    kwargs: dict[str, Any] = {"api_key": cfg.api_key}
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    return _sdk.AsyncAnthropic(**kwargs)


def _make_openai_client():
    """Return an AsyncOpenAI client pointed at a local or remote OpenAI-compatible server."""
    try:
        from openai import AsyncOpenAI
    except ImportError as exc:
        raise RuntimeError(
            "openai package not installed. Run: pip install openai"
        ) from exc
    return AsyncOpenAI(
        api_key=cfg.api_key or "local",          # local servers accept any non-empty key
        base_url=cfg.base_url or "http://localhost:11434/v1",  # Ollama default
    )


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    """Convert Anthropic tool definitions to OpenAI function-calling format."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t["description"],
                "parameters": t["input_schema"],
            },
        }
        for t in tools
    ]


# ─────────────────────────────────────────────────────────────────────────────
# TOOL DEFINITIONS
# Each tool mirrors a capability in mcp_config.json.
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_TOOLS: list[dict] = [

    # ── SIEM & Monitoring ────────────────────────────────────────────────────
    {
        "name": "query_sentinel",
        "description": (
            "Query Microsoft Sentinel for security events, incidents, analytics rules, "
            "and KQL-based threat detection. Use for log correlation and incident investigation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query":      {"type": "string", "description": "KQL query to execute"},
                "time_range": {"type": "string", "description": "Window: '1h', '24h', '7d', '30d'"},
                "workspace":  {"type": "string", "description": "Sentinel workspace name (optional)"},
            },
            "required": ["query"],
        },
    },
    {
        "name": "query_splunk",
        "description": (
            "Run SPL searches against Splunk for log analysis, threat detection, "
            "and security event correlation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "search":     {"type": "string", "description": "SPL search query"},
                "time_range": {"type": "string", "description": "Time range, e.g. '-24h@h'"},
                "index":      {"type": "string", "description": "Splunk index (optional)"},
            },
            "required": ["search"],
        },
    },
    {
        "name": "query_datadog",
        "description": "Query Datadog for metrics, logs, traces, and security signals.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query":      {"type": "string", "description": "Datadog query string"},
                "query_type": {"type": "string", "enum": ["logs", "metrics", "security"]},
                "time_range": {"type": "string", "description": "Time range"},
            },
            "required": ["query", "query_type"],
        },
    },

    # ── Vulnerability Scanning ───────────────────────────────────────────────
    {
        "name": "get_ghas_alerts",
        "description": (
            "Retrieve GitHub Advanced Security alerts: Dependabot (CVEs), "
            "code scanning (CodeQL), and secret scanning alerts for a repository."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "repo":       {"type": "string", "description": "Repository in owner/repo format"},
                "alert_type": {
                    "type": "string",
                    "enum": ["dependabot", "code-scanning", "secret-scanning", "all"],
                },
                "severity":   {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "all"],
                },
                "cve_id":     {"type": "string", "description": "Filter by CVE ID (optional)"},
            },
            "required": ["repo", "alert_type"],
        },
    },
    {
        "name": "scan_semgrep",
        "description": (
            "Run Semgrep SAST analysis against a repository to find vulnerabilities, "
            "insecure coding patterns, and policy violations across 30+ languages."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "repo":   {"type": "string", "description": "Repository or path to scan"},
                "rules":  {"type": "string", "description": "Ruleset or rule ID"},
                "filter": {"type": "string", "description": "Filter by file or pattern (optional)"},
            },
            "required": ["repo"],
        },
    },
    {
        "name": "check_snyk",
        "description": (
            "Run Snyk SCA to check dependency vulnerabilities, reachability analysis, "
            "and transitive dependency trees."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "repo":               {"type": "string", "description": "Repository or project"},
                "cve_id":             {"type": "string", "description": "Check specific CVE (optional)"},
                "check_reachability": {"type": "boolean", "description": "Perform reachability analysis"},
            },
            "required": ["repo"],
        },
    },
    {
        "name": "scan_trivy",
        "description": (
            "Scan container images, filesystems, or SBOMs for OS and library vulnerabilities. "
            "No credentials required."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target":   {"type": "string", "description": "Image name, directory, or SBOM file"},
                "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"]},
                "format":   {"type": "string", "enum": ["table", "json", "sarif"]},
            },
            "required": ["target"],
        },
    },

    # ── Threat Intelligence ──────────────────────────────────────────────────
    {
        "name": "check_greynoise",
        "description": (
            "Check GreyNoise for IP reputation, active CVE exploitation status, "
            "and RIOT (benign business traffic) classification."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query":      {"type": "string", "description": "IP address or CVE ID"},
                "query_type": {"type": "string", "enum": ["ip", "cve", "tag"]},
            },
            "required": ["query", "query_type"],
        },
    },
    {
        "name": "query_opencti",
        "description": (
            "Query OpenCTI for IOCs, threat actors, malware families, campaigns, "
            "and MITRE ATT&CK technique mappings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "IP, domain, hash, CVE, actor, or malware"},
                "type":  {
                    "type": "string",
                    "enum": ["indicator", "threat-actor", "malware", "campaign",
                             "vulnerability", "all"],
                },
            },
            "required": ["query", "type"],
        },
    },
    {
        "name": "check_virustotal",
        "description": "Look up file hashes, URLs, IPs, or domains in VirusTotal.",
        "input_schema": {
            "type": "object",
            "properties": {
                "ioc":      {"type": "string", "description": "Hash, URL, IP, or domain"},
                "ioc_type": {"type": "string", "enum": ["hash", "url", "ip", "domain"]},
            },
            "required": ["ioc", "ioc_type"],
        },
    },

    # ── Cloud Security ───────────────────────────────────────────────────────
    {
        "name": "run_prowler",
        "description": (
            "Run Prowler cloud security posture checks against AWS, Azure, or GCP "
            "for CIS, SOC 2, PCI-DSS, and NIST compliance."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "provider":  {"type": "string", "enum": ["aws", "azure", "gcp"]},
                "framework": {"type": "string",
                              "description": "cis_level1 | soc2 | pci_dss | nist_800_53 (optional)"},
                "service":   {"type": "string", "description": "iam, s3, ec2, rds, etc. (optional)"},
                "severity":  {"type": "string", "enum": ["critical", "high", "medium", "low", "all"]},
            },
            "required": ["provider"],
        },
    },
    {
        "name": "query_cloudflare",
        "description": (
            "Query Cloudflare for WAF events, firewall rules, Zero Trust policies, "
            "security analytics, and IP blocking."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action":  {
                    "type": "string",
                    "enum": ["get_waf_events", "get_firewall_rules",
                             "get_analytics", "block_ip", "update_rule"],
                },
                "filters": {"type": "object", "description": "Time range, IP, rule ID, etc. (optional)"},
            },
            "required": ["action"],
        },
    },

    # ── Secrets & Identity ───────────────────────────────────────────────────
    {
        "name": "check_vault_radar",
        "description": (
            "Check HashiCorp Vault Radar for leaked secrets, exposed API keys, "
            "and credentials across repositories."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "scan_target": {"type": "string", "description": "Repository, path, or scan ID"},
                "severity":    {"type": "string", "enum": ["critical", "high", "medium", "low", "all"]},
                "secret_type": {"type": "string", "description": "aws_key, github_token, etc. (optional)"},
            },
            "required": ["scan_target"],
        },
    },
    {
        "name": "manage_vault",
        "description": (
            "Interact with HashiCorp Vault: retrieve secrets, rotate credentials, "
            "revoke tokens, list leases, and audit access logs."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["read_secret", "rotate_secret", "revoke_token",
                             "list_audit_logs", "list_leases"],
                },
                "path":   {"type": "string", "description": "Vault secret path or mount point"},
                "params": {"type": "object", "description": "Additional parameters (optional)"},
            },
            "required": ["action", "path"],
        },
    },
    {
        "name": "manage_okta",
        "description": (
            "Manage Okta users and sessions for identity-aware incident response: "
            "check status, suspend accounts, clear sessions, review MFA."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["get_user", "suspend_user", "clear_sessions",
                             "list_user_apps", "get_group", "check_mfa", "force_mfa_reset"],
                },
                "user":   {"type": "string", "description": "User email or Okta user ID"},
                "params": {"type": "object", "description": "Additional parameters (optional)"},
            },
            "required": ["action", "user"],
        },
    },

    # ── Detection Engineering ────────────────────────────────────────────────
    {
        "name": "search_detections",
        "description": (
            "Search the Security Detections database for Sigma rules, ESCU rules, "
            "Elastic detection rules, and KQL queries for a given threat, CVE, or technique."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query":     {"type": "string",
                              "description": "CVE ID, MITRE technique (T1190), malware, or actor"},
                "rule_type": {"type": "string", "enum": ["sigma", "escu", "elastic", "kql", "all"]},
                "platform":  {"type": "string",
                              "description": "Target SIEM: splunk, sentinel, elastic (optional)"},
            },
            "required": ["query"],
        },
    },

    # ── Ticketing & Notifications ────────────────────────────────────────────
    {
        "name": "create_jira_ticket",
        "description": (
            "Create a Jira ticket for security findings, incidents, or remediation tasks "
            "with full context, priority, and SLA assignment."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "project":     {"type": "string", "description": "Jira project key, e.g. SEC or OPS"},
                "summary":     {"type": "string", "description": "Ticket title"},
                "description": {"type": "string", "description": "Full findings and remediation details"},
                "priority":    {"type": "string", "enum": ["Highest", "High", "Medium", "Low", "Lowest"]},
                "issue_type":  {"type": "string", "enum": ["Bug", "Task", "Security", "Incident"]},
                "labels":      {"type": "array", "items": {"type": "string"}},
            },
            "required": ["project", "summary", "description", "priority"],
        },
    },
    {
        "name": "post_slack",
        "description": "Post a security alert or status update to a Slack channel.",
        "input_schema": {
            "type": "object",
            "properties": {
                "channel": {"type": "string", "description": "Slack channel, e.g. #security-alerts"},
                "message": {"type": "string", "description": "Message content"},
                "urgency": {"type": "string", "enum": ["normal", "urgent"]},
            },
            "required": ["channel", "message"],
        },
    },

    # ── Compliance ───────────────────────────────────────────────────────────
    {
        "name": "check_compliance",
        "description": (
            "Check compliance status and generate gap reports from Drata or Vanta "
            "for SOC 2, ISO 27001, HIPAA, or PCI-DSS."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "platform":   {"type": "string", "enum": ["drata", "vanta"]},
                "framework":  {"type": "string", "description": "soc2 | iso27001 | hipaa | pci_dss"},
                "control_id": {"type": "string", "description": "Specific control to check (optional)"},
            },
            "required": ["platform", "framework"],
        },
    },
]


# ─────────────────────────────────────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are SOCPilot, an AI Security Operations Co-pilot.

You assist security analysts by orchestrating investigations across SIEM platforms,
vulnerability scanners, threat intelligence feeds, cloud security tools, identity
providers, compliance platforms, and ticketing systems — all running inside the
organisation's private network.

## Available Tool Categories
- **SIEM**: Sentinel (KQL), Splunk (SPL), Datadog
- **Vuln scanning**: GHAS / Dependabot, Semgrep, Snyk, Trivy
- **Threat intelligence**: GreyNoise (IP/CVE), OpenCTI (actors/IOCs), VirusTotal
- **Cloud security**: Prowler (AWS / Azure / GCP posture), Cloudflare (WAF / Zero Trust)
- **Secrets & identity**: HashiCorp Vault, Vault Radar, Okta
- **Compliance**: Drata, Vanta
- **Detection engineering**: Security Detections (Sigma / ESCU / KQL)
- **Ticketing**: Jira, Slack

## SOC Playbooks
1. **vuln-triage**: gather context → enrich threat intel → risk assess → ticket → notify
2. **incident-response**: correlate logs → IP reputation → scope users → contain → notify
3. **threat-hunting**: find detection rules → translate → run hunt → enrich IOCs
4. **compliance-audit**: cloud checks → code scanning → secret hygiene → gap report
5. **secret-leak-response**: trace scope → rotate → disable sessions → ticket → notify
6. **cloud-posture-review**: Prowler checks → WAF events → drift → remediation roadmap

## Risk Assessment Framework
| Priority | SLA       | Criteria                                                         |
|----------|-----------|------------------------------------------------------------------|
| P1       | Immediate | Actively exploited + confirmed reachable + internet-facing       |
| P2       | 48 h      | Actively exploited OR reachable (not both); PoC available        |
| P3       | 7 d       | Vulnerability present, not actively exploited                    |
| P4       | 30 d      | Low severity or unreachable                                      |

## Operating Principles
1. **Plan before acting** — state which tools you will call and why.
2. **Correlate across sources** — single-tool findings are incomplete.
3. **Quantify risk** — CVSS + active exploitation + reachability = true priority.
4. **Flag destructive actions** — present containment steps (session termination,
   credential rotation, IP blocking) for analyst approval before executing.
5. **Close the loop** — create a Jira ticket and post a Slack update for every
   actionable finding.
6. **Be concise** — lead with the verdict, follow with evidence.
"""


# ─────────────────────────────────────────────────────────────────────────────
# PLAYBOOK PROMPTS
# ─────────────────────────────────────────────────────────────────────────────

PLAYBOOK_PROMPTS: dict[str, str] = {
    "vuln-triage": (
        "Run the full vulnerability triage playbook for: {target}\n\n"
        "Steps:\n"
        "1. Pull GHAS / Dependabot alerts for the affected repository\n"
        "2. Check GreyNoise — is this CVE being actively exploited in the wild?\n"
        "3. Check OpenCTI — are there threat actor campaigns targeting this CVE?\n"
        "4. Run Snyk reachability analysis — is the vulnerable code actually called?\n"
        "5. Search Security Detections for Sigma / ESCU / KQL rules covering this CVE\n"
        "6. Provide a complete risk assessment with P1–P4 priority and SLA\n"
        "7. Create a Jira ticket in the SEC project with all findings\n"
        "8. Post a summary to Slack #vuln-triage"
    ),
    "incident-response": (
        "Run the full incident response playbook for: {target}\n\n"
        "Steps:\n"
        "1. Query Sentinel and Splunk for related events in the last 24 h\n"
        "2. Check GreyNoise for any involved IP addresses\n"
        "3. Query OpenCTI for threat intelligence on the IOCs\n"
        "4. Check Okta — affected user sessions, MFA status, group memberships\n"
        "5. Check Vault / Vault Radar for exposed or at-risk secrets\n"
        "6. Determine blast radius and scope\n"
        "7. List recommended containment actions (await approval before executing)\n"
        "8. Create a Jira incident ticket\n"
        "9. Post an IR status update to Slack #security-incidents"
    ),
    "threat-hunting": (
        "Run the threat hunting playbook for: {target}\n\n"
        "Steps:\n"
        "1. Search the Security Detections database for matching Sigma / ESCU / KQL rules\n"
        "2. Translate the best rules to KQL and run against Sentinel\n"
        "3. Translate to SPL and run against Splunk\n"
        "4. Check GreyNoise for related CVEs or observed scanning IPs\n"
        "5. Enrich any discovered IOCs via OpenCTI\n"
        "6. Summarise hunt findings and recommend detection gaps to close"
    ),
    "compliance-audit": (
        "Run the compliance audit playbook for: {target}\n\n"
        "Steps:\n"
        "1. Check Drata / Vanta for current compliance posture and failing controls\n"
        "2. Run Prowler cloud posture checks\n"
        "3. Check GHAS for code scanning coverage and open alerts\n"
        "4. Check Vault Radar for any leaked secrets\n"
        "5. Generate a prioritised gap report with remediation items"
    ),
    "secret-leak-response": (
        "Run the secret leak response playbook for: {target}\n\n"
        "Steps:\n"
        "1. Check Vault Radar — scope the exposure and risk score\n"
        "2. Check GHAS secret scanning — any additional exposures in other repos?\n"
        "3. Rotate the exposed credential via Vault (flag for approval)\n"
        "4. Check Okta — any sessions authenticated with the compromised credential?\n"
        "5. Create a Jira incident ticket\n"
        "6. Post a notification to Slack #security-alerts with remediation status"
    ),
    "cloud-posture-review": (
        "Run the cloud posture review playbook for: {target}\n\n"
        "Steps:\n"
        "1. Run Prowler checks for the cloud environment\n"
        "2. Query Cloudflare for WAF events and security analytics\n"
        "3. Query Sentinel / Datadog for cloud-related security events\n"
        "4. Check Vault for secret management hygiene\n"
        "5. Identify configuration drift and critical findings\n"
        "6. Generate a prioritised remediation roadmap"
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# MOCK RESPONSES (MCP_MODE=mock)
# ─────────────────────────────────────────────────────────────────────────────

def _mock_response(name: str, inputs: dict[str, Any]) -> str:
    """Realistic sample responses for offline/dev mode."""
    cve    = inputs.get("cve_id", "CVE-2024-50623")
    repo   = inputs.get("repo", "payments-api")
    target = inputs.get("target", inputs.get("scan_target", "unknown"))
    tr     = inputs.get("time_range", "24h")
    query  = inputs.get("query", "")
    action = inputs.get("action", "")
    user   = inputs.get("user", "user@company.com")

    responses: dict[str, str] = {
        "query_sentinel": (
            f"Sentinel KQL — {tr} window:\n"
            f"  47 matching events | 3 high-severity incidents opened\n"
            f"  Top source IPs: 185.220.101.34 (TOR), 45.142.212.55\n"
            f"  Affected resources: payments-api, auth-service\n"
            f"  Anomaly: 23 failed auth → 1 success at 02:34 UTC\n"
            f"  [Mock — set SENTINEL credentials for live data]"
        ),
        "query_splunk": (
            f"Splunk SPL — '{inputs.get('search','')[:50]}':\n"
            f"  156 events | peak 02:34 UTC | index=security host=prod-web-01\n"
            f"  Notable: brute-force pattern then lateral movement\n"
            f"  [Mock — set SPLUNK_URL for live data]"
        ),
        "query_datadog": (
            f"Datadog {inputs.get('query_type','logs')} — '{query[:40]}':\n"
            f"  890 log lines | 14 security signals fired\n"
            f"  P1 signal: unusual outbound traffic spike (3× baseline)\n"
            f"  [Mock — set DD_API_KEY for live data]"
        ),
        "get_ghas_alerts": (
            f"GHAS alerts — {repo}:\n"
            f"  Dependabot: 12 alerts (2 critical, 5 high)\n"
            f"  {'→ ' + cve + ' FOUND in direct dependency' if inputs.get('cve_id') else '→ Latest critical: CVE-2024-50623 (Cleo Harmony RCE, CVSS 9.8)'}\n"
            f"  Code scanning: 3 alerts (SQL injection, path traversal)\n"
            f"  Secret scanning: 1 exposed token — rotation required\n"
            f"  [Mock — set GITHUB_TOKEN for live data]"
        ),
        "scan_semgrep": (
            f"Semgrep scan — {repo}:\n"
            f"  8 findings across 4 files\n"
            f"  CRITICAL: SQL injection @ UserRepository.java:L142\n"
            f"  HIGH: Hardcoded credential @ config.py:L67\n"
            f"  MEDIUM: Insecure deserialisation @ DataHandler.java:L89\n"
            f"  [Mock — set SEMGREP_APP_TOKEN for live data]"
        ),
        "check_snyk": (
            f"Snyk SCA — {repo}:\n"
            f"  6 vulnerable dependencies\n"
            f"  CRITICAL: {cve} in com.cleo:harmony:5.6.0 (direct dep)\n"
            f"  {'Reachability: CONFIRMED — call path executes vulnerable function in FileUploadController.java' if inputs.get('check_reachability') else 'Reachability: not checked'}\n"
            f"  Fix: upgrade to com.cleo:harmony:5.8.0\n"
            f"  [Mock — set SNYK_TOKEN for live data]"
        ),
        "scan_trivy": (
            f"Trivy scan — {target}:\n"
            f"  23 CVEs | 2 critical, 7 high, 14 medium\n"
            f"  Critical: CVE-2024-50623, CVE-2024-41110 (container escape)\n"
            f"  Base image: ubuntu:22.04 — upgrade to 24.04 recommended\n"
            f"  [No credentials required — run Trivy locally]"
        ),
        "check_greynoise": (
            f"GreyNoise — {query}:\n"
            + (
                f"  Classification: MALICIOUS | Tags: TOR, VPN, Mass-scanner\n"
                f"  Last seen: 2 h ago | Targeting: web servers, IoT\n"
                f"  RIOT: No (not a known benign business IP)\n"
                if inputs.get("query_type") == "ip"
                else
                f"  {query}: ACTIVELY EXPLOITED\n"
                f"  2 400+ IPs scanning for this CVE in last 24 h\n"
                f"  First exploitation: 2024-10-28 | Trend: +300% this week\n"
                f"  Linked campaigns: Cl0p ransomware, Scattered Spider\n"
            )
            + "  [Mock — set GREYNOISE_API_KEY for live data]"
        ),
        "query_opencti": (
            f"OpenCTI — '{query}':\n"
            f"  3 threat actors matched | Primary: Cl0p (confidence 85%)\n"
            f"  Campaigns: MOVEit exploitation, Cleo mass exploitation\n"
            f"  MITRE: T1190 (Exploit Public App), T1486 (Data Encrypted)\n"
            f"  IOCs: 47 IPs | 12 domains | 8 file hashes\n"
            f"  [Mock — set OPENCTI_URL for live data]"
        ),
        "check_virustotal": (
            f"VirusTotal — {inputs.get('ioc','unknown')}:\n"
            f"  Detections: 42/70 AV engines | Verdict: MALICIOUS\n"
            f"  Family: Clop ransomware | First seen: 2024-10-15 | Last seen: today\n"
            f"  [Mock — set VT_API_KEY for live data]"
        ),
        "run_prowler": (
            f"Prowler {inputs.get('provider','aws').upper()} — {inputs.get('framework','cis_level1')}:\n"
            f"  156 checks | 23 failures | pass rate 85.3%\n"
            f"  CRITICAL (3): public S3 bucket, root API key active, no MFA on root\n"
            f"  HIGH (8): overly permissive security group, CloudTrail disabled in eu-west-2\n"
            f"  Remediation scripts available for all findings\n"
            f"  [Mock — set AWS credentials for live data]"
        ),
        "query_cloudflare": (
            f"Cloudflare {action}:\n"
            f"  WAF blocks last 24 h: 1 247 | SQL injection 34%, XSS 28%, Bot 18%\n"
            f"  89 unique IPs blocked | 456 challenges issued\n"
            f"  Zero Trust active sessions: 1 203\n"
            f"  [Mock — set CLOUDFLARE_API_TOKEN for live data]"
        ),
        "check_vault_radar": (
            f"Vault Radar — {target}:\n"
            f"  3 leaked secrets detected | Risk score: 94/100\n"
            f"  CRITICAL: AWS Access Key in commit abc1234 (payments-service) — STILL VALID\n"
            f"  HIGH: GitHub PAT in .env file — STILL VALID\n"
            f"  MEDIUM: DB password in config backup\n"
            f"  [Mock — set HCP_CLIENT_ID for live data]"
        ),
        "manage_vault": (
            f"Vault {action} @ {inputs.get('path','<path>')}:\n"
            f"  Action completed | Lease: lease-abc123\n"
            f"  Audit log entry written | Previous rotation: 2024-11-20 14:32 UTC\n"
            f"  [Mock — set VAULT_ADDR for live data]"
        ),
        "manage_okta": (
            f"Okta {action} — {user}:\n"
            f"  Status: Active | Last login: 02:31 UTC (ANOMALOUS)\n"
            f"  Active sessions: 3 (US, RU, NG) — impossible travel detected\n"
            f"  MFA: enrolled via SMS push (not FIDO2)\n"
            f"  Groups: engineering, payments-team | Apps: 23 assigned\n"
            f"  [Mock — set OKTA_ORG_URL for live data]"
        ),
        "search_detections": (
            f"Security Detections — '{query}':\n"
            f"  7 rules found\n"
            f"  Sigma (3): file-upload-exploit.yml, webshell-detection.yml, lateral-movement.yml\n"
            f"  ESCU (2): Splunk — remote-code-execution-via-cleo.xml\n"
            f"  Elastic (2): EQL — file_upload_rce.toml, c2_beacon_detection.toml\n"
            f"  ATT&CK coverage: T1190 (Initial Access), T1059 (Execution)\n"
            f"  KQL translation available for Sentinel\n"
            f"  [No auth required — open-source rule database]"
        ),
        "create_jira_ticket": (
            f"Jira ticket created:\n"
            f"  ID: {inputs.get('project','SEC')}-4521\n"
            f"  '{inputs.get('summary','')[:60]}'\n"
            f"  Priority: {inputs.get('priority','High')} | "
            f"SLA: {'4 h' if inputs.get('priority') == 'Highest' else '48 h'}\n"
            f"  URL: https://your-org.atlassian.net/browse/{inputs.get('project','SEC')}-4521\n"
            f"  [Mock — set JIRA_URL for live data]"
        ),
        "post_slack": (
            f"Slack → {inputs.get('channel','#security')}:\n"
            f"  Message delivered\n"
            f"  {'@here notification sent' if inputs.get('urgency') == 'urgent' else 'Standard notification'}\n"
            f"  Thread created for follow-up replies\n"
            f"  [Mock — set SLACK_BOT_TOKEN for live data]"
        ),
        "check_compliance": (
            f"Compliance ({inputs.get('platform','drata')}, {inputs.get('framework','soc2')}):\n"
            f"  Overall: 78% | 89/114 controls passing | 25 failing\n"
            f"  Critical gaps: CC6.1 encryption-at-rest, CC7.2 monitoring, CC8.1 change-mgmt\n"
            f"  Last assessment: 2024-11-15 | Report: available\n"
            f"  [Mock — set compliance platform credentials for live data]"
        ),
    }

    return responses.get(
        name,
        f"[{name}] Executed with inputs: {json.dumps(inputs)}\n"
        f"Set MCP_MODE=live and configure credentials in .env for real data.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC TOOL EXECUTOR
# ─────────────────────────────────────────────────────────────────────────────

async def execute_tool(
    name: str,
    inputs: dict[str, Any],
    pool: Any | None = None,   # MCPClientPool | None
) -> str:
    """
    Dispatch a tool call to the appropriate MCP server (or mock).

    MCP_MODE=mock  — returns realistic sample data; no external calls.
    MCP_MODE=live  — routes to the MCP server process via pool.call_tool().
    """
    if cfg.live and pool is not None:
        return await pool.call_tool(name, inputs)
    return _mock_response(name, inputs)


# ─────────────────────────────────────────────────────────────────────────────
# CORE ASYNC GENERATOR — dispatcher
# ─────────────────────────────────────────────────────────────────────────────

async def run_investigation(
    query: str,
    *,
    history: list[dict] | None = None,
    pool: Any | None = None,
    verbose: bool = False,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    Run the SOCPilot agent as an async generator that yields typed events.

    Event shapes:
        {"type": "thinking",     "text": "..."}          # Anthropic + verbose=True only
        {"type": "text",         "text": "..."}          # streamed response tokens
        {"type": "tool_call",    "name": "...", "inputs": {...}}
        {"type": "tool_result",  "name": "...", "content": "..."}
        {"type": "done",         "turns": N}
        {"type": "error",        "message": "..."}

    AI_PROVIDER=anthropic (default) → calls Anthropic API (requires AI_API_KEY)
    AI_PROVIDER=openai              → calls any OpenAI-compatible local server
                                      (Ollama, LM Studio, vLLM — fully air-gapped)
    """
    if cfg.provider == "demo":
        async for event in _run_demo(query, history=history, pool=pool):
            yield event
    elif cfg.provider == "openai":
        async for event in _run_openai(query, history=history, pool=pool):
            yield event
    else:
        async for event in _run_anthropic(query, history=history, pool=pool, verbose=verbose):
            yield event


# ─────────────────────────────────────────────────────────────────────────────
# ANTHROPIC BACKEND  (default — calls Anthropic API externally)
# ─────────────────────────────────────────────────────────────────────────────

async def _run_anthropic(
    query: str,
    *,
    history: list[dict] | None = None,
    pool: Any | None = None,
    verbose: bool = False,
) -> AsyncGenerator[dict[str, Any], None]:
    client = _make_anthropic_client()

    if history is None:
        messages: list[dict] = []
    else:
        messages = history

    messages.append({"role": "user", "content": query})

    turn = 0
    try:
        while True:
            turn += 1
            collected_content: list[Any] = []
            stop_reason: str = "end_turn"

            async with client.messages.stream(
                model=cfg.model,
                max_tokens=8192,
                thinking={"type": "adaptive"},
                system=_SYSTEM_PROMPT,
                tools=SECURITY_TOOLS,
                messages=messages,
            ) as stream:
                in_thinking = False

                async for event in stream:
                    if event.type == "content_block_start":
                        btype = event.content_block.type
                        if btype == "thinking":
                            in_thinking = True
                        elif btype == "text":
                            in_thinking = False

                    elif event.type == "content_block_delta":
                        delta = event.delta
                        if delta.type == "thinking_delta":
                            if verbose:
                                yield {"type": "thinking", "text": delta.thinking}
                        elif delta.type == "text_delta":
                            in_thinking = False
                            yield {"type": "text", "text": delta.text}

                final = await stream.get_final_message()
                collected_content = list(final.content)
                stop_reason       = final.stop_reason or "end_turn"

            messages.append({"role": "assistant", "content": collected_content})

            if stop_reason == "end_turn":
                yield {"type": "done", "turns": turn}
                return

            tool_blocks = [b for b in collected_content if b.type == "tool_use"]
            if not tool_blocks:
                yield {"type": "done", "turns": turn}
                return

            for tb in tool_blocks:
                yield {"type": "tool_call", "name": tb.name, "inputs": tb.input}

            if cfg.live and pool is not None:
                calls   = [(tb.name, tb.input) for tb in tool_blocks]
                results = await pool.execute_parallel(calls)
                tool_results = [
                    {"type": "tool_result", "tool_use_id": tb.id, "content": res}
                    for tb, res in zip(tool_blocks, results)
                ]
                for tb, res in zip(tool_blocks, results):
                    yield {"type": "tool_result", "name": tb.name, "content": res}
            else:
                tool_results = []
                for tb in tool_blocks:
                    result = await execute_tool(tb.name, tb.input, pool)
                    yield {"type": "tool_result", "name": tb.name, "content": result}
                    tool_results.append({
                        "type":        "tool_result",
                        "tool_use_id": tb.id,
                        "content":     result,
                    })

            messages.append({"role": "user", "content": tool_results})

    except Exception as exc:
        yield {"type": "error", "message": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# OPENAI-COMPATIBLE BACKEND  (fully local — Ollama / LM Studio / vLLM / etc.)
# ─────────────────────────────────────────────────────────────────────────────

async def _run_openai(
    query: str,
    *,
    history: list[dict] | None = None,
    pool: Any | None = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    OpenAI-compatible backend for local LLMs.

    Recommended models (tool-calling support required):
        Ollama:    qwen2.5:7b, llama3.2:3b, mistral:7b, llama3.1:8b
        LM Studio: any GGUF model with tool-calling support
        vLLM:      Qwen2.5-7B-Instruct, Meta-Llama-3.1-8B-Instruct

    Config (.env):
        AI_PROVIDER=openai
        AI_BASE_URL=http://localhost:11434/v1   # Ollama
        AI_MODEL=qwen2.5:7b
        AI_API_KEY=ollama                        # any non-empty string
    """
    client = _make_openai_client()
    oai_tools = _to_openai_tools(SECURITY_TOOLS)

    if history is None:
        messages: list[dict] = []
    else:
        messages = history

    messages.append({"role": "user", "content": query})

    turn = 0
    try:
        while True:
            turn += 1
            text_accum   = ""
            pending_calls: dict[int, dict[str, str]] = {}   # stream index → {id, name, args}
            finish_reason = "stop"

            # System prompt is prepended per-call (not stored in history)
            api_messages = [{"role": "system", "content": _SYSTEM_PROMPT}] + messages

            stream = await client.chat.completions.create(
                model=cfg.model,
                messages=api_messages,
                tools=oai_tools,
                stream=True,
                temperature=0,          # deterministic for security analysis
                max_tokens=8192,
            )

            async for chunk in stream:
                if not chunk.choices:
                    continue
                choice = chunk.choices[0]

                if choice.finish_reason:
                    finish_reason = choice.finish_reason

                delta = choice.delta

                # Streamed text
                if delta.content:
                    yield {"type": "text", "text": delta.content}
                    text_accum += delta.content

                # Streamed tool-call deltas (arguments arrive in fragments)
                if delta.tool_calls:
                    for tc in delta.tool_calls:
                        idx = tc.index
                        if idx not in pending_calls:
                            pending_calls[idx] = {"id": "", "name": "", "args": ""}
                        if tc.id:
                            pending_calls[idx]["id"] = tc.id
                        if tc.function:
                            if tc.function.name:
                                pending_calls[idx]["name"] += tc.function.name
                            if tc.function.arguments:
                                pending_calls[idx]["args"] += tc.function.arguments

            # Build the assistant message for history
            asst_msg: dict[str, Any] = {"role": "assistant", "content": text_accum or None}
            if pending_calls:
                asst_msg["tool_calls"] = [
                    {
                        "id":       tc["id"],
                        "type":     "function",
                        "function": {"name": tc["name"], "arguments": tc["args"]},
                    }
                    for tc in pending_calls.values()
                ]
            messages.append(asst_msg)

            # No tool calls → done
            if not pending_calls or finish_reason == "stop":
                yield {"type": "done", "turns": turn}
                return

            # Execute each tool call and feed results back
            tool_result_msgs: list[dict] = []
            for tc in pending_calls.values():
                name = tc["name"]
                try:
                    inputs = json.loads(tc["args"])
                except json.JSONDecodeError:
                    inputs = {}

                yield {"type": "tool_call", "name": name, "inputs": inputs}
                result = await execute_tool(name, inputs, pool)
                yield {"type": "tool_result", "name": name, "content": result}

                tool_result_msgs.append({
                    "role":         "tool",
                    "tool_call_id": tc["id"],
                    "content":      result,
                })

            messages.extend(tool_result_msgs)

    except Exception as exc:
        yield {"type": "error", "message": str(exc)}


# ─────────────────────────────────────────────────────────────────────────────
# DEMO MODE  (AI_PROVIDER=demo)
# Zero credentials — pre-recorded realistic investigation scripts.
# Streams text and tool events with realistic timing so every UI feature
# (markdown rendering, tool call cards, tool result blocks) can be tested
# without any API key or MCP credentials.
# ─────────────────────────────────────────────────────────────────────────────

async def _demo_text(text: str):
    """Stream text in small chunks simulating LLM token output."""
    i = 0
    while i < len(text):
        size = 4 + (i * 7 % 5)   # 4–8 chars, deterministic variation
        chunk = text[i:i + size]
        yield {"type": "text", "text": chunk}
        i += size
        # Slightly longer pause at paragraph / section breaks
        await asyncio.sleep(0.045 if chunk.endswith(("\n\n", "---\n", ":\n")) else 0.013)


async def _demo_tool(name: str, inputs: dict[str, Any], result: str):
    """Yield tool_call, simulate latency, then yield tool_result."""
    yield {"type": "tool_call", "name": name, "inputs": inputs}
    await asyncio.sleep(0.55 + len(result) / 3000)
    yield {"type": "tool_result", "name": name, "content": result}


# ── Scenario helpers ──────────────────────────────────────────────────────────

async def _demo_vuln_triage(query: str):
    import re as _re
    m = _re.search(r'CVE-\d{4}-\d{4,}', query, _re.IGNORECASE)
    cve    = m.group(0).upper() if m else "CVE-2024-50623"
    target = "payments-api"

    async for ev in _demo_text(
        f"## Vulnerability Triage — {cve}\n\n"
        "Running a full assessment across your security stack: active exploitation "
        "status, affected repositories, reachability, and detection coverage.\n\n"
        f"**→ Checking GreyNoise for active exploitation of {cve}...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "check_greynoise",
        {"query": cve, "query_type": "cve"},
        f"GreyNoise — {cve}:\n"
        "  ACTIVELY EXPLOITED\n"
        "  2,400+ IPs scanning for this CVE in last 24 h\n"
        "  First exploitation: 2024-10-28 | Trend: +300% this week\n"
        "  Linked campaigns: Cl0p ransomware, Scattered Spider\n"
        "  [Demo — set GREYNOISE_API_KEY for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        f"\n**→ Pulling GHAS/Dependabot alerts for {target}...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "get_ghas_alerts",
        {"repo": f"acme-corp/{target}", "alert_type": "dependabot",
         "severity": "critical", "cve_id": cve},
        f"GHAS alerts — acme-corp/{target}:\n"
        f"  Dependabot: 12 alerts (2 critical, 5 high)\n"
        f"  → {cve} FOUND in direct dependency com.cleo:harmony:5.6.0\n"
        "  Code scanning: 3 alerts (SQL injection, path traversal)\n"
        "  Secret scanning: 1 exposed token — rotation required\n"
        "  [Demo — set GITHUB_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Snyk reachability analysis...**\n"):
        yield ev

    async for ev in _demo_tool(
        "check_snyk",
        {"repo": f"acme-corp/{target}", "cve_id": cve, "check_reachability": True},
        f"Snyk SCA — acme-corp/{target}:\n"
        f"  CRITICAL: {cve} in com.cleo:harmony:5.6.0 (direct dep)\n"
        "  Reachability: CONFIRMED — vulnerable function called in "
        "FileUploadController.java:L89\n"
        "  Fix: upgrade to com.cleo:harmony:5.8.0\n"
        "  [Demo — set SNYK_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "search_detections",
        {"query": cve, "rule_type": "all"},
        f"Security Detections — '{cve}':\n"
        "  7 rules found\n"
        "  Sigma (3): file-upload-exploit.yml, webshell-detection.yml, lateral-movement.yml\n"
        "  ESCU (2): remote-code-execution-via-cleo.xml\n"
        "  ATT&CK: T1190 (Initial Access), T1059 (Execution)\n"
        "  [No auth required — open-source rule database]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Risk Assessment\n\n"
        "| Factor | Value |\n"
        "|---|---|\n"
        "| CVSS Score | **9.8 (Critical)** |\n"
        f"| Active Exploitation | ✅ Confirmed — 2,400+ scanner IPs |\n"
        f"| Affected repo | `acme-corp/{target}` |\n"
        "| Dependency | `com.cleo:harmony:5.6.0` (direct) |\n"
        "| Reachable code path | ✅ Confirmed via Snyk |\n"
        "| Detection rules | ✅ 7 rules available |\n"
        "| Threat actors | Cl0p ransomware, Scattered Spider |\n\n"
        "## 🔴 Priority: **P1 — Immediate Action Required**\n\n"
        "The vulnerability is **actively exploited** by ransomware groups, present in a "
        "**direct dependency**, and the vulnerable code path is **confirmed reachable** "
        "in production.\n\n"
        "### Recommended Actions\n\n"
        "**Immediate (0–4 h):**\n"
        f"- Upgrade `com.cleo:harmony` → `5.8.0` in `{target}`\n"
        "- Block known scanner IPs (185.220.101.34, 45.142.212.55) at WAF\n"
        "- Rotate the exposed GitHub token found in secret scanning\n\n"
        "**Short-term (24–48 h):**\n"
        "- Deploy Sigma rules to Sentinel and Splunk (7 rules available)\n"
        "- Run Trivy scan on all container images using this dependency\n\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "create_jira_ticket",
        {"project": "SEC",
         "summary": f"P1: {cve} actively exploited in {target} — patch required",
         "description": "Full findings attached.", "priority": "Highest",
         "issue_type": "Security", "labels": ["p1", "vuln-triage", cve.lower()]},
        "Jira ticket created:\n"
        "  ID: SEC-4521\n"
        f"  'P1: {cve} actively exploited in {target}'\n"
        "  Priority: Highest | SLA: 4 h\n"
        "  URL: https://your-org.atlassian.net/browse/SEC-4521\n"
        "  [Demo — set JIRA_URL for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "post_slack",
        {"channel": "#vuln-triage",
         "message": f"🔴 P1: {cve} actively exploited — {target} affected. "
                    "Patch within 4 h. Jira: SEC-4521",
         "urgency": "urgent"},
        "Slack → #vuln-triage:\n"
        "  Message delivered | @here notification sent\n"
        "  Thread created for follow-up\n"
        "  [Demo — set SLACK_BOT_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n**Jira SEC-4521 created · Slack alert posted to #vuln-triage ✓**\n"
    ):
        yield ev

    yield {"type": "done", "turns": 2}


async def _demo_incident(query: str):
    async for ev in _demo_text(
        "## Incident Response\n\n"
        "Correlating events across SIEM, enriching IOCs, checking identity "
        "impact, and scoping blast radius.\n\n"
        "**→ Querying Sentinel for related events (last 24 h)...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "query_sentinel",
        {"query": "SecurityEvent | where EventID in (4624,4625,4648) | "
                  "summarize count() by IpAddress, Account | order by count_ desc",
         "time_range": "24h"},
        "Sentinel KQL — 24h window:\n"
        "  47 matching events | 3 high-severity incidents opened\n"
        "  Top source IPs: 185.220.101.34 (TOR exit), 45.142.212.55\n"
        "  Anomaly: 23 failed auth → 1 success at 02:34 UTC from RU\n"
        "  Affected resources: payments-api, auth-service\n"
        "  [Demo — set SENTINEL credentials for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "query_splunk",
        {"search": "index=security sourcetype=win_security EventCode=4648 "
                   "| stats count by src_ip, user | sort -count",
         "time_range": "-24h@h"},
        "Splunk SPL — 24h window:\n"
        "  156 events | peak 02:34 UTC | index=security host=prod-web-01\n"
        "  Notable: brute-force pattern then lateral movement to db-server-02\n"
        "  [Demo — set SPLUNK_URL for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Checking GreyNoise for attacker IP reputation...**\n"):
        yield ev

    async for ev in _demo_tool(
        "check_greynoise",
        {"query": "185.220.101.34", "query_type": "ip"},
        "GreyNoise — 185.220.101.34:\n"
        "  Classification: MALICIOUS | Tags: TOR exit node, Mass-scanner\n"
        "  Last seen: 2 h ago | Targeting: SSH, RDP, web login forms\n"
        "  RIOT: No — not a known benign business IP\n"
        "  [Demo — set GREYNOISE_API_KEY for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Checking Okta for affected user sessions...**\n"):
        yield ev

    async for ev in _demo_tool(
        "manage_okta",
        {"action": "get_user", "user": "j.smith@acme.com"},
        "Okta — j.smith@acme.com:\n"
        "  Status: Active | Last login: 02:31 UTC (ANOMALOUS)\n"
        "  Active sessions: 3 (US, RU, NG) — impossible travel detected\n"
        "  MFA: SMS push only (not FIDO2/hardware key)\n"
        "  Groups: engineering, payments-team | Apps: 23 assigned\n"
        "  [Demo — set OKTA_ORG_URL for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Incident Assessment\n\n"
        "| Factor | Status |\n"
        "|---|---|\n"
        "| Source IP | 185.220.101.34 — TOR exit, malicious |\n"
        "| Authentication | Credential stuffing → 1 successful login |\n"
        "| Affected user | j.smith@acme.com (payments-team) |\n"
        "| Impossible travel | ✅ Detected (US → RU → NG within 2 h) |\n"
        "| Blast radius | payments-api, auth-service, 23 apps accessible |\n\n"
        "## Severity: **P1 — Active Compromise**\n\n"
        "A compromised account with access to `payments-api` has an active session "
        "from a TOR exit node. Immediate containment required.\n\n"
        "### Containment Steps _(awaiting analyst approval)_\n\n"
        "1. Suspend `j.smith@acme.com` Okta session immediately\n"
        "2. Force password reset + re-enroll with FIDO2 key\n"
        "3. Block 185.220.101.34 at WAF and firewall\n"
        "4. Review all actions by j.smith in the last 48 h\n"
        "5. Notify j.smith through out-of-band channel (phone)\n\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "create_jira_ticket",
        {"project": "SEC",
         "summary": "P1 IR: Compromised account j.smith — TOR login to payments-api",
         "description": "Active session from TOR exit. Impossible travel confirmed.",
         "priority": "Highest", "issue_type": "Incident"},
        "Jira ticket created:\n"
        "  ID: SEC-4522\n"
        "  'P1 IR: Compromised account j.smith — TOR login to payments-api'\n"
        "  Priority: Highest | SLA: Immediate\n"
        "  [Demo — set JIRA_URL for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "post_slack",
        {"channel": "#security-incidents",
         "message": "🚨 P1 INCIDENT: Compromised account (j.smith) — "
                    "TOR login to payments-api. Containment steps in SEC-4522.",
         "urgency": "urgent"},
        "Slack → #security-incidents:\n"
        "  Message delivered | @here notification sent\n"
        "  [Demo — set SLACK_BOT_TOKEN for live data]",
    ):
        yield ev

    yield {"type": "done", "turns": 2}


async def _demo_default(query: str):
    async for ev in _demo_text(
        "## Security Investigation\n\n"
        "Running a multi-source investigation across your security stack.\n\n"
        "**→ Querying SIEM for relevant events...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "query_sentinel",
        {"query": "SecurityAlert | where TimeGenerated > ago(24h) | "
                  "summarize count() by AlertName, Severity",
         "time_range": "24h"},
        "Sentinel — 24h window:\n"
        "  47 security alerts | 3 high | 12 medium\n"
        "  Top alert: Unusual network scanning from internal host\n"
        "  Affected: prod-web-01, db-server-02\n"
        "  [Demo — set SENTINEL credentials for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "check_greynoise",
        {"query": "185.220.101.34", "query_type": "ip"},
        "GreyNoise — 185.220.101.34:\n"
        "  Classification: MALICIOUS | Tags: TOR exit node\n"
        "  Last seen: 2 h ago | RIOT: No\n"
        "  [Demo — set GREYNOISE_API_KEY for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "query_opencti",
        {"query": "185.220.101.34", "type": "indicator"},
        "OpenCTI — '185.220.101.34':\n"
        "  3 threat actor matches | Primary: Cl0p (confidence 85%)\n"
        "  Campaigns: MOVEit exploitation, Cleo mass exploitation\n"
        "  MITRE: T1190, T1486 | IOCs: 47 IPs, 12 domains\n"
        "  [Demo — set OPENCTI_URL for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Findings Summary\n\n"
        "Based on the multi-source analysis:\n\n"
        "- **SIEM**: 47 alerts in 24 h, 3 high-severity incidents involving "
        "`prod-web-01` and `db-server-02`\n"
        "- **Threat Intel**: Source IP 185.220.101.34 is a known malicious TOR "
        "exit node linked to Cl0p ransomware campaigns\n"
        "- **Recommendation**: Investigate the internal host generating scan "
        "traffic and review firewall egress rules\n\n"
        "### Next Steps\n\n"
        "1. Run the **Incident Response** playbook if a compromise is confirmed\n"
        "2. Deploy the Sigma rules identified in the Security Detections database\n"
        "3. Review cloud posture with the **Cloud Posture Review** playbook\n\n"
        "_This is a demo response. Set `AI_PROVIDER=anthropic` and `AI_API_KEY` "
        "for live AI-powered investigations._\n"
    ):
        yield ev

    yield {"type": "done", "turns": 1}


async def _demo_threat_hunt(query: str):
    async for ev in _demo_text(
        "## Threat Hunt\n\n"
        "Searching for attacker TTPs across detection libraries, SIEM logs, "
        "and threat intelligence sources.\n\n"
        "**→ Searching Security Detections for matching rules...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "search_detections",
        {"query": query[:60], "rule_type": "all"},
        "Security Detections:\n"
        "  12 rules matched\n"
        "  Sigma (6): T1190-exploit-public.yml, lateral-movement-smb.yml,\n"
        "    rdp-bruteforce.yml, dns-tunneling.yml, process-injection.yml\n"
        "  ESCU (3): bruteforce-lockout.xml, exfil-via-dns.xml, cred-dump-lsass.xml\n"
        "  KQL (3): AzureSentinel detection rules\n"
        "  ATT&CK coverage: T1190, T1078, T1021, T1071, T1055, T1003\n"
        "  [No auth required — open-source rule database]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Running KQL hunt against Sentinel (last 7 days)...**\n"):
        yield ev

    async for ev in _demo_tool(
        "query_sentinel",
        {"query": "SecurityEvent | where TimeGenerated > ago(7d) | "
                  "where EventID in (4624,4625,4648) | "
                  "summarize count() by Account, Computer | where count_ > 100",
         "time_range": "7d"},
        "Sentinel KQL Hunt — 7-day window:\n"
        "  Suspicious authentication patterns:\n"
        "  svc-backup: 5,421 logins — anomalous spike vs 30-day baseline\n"
        "  admin@acme.com: 312 failed logins from 14 IPs — brute-force pattern\n"
        "  WORKSTATION-07 → DC-01: 89 lateral movement events via SMB\n"
        "  [Demo — set SENTINEL credentials for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Running SPL hunt against Splunk...**\n"):
        yield ev

    async for ev in _demo_tool(
        "query_splunk",
        {"query": "index=wineventlog EventCode=4688 | stats count by "
                  "ParentProcessName, ProcessName | where count > 50 | sort -count",
         "earliest": "-7d"},
        "Splunk SPL Hunt — 7-day window:\n"
        "  Suspicious process spawning:\n"
        "  powershell.exe → cmd.exe (1,203 events) — possible C2\n"
        "  winword.exe → powershell.exe (44 events) — macro execution\n"
        "  svchost.exe → rundll32.exe (22 events) — DLL side-loading\n"
        "  [Demo — set SPLUNK_URL for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "query_opencti",
        {"query": "lateral movement smb T1021", "type": "indicator"},
        "OpenCTI — Threat Intelligence:\n"
        "  3 active campaigns using SMB lateral movement\n"
        "  Primary: Cl0p (confidence 78%) | Secondary: APT41\n"
        "  Related IOCs: 18 IPs, 7 domains, 4 hashes\n"
        "  TTP overlap: T1021.002, T1078, T1003 — matches hunt findings\n"
        "  [Demo — set OPENCTI_URL for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Hunt Findings\n\n"
        "| Finding | Severity | ATT&CK |\n"
        "|---|---|---|\n"
        "| svc-backup anomalous login spike | **High** | T1078 — Valid Accounts |\n"
        "| Brute-force against admin@acme.com | **High** | T1110 — Brute Force |\n"
        "| Lateral movement WORKSTATION-07→DC-01 | **Critical** | T1021 — Remote Services |\n"
        "| Suspicious macro → PowerShell execution | **Medium** | T1059 — Execution |\n\n"
        "## Detection Gaps to Close\n\n"
        "- No alerting on `svc-backup` authentication anomalies\n"
        "- No detection for Office macro → PowerShell spawning\n"
        "- SMB lateral movement alert threshold too high (fires at >500 events)\n\n"
        "### Recommended Actions\n\n"
        "1. **Immediate**: Investigate WORKSTATION-07 for C2 implant\n"
        "2. **Deploy** the 6 Sigma rules to Sentinel and Splunk\n"
        "3. **Tune** SMB alert threshold to 50 events/h\n"
        "4. **Review** svc-backup service account — disable if not needed\n\n"
    ):
        yield ev

    yield {"type": "done", "turns": 2}


async def _demo_compliance(query: str):
    import re as _re
    m = _re.search(r'(soc.?2|iso.?27001|pci.?dss|hipaa|aws|azure|gcp|prod)', query, _re.IGNORECASE)
    target = m.group(0) if m else "aws-production"

    async for ev in _demo_text(
        "## Compliance Audit\n\n"
        f"Running a full compliance and posture assessment for `{target}`.\n\n"
        "**→ Checking Drata compliance posture...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "check_drata",
        {"scope": target},
        "Drata Compliance:\n"
        "  SOC 2 Type II: 84% controls passing (16 failing)\n"
        "  Failing controls:\n"
        "    CC6.1 — MFA not enforced for 3 service accounts\n"
        "    CC7.2 — No automated vulnerability scanning on schedule\n"
        "    CC9.2 — Vendor risk assessment overdue (12 vendors)\n"
        "  ISO 27001: 91% — 4 gaps in A.12.6 (technical vulnerability)\n"
        "  [Demo — set DRATA_API_KEY for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Running Prowler cloud posture checks...**\n"):
        yield ev

    async for ev in _demo_tool(
        "run_prowler",
        {"provider": "aws", "services": ["iam", "s3", "ec2", "rds"],
         "compliance": "cis_aws_foundations_benchmark"},
        "Prowler — AWS CIS Foundations:\n"
        "  Total checks: 247 | Pass: 198 | FAIL: 49\n"
        "  CRITICAL (8): root-mfa-disabled, s3-public-access (3),\n"
        "    rds-public-access (2), sg-0.0.0.0-443, iam-root-access-key\n"
        "  HIGH (19): iam-password-policy, cloudtrail-kms, vpc-flow-logs-disabled...\n"
        "  [Demo — set AWS credentials for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "get_ghas_alerts",
        {"repo": "acme-corp/all", "alert_type": "code_scanning"},
        "GHAS Code Scanning — All Repos:\n"
        "  19 open alerts | 3 critical, 8 high, 8 medium\n"
        "  Critical: SQL injection (api/db.py:L47), path traversal (utils/files.py:L203)\n"
        "  Secret scanning: 2 exposed tokens (AWS key, Slack bot token)\n"
        "  Code coverage: 62% — below 80% policy threshold\n"
        "  [Demo — set GITHUB_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "check_vault_radar",
        {"scope": "all-repos"},
        "Vault Radar — Secret Scanning:\n"
        "  4 active findings across 3 repositories\n"
        "  HIGH: AWS_ACCESS_KEY_ID in acme-corp/legacy-api (committed 14 days ago)\n"
        "  HIGH: SLACK_BOT_TOKEN in acme-corp/data-pipeline\n"
        "  MEDIUM: Generic API key pattern in acme-corp/docs\n"
        "  Recommended: rotate all 4 secrets immediately\n"
        "  [Demo — set VAULT_ADDR for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Compliance Gap Report\n\n"
        f"**Environment:** `{target}` | **Date:** 2026-02-24\n\n"
        "| Category | Status | Gaps |\n"
        "|---|---|---|\n"
        "| SOC 2 Type II | 🟡 84% | 16 failing controls |\n"
        "| CIS AWS Foundations | 🔴 80% | 49 findings (8 critical) |\n"
        "| Secret Management | 🔴 FAIL | 4 exposed secrets |\n"
        "| Code Security | 🟡 62% coverage | 19 open GHAS alerts |\n\n"
        "## Prioritised Remediation\n\n"
        "**P0 — Rotate immediately:**\n"
        "- AWS_ACCESS_KEY_ID and SLACK_BOT_TOKEN (exposed in git)\n\n"
        "**P1 — Fix within 24 h:**\n"
        "- Enable MFA on 3 service accounts (CC6.1 violation)\n"
        "- Remove public access from 3 S3 buckets\n"
        "- Disable public RDS access on 2 instances\n\n"
        "**P2 — Fix within 1 week:**\n"
        "- Enable CloudTrail KMS encryption\n"
        "- Enable VPC flow logs in all regions\n"
        "- Schedule automated vulnerability scanning\n\n"
    ):
        yield ev

    yield {"type": "done", "turns": 2}


async def _demo_secret_leak(query: str):
    async for ev in _demo_text(
        "## Secret Leak Response\n\n"
        "Scoping the exposure, identifying all affected systems, "
        "and coordinating credential rotation.\n\n"
        "**→ Checking Vault Radar for exposure scope...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "check_vault_radar",
        {"scope": "full-scan"},
        "Vault Radar — Exposure Report:\n"
        "  CRITICAL: AWS_ACCESS_KEY_ID (AKIA...) committed to acme-corp/payments-api\n"
        "  First detected: 2026-02-23 14:22 UTC (26 hours ago)\n"
        "  Risk score: 98/100 — active credentials, visible in commit history\n"
        "  Additional exposures: same key in 2 CI/CD pipeline logs\n"
        "  [Demo — set VAULT_ADDR for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Checking GHAS secret scanning for additional exposures...**\n"):
        yield ev

    async for ev in _demo_tool(
        "get_ghas_alerts",
        {"alert_type": "secret_scanning", "state": "open"},
        "GHAS Secret Scanning — All Repos:\n"
        "  3 open secret alerts\n"
        "  acme-corp/payments-api: AWS key (confirmed match)\n"
        "  acme-corp/data-pipeline: Slack bot token\n"
        "  acme-corp/legacy-api: Generic API key (40 days exposed)\n"
        "  [Demo — set GITHUB_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "rotate_vault_secret",
        {"path": "aws/payments-api/access-key", "flag_approval": True},
        "Vault — Secret Rotation:\n"
        "  ⚠️ APPROVAL REQUIRED before rotation executes\n"
        "  Current: akia-redacted-key (created 2025-09-12)\n"
        "  Rotation plan: generate new IAM key → update Vault → redeploy secrets\n"
        "  Estimated downtime: 0 (blue/green rotation supported)\n"
        "  Awaiting approval from: @security-on-call, @infra-lead\n"
        "  [Demo — set VAULT_ADDR for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "get_okta_user",
        {"query": "svc-payments", "check_sessions": True},
        "Okta — Service Account Activity:\n"
        "  svc-payments@acme.com — last auth: 2026-02-24 08:11 UTC\n"
        "  Active sessions: 0 (API key auth, not OIDC)\n"
        "  IAM key used in 14 API calls in last 24 h\n"
        "  Most sensitive: s3:GetObject on payments-archive bucket\n"
        "  No evidence of unauthorized access detected\n"
        "  [Demo — set OKTA credentials for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "create_jira_ticket",
        {"project": "SEC",
         "summary": "P1: AWS key exposed in payments-api — rotate immediately",
         "issue_type": "Security", "priority": "Highest",
         "labels": ["secret-leak", "p1", "aws"]},
        "Jira ticket created:\n"
        "  ID: SEC-4522\n"
        "  'P1: AWS key exposed in payments-api — rotate immediately'\n"
        "  Priority: Highest | SLA: 4 h | Assignee: @security-on-call\n"
        "  [Demo — set JIRA_URL for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "post_slack",
        {"channel": "#security-alerts",
         "message": "🔴 SECRET LEAK: AWS key exposed in payments-api (26 h). "
                    "Rotation pending approval. Jira: SEC-4522",
         "urgency": "urgent"},
        "Slack → #security-alerts:\n"
        "  Message delivered | @security-team notified\n"
        "  [Demo — set SLACK_BOT_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Secret Leak Summary\n\n"
        "| Item | Status |\n"
        "|---|---|\n"
        "| Exposed credential | AWS_ACCESS_KEY_ID |\n"
        "| Exposure duration | 26 hours |\n"
        "| Additional repos affected | 2 |\n"
        "| Unauthorized usage | None detected |\n"
        "| Rotation status | **⚠️ Pending approval** |\n"
        "| Jira ticket | SEC-4522 (P1) |\n\n"
        "### Immediate Actions Required\n\n"
        "1. **Approve rotation** in Vault (SEC-4522 comment thread)\n"
        "2. **Revoke** the key directly in AWS IAM Console — don't wait for rotation\n"
        "3. **Audit** CloudTrail for any API calls using this key\n"
        "4. **Clean** git history with `git filter-repo` to remove the committed key\n\n"
    ):
        yield ev

    yield {"type": "done", "turns": 2}


async def _demo_cloud_posture(query: str):
    async for ev in _demo_text(
        "## Cloud Posture Review\n\n"
        "Running a comprehensive cloud security assessment: configuration drift, "
        "WAF analytics, SIEM cloud events, and secrets hygiene.\n\n"
        "**→ Running Prowler cloud posture checks...**\n"
    ):
        yield ev

    async for ev in _demo_tool(
        "run_prowler",
        {"provider": "aws", "services": ["iam", "s3", "ec2", "rds", "lambda"],
         "compliance": "cis_aws_foundations_benchmark"},
        "Prowler — AWS (us-east-1 + us-west-2):\n"
        "  Total: 312 checks | Pass: 257 | FAIL: 55\n"
        "  CRITICAL (6):\n"
        "    root-account-mfa-disabled\n"
        "    s3-bucket-public-read (payments-archive)\n"
        "    ec2-sg-unrestricted-ssh (sg-0a1b2c3d)\n"
        "    rds-public-access (db-prod-mysql)\n"
        "    iam-root-access-key-active\n"
        "    lambda-function-public (payments-webhook)\n"
        "  [Demo — set AWS credentials for live data]",
    ):
        yield ev

    async for ev in _demo_text("\n**→ Querying Cloudflare WAF events (last 24 h)...**\n"):
        yield ev

    async for ev in _demo_tool(
        "query_cloudflare",
        {"query": "security_events", "time_range": "24h"},
        "Cloudflare WAF — 24h:\n"
        "  Total requests: 4.2M | Blocked: 18,240 (0.43%)\n"
        "  Top threats: SQLi (6,120), XSS (4,890), LFI (3,201)\n"
        "  Bot traffic: 38% | Verified bots: 12% | Unverified: 26%\n"
        "  DDoS: No active attack | Peak: 12K req/s at 03:14 UTC\n"
        "  [Demo — set CLOUDFLARE_API_TOKEN for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "query_sentinel",
        {"query": "AzureActivity | where ActivityStatusValue == 'Failed' | "
                  "summarize count() by Caller, OperationNameValue | top 10 by count_",
         "time_range": "24h"},
        "Sentinel — Cloud Activity Anomalies:\n"
        "  terraform@acme.com: 847 failed API calls (unusual spike)\n"
        "  unknown-svc: 234 failed S3 PutObject (access denied)\n"
        "  Root account: 3 direct console logins (policy violation)\n"
        "  [Demo — set SENTINEL credentials for live data]",
    ):
        yield ev

    async for ev in _demo_tool(
        "check_vault",
        {"path": "secret/", "check_ttl": True},
        "Vault — Secrets Hygiene:\n"
        "  Total secrets: 184 | Expiring <30d: 23 | Expired: 7\n"
        "  Orphaned secrets (no app reference): 31\n"
        "  Secrets without rotation policy: 48\n"
        "  Last audit: 47 days ago (policy: monthly)\n"
        "  [Demo — set VAULT_ADDR for live data]",
    ):
        yield ev

    async for ev in _demo_text(
        "\n---\n\n"
        "## Cloud Posture Summary\n\n"
        "| Domain | Score | Critical Findings |\n"
        "|---|---|---|\n"
        "| AWS Configuration | 82% | 6 critical misconfigs |\n"
        "| WAF / Perimeter | 94% | No active attack |\n"
        "| Cloud Activity | 🟡 Review | Terraform anomaly + root logins |\n"
        "| Secrets Hygiene | 🔴 Poor | 7 expired, 31 orphaned |\n\n"
        "## Prioritised Remediation Roadmap\n\n"
        "**Immediate (today):**\n"
        "- Enable MFA on AWS root account\n"
        "- Remove public access from `payments-archive` S3 bucket\n"
        "- Restrict SSH security group to VPN CIDR\n"
        "- Disable root IAM access key\n\n"
        "**This week:**\n"
        "- Disable public access on `db-prod-mysql` RDS instance\n"
        "- Add auth to `payments-webhook` Lambda or make it private\n"
        "- Rotate 7 expired Vault secrets and apply rotation policies\n"
        "- Investigate terraform@acme.com API call spike\n\n"
    ):
        yield ev

    yield {"type": "done", "turns": 2}


async def _run_demo(
    query: str,
    *,
    history: list[dict] | None = None,
    pool: Any | None = None,
) -> AsyncGenerator[dict[str, Any], None]:
    """
    Demo mode dispatcher — zero credentials, fully offline.
    Picks a pre-recorded scenario based on query keywords.

    Set AI_PROVIDER=demo (no AI_API_KEY needed) to use this mode.
    """
    import re as _re
    q = query.lower()

    if _re.search(r'cve-\d{4}|dependabot|semgrep|snyk\b|reachab|vuln(?:nerabilit)?', q):
        async for ev in _demo_vuln_triage(query):
            yield ev
    elif _re.search(r'incident|breach|compromis|suspicious login|alert sec|intrus|attacker', q):
        async for ev in _demo_incident(query):
            yield ev
    elif _re.search(r'threat.hunt|hunting playbook|sigma.rule|escu|t\d{4}\b|lateral.mov', q):
        async for ev in _demo_threat_hunt(query):
            yield ev
    elif _re.search(r'compliance|audit playbook|drata|vanta|soc.?2|iso.?27001|pci', q):
        async for ev in _demo_compliance(query):
            yield ev
    elif _re.search(r'secret.leak|vault.radar|token.expos|credential.leak|leak response', q):
        async for ev in _demo_secret_leak(query):
            yield ev
    elif _re.search(r'cloud.posture|prowler|cloudflare|cloud.audit|posture.review', q):
        async for ev in _demo_cloud_posture(query):
            yield ev
    else:
        async for ev in _demo_default(query):
            yield ev


# ─────────────────────────────────────────────────────────────────────────────
# CLI RUNNER
# ─────────────────────────────────────────────────────────────────────────────

async def _run_cli(query: str, verbose: bool, output: str | None) -> None:
    """Drive run_investigation() for the CLI, printing events to stdout."""
    divider = "─" * 62
    lines: list[str] = []        # accumulated text for --output

    print(f"\n{divider}")
    print(f"  SOCPilot › {query[:70]}{'…' if len(query) > 70 else ''}")
    print(divider)

    # Collect pool lazily — only import MCPClientPool when needed
    pool = None
    if cfg.live:
        from mcp_client import MCPClientPool
        pool = MCPClientPool(cfg)
        await pool.__aenter__()

    try:
        async for event in run_investigation(query, pool=pool, verbose=verbose):
            etype = event["type"]

            if etype == "thinking" and verbose:
                print(event["text"], end="", flush=True)

            elif etype == "text":
                text = event["text"]
                print(text, end="", flush=True)
                lines.append(text)

            elif etype == "tool_call":
                print(f"\n\n  ├─ [{event['name']}] {json.dumps(event['inputs'])[:120]}")

            elif etype == "tool_result":
                first = event["content"].splitlines()[0] if event["content"] else ""
                print(f"  └─ {first}")
                lines.append(f"\n**Tool: {event['name']}**\n{event['content']}\n")

            elif etype == "done":
                print(f"\n\n{divider}")
                print("  Investigation complete.")
                print(divider + "\n")

            elif etype == "error":
                print(f"\n\n  [Error] {event['message']}", file=sys.stderr)

    finally:
        if pool is not None:
            await pool.__aexit__(None, None, None)

    if output:
        report_path = Path(output)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        header = f"# SOCPilot Report\n\n**Query:** {query}\n\n**Generated:** {ts}\n\n---\n\n"
        report_path.write_text(header + "".join(lines))
        print(f"  Report saved → {report_path}")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description="SOCPilot — AI Security Operations Co-pilot",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python agent.py "Is CVE-2024-50623 actively exploited? Check payments-api."
  python agent.py --playbook vuln-triage "CVE-2024-50623 in payments-api"
  python agent.py --playbook incident-response "alert SEC-7721"
  python agent.py --playbook threat-hunting "Cl0p ransomware TTPs"
  python agent.py --playbook secret-leak-response "AWS key in payments-service"
  python agent.py --playbook cloud-posture-review "AWS prod account"
  python agent.py --playbook compliance-audit "AWS prod" --output reports/audit.md
  python agent.py --list-playbooks
  python agent.py --verbose "hunt for T1190 exploitation in our environment"
""",
    )
    parser.add_argument("query", nargs="?", help="Security query or investigation prompt")
    parser.add_argument(
        "--playbook", "-p",
        choices=list(PLAYBOOK_PROMPTS.keys()),
        metavar="NAME",
        help=f"Run a SOC playbook. Choices: {', '.join(PLAYBOOK_PROMPTS.keys())}",
    )
    parser.add_argument(
        "--list-playbooks", "-l",
        action="store_true",
        help="List available playbooks and exit",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show the agent's internal reasoning steps",
    )
    parser.add_argument(
        "--output", "-o",
        metavar="FILE",
        help="Save the investigation report to a Markdown file",
    )

    args = parser.parse_args()

    # --list-playbooks needs no API key
    if args.list_playbooks:
        print("\nAvailable SOC Playbooks:\n")
        for name, prompt in PLAYBOOK_PROMPTS.items():
            first_line = prompt.split("\n")[0].replace("{target}", "<target>")
            print(f"  {name:<28} {first_line[:55]}")
        print(
            "\nUsage:\n"
            "  python agent.py --playbook <name> \"<target>\"\n"
            "\nExample:\n"
            "  python agent.py --playbook vuln-triage \"CVE-2024-50623 in payments-api\"\n"
        )
        return

    # All other modes require an API key
    if not cfg.api_key:
        print(
            "Error: AI_API_KEY is not set.\n"
            "  cp .env.example .env\n"
            "  # Edit .env and set AI_API_KEY=<your key>\n"
            "  source .env  (or use python-dotenv)"
        )
        sys.exit(1)

    # Piped input
    if not args.query and not sys.stdin.isatty():
        args.query = sys.stdin.read().strip()

    # Playbook mode
    if args.playbook:
        if not args.query:
            parser.error(
                f"--playbook requires a target argument.\n"
                f"  python agent.py --playbook {args.playbook} \"<target>\""
            )
        prompt = PLAYBOOK_PROMPTS[args.playbook].format(target=args.query)
        asyncio.run(_run_cli(prompt, args.verbose, args.output))
        return

    # Direct query mode
    if args.query:
        asyncio.run(_run_cli(args.query, args.verbose, args.output))
        return

    # ── Interactive CLI ──────────────────────────────────────────────────────
    print("\n  SOCPilot — AI Security Operations Co-pilot")
    print("  Private-subnet deployment | Type 'help' for commands, 'exit' to quit\n")

    history: list[dict] = []

    async def _interactive_loop() -> None:
        pool = None
        if cfg.live:
            from mcp_client import MCPClientPool
            pool = MCPClientPool(cfg)
            await pool.__aenter__()

        try:
            while True:
                try:
                    raw = input("SOCPilot> ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\n  Session ended.")
                    break

                if not raw:
                    continue
                if raw.lower() in ("exit", "quit", "q"):
                    print("  Session ended.")
                    break
                if raw.lower() in ("help", "--help", "?"):
                    print(
                        "\n  Commands:\n"
                        "    <query>                       Free-form security question\n"
                        "    --playbook <name> <target>    Run a structured SOC playbook\n"
                        "    --list-playbooks              Show available playbooks\n"
                        "    clear                         Clear session history\n"
                        "    exit                          Quit\n"
                        "\n  Example queries:\n"
                        "    Is CVE-2024-50623 being exploited? Check payments-api.\n"
                        "    --playbook vuln-triage CVE-2024-50623 in payments-api\n"
                        "    --playbook incident-response suspicious login 185.220.101.45\n"
                    )
                    continue
                if raw.lower() == "clear":
                    history.clear()
                    print("  Session history cleared.")
                    continue
                if raw.lower() in ("--list-playbooks", "-l"):
                    for name in PLAYBOOK_PROMPTS:
                        print(f"    {name}")
                    continue

                # Inline playbook shorthand
                if raw.startswith("--playbook "):
                    parts = raw.split(None, 2)
                    pb_name   = parts[1] if len(parts) > 1 else ""
                    pb_target = parts[2] if len(parts) > 2 else ""
                    if pb_name in PLAYBOOK_PROMPTS:
                        prompt = PLAYBOOK_PROMPTS[pb_name].format(target=pb_target)
                    else:
                        print(f"  Unknown playbook '{pb_name}'. "
                              f"Available: {', '.join(PLAYBOOK_PROMPTS.keys())}")
                        continue
                else:
                    prompt = raw

                print()
                divider = "─" * 62
                async for event in run_investigation(
                    prompt, history=history, pool=pool, verbose=args.verbose
                ):
                    etype = event["type"]
                    if etype == "text":
                        print(event["text"], end="", flush=True)
                    elif etype == "tool_call":
                        print(f"\n\n  ├─ [{event['name']}] {json.dumps(event['inputs'])[:120]}")
                    elif etype == "tool_result":
                        first = event["content"].splitlines()[0] if event["content"] else ""
                        print(f"  └─ {first}")
                    elif etype == "done":
                        print(f"\n\n{divider}\n")
                    elif etype == "error":
                        print(f"\n\n  [Error] {event['message']}\n", file=sys.stderr)
        finally:
            if pool is not None:
                await pool.__aexit__(None, None, None)

    asyncio.run(_interactive_loop())


if __name__ == "__main__":
    main()