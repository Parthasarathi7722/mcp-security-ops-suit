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
    if cfg.provider == "openai":
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