#!/usr/bin/env python3
"""
onboard.py — SOCPilot Interactive Tool Onboarding Wizard

Guides you through selecting which MCP security tools to enable,
collecting the required credentials, and writing a ready-to-use .env file.

Usage:
    python onboard.py               # full wizard
    python onboard.py --check       # verify existing .env against selected tools
    python onboard.py --add splunk  # add a single tool to an existing .env
    python onboard.py --list        # list all available tools and their tiers

No external packages required — runs on stdlib + python-dotenv (optional).
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from textwrap import dedent
from typing import Any

# ─────────────────────────────────────────────────────────────────────────────
# Terminal colours (degrade gracefully on Windows / no-TTY)
# ─────────────────────────────────────────────────────────────────────────────

_COLOUR = sys.stdout.isatty() and os.name != "nt"

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOUR else text

def green(t: str)  -> str: return _c("32", t)
def yellow(t: str) -> str: return _c("33", t)
def cyan(t: str)   -> str: return _c("36", t)
def bold(t: str)   -> str: return _c("1",  t)
def dim(t: str)    -> str: return _c("2",  t)
def red(t: str)    -> str: return _c("31", t)


# ─────────────────────────────────────────────────────────────────────────────
# Credential descriptor
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Cred:
    key:      str             # env var name
    label:    str             # human label for the prompt
    secret:   bool = True     # mask input with getpass
    optional: bool = False    # True → skip with empty is OK
    hint:     str = ""        # short "where to find" hint shown below the prompt


# ─────────────────────────────────────────────────────────────────────────────
# Tool catalogue
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Tool:
    id:          str
    display:     str
    category:    str
    description: str
    tiers:       list[str]            # "solo" | "team" | "enterprise"
    credentials: list[Cred]
    free:        bool = False
    doc_url:     str = ""
    test_cmd:    list[str] = field(default_factory=list)  # optional smoke-test


TOOLS: dict[str, Tool] = {

    # ── SIEM & Monitoring ────────────────────────────────────────────────────

    "sentinel": Tool(
        id="sentinel", display="Microsoft Sentinel", category="SIEM",
        description="KQL queries, incident management, analytics rules",
        tiers=["team", "enterprise"],
        doc_url="https://github.com/dstreefkerk/ms-sentinel-mcp-server",
        credentials=[
            Cred("AZURE_TENANT_ID",        "Azure Tenant ID",        secret=False,
                 hint="Azure Portal → Entra ID → Overview → Tenant ID"),
            Cred("AZURE_CLIENT_ID",        "Azure Client ID",        secret=False,
                 hint="App Registration → Overview → Application (client) ID"),
            Cred("AZURE_CLIENT_SECRET",    "Azure Client Secret",    secret=True,
                 hint="App Registration → Certificates & Secrets → New client secret"),
            Cred("AZURE_SUBSCRIPTION_ID",  "Azure Subscription ID",  secret=False,
                 hint="Azure Portal → Subscriptions → Subscription ID"),
            Cred("SENTINEL_WORKSPACE_ID",  "Sentinel Workspace ID",  secret=False,
                 hint="Sentinel → Settings → Workspace settings → Workspace ID"),
            Cred("SENTINEL_RESOURCE_GROUP","Sentinel Resource Group", secret=False),
            Cred("SENTINEL_WORKSPACE_NAME","Sentinel Workspace Name", secret=False),
        ],
    ),
    "splunk": Tool(
        id="splunk", display="Splunk", category="SIEM",
        description="SPL searches, notable events, incident response",
        tiers=["team", "enterprise"],
        doc_url="https://docs.splunk.com/Documentation/Splunk/latest/Security/UsetheAuthenticationManager",
        credentials=[
            Cred("SPLUNK_URL",   "Splunk URL (https://your-splunk:8089)", secret=False,
                 hint="Your Splunk instance URL including port"),
            Cred("SPLUNK_TOKEN", "Splunk HEC / API token", secret=True,
                 hint="Settings → Tokens → New Token (or use an existing service account)"),
        ],
    ),
    "elastic": Tool(
        id="elastic", display="Elastic Security", category="SIEM",
        description="EQL/KQL log queries, security signals, trace analysis",
        tiers=["enterprise"],
        doc_url="https://www.elastic.co/guide/en/elasticsearch/reference/current/security-api-create-api-key.html",
        credentials=[
            Cred("ELASTICSEARCH_URL",     "Elasticsearch URL", secret=False,
                 hint="https://your-cluster.es.io:9243"),
            Cred("ELASTICSEARCH_API_KEY", "Elasticsearch API Key", secret=True,
                 hint="Kibana → Stack Management → API Keys → Create"),
        ],
    ),
    "datadog": Tool(
        id="datadog", display="Datadog", category="SIEM",
        description="Metrics, logs, security signals, RCA",
        tiers=["enterprise"],
        doc_url="https://docs.datadoghq.com/account_management/api-app-keys/",
        credentials=[
            Cred("DD_API_KEY", "Datadog API Key", secret=True,
                 hint="Datadog → Organization Settings → API Keys"),
            Cred("DD_APP_KEY", "Datadog Application Key", secret=True,
                 hint="Datadog → Organization Settings → Application Keys"),
        ],
    ),

    # ── Vulnerability Scanning ───────────────────────────────────────────────

    "ghas": Tool(
        id="ghas", display="GitHub Advanced Security (GHAS)", category="Vuln Scanning",
        description="Dependabot, CodeQL, secret scanning alerts",
        tiers=["solo", "team", "enterprise"], free=True,
        doc_url="https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens",
        credentials=[
            Cred("GITHUB_TOKEN", "GitHub Personal Access Token", secret=True,
                 hint="GitHub → Settings → Developer settings → Personal access tokens → Fine-grained (security_events:read)"),
            Cred("GITHUB_OWNER", "GitHub Organisation or User", secret=False,
                 hint="The org or username that owns the repos to scan"),
        ],
    ),
    "semgrep": Tool(
        id="semgrep", display="Semgrep", category="Vuln Scanning",
        description="SAST, 5000+ rules, 30+ languages",
        tiers=["solo", "team", "enterprise"], free=True,
        doc_url="https://semgrep.dev/orgs/-/settings/tokens",
        credentials=[
            Cred("SEMGREP_APP_TOKEN", "Semgrep App Token", secret=True,
                 hint="semgrep.dev → Settings → Tokens (community tier is free)"),
        ],
    ),
    "snyk": Tool(
        id="snyk", display="Snyk", category="Vuln Scanning",
        description="SCA, reachability analysis, IaC and container scanning",
        tiers=["team", "enterprise"],
        doc_url="https://docs.snyk.io/getting-started/how-to-obtain-and-authenticate-with-your-snyk-api-token",
        credentials=[
            Cred("SNYK_TOKEN",  "Snyk API Token", secret=True,
                 hint="app.snyk.io → Account Settings → Auth Token"),
            Cred("SNYK_ORG_ID", "Snyk Organisation ID", secret=False,
                 hint="app.snyk.io → Organisation → Settings → Organisation ID"),
        ],
    ),
    "trivy": Tool(
        id="trivy", display="Trivy", category="Vuln Scanning",
        description="Container image and SBOM scanning — no credentials required",
        tiers=["team", "enterprise"], free=True,
        credentials=[],   # no auth
    ),
    "stackhawk": Tool(
        id="stackhawk", display="StackHawk", category="Vuln Scanning",
        description="DAST, API security testing",
        tiers=["enterprise"],
        doc_url="https://app.stackhawk.com/settings/account",
        credentials=[
            Cred("STACKHAWK_API_KEY", "StackHawk API Key", secret=True,
                 hint="app.stackhawk.com → Account Settings → API Keys"),
        ],
    ),

    # ── Threat Intelligence ──────────────────────────────────────────────────

    "greynoise": Tool(
        id="greynoise", display="GreyNoise", category="Threat Intelligence",
        description="IP reputation, CVE exploitation status, RIOT classification",
        tiers=["solo", "team", "enterprise"], free=True,
        doc_url="https://viz.greynoise.io/account/api-key",
        credentials=[
            Cred("GREYNOISE_API_KEY", "GreyNoise API Key", secret=True,
                 hint="viz.greynoise.io → Account → API Key (community key is free)"),
        ],
    ),
    "opencti": Tool(
        id="opencti", display="OpenCTI", category="Threat Intelligence",
        description="IOCs, threat actors, malware families, MITRE ATT&CK",
        tiers=["team", "enterprise"],
        doc_url="https://docs.opencti.io/latest/deployment/configuration/",
        credentials=[
            Cred("OPENCTI_URL",   "OpenCTI URL", secret=False,
                 hint="https://your-opencti-instance.internal"),
            Cred("OPENCTI_TOKEN", "OpenCTI API Token", secret=True,
                 hint="OpenCTI → Profile → API Access"),
        ],
    ),
    "virustotal": Tool(
        id="virustotal", display="VirusTotal", category="Threat Intelligence",
        description="File, URL, IP and domain analysis (70+ AV engines)",
        tiers=["enterprise"],
        doc_url="https://www.virustotal.com/gui/user/apikey",
        credentials=[
            Cred("VT_API_KEY", "VirusTotal API Key", secret=True,
                 hint="virustotal.com → Profile icon → API Key"),
        ],
    ),

    # ── Cloud Security ───────────────────────────────────────────────────────

    "prowler": Tool(
        id="prowler", display="Prowler", category="Cloud Security",
        description="CIS, SOC 2, PCI-DSS cloud posture checks for AWS/Azure/GCP",
        tiers=["team", "enterprise"], free=True,
        doc_url="https://docs.prowler.com",
        credentials=[
            Cred("AWS_ACCESS_KEY_ID",     "AWS Access Key ID",     secret=False,
                 hint="IAM → Security credentials → Create access key (ReadOnlyAccess policy)"),
            Cred("AWS_SECRET_ACCESS_KEY", "AWS Secret Access Key", secret=True),
            Cred("AWS_DEFAULT_REGION",    "AWS Default Region",    secret=False,
                 hint="e.g. us-east-1"),
        ],
    ),
    "cloudflare": Tool(
        id="cloudflare", display="Cloudflare", category="Cloud Security",
        description="WAF events, Zero Trust, security analytics, IP blocking",
        tiers=["enterprise"],
        doc_url="https://dash.cloudflare.com/profile/api-tokens",
        credentials=[
            Cred("CLOUDFLARE_API_TOKEN",  "Cloudflare API Token",  secret=True,
                 hint="dash.cloudflare.com → Profile → API Tokens → Create Token"),
            Cred("CLOUDFLARE_ACCOUNT_ID", "Cloudflare Account ID", secret=False,
                 hint="dash.cloudflare.com → right sidebar → Account ID"),
        ],
    ),

    # ── Secrets & Identity ───────────────────────────────────────────────────

    "vault": Tool(
        id="vault", display="HashiCorp Vault", category="Secrets & Identity",
        description="Secret retrieval, credential rotation, token revocation",
        tiers=["team", "enterprise"],
        doc_url="https://developer.hashicorp.com/vault/docs/concepts/tokens",
        credentials=[
            Cred("VAULT_ADDR",  "Vault Address", secret=False,
                 hint="https://vault.your-org.internal:8200"),
            Cred("VAULT_TOKEN", "Vault Token",   secret=True,
                 hint="vault token create -policy=socpilot-read"),
        ],
    ),
    "vault-radar": Tool(
        id="vault-radar", display="Vault Radar (HCP)", category="Secrets & Identity",
        description="Leaked secret detection across repos, risk scoring",
        tiers=["team", "enterprise"],
        doc_url="https://developer.hashicorp.com/hcp/docs/hcp/security/service-principals",
        credentials=[
            Cred("HCP_CLIENT_ID",     "HCP Client ID",     secret=False,
                 hint="HCP Portal → Access Control → Service Principals → Create"),
            Cred("HCP_CLIENT_SECRET", "HCP Client Secret", secret=True),
            Cred("HCP_PROJECT_ID",    "HCP Project ID",    secret=False,
                 hint="HCP Portal → Project → Settings → Project ID"),
        ],
    ),
    "okta": Tool(
        id="okta", display="Okta", category="Secrets & Identity",
        description="User status, session management, MFA review, de-provisioning",
        tiers=["enterprise"],
        doc_url="https://developer.okta.com/docs/reference/core-okta-api/",
        credentials=[
            Cred("OKTA_ORG_URL",   "Okta Organisation URL", secret=False,
                 hint="https://your-org.okta.com"),
            Cred("OKTA_API_TOKEN", "Okta API Token",         secret=True,
                 hint="Okta Admin → Security → API → Tokens → Create Token"),
        ],
    ),

    # ── Compliance ───────────────────────────────────────────────────────────

    "drata": Tool(
        id="drata", display="Drata", category="Compliance",
        description="SOC 2/ISO 27001 controls, compliance tests, gap reports",
        tiers=["enterprise"],
        doc_url="https://drata.com/product/api",
        credentials=[
            Cred("DRATA_API_KEY", "Drata API Key", secret=True,
                 hint="Drata → Settings → Integrations → API Access"),
        ],
    ),
    "vanta": Tool(
        id="vanta", display="Vanta", category="Compliance",
        description="SOC 2/ISO 27001 status, remediation tasks, risk management",
        tiers=["enterprise"],
        doc_url="https://developer.vanta.com/",
        credentials=[
            Cred("VANTA_API_TOKEN", "Vanta API Token", secret=True,
                 hint="Vanta → Integrations → API → Generate Token"),
        ],
    ),

    # ── Detection Engineering ────────────────────────────────────────────────

    "security-detections": Tool(
        id="security-detections", display="Security Detections (Sigma/ESCU/KQL)",
        category="Detection Engineering",
        description="Open-source Sigma, ESCU, Elastic, and KQL detection rules — no auth",
        tiers=["solo", "team", "enterprise"], free=True,
        credentials=[],   # no auth
    ),

    # ── Ticketing & Notifications ────────────────────────────────────────────

    "jira": Tool(
        id="jira", display="Jira", category="Ticketing",
        description="Create and manage security tickets, SLA tracking",
        tiers=["team", "enterprise"],
        doc_url="https://support.atlassian.com/atlassian-account/docs/manage-api-tokens-for-your-atlassian-account/",
        credentials=[
            Cred("JIRA_URL",       "Jira URL",              secret=False,
                 hint="https://your-org.atlassian.net"),
            Cred("JIRA_EMAIL",     "Jira Account Email",    secret=False),
            Cred("JIRA_API_TOKEN", "Jira API Token",        secret=True,
                 hint="id.atlassian.com → Security → Create and manage API tokens"),
        ],
    ),
    "slack": Tool(
        id="slack", display="Slack", category="Ticketing",
        description="Security alerts, IR updates, channel notifications",
        tiers=["team", "enterprise"],
        doc_url="https://api.slack.com/authentication/token-types#bot",
        credentials=[
            Cred("SLACK_BOT_TOKEN", "Slack Bot Token", secret=True,
                 hint="api.slack.com → Your App → OAuth & Permissions → Bot User OAuth Token (xoxb-...)"),
            Cred("SLACK_TEAM_ID",   "Slack Team/Workspace ID", secret=False,
                 hint="Slack → Workspace Settings → copy the ID from the URL (T...)"),
        ],
    ),
}


# ─────────────────────────────────────────────────────────────────────────────
# Tier definitions
# ─────────────────────────────────────────────────────────────────────────────

TIERS: dict[str, dict] = {
    "solo": {
        "label":       "Solo Analyst  (free / low-cost)",
        "description": "GHAS + Semgrep + GreyNoise + Security Detections",
        "tools":       ["ghas", "semgrep", "greynoise", "security-detections"],
    },
    "team": {
        "label":       "Team SOC  (mid-market)",
        "description": "Solo tier + SIEM + Prowler + Vault + Jira + Slack + Snyk",
        "tools": [
            "ghas", "semgrep", "greynoise", "security-detections",
            "sentinel", "splunk", "snyk", "trivy",
            "opencti", "prowler", "vault", "vault-radar", "jira", "slack",
        ],
    },
    "enterprise": {
        "label":       "Enterprise SOC  (full stack)",
        "description": "All tools",
        "tools":       list(TOOLS.keys()),
    },
}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _divider(char: str = "─", width: int = 62) -> str:
    return char * width


def _header(title: str) -> None:
    print(f"\n{_divider()}")
    print(f"  {bold(title)}")
    print(_divider())


def _prompt(label: str, secret: bool, hint: str, existing: str) -> str:
    """Prompt for a credential value, showing hint and existing masked value."""
    if hint:
        print(dim(f"    ↳ {hint}"))
    placeholder = f"[current: {'*' * min(len(existing), 8)}…]" if existing else "[not set]"
    prompt_str = f"    {cyan(label)} {dim(placeholder)}: "
    try:
        if secret:
            value = getpass.getpass(prompt=prompt_str)
        else:
            value = input(prompt_str)
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.")
        sys.exit(0)
    return value.strip() or existing   # keep existing if user hits Enter


def _confirm(question: str, default: bool = True) -> bool:
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        raw = input(f"  {question}{suffix}").strip().lower()
    except (KeyboardInterrupt, EOFError):
        return default
    if not raw:
        return default
    return raw.startswith("y")


def _numbered_menu(options: list[str], prompt: str = "Select") -> list[int]:
    """
    Display a numbered menu; return list of selected indices (0-based).
    Supports: individual numbers (1 3 5), ranges (1-5), 'all', 'none'.
    """
    for i, opt in enumerate(options, 1):
        print(f"    {dim(str(i).rjust(2))}.  {opt}")
    print()
    try:
        raw = input(f"  {bold(prompt)} (e.g. 1 3 5 | 1-5 | all | none): ").strip()
    except (KeyboardInterrupt, EOFError):
        print("\n  Aborted.")
        sys.exit(0)
    if raw.lower() == "all":
        return list(range(len(options)))
    if raw.lower() == "none":
        return []
    selected: set[int] = set()
    for token in raw.replace(",", " ").split():
        if "-" in token:
            parts = token.split("-", 1)
            try:
                lo, hi = int(parts[0]) - 1, int(parts[1]) - 1
                selected.update(range(max(0, lo), min(len(options) - 1, hi) + 1))
            except ValueError:
                pass
        else:
            try:
                idx = int(token) - 1
                if 0 <= idx < len(options):
                    selected.add(idx)
            except ValueError:
                pass
    return sorted(selected)


def _load_existing_env(path: Path) -> dict[str, str]:
    """Parse an existing .env file into a dict (best-effort)."""
    env: dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            env[key.strip()] = val.strip().strip('"').strip("'")
    return env


def _write_env(values: dict[str, str], path: Path) -> None:
    """Write (or overwrite) a .env file from a flat dict."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    header = dedent(f"""\
        # ─────────────────────────────────────────────────────────────────────
        # SOCPilot — Environment Configuration
        # Generated by onboard.py on {ts}
        # .env is gitignored — never commit credentials.
        # ─────────────────────────────────────────────────────────────────────

        # ── AI Inference ───────────────────────────────────────────────────────
    """)

    # Group vars by category using the TOOLS catalogue
    tool_vars: dict[str, list[str]] = {}   # tool_id → list of env keys
    for tool_id, tool in TOOLS.items():
        tool_vars[tool_id] = [c.key for c in tool.credentials]

    all_tool_keys: set[str] = {c.key for tool in TOOLS.values() for c in tool.credentials}
    core_keys = {"AI_API_KEY", "AI_MODEL", "AI_BASE_URL", "MCP_MODE",
                 "SERVER_HOST", "SERVER_PORT", "REPORTS_DIR"}

    lines = [header]
    for key in ["AI_API_KEY", "AI_MODEL", "AI_BASE_URL"]:
        val = values.get(key, "")
        prefix = "# " if key != "AI_API_KEY" and not val else ""
        lines.append(f"{prefix}{key}={val}\n")

    lines.append("\n# ── Agent Mode ─────────────────────────────────────────────────────────\n")
    lines.append(f"MCP_MODE={values.get('MCP_MODE', 'live')}\n")

    category_order = [
        ("SIEM & Monitoring",        ["sentinel", "splunk", "elastic", "datadog"]),
        ("Vulnerability Scanning",   ["ghas", "semgrep", "snyk", "trivy", "stackhawk"]),
        ("Threat Intelligence",      ["greynoise", "opencti", "virustotal"]),
        ("Cloud Security",           ["prowler", "cloudflare"]),
        ("Secrets & Identity",       ["vault", "vault-radar", "okta"]),
        ("Compliance",               ["drata", "vanta"]),
        ("Detection Engineering",    ["security-detections"]),
        ("Ticketing & Notifications",["jira", "slack"]),
    ]

    for category, tool_ids in category_order:
        keys_in_category: list[str] = []
        for tid in tool_ids:
            keys_in_category.extend(tool_vars.get(tid, []))
        if not keys_in_category:
            continue
        lines.append(f"\n# ── {category} {'─' * max(0, 54 - len(category))}\n")
        for key in keys_in_category:
            val = values.get(key, "")
            lines.append(f"{key}={val}\n")

    # Any extra keys not covered above
    remaining = {k: v for k, v in values.items()
                 if k not in all_tool_keys and k not in core_keys}
    if remaining:
        lines.append("\n# ── Additional ─────────────────────────────────────────────────────\n")
        for key, val in remaining.items():
            lines.append(f"{key}={val}\n")

    path.write_text("".join(lines))


def _test_server(tool_id: str) -> tuple[bool, str]:
    """
    Quick smoke-test: spawn the MCP server and check it sends a valid
    JSON-RPC response to an initialize call within 10 seconds.
    Requires Node.js (npx) or uv (uvx) to be installed.
    """
    tool = TOOLS.get(tool_id)
    if tool is None:
        return False, "unknown tool"

    config_path = Path(__file__).parent / "mcp_config.json"
    if not config_path.exists():
        return False, "mcp_config.json not found"

    with config_path.open() as fh:
        raw = json.load(fh)
    server_cfg = raw.get("mcpServers", {}).get(tool_id)
    if server_cfg is None:
        return False, f"'{tool_id}' not in mcp_config.json"

    command = server_cfg.get("command", "")
    args    = server_cfg.get("args", [])

    # Check the runtime is available
    runtime_present = shutil.which(command)
    if not runtime_present:
        return False, f"'{command}' not found in PATH — install it first"

    init_msg = json.dumps({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "clientInfo": {"name": "onboard", "version": "1.0.0"},
        },
    }) + "\n"

    try:
        proc = subprocess.Popen(
            [command, *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ},
        )
        stdout, _ = proc.communicate(input=init_msg.encode(), timeout=15)
        for line in stdout.splitlines():
            try:
                msg = json.loads(line)
                if msg.get("id") == 1 and "result" in msg:
                    server_name = (msg["result"]
                                   .get("serverInfo", {})
                                   .get("name", tool_id))
                    return True, f"OK — server reports as '{server_name}'"
            except json.JSONDecodeError:
                continue
        return False, "server started but did not respond to initialize"
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, "server did not respond within 15 s"
    except Exception as exc:
        return False, str(exc)


# ─────────────────────────────────────────────────────────────────────────────
# Wizard steps
# ─────────────────────────────────────────────────────────────────────────────

def step_welcome() -> None:
    print(f"""
{_divider("═")}
  {bold("SOCPilot — Interactive Onboarding Wizard")}
{_divider("═")}

  This wizard will guide you through:

    1. Choosing which security tools to enable
    2. Collecting the required credentials
    3. Writing a ready-to-use .env file
    4. Optionally testing each MCP server connection

  Credentials are written only to .env (gitignored).
  Nothing is sent anywhere during this wizard.
""")


def step_select_tier() -> list[str]:
    """Returns a list of tool IDs the user wants to enable."""

    _header("Step 1 — Choose your deployment tier")

    tier_opts = []
    for tid, tier in TIERS.items():
        count = len(tier["tools"])
        free_count = sum(1 for t in tier["tools"] if TOOLS[t].free)
        tier_opts.append(
            f"{bold(tier['label']):<48} "
            f"{dim(str(count) + ' tools, ' + str(free_count) + ' free')}"
        )
    tier_opts.append(f"{bold('Custom'):<48} {dim('Pick tools individually')}")

    indices = _numbered_menu(tier_opts, "Select a tier")
    if not indices:
        print(red("  Nothing selected — exiting."))
        sys.exit(0)

    tier_idx = indices[0]
    tier_keys = list(TIERS.keys())

    if tier_idx < len(tier_keys):
        chosen_tier = tier_keys[tier_idx]
        selected_ids = list(TIERS[chosen_tier]["tools"])
        print(f"\n  {green('✓')} Selected: {bold(TIERS[chosen_tier]['label'])}")
    else:
        # Custom — show individual tool picker grouped by category
        _header("Step 1b — Select individual tools")
        categories: dict[str, list[str]] = {}
        for tid, tool in TOOLS.items():
            categories.setdefault(tool.category, []).append(tid)

        tool_display: list[str] = []
        tool_id_order: list[str] = []
        for cat, tids in categories.items():
            for tid in tids:
                t = TOOLS[tid]
                free_tag = dim(" (free)") if t.free else ""
                tool_display.append(
                    f"{cyan(cat):<30} {t.display:<36}{free_tag}"
                )
                tool_id_order.append(tid)

        idxs = _numbered_menu(tool_display, "Select tools")
        selected_ids = [tool_id_order[i] for i in idxs]

    if not selected_ids:
        print(red("  No tools selected — exiting."))
        sys.exit(0)

    return selected_ids


def step_collect_credentials(
    selected_ids: list[str],
    existing_env: dict[str, str],
) -> dict[str, str]:
    """Walk through each selected tool and collect credentials."""

    values = dict(existing_env)   # start from whatever's already in .env

    # Core inference key first
    _header("Step 2 — AI Inference Key")
    print(f"  Required for all agent functionality.\n")
    existing_key = values.get("AI_API_KEY", "")
    new_key = _prompt("AI API Key", secret=True,
                      hint="Obtain from your inference provider console",
                      existing=existing_key)
    if new_key:
        values["AI_API_KEY"] = new_key

    values.setdefault("MCP_MODE", "live")

    # Per-tool credentials
    tools_with_creds = [TOOLS[tid] for tid in selected_ids if TOOLS[tid].credentials]
    if not tools_with_creds:
        print(f"\n  {green('✓')} All selected tools require no credentials.")
        return values

    _header(f"Step 3 — Tool Credentials  ({len(tools_with_creds)} tools)")

    for tool in tools_with_creds:
        already_configured = all(
            values.get(c.key, "") for c in tool.credentials if not c.optional
        )
        status = green("(already set)") if already_configured else yellow("(needs setup)")
        print(f"\n  {bold(tool.display)}  {dim(tool.category)}  {status}")
        if tool.doc_url:
            print(dim(f"  Docs: {tool.doc_url}"))
        print()

        if already_configured:
            if not _confirm(f"Reconfigure {tool.display}?", default=False):
                continue

        for cred in tool.credentials:
            existing = values.get(cred.key, "")
            val = _prompt(cred.label, secret=cred.secret,
                          hint=cred.hint, existing=existing)
            if val:
                values[cred.key] = val

    return values


def step_test_connections(selected_ids: list[str]) -> None:
    """Optionally smoke-test each selected MCP server."""
    _header("Step 4 — Test MCP Server Connections  (optional)")
    print("  Starts each MCP server subprocess and checks for a valid response.\n"
          "  Requires Node.js 20+ (npx) and/or uv (uvx) to be installed.\n")

    if not _confirm("Run connectivity tests now?", default=True):
        print(dim("  Skipped."))
        return

    # Tools with no credentials (trivy, security-detections) can still be tested
    testable = [tid for tid in selected_ids
                if TOOLS[tid].id in _load_mcp_server_ids()]

    for tid in testable:
        tool = TOOLS[tid]
        print(f"  Testing {cyan(tool.display)}… ", end="", flush=True)
        ok, msg = _test_server(tid)
        symbol = green("✓") if ok else red("✗")
        print(f"{symbol}  {msg}")

    print()


def _load_mcp_server_ids() -> set[str]:
    p = Path(__file__).parent / "mcp_config.json"
    if not p.exists():
        return set()
    with p.open() as fh:
        raw = json.load(fh)
    return {k for k in raw.get("mcpServers", {}) if not k.startswith("__")}


def step_write_env(values: dict[str, str], env_path: Path) -> None:
    """Confirm and write the .env file."""
    _header("Step 5 — Write .env")

    if env_path.exists():
        print(f"  {yellow('!')} {env_path} already exists.")
        if _confirm("Overwrite?", default=True):
            backup = env_path.with_suffix(".env.bak")
            shutil.copy(env_path, backup)
            print(dim(f"    Backup saved to {backup}"))
        else:
            print(dim("  Skipped — .env not changed."))
            return

    _write_env(values, env_path)
    print(f"\n  {green('✓')} Written to {bold(str(env_path))}")


def step_next_steps(selected_ids: list[str]) -> None:
    """Print what to do next."""
    _header("Setup Complete — Next Steps")

    has_live_tools = any(TOOLS[t].credentials for t in selected_ids)
    print(f"""
  1. {bold("Test in mock mode")} (no credentials needed):
       python agent.py "Is CVE-2024-50623 actively exploited?"

  2. {bold("Run with live MCP tools")} (after setting MCP_MODE=live in .env):
       python agent.py --playbook vuln-triage "CVE-2024-50623 in payments-api"

  3. {bold("Start the HTTP API server")}:
       uvicorn server:app --host 0.0.0.0 --port 8000

  4. {bold("Docker deployment")}:
       docker compose up -d

  5. {bold("Re-run this wizard")} to add or update tools:
       python onboard.py --add <tool_id>
       python onboard.py --check

  {dim("Enabled tools:")} {', '.join(bold(t) for t in selected_ids)}
""")


# ─────────────────────────────────────────────────────────────────────────────
# --check mode
# ─────────────────────────────────────────────────────────────────────────────

def cmd_check(env_path: Path) -> None:
    """Verify the existing .env against all known credential requirements."""
    _header("Credential Check")
    existing = _load_existing_env(env_path)

    if not existing.get("AI_API_KEY"):
        print(f"  {red('✗')} AI_API_KEY      — not set")
    else:
        print(f"  {green('✓')} AI_API_KEY      — set")

    print()
    for cat, tids in [
        ("SIEM", ["sentinel", "splunk", "elastic", "datadog"]),
        ("Vuln", ["ghas", "semgrep", "snyk", "trivy", "stackhawk"]),
        ("TI",   ["greynoise", "opencti", "virustotal"]),
        ("Cloud",["prowler", "cloudflare"]),
        ("Sec",  ["vault", "vault-radar", "okta"]),
        ("Comp", ["drata", "vanta"]),
        ("Tick", ["jira", "slack"]),
    ]:
        for tid in tids:
            tool = TOOLS[tid]
            if not tool.credentials:
                print(f"  {green('✓')} {tool.display:<36} {dim('(no credentials needed)')}")
                continue
            missing = [c.key for c in tool.credentials
                       if not c.optional and not existing.get(c.key)]
            if missing:
                print(f"  {red('✗')} {tool.display:<36} missing: {', '.join(missing)}")
            else:
                print(f"  {green('✓')} {tool.display:<36} all credentials set")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# --list mode
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list() -> None:
    """Print all tools with their tier and credential count."""
    _header("Available MCP Tools")
    current_cat = ""
    for tool in TOOLS.values():
        if tool.category != current_cat:
            current_cat = tool.category
            print(f"\n  {bold(current_cat)}")
        tiers_str = ", ".join(tool.tiers)
        cred_str  = f"{len(tool.credentials)} credentials" if tool.credentials else "no credentials"
        free_tag  = green("  free") if tool.free else ""
        print(f"    {cyan(tool.id):<28} {tool.display:<34} {dim(tiers_str):<24} {dim(cred_str)}{free_tag}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# --add mode
# ─────────────────────────────────────────────────────────────────────────────

def cmd_add(tool_id: str, env_path: Path) -> None:
    """Add or reconfigure a single tool in an existing .env."""
    if tool_id not in TOOLS:
        print(red(f"  Unknown tool '{tool_id}'. Run --list to see options."))
        sys.exit(1)

    existing = _load_existing_env(env_path)
    tool     = TOOLS[tool_id]

    _header(f"Adding — {tool.display}")
    if tool.doc_url:
        print(dim(f"  Docs: {tool.doc_url}\n"))

    new_values = dict(existing)
    for cred in tool.credentials:
        val = _prompt(cred.label, secret=cred.secret,
                      hint=cred.hint, existing=existing.get(cred.key, ""))
        if val:
            new_values[cred.key] = val

    step_write_env(new_values, env_path)
    print(f"\n  {green('✓')} {tool.display} added. Re-run the server to pick up the changes.\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="onboard.py",
        description="SOCPilot Interactive Onboarding Wizard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=dedent("""
            Examples:
              python onboard.py                   # full wizard
              python onboard.py --check           # verify existing .env
              python onboard.py --add splunk      # add a single tool
              python onboard.py --list            # list all available tools
        """),
    )
    parser.add_argument("--check",    action="store_true",
                        help="Check existing .env for missing credentials")
    parser.add_argument("--add",      metavar="TOOL_ID",
                        help="Add / reconfigure a single tool in an existing .env")
    parser.add_argument("--list",     action="store_true",
                        help="List all available tools and their tiers")
    parser.add_argument("--env-file", metavar="PATH", default=".env",
                        help=".env file path (default: .env)")
    args = parser.parse_args()

    env_path = Path(args.env_file)

    if args.list:
        cmd_list()
        return

    if args.check:
        cmd_check(env_path)
        return

    if args.add:
        cmd_add(args.add, env_path)
        return

    # ── Full wizard ───────────────────────────────────────────────────────────
    step_welcome()
    selected_ids  = step_select_tier()
    existing_env  = _load_existing_env(env_path)
    values        = step_collect_credentials(selected_ids, existing_env)
    step_test_connections(selected_ids)
    step_write_env(values, env_path)
    step_next_steps(selected_ids)


if __name__ == "__main__":
    main()