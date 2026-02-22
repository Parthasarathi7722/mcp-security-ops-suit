"""
config.py — Centralised configuration for SOCPilot.

Reads from environment variables (populated by .env via python-dotenv or
injected by Docker / Kubernetes secrets). No values are hard-coded here.

Usage:
    from config import cfg

    cfg.api_key      # AI inference key
    cfg.model        # inference model identifier
    cfg.base_url     # optional proxy / self-hosted endpoint
    cfg.live         # True when MCP_MODE=live
    cfg.server_host  # FastAPI bind host
    cfg.server_port  # FastAPI bind port
    cfg.mcp_config   # parsed mcp_config.json dict
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    from dotenv import load_dotenv
    load_dotenv(override=False)   # .env is optional; env vars take precedence
except ImportError:
    pass   # python-dotenv not installed — rely on environment


# ─────────────────────────────────────────────────────────────────────────────
# MCP config loader
# ─────────────────────────────────────────────────────────────────────────────

def _load_mcp_config() -> dict[str, Any]:
    """Load mcp_config.json, strip comment keys, return the servers dict."""
    config_path = Path(__file__).parent / "mcp_config.json"
    if not config_path.exists():
        return {}
    with config_path.open() as fh:
        raw: dict[str, Any] = json.load(fh)
    servers: dict[str, Any] = raw.get("mcpServers", {})
    # Strip pseudo-comment keys (prefixed "__comment_")
    return {k: v for k, v in servers.items() if not k.startswith("__comment_")}


# ─────────────────────────────────────────────────────────────────────────────
# Tool → server mapping
# Keeps agent.py and mcp_client.py decoupled from the config file format.
# ─────────────────────────────────────────────────────────────────────────────

TOOL_TO_SERVER: dict[str, str] = {
    # SIEM
    "query_sentinel":   "sentinel",
    "query_splunk":     "splunk",
    "query_elastic":    "elastic",
    "query_datadog":    "datadog",
    # Vulnerability scanning
    "scan_semgrep":     "semgrep",
    "check_snyk":       "snyk",
    "scan_trivy":       "trivy",
    "get_ghas_alerts":  "ghas",
    "run_stackhawk":    "stackhawk",
    # Threat intelligence
    "check_greynoise":  "greynoise",
    "query_opencti":    "opencti",
    "check_virustotal": "virustotal",
    # Cloud security
    "run_prowler":      "prowler",
    "query_cloudflare": "cloudflare",
    # Secrets & identity
    "check_vault_radar":"vault-radar",
    "manage_vault":     "vault",
    "manage_okta":      "okta",
    # Compliance
    "check_compliance": "drata",      # or vanta — resolved at call time
    # Detection engineering
    "search_detections":"security-detections",
    # Ticketing & notifications
    "create_jira_ticket":"jira",
    "post_slack":       "slack",
}


# ─────────────────────────────────────────────────────────────────────────────
# Config dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Config:
    # ── AI inference ──────────────────────────────────────────────────────────
    api_key:   str = field(default_factory=lambda: (
        os.environ.get("AI_API_KEY") or os.environ.get("_FALLBACK_KEY", "")
    ))
    model:     str = field(default_factory=lambda:
        os.environ.get("AI_MODEL", "claude-opus-4-6")
    )
    base_url:  str | None = field(default_factory=lambda:
        os.environ.get("AI_BASE_URL") or None
    )
    # "anthropic" (default, calls Anthropic API) |
    # "openai"   (OpenAI-compatible — Ollama, LM Studio, vLLM, etc., fully local)
    provider:  str = field(default_factory=lambda:
        os.environ.get("AI_PROVIDER", "anthropic").lower()
    )

    # ── Agent mode ────────────────────────────────────────────────────────────
    live:      bool = field(default_factory=lambda:
        os.environ.get("MCP_MODE", "mock").lower() == "live"
    )

    # ── HTTP server ───────────────────────────────────────────────────────────
    server_host: str = field(default_factory=lambda:
        os.environ.get("SERVER_HOST", "0.0.0.0")
    )
    server_port: int = field(default_factory=lambda:
        int(os.environ.get("SERVER_PORT", "8000"))
    )

    # ── MCP servers ───────────────────────────────────────────────────────────
    mcp_config:      dict[str, Any] = field(default_factory=_load_mcp_config)
    tool_to_server:  dict[str, str] = field(default_factory=lambda: dict(TOOL_TO_SERVER))

    # ── Reports ───────────────────────────────────────────────────────────────
    reports_dir: Path = field(default_factory=lambda:
        Path(os.environ.get("REPORTS_DIR", "reports"))
    )

    def server_env(self, server_name: str) -> dict[str, str]:
        """
        Resolve the env block for an MCP server, substituting
        ${VAR_NAME} placeholders from the current process environment.
        """
        server = self.mcp_config.get(server_name, {})
        raw_env: dict[str, str] = server.get("env", {})
        resolved: dict[str, str] = {}
        for key, val in raw_env.items():
            if val.startswith("${") and val.endswith("}"):
                var = val[2:-1]
                resolved[key] = os.environ.get(var, "")
            else:
                resolved[key] = val
        return resolved

    def server_command(self, server_name: str) -> tuple[str, list[str]]:
        """Return (command, args) for spawning an MCP server subprocess."""
        server = self.mcp_config.get(server_name, {})
        return server.get("command", ""), server.get("args", [])

    def validate(self) -> list[str]:
        """Return a list of configuration warnings (non-fatal)."""
        warnings: list[str] = []
        if not self.api_key:
            warnings.append("AI_API_KEY is not set — inference calls will fail")
        if self.live and not self.mcp_config:
            warnings.append("MCP_MODE=live but mcp_config.json is missing or empty")
        return warnings


# Singleton — import this everywhere instead of constructing ad-hoc.
cfg = Config()