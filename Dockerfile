# ─────────────────────────────────────────────────────────────────────────────
# SOCPilot — Dockerfile
#
# Multi-tool stack:
#   • Python 3.12   — agent, server, MCP client
#   • Node.js 20    — npx-based MCP servers (majority of tools)
#   • uv / uvx      — Python-based MCP servers (greynoise, semgrep, prowler)
#
# Security:
#   • Non-root user (socpilot:socpilot)
#   • Minimal surface: no sshd, no cron, no extra package managers
#   • Credentials injected at runtime via env_file / K8s secrets
#   • Healthcheck endpoint at /health
#
# Build:
#   docker build -t socpilot:latest .
#
# Run (development):
#   docker run --env-file .env -p 8000:8000 socpilot:latest
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim AS base

# ── System packages ───────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Node.js 20 (required by npx-based MCP servers) ───────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── uv (required by uvx-based MCP servers: greynoise, semgrep, prowler) ──────
RUN curl -LsSf https://astral.sh/uv/install.sh | sh
ENV PATH="/root/.local/bin:${PATH}"

# ─────────────────────────────────────────────────────────────────────────────
# Python dependencies
# ─────────────────────────────────────────────────────────────────────────────

WORKDIR /app
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

# ─────────────────────────────────────────────────────────────────────────────
# Application source
# ─────────────────────────────────────────────────────────────────────────────

COPY config.py mcp_client.py agent.py server.py mcp_config.json ./

# Pre-create the reports directory
RUN mkdir -p /app/reports

# ─────────────────────────────────────────────────────────────────────────────
# Non-root user
# ─────────────────────────────────────────────────────────────────────────────

RUN groupadd --gid 1001 socpilot \
    && useradd --uid 1001 --gid socpilot --no-create-home --shell /bin/false socpilot \
    && chown -R socpilot:socpilot /app \
    && chown -R socpilot:socpilot /root/.local   # uv cache

USER socpilot

# ─────────────────────────────────────────────────────────────────────────────
# Runtime
# ─────────────────────────────────────────────────────────────────────────────

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_MODE=mock \
    SERVER_HOST=0.0.0.0 \
    SERVER_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/health || exit 1

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000", \
     "--workers", "1", "--log-level", "info"]