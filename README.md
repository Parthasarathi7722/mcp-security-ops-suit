# SOCPilot — AI Security Operations Co-pilot

An AI-powered security operations agent for private-subnet deployment.
Connects to 20+ security tools via MCP (Model Context Protocol) and orchestrates end-to-end investigations — from a single command or HTTP API call.

All MCP tool calls stay inside your network. Only the AI inference request crosses the boundary.

---

## Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Project Layout](#project-layout)
- [Quick Start](#quick-start)
  - [Option A — Mock mode (zero credentials)](#option-a--mock-mode-zero-credentials)
  - [Option B — Live mode with real tools](#option-b--live-mode-with-real-tools)
  - [Option C — Docker](#option-c--docker)
- [Onboarding Wizard](#onboarding-wizard)
- [CLI Reference](#cli-reference)
- [HTTP API](#http-api)
- [WebSocket Sessions](#websocket-sessions)
- [SIEM Webhook](#siem-webhook)
- [SOC Playbooks](#soc-playbooks)
- [Configuration Reference](#configuration-reference)
- [Adding New Tools](#adding-new-tools)
- [Security Notes](#security-notes)
- [Troubleshooting](#troubleshooting)

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                  Analyst / Automation                       │
│         CLI  │  HTTP (SSE)  │  WebSocket  │  SIEM webhook  │
└──────────────┴──────────────┴─────────────┴────────────────┘
                              │
                         agent.py
                    run_investigation()
                    (async generator)
                              │
               ┌──────────────┴──────────────┐
               │                             │
          MCP_MODE=mock               MCP_MODE=live
          (sample data)               mcp_client.py
                                   MCPClientPool
                                   asyncio.gather()
                                         │
              ┌──────┬─────────┬──────────┼──────────┬──────┐
              │      │         │          │          │      │
           npx/uvx subprocess per MCP server (stdio JSON-RPC)
              │      │         │          │          │      │
          Sentinel  GHAS  GreyNoise   OpenCTI    Vault   Jira
          Splunk    Snyk  VirusTotal  Prowler    Okta    Slack
          …         …    …           …          …       …
```

**Data flow — single investigation turn:**

1. Analyst sends a query (CLI / HTTP / WebSocket)
2. `run_investigation()` calls the AI with the query + tool definitions
3. AI responds with one or more `tool_use` blocks
4. All tool calls in the same turn execute **in parallel** via `asyncio.gather()`
5. Results are fed back; AI reasons over them and may call more tools
6. Final analysis is streamed back token-by-token

---

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.12+ | `python3 --version` |
| Node.js | 20+ | `node --version` — required for `npx`-based MCP servers |
| uv | latest | `uv --version` — required for `uvx`-based servers (greynoise, semgrep, prowler) |
| AI API key | — | From your inference provider |

Install Node.js: https://nodejs.org/en/download
Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`

---

## Project Layout

```
mcp-security-ops-suite/
├── agent.py            ← Core agent — async generator + CLI
├── server.py           ← FastAPI REST + WebSocket + SIEM webhook
├── mcp_client.py       ← Async MCP subprocess client (JSON-RPC over stdio)
├── config.py           ← Centralised configuration (reads .env)
├── onboard.py          ← Interactive tool onboarding wizard
├── mcp_config.json     ← MCP server spawn commands + env var references
├── .env.example        ← Template for credentials (copy → .env)
├── requirements.txt    ← Python dependencies
├── Dockerfile          ← Python 3.12 + Node 20 + uv, non-root user
├── docker-compose.yml  ← Private-subnet deployment
├── playbooks/          ← SOC workflow playbooks (Markdown)
└── architecture/       ← Reference architecture diagrams
```

---

## Quick Start

### Option A — Mock mode (zero credentials)

Try the agent immediately with realistic sample data — no API key, no tool credentials.

```bash
git clone <this-repo> && cd mcp-security-ops-suite

# Create a virtual environment and install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Set your inference API key (the only required credential in mock mode)
export AI_API_KEY=<your-key>

# Run an investigation (mock data)
python agent.py "Is CVE-2024-50623 actively exploited? Check payments-api."

# Run a full SOC playbook
python agent.py --playbook vuln-triage "CVE-2024-50623 in payments-api"

# Start an interactive session
python agent.py
```

Mock mode returns realistic responses for all tools. Switch to `MCP_MODE=live` when you're ready to connect real services.

---

### Option B — Live mode with real tools

```bash
# 1. Run the onboarding wizard to pick tools and collect credentials
python onboard.py

# 2. The wizard writes .env with your selections.
#    MCP_MODE=live is set automatically.

# 3. Load the .env and run
source .env
python agent.py --playbook incident-response "suspicious login 185.220.101.34"

# Or start the HTTP server
uvicorn server:app --host 0.0.0.0 --port 8000
```

---

### Option C — Docker

```bash
# 1. Run onboarding to generate .env
python onboard.py

# 2. Build and start
docker compose up -d

# 3. Check health
curl http://localhost:8000/health

# 4. Run an investigation via the API
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Check GreyNoise for 185.220.101.34"}' \
  --no-buffer

# 5. Tail logs
docker compose logs -f
```

---

## Onboarding Wizard

`onboard.py` is an interactive CLI wizard for configuring which MCP security tools to enable. Run it before switching to live mode.

### Full wizard

```bash
python onboard.py
```

**Steps:**

1. **Choose a tier** — pick the tool set that matches your stack:

   | Tier | Tools | Cost |
   |---|---|---|
   | Solo Analyst | GHAS, Semgrep, GreyNoise, Security Detections | Free |
   | Team SOC | Solo + Sentinel/Splunk, Snyk, Trivy, Prowler, Vault, Jira, Slack | Varies by SIEM |
   | Enterprise | All 20+ tools | Enterprise licensing |
   | Custom | Choose individually | — |

2. **Enter credentials** — prompted per tool with masked input and documentation links.

3. **Test connections** *(optional)* — spawns each MCP server subprocess and verifies the initialize handshake.

4. **Write `.env`** — existing `.env` is backed up before overwriting.

### Subcommands

```bash
# Check which credentials are set / missing
python onboard.py --check

# Add or reconfigure a single tool
python onboard.py --add splunk
python onboard.py --add greynoise

# List all available tools with tiers and credential counts
python onboard.py --list

# Use a different .env file
python onboard.py --env-file /etc/socpilot/.env
```

### Available tools

```
Category              Tool                           Tiers            Credentials
────────────────────────────────────────────────────────────────────────────────
SIEM                  Microsoft Sentinel             team, enterprise  7
SIEM                  Splunk                         team, enterprise  2
SIEM                  Elastic Security               enterprise        2
SIEM                  Datadog                        enterprise        2
Vuln Scanning         GHAS                           solo+             2  (free)
Vuln Scanning         Semgrep                        solo+             1  (free)
Vuln Scanning         Snyk                           team+             2
Vuln Scanning         Trivy                          team+             0  (free)
Vuln Scanning         StackHawk                      enterprise        1
Threat Intelligence   GreyNoise                      solo+             1  (free)
Threat Intelligence   OpenCTI                        team+             2
Threat Intelligence   VirusTotal                     enterprise        1
Cloud Security        Prowler                        team+             3  (free)
Cloud Security        Cloudflare                     enterprise        2
Secrets & Identity    HashiCorp Vault                team+             2
Secrets & Identity    Vault Radar                    team+             3
Secrets & Identity    Okta                           enterprise        2
Compliance            Drata                          enterprise        1
Compliance            Vanta                          enterprise        1
Detection Eng.        Security Detections            solo+             0  (free)
Ticketing             Jira                           team+             3
Ticketing             Slack                          team+             2
```

---

## CLI Reference

```
python agent.py [OPTIONS] [QUERY]
```

| Option | Short | Description |
|---|---|---|
| `--playbook NAME` | `-p` | Run a named SOC playbook (see list below) |
| `--list-playbooks` | `-l` | Print all playbook names and exit |
| `--verbose` | `-v` | Show AI reasoning steps (thinking blocks) |
| `--output FILE` | `-o` | Save the report to a Markdown file |

### Examples

```bash
# Free-form investigation
python agent.py "Is CVE-2024-50623 being actively exploited? Check payments-api."

# Run a structured playbook
python agent.py --playbook vuln-triage "CVE-2024-50623 in payments-api"
python agent.py --playbook incident-response "alert SEC-7721"
python agent.py --playbook threat-hunting "Cl0p ransomware TTPs"
python agent.py --playbook secret-leak-response "AWS key leaked in payments-service"
python agent.py --playbook cloud-posture-review "AWS prod account"
python agent.py --playbook compliance-audit "SOC 2 readiness"

# Save a report
python agent.py --playbook compliance-audit "AWS prod" --output reports/audit-$(date +%F).md

# Show internal reasoning
python agent.py --verbose "hunt for T1190 exploitation in our environment"

# Pipe a query from another process
echo "check 185.220.101.34 and 45.142.212.55" | python agent.py

# Interactive mode (multi-turn session with history)
python agent.py
SOCPilot> --playbook vuln-triage CVE-2024-50623 in payments-api
SOCPilot> now check if the auth-service is also affected
SOCPilot> create a P1 Jira ticket for both findings
SOCPilot> clear     ← resets session history
SOCPilot> exit
```

---

## HTTP API

Start the server:

```bash
uvicorn server:app --host 0.0.0.0 --port 8000
# Or: python server.py
```

API documentation (Swagger UI): `http://localhost:8000/docs`

### Endpoints

#### `GET /health`
Liveness check.
```json
{"status": "ok", "mode": "mock", "ts": "2025-01-15T10:30:00+00:00"}
```

#### `GET /playbooks`
List available SOC playbooks.
```json
{"playbooks": ["vuln-triage", "incident-response", "threat-hunting", ...]}
```

#### `GET /tools`
Return all tool definitions with their input schemas.

#### `POST /query` — SSE streaming
Run a free-form investigation. Returns a Server-Sent Events stream.

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Check GreyNoise for IP 185.220.101.34", "verbose": false}' \
  --no-buffer
```

Response stream — each line is `data: <JSON>\n\n`:
```
data: {"type": "text",        "text": "I'll check GreyNoise for..."}
data: {"type": "tool_call",   "name": "check_greynoise", "inputs": {"query": "185.220.101.34", "query_type": "ip"}}
data: {"type": "tool_result", "name": "check_greynoise", "content": "Classification: MALICIOUS..."}
data: {"type": "text",        "text": "The IP 185.220.101.34 is classified as..."}
data: {"type": "done",        "turns": 2}
```

#### `POST /playbook` — SSE streaming
Run a named playbook against a target.

```bash
curl -X POST http://localhost:8000/playbook \
  -H "Content-Type: application/json" \
  -d '{"playbook": "vuln-triage", "target": "CVE-2024-50623 in payments-api"}' \
  --no-buffer
```

#### `POST /report`
Run a playbook and save the result to a Markdown file. Synchronous (waits for completion).

```bash
curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{"playbook": "compliance-audit", "target": "AWS prod", "filename": "audit-jan.md"}'
```

```json
{"status": "ok", "file": "reports/audit-jan.md", "turns": 4, "bytes": 8423}
```

#### Consuming the SSE stream in Python

```python
import httpx

with httpx.Client(timeout=300) as client:
    with client.stream("POST", "http://localhost:8000/query",
                       json={"query": "Is CVE-2024-50623 exploited?"}) as r:
        for line in r.iter_lines():
            if line.startswith("data: "):
                import json
                event = json.loads(line[6:])
                if event["type"] == "text":
                    print(event["text"], end="", flush=True)
```

#### Consuming the SSE stream in JavaScript

```javascript
const response = await fetch("http://localhost:8000/query", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({query: "Check for Cl0p ransomware IOCs"}),
});

const reader = response.body.getReader();
const decoder = new TextDecoder();

while (true) {
  const {done, value} = await reader.read();
  if (done) break;
  const lines = decoder.decode(value).split("\n");
  for (const line of lines) {
    if (line.startsWith("data: ")) {
      const event = JSON.parse(line.slice(6));
      if (event.type === "text") process.stdout.write(event.text);
    }
  }
}
```

---

## WebSocket Sessions

The `/ws/{session_id}` endpoint maintains a stateful conversation across multiple queries. History is preserved for the life of the connection — the agent remembers previous findings.

```bash
# Using wscat (npm install -g wscat)
wscat -c ws://localhost:8000/ws/analyst-session-1
> {"query": "Check GreyNoise for 185.220.101.34"}
< {"type": "text", "text": "..."}
< {"type": "done", "turns": 2}
> {"query": "Now check if OpenCTI has any threat actor campaigns using this IP"}
< {"type": "text", "text": "Based on my earlier GreyNoise findings..."}   ← remembers context
```

```python
import asyncio
import json
import websockets

async def session():
    async with websockets.connect("ws://localhost:8000/ws/my-session") as ws:
        queries = [
            "Check GreyNoise for 185.220.101.34",
            "What threat actors use IPs in this range?",
            "Create a Jira ticket summarising these findings",
        ]
        for query in queries:
            await ws.send(json.dumps({"query": query}))
            while True:
                msg = json.loads(await ws.recv())
                if msg["type"] == "text":
                    print(msg["text"], end="", flush=True)
                elif msg["type"] == "done":
                    print(f"\n--- Turn {msg['turns']} complete ---\n")
                    break

asyncio.run(session())
```

---

## SIEM Webhook

`POST /webhook/siem` receives a SIEM alert and automatically triggers the incident-response playbook.

### Configure your SIEM

**Microsoft Sentinel — Logic App action:**
```
HTTP POST https://your-server:8000/webhook/siem
Content-Type: application/json
Body: {
  "alert_id":   "@{triggerBody()?['SystemAlertId']}",
  "title":      "@{triggerBody()?['AlertDisplayName']}",
  "severity":   "@{triggerBody()?['AlertSeverity']}",
  "description":"@{triggerBody()?['Description']}",
  "raw":        @{triggerBody()}
}
```

**Splunk — Alert action:**
```
curl -X POST https://your-server:8000/webhook/siem \
  -d '{"alert_id":"$name$","title":"$name$","severity":"$result.severity$","description":"$result.description$"}'
```

**Elastic Watcher:**
```json
"actions": {
  "notify_socpilot": {
    "webhook": {
      "method": "post",
      "url": "https://your-server:8000/webhook/siem",
      "body": "{\"alert_id\": \"{{ctx.id}}\", \"title\": \"{{ctx.metadata.name}}\", \"severity\": \"high\", \"raw\": {{#toJson}}ctx{{/toJson}}}"
    }
  }
}
```

The webhook returns an SSE stream of the investigation events. For fire-and-forget integration, consume asynchronously or discard the response body.

---

## SOC Playbooks

| Playbook | Use case | Tools invoked |
|---|---|---|
| `vuln-triage` | New CVE or Dependabot alert | GHAS → GreyNoise → OpenCTI → Snyk → Detections → Jira → Slack |
| `incident-response` | Active alert, suspicious behaviour | Sentinel → Splunk → GreyNoise → OpenCTI → Okta → Vault → Jira → Slack |
| `threat-hunting` | TTP or threat actor investigation | Detections → Sentinel → Splunk → GreyNoise → OpenCTI |
| `compliance-audit` | SOC 2 / ISO 27001 gap report | Drata/Vanta → Prowler → GHAS → Vault Radar |
| `secret-leak-response` | Exposed credential | Vault Radar → GHAS → Vault → Okta → Jira → Slack |
| `cloud-posture-review` | Cloud security posture | Prowler → Cloudflare → Sentinel → Vault |

### Risk assessment framework

| Priority | SLA | Trigger |
|---|---|---|
| P1 | Immediate | Actively exploited + confirmed reachable + internet-facing |
| P2 | 48 h | Actively exploited OR reachable (not both); PoC available |
| P3 | 7 d | Vulnerability present, not actively exploited |
| P4 | 30 d | Low severity or unreachable |

---

## Configuration Reference

All settings are read from environment variables (populated from `.env` by `python-dotenv`).

| Variable | Required | Default | Description |
|---|---|---|---|
| `AI_API_KEY` | Yes | — | Inference provider API key |
| `AI_MODEL` | No | `claude-opus-4-6` | Override the inference model |
| `AI_BASE_URL` | No | — | Point to a self-hosted or proxy endpoint |
| `MCP_MODE` | No | `mock` | `mock` = sample data · `live` = real MCP servers |
| `SERVER_HOST` | No | `0.0.0.0` | FastAPI bind host |
| `SERVER_PORT` | No | `8000` | FastAPI bind port |
| `REPORTS_DIR` | No | `reports/` | Where `--output` and `/report` write files |
| `MCP_TIMEOUT` | No | `60` | Seconds before an MCP tool call times out |

See `.env.example` for the full list of per-tool credential variables.

---

## Adding New Tools

### 1. Add the MCP server to `mcp_config.json`

```json
"mythic": {
  "command": "npx",
  "args": ["-y", "@mythic/mcp-server"],
  "env": {
    "MYTHIC_URL":   "${MYTHIC_URL}",
    "MYTHIC_TOKEN": "${MYTHIC_TOKEN}"
  }
}
```

### 2. Add the tool definition to `agent.py`

Add a new entry to the `SECURITY_TOOLS` list:

```python
{
    "name": "query_mythic",
    "description": "Query the Mythic C2 framework for active implants and agent activity.",
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {"type": "string", "description": "Operation name"},
            "filter":    {"type": "string", "description": "Filter expression"},
        },
        "required": ["operation"],
    },
},
```

### 3. Add the tool→server mapping to `config.py`

```python
TOOL_TO_SERVER: dict[str, str] = {
    ...
    "query_mythic": "mythic",
}
```

### 4. Add a mock response to `agent.py`

In the `_mock_response()` function's `responses` dict:

```python
"query_mythic": (
    f"Mythic — {inputs.get('operation','default')}:\n"
    f"  3 active agents | 1 stale (last seen 48 h)\n"
    f"  [Mock — set MYTHIC_URL for live data]"
),
```

### 5. Add the tool to the onboarding wizard in `onboard.py`

```python
"mythic": Tool(
    id="mythic", display="Mythic C2", category="Incident Response",
    description="Active implant tracking, agent management",
    tiers=["enterprise"],
    credentials=[
        Cred("MYTHIC_URL",   "Mythic URL",   secret=False),
        Cred("MYTHIC_TOKEN", "Mythic Token", secret=True),
    ],
),
```

Also add `"mythic"` to the appropriate tier in `TIERS`.

### 6. Add the map entry to `mcp_client.py`

```python
_MCP_TOOL_NAMES: dict[str, str] = {
    ...
    "query_mythic": "get_agents",  # the actual tool name the MCP server exposes
}
```

---

## Security Notes

- **Credentials** are injected at runtime via `.env` or Docker `env_file`. They are never baked into the image or committed to source control. `.env` is gitignored.

- **Network isolation**: In production, run the container with restricted egress. MCP subprocess calls are all internal; only the AI inference request needs outbound internet access (or route it through your proxy via `AI_BASE_URL`).

- **Destructive actions**: The system prompt instructs the agent to flag containment actions (session suspension, credential rotation, IP blocking) for analyst approval before executing. Always review before allowing `manage_okta`, `manage_vault`, or `query_cloudflare` with mutating actions.

- **Prompt injection**: MCP tool results are untrusted external data. Treat AI output as advisory — verify critical findings independently before taking action.

- **Least privilege**: Each MCP server should use a read-only or scoped credential where possible. Do not use root / admin tokens.

- **TLS**: Use a reverse proxy (nginx, Caddy, Cloudflare Tunnel) to terminate TLS in front of the FastAPI server. Do not expose port 8000 directly to the internet.

---

## Troubleshooting

### `AI_API_KEY is not set`
```bash
export AI_API_KEY=<your-key>
# or add to .env: AI_API_KEY=<your-key>
```

### `ModuleNotFoundError: No module named 'anthropic'`
```bash
pip install -r requirements.txt
```

### `'npx' not found in PATH`
Install Node.js 20+: https://nodejs.org/en/download

### `'uvx' not found in PATH`
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# Then reload your shell or: source ~/.bashrc
```

### MCP server times out
- Check credentials are set in `.env` (`python onboard.py --check`)
- Increase timeout: `MCP_TIMEOUT=120`
- Test the server manually: `python onboard.py --add <tool_id>`

### Mock mode not returning data
Ensure `MCP_MODE` is not set to `live`:
```bash
unset MCP_MODE   # or set MCP_MODE=mock in .env
```

### Docker container exits immediately
```bash
docker compose logs socpilot
# Most common cause: AI_API_KEY not set in .env
```

### Port 8000 already in use
```bash
SERVER_PORT=8001 uvicorn server:app --host 0.0.0.0 --port 8001
# or update SERVER_PORT in .env
```

### Check which tools have credentials configured
```bash
python onboard.py --check
```