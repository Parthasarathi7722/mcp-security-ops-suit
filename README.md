# SOCPilot — AI Security Operations Co-pilot

An AI-powered SOC agent for private-subnet deployment. Connects to 20+ security tools via MCP (Model Context Protocol) and orchestrates end-to-end investigations — from a single command, a browser chat, or an HTTP API call.

All MCP tool calls stay inside your network. Only the AI inference request crosses the boundary.

---

## Contents

- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Project Layout](#project-layout)
- [Quick Start](#quick-start)
  - [Option A — Demo mode (zero credentials)](#option-a--demo-mode-zero-credentials)
  - [Option B — Real AI, mock tools](#option-b--real-ai-mock-tools)
  - [Option C — Live mode with real tools](#option-c--live-mode-with-real-tools)
  - [Option D — Docker](#option-d--docker)
- [Browser UI](#browser-ui)
- [Onboarding Wizards](#onboarding-wizards)
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
│              Analyst Interface                              │
│   Browser UI  │  CLI  │  HTTP (SSE)  │  WebSocket  │  SIEM │
└───────────────┴───────┴──────────────┴─────────────┴───────┘
                              │
                         server.py
                         FastAPI app
                              │
                         agent.py
                    run_investigation()
                    (async generator)
                              │
               ┌──────────────┴──────────────┐
               │                             │
          AI_PROVIDER=demo            AI_PROVIDER=anthropic
          (pre-recorded)              or openai (Ollama etc.)
                                             │
                                    MCP_MODE=mock     MCP_MODE=live
                                    (sample data)     mcp_client.py
                                                      MCPClientPool
                                                      asyncio.gather()
                                                           │
              ┌──────┬─────────┬──────────┬──────────┬──────┐
              │      │         │          │          │      │
           npx/uvx subprocess per MCP server (stdio JSON-RPC)
              │      │         │          │          │      │
          Sentinel  GHAS  GreyNoise   OpenCTI    Vault   Jira
          Splunk    Snyk  VirusTotal  Prowler    Okta    Slack
          …         …    …           …          …       …
```

**Data flow — single investigation turn:**

1. Analyst sends a query (Browser / CLI / HTTP / WebSocket)
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
| Node.js | 20+ | `node --version` — required for `npx`-based MCP servers (live mode only) |
| uv | latest | `uv --version` — required for `uvx`-based MCP servers (live mode only) |
| AI API key | — | Only needed for `AI_PROVIDER=anthropic` or `openai`. Not required for demo mode. |

Install Node.js: https://nodejs.org/en/download
Install uv: `curl -LsSf https://astral.sh/uv/install.sh | sh`

---

## Project Layout

```
mcp-security-ops-suite/
├── agent.py            ← Core agent: run_investigation() + CLI + demo scenarios
├── server.py           ← FastAPI app: REST + WebSocket + UI serving + session store
├── mcp_client.py       ← Async MCP subprocess client (JSON-RPC over stdio)
├── config.py           ← Centralised configuration (reads .env)
├── onboard.py          ← CLI onboarding wizard (also powers the web wizard)
├── mcp_config.json     ← MCP server spawn commands + env var references
├── .env.example        ← Template for credentials (copy → .env)
├── requirements.txt    ← Python dependencies
├── Dockerfile          ← Python 3.12 + Node 20 + uv, non-root user
├── docker-compose.yml  ← Private-subnet deployment
├── ui/
│   └── index.html      ← Single-file SPA (served at GET /)
├── sessions/           ← Persisted WebSocket session history (auto-created)
├── reports/            ← Generated investigation reports (auto-created)
├── playbooks/          ← SOC workflow documentation
├── architecture/       ← Reference architecture diagrams
├── mcp-configs/        ← Example MCP server configuration snippets
└── scripts/            ← Helper scripts
```

---

## Quick Start

### Option A — Demo mode (zero credentials)

Try the full UI with realistic streaming investigations. No API key, no tool credentials, no configuration needed.

```bash
git clone <this-repo> && cd mcp-security-ops-suite

# Create a virtual environment and install dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Start the server in demo mode
AI_PROVIDER=demo MCP_MODE=mock uvicorn server:app --host 0.0.0.0 --port 8000

# Open http://localhost:8000 in your browser
```

Demo mode streams pre-recorded investigations with realistic tool calls, full Markdown output, and collapsible tool cards — so you can explore every UI feature before connecting any real services.

---

### Option B — Real AI, mock tools

Use a real AI model (Anthropic or local Ollama/LM Studio) with simulated tool responses. Good for testing AI configuration before connecting live security tools.

```bash
# Anthropic (cloud)
export AI_PROVIDER=anthropic
export AI_API_KEY=sk-ant-api03-...

# OR local Ollama (fully air-gapped)
export AI_PROVIDER=openai
export AI_BASE_URL=http://localhost:11434/v1
export AI_MODEL=qwen2.5:7b
export AI_API_KEY=ollama   # any non-empty string

export MCP_MODE=mock

uvicorn server:app --host 0.0.0.0 --port 8000
# Open http://localhost:8000
```

---

### Option C — Live mode with real tools

```bash
# 1. Run the onboarding wizard to pick tools and collect credentials
python onboard.py
# OR use the web wizard: start the server and click "🔌 MCP Tools" in the UI header

# 2. The wizard writes .env with your selections. MCP_MODE=live is set automatically.

# 3. Load the .env and start
source .env
uvicorn server:app --host 0.0.0.0 --port 8000

# 4. Or use the CLI directly
python agent.py --playbook incident-response "suspicious login 185.220.101.34"
```

---

### Option D — Docker

```bash
# 1. Generate .env (via wizard or copy from .env.example)
python onboard.py   # or: cp .env.example .env && edit .env

# 2. Build and start
docker compose up -d

# 3. Check health
curl http://localhost:8000/health

# 4. Tail logs
docker compose logs -f
```

---

## Browser UI

The server serves a single-page application at `http://localhost:8000`.

### Features

| Feature | How to use |
|---|---|
| **Streaming chat** | Type a query in the input box, press Send |
| **Tool call cards** | Expandable cards show each MCP tool called, its inputs, and the result |
| **Playbook launcher** | Click a playbook in the sidebar → enter a target → watch it stream |
| **Report generator** | Sidebar → **Generate Report** → pick playbook + target → downloads `.md` |
| **AI Engine setup** | Header → **⚙ AI Engine** → configure provider, API key, and model |
| **MCP Tools setup** | Header → **🔌 MCP Tools** → tier selection, tool picker, credential forms |
| **Session history** | Persists across page refreshes; **Clear History** wipes it; **+ New Chat** starts fresh |

### Demo mode badge

When running with `AI_PROVIDER=demo`, a purple **demo** badge appears next to the mode indicator. All features are functional — responses are pre-recorded realistic investigations, not live AI calls.

---

## Onboarding Wizards

Two separate wizards handle AI configuration and MCP tool setup independently.

### Web wizard (recommended)

Start the server and use the header buttons:

- **⚙ AI Engine** — Choose between Anthropic cloud, local Ollama/LM Studio/vLLM, or demo mode. Generates and optionally applies the AI-related `.env` variables.
- **🔌 MCP Tools** — Tier selection (Solo/Team/Enterprise/Custom), tool picker, per-tool credential forms with documentation links. Generates and optionally applies the MCP credential variables.

Both wizards can download a `.env` snippet or apply changes directly to the running server.

### CLI wizard

```bash
python onboard.py
```

**Steps:**

1. **Choose a tier** — picks the tool set matching your stack:

   | Tier | Tools | Cost |
   |---|---|---|
   | Solo Analyst | GHAS, Semgrep, GreyNoise, Security Detections | Free |
   | Team SOC | Solo + Sentinel/Splunk, Snyk, Trivy, Prowler, Vault, Jira, Slack | Varies |
   | Enterprise | All 20+ tools | Enterprise licensing |
   | Custom | Choose individually | — |

2. **Enter credentials** — prompted per tool with masked input and documentation links.
3. **Write `.env`** — existing `.env` is backed up before overwriting.

**Subcommands:**

```bash
python onboard.py --check              # Show which credentials are set / missing
python onboard.py --add splunk         # Add or reconfigure a single tool
python onboard.py --list               # List all available tools with tiers
python onboard.py --env-file /etc/socpilot/.env   # Use a different .env file
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
| `--playbook NAME` | `-p` | Run a named SOC playbook |
| `--list-playbooks` | `-l` | Print all playbook names and exit |
| `--verbose` | `-v` | Show AI reasoning steps |
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

# Interactive multi-turn session
python agent.py
SOCPilot> --playbook vuln-triage CVE-2024-50623 in payments-api
SOCPilot> now check if auth-service is also affected
SOCPilot> create a P1 Jira ticket for both findings
SOCPilot> clear     ← resets session history
SOCPilot> exit
```

> **Note:** The CLI requires an AI API key (`AI_PROVIDER=anthropic` or `openai`). Demo mode is browser-only.

---

## HTTP API

Start the server:

```bash
uvicorn server:app --host 0.0.0.0 --port 8000 --reload
```

Swagger UI: `http://localhost:8000/docs`

### Endpoints

#### `GET /`
Serves the browser UI (`ui/index.html`).

#### `GET /health`
Liveness check — returns provider, mode, model, and timestamp.
```json
{"status": "ok", "mode": "mock", "provider": "demo", "model": "claude-opus-4-6", "ts": "2026-02-24T10:30:00+00:00"}
```

#### `GET /health/llm`
Probes the configured AI provider with a minimal request. Returns latency and status.
```json
{"provider": "anthropic", "model": "claude-opus-4-6", "status": "ok", "latency_ms": 420, "response": "pong"}
```
Returns `{"status": "ok", "latency_ms": 0}` immediately in demo mode.

#### `GET /playbooks`
List available SOC playbooks.
```json
{"playbooks": ["vuln-triage", "incident-response", "threat-hunting", "compliance-audit", "secret-leak-response", "cloud-posture-review"]}
```

#### `GET /playbooks/detail`
Full prompt templates for each playbook (with `{target}` placeholder).

#### `GET /tools`
All tool definitions with input schemas.

#### `POST /query` — SSE streaming
Run a free-form investigation. Returns Server-Sent Events.

```bash
curl -X POST http://localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"query": "Check GreyNoise for IP 185.220.101.34", "verbose": false}' \
  --no-buffer
```

Response stream — each line is `data: <JSON>\n\n`:
```
data: {"type": "text",        "text": "Checking GreyNoise for..."}
data: {"type": "tool_call",   "name": "check_greynoise", "inputs": {"query": "185.220.101.34"}}
data: {"type": "tool_result", "name": "check_greynoise", "content": "Classification: MALICIOUS..."}
data: {"type": "text",        "text": "The IP is classified as malicious..."}
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
Run a playbook and save the result to a Markdown file. Waits for completion.

```bash
curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{"playbook": "compliance-audit", "target": "AWS prod"}'
```
```json
{"status": "ok", "file": "reports/compliance-audit-20260224-103000.md", "turns": 4, "bytes": 8423}
```

#### `GET /reports/{filename}`
Download a generated report file. Path-traversal safe.

#### `GET /onboard/tools`
Returns the full tool catalog and tier definitions used by the web onboarding wizard.

#### `POST /onboard/env`
Write or merge `.env` values on the server. Used by the web wizard's "Apply to Server" button.
```json
{"values": {"AI_API_KEY": "sk-ant-...", "AI_PROVIDER": "anthropic"}}
```

#### `DELETE /sessions/{session_id}`
Clear conversation history for a session from both memory and disk. Called by the browser UI's "Clear History" button.

#### Consuming the SSE stream in Python

```python
import httpx, json

with httpx.Client(timeout=300) as client:
    with client.stream("POST", "http://localhost:8000/query",
                       json={"query": "Is CVE-2024-50623 exploited?"}) as r:
        for line in r.iter_lines():
            if line.startswith("data: "):
                event = json.loads(line[6:])
                if event["type"] == "text":
                    print(event["text"], end="", flush=True)
```

---

## WebSocket Sessions

`/ws/{session_id}` maintains a stateful conversation across multiple queries. The agent remembers all previous findings within the session.

### History persistence

Session history is stored in two places:
- **Memory** (`_session_store`): survives WebSocket reconnects within the same server run
- **Disk** (`sessions/<id>.json`): survives server restarts

History is automatically restored when the same `session_id` reconnects. The browser UI stores the session ID in `localStorage`, so history survives page refreshes. "Clear History" deletes both the in-memory and on-disk state.

```bash
# Using wscat
wscat -c ws://localhost:8000/ws/analyst-session-1
> {"query": "Check GreyNoise for 185.220.101.34"}
< {"type": "text", "text": "..."}
< {"type": "done", "turns": 2}
> {"query": "Now check if OpenCTI has any threat actor campaigns using this IP"}
< {"type": "text", "text": "Based on my earlier GreyNoise findings..."}   ← remembers context
```

```python
import asyncio, json, websockets

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

`POST /webhook/siem` receives a SIEM alert and automatically triggers the incident-response playbook. Returns an SSE stream.

### Configure your SIEM

**Microsoft Sentinel — Logic App action:**
```
HTTP POST https://your-server:8000/webhook/siem
Content-Type: application/json
Body: {
  "alert_id":    "@{triggerBody()?['SystemAlertId']}",
  "title":       "@{triggerBody()?['AlertDisplayName']}",
  "severity":    "@{triggerBody()?['AlertSeverity']}",
  "description": "@{triggerBody()?['Description']}",
  "raw":         @{triggerBody()}
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

---

## SOC Playbooks

Invoke playbooks from the browser UI sidebar, via the CLI `--playbook` flag, or via `POST /playbook`.

| Playbook | Use case | Tools invoked |
|---|---|---|
| `vuln-triage` | New CVE or Dependabot alert | GHAS → GreyNoise → OpenCTI → Snyk → Detections → Jira → Slack |
| `incident-response` | Active alert, suspicious behaviour | Sentinel → Splunk → GreyNoise → OpenCTI → Okta → Vault → Jira → Slack |
| `threat-hunting` | TTP or threat actor investigation | Detections → Sentinel → Splunk → GreyNoise → OpenCTI |
| `compliance-audit` | SOC 2 / ISO 27001 gap report | Drata/Vanta → Prowler → GHAS → Vault Radar |
| `secret-leak-response` | Exposed credential | Vault Radar → GHAS → Vault → Okta → Jira → Slack |
| `cloud-posture-review` | Cloud security posture | Prowler → Cloudflare → Sentinel → Vault |

See `playbooks/` for detailed step-by-step workflows, example sessions, and decision matrices.

### Risk assessment framework

| Priority | SLA | Trigger |
|---|---|---|
| P1 | Immediate | Actively exploited + confirmed reachable + internet-facing |
| P2 | 48 h | Actively exploited OR reachable (not both); PoC available |
| P3 | 7 d | Vulnerability present, not actively exploited |
| P4 | 30 d | Low severity or unreachable |

---

## Configuration Reference

All settings are read from environment variables (populated from `.env` via `python-dotenv`).

| Variable | Required | Default | Description |
|---|---|---|---|
| `AI_PROVIDER` | No | `anthropic` | `demo` · `anthropic` · `openai` (also covers Ollama/LM Studio/vLLM) |
| `AI_API_KEY` | Conditional | — | Required for `anthropic`/`openai`. Not needed for `demo`. |
| `AI_MODEL` | No | `claude-opus-4-6` | Override the inference model |
| `AI_BASE_URL` | No | — | Custom endpoint (Ollama: `http://localhost:11434/v1`, etc.) |
| `MCP_MODE` | No | `mock` | `mock` = sample data · `live` = real MCP servers |
| `SERVER_HOST` | No | `0.0.0.0` | FastAPI bind host |
| `SERVER_PORT` | No | `8000` | FastAPI bind port |
| `REPORTS_DIR` | No | `reports/` | Where `--output` and `POST /report` write files |
| `MCP_TIMEOUT` | No | `60` | Seconds before an MCP tool call times out |

See `.env.example` for all per-tool credential variables and usage examples.

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

Add an entry to the `SECURITY_TOOLS` list:

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

In the `_mock_response()` function:

```python
"query_mythic": (
    f"Mythic — {inputs.get('operation','default')}:\n"
    f"  3 active agents | 1 stale (last seen 48 h)\n"
    f"  [Mock — set MYTHIC_URL for live data]"
),
```

### 5. Add the tool to `onboard.py`

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

### 6. Add the name mapping to `mcp_client.py`

```python
_MCP_TOOL_NAMES: dict[str, str] = {
    ...
    "query_mythic": "get_agents",  # the actual tool name the MCP server exposes
}
```

---

## Security Notes

- **Credentials** are injected at runtime via `.env` or Docker `env_file`. Never baked into the image or committed to source control. `.env` is gitignored.

- **Session files** (`sessions/`) contain conversation history including tool results. Add `sessions/` to `.gitignore` and restrict file system permissions if conversations contain sensitive findings.

- **Network isolation**: In production, run the container with restricted egress. MCP calls are all internal; only the AI inference request needs outbound internet access (or route via `AI_BASE_URL`).

- **Destructive actions**: The system prompt instructs the agent to flag containment actions (session suspension, credential rotation, IP blocking) for analyst approval before executing.

- **Prompt injection**: MCP tool results are untrusted external data. Treat AI output as advisory — verify critical findings independently.

- **Least privilege**: Each MCP server should use a read-only or scoped credential where possible.

- **TLS**: Use a reverse proxy (nginx, Caddy, Cloudflare Tunnel) to terminate TLS in front of the FastAPI server. Do not expose port 8000 directly to the internet.

---

## Troubleshooting

### No API key — want to try the UI first
Use demo mode — no key needed:
```bash
AI_PROVIDER=demo MCP_MODE=mock uvicorn server:app --host 0.0.0.0 --port 8000
```

### `AI_API_KEY is not set` error
```bash
export AI_API_KEY=sk-ant-...
# or add to .env: AI_API_KEY=sk-ant-...
# or switch to demo mode: AI_PROVIDER=demo
```

### `ModuleNotFoundError: No module named 'anthropic'`
```bash
pip install -r requirements.txt
```

### `'npx' not found in PATH`
Only needed for live MCP mode. Install Node.js 20+: https://nodejs.org/en/download

### `'uvx' not found in PATH`
Only needed for live MCP mode.
```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source ~/.bashrc   # or restart your shell
```

### MCP server times out
- Verify credentials: `python onboard.py --check`
- Increase timeout: `MCP_TIMEOUT=120`
- Test individually: `python onboard.py --add <tool_id>`

### Port 8000 already in use
```bash
SERVER_PORT=8001 uvicorn server:app --host 0.0.0.0 --port 8001
# or update SERVER_PORT in .env
```

### Docker container exits immediately
```bash
docker compose logs socpilot
# Most common cause: AI_API_KEY not set (use AI_PROVIDER=demo to avoid this)
```

### Check which tools have credentials configured
```bash
python onboard.py --check
```
