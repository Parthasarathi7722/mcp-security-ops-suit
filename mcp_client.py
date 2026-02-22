"""
mcp_client.py — Async MCP (Model Context Protocol) client.

Implements the JSON-RPC 2.0 stdio transport used by all MCP servers in
mcp_config.json. Provides:

  MCPServerProcess   — manages the lifecycle of a single MCP server subprocess
  MCPClientPool      — lazy per-server startup, parallel execution, graceful shutdown

Usage:
    async with MCPClientPool(cfg) as pool:
        result = await pool.call_tool("query_sentinel", {"query": "..."})

Wire this into agent.py by replacing the _route_to_mcp stub with:
    return await pool.call_tool(tool_name, tool_inputs)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from typing import Any

from config import cfg, Config

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_REQUEST_TIMEOUT = float(os.environ.get("MCP_TIMEOUT", "60"))


def _jsonrpc(method: str, params: Any, req_id: int) -> bytes:
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}
    line = json.dumps(msg) + "\n"
    return line.encode()


async def _read_response(reader: asyncio.StreamReader, req_id: int) -> Any:
    """
    Read newline-delimited JSON from stdout until we see a response that
    matches req_id. Skips notification messages (no 'id' field).
    """
    deadline = asyncio.get_event_loop().time() + _REQUEST_TIMEOUT
    while True:
        remaining = deadline - asyncio.get_event_loop().time()
        if remaining <= 0:
            raise TimeoutError(f"MCP response timeout after {_REQUEST_TIMEOUT}s")
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=remaining)
        except asyncio.TimeoutError:
            raise TimeoutError(f"MCP response timeout after {_REQUEST_TIMEOUT}s")
        if not line:
            raise EOFError("MCP server closed stdout unexpectedly")
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            logger.debug("Non-JSON line from MCP server: %s", line[:120])
            continue
        if msg.get("id") == req_id:
            return msg


# ─────────────────────────────────────────────────────────────────────────────
# MCPServerProcess
# ─────────────────────────────────────────────────────────────────────────────

class MCPServerProcess:
    """
    Wraps a single MCP server subprocess communicating over stdio.

    Lifecycle:
        proc = MCPServerProcess("sentinel", cfg)
        await proc.start()          # spawn + initialize handshake
        result = await proc.call_tool("run_kql_query", {...})
        await proc.stop()           # SIGTERM → wait → SIGKILL

    The process is started lazily by MCPClientPool on the first call.
    """

    def __init__(self, server_name: str, config: Config) -> None:
        self.name   = server_name
        self._cfg   = config
        self._proc: asyncio.subprocess.Process | None = None
        self._lock  = asyncio.Lock()
        self._seq   = 0        # JSON-RPC request ID counter

    # ── internal ─────────────────────────────────────────────────────────────

    def _next_id(self) -> int:
        self._seq += 1
        return self._seq

    async def _send(self, data: bytes) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(data)
        await self._proc.stdin.drain()

    async def _rpc(self, method: str, params: Any) -> Any:
        assert self._proc and self._proc.stdout
        req_id = self._next_id()
        await self._send(_jsonrpc(method, params, req_id))
        response = await _read_response(self._proc.stdout, req_id)
        if "error" in response:
            err = response["error"]
            raise RuntimeError(
                f"MCP error from {self.name}: [{err.get('code')}] {err.get('message')}"
            )
        return response.get("result")

    # ── public API ────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Spawn the subprocess and complete the MCP initialize handshake."""
        async with self._lock:
            if self._proc is not None:
                return

            command, args = self._cfg.server_command(self.name)
            if not command:
                raise ValueError(
                    f"Server '{self.name}' not found in mcp_config.json"
                )

            env = {**os.environ, **self._cfg.server_env(self.name)}

            logger.info("Starting MCP server: %s %s", command, " ".join(args))
            self._proc = await asyncio.create_subprocess_exec(
                command, *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )

            # MCP initialize handshake
            result = await self._rpc("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities":    {"tools": {}},
                "clientInfo":      {"name": "socpilot", "version": "1.0.0"},
            })
            logger.debug("MCP %s initialized: %s", self.name,
                         result.get("serverInfo", {}).get("name", "?"))

            # Notify server that init is complete
            notification = json.dumps({
                "jsonrpc": "2.0",
                "method":  "notifications/initialized",
                "params":  {},
            }) + "\n"
            await self._send(notification.encode())

    async def list_tools(self) -> list[dict]:
        """Retrieve the tool manifest from this MCP server."""
        result = await self._rpc("tools/list", {})
        return result.get("tools", [])

    async def call_tool(self, tool_name: str, arguments: dict[str, Any]) -> str:
        """
        Call a tool on this MCP server and return the text content.
        Raises RuntimeError on MCP-level errors.
        """
        result = await self._rpc("tools/call", {
            "name":      tool_name,
            "arguments": arguments,
        })
        # MCP result is { content: [ {type: "text", text: "..."}, ... ], isError: bool }
        is_error = result.get("isError", False)
        content_blocks = result.get("content", [])
        text = "\n".join(
            block.get("text", "")
            for block in content_blocks
            if block.get("type") == "text"
        )
        if is_error:
            raise RuntimeError(f"MCP tool error from {self.name}/{tool_name}: {text}")
        return text

    async def stop(self) -> None:
        """Terminate the subprocess gracefully."""
        async with self._lock:
            if self._proc is None:
                return
            try:
                self._proc.terminate()
                await asyncio.wait_for(self._proc.wait(), timeout=5.0)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    self._proc.kill()
                except ProcessLookupError:
                    pass
            finally:
                self._proc = None
                logger.info("MCP server stopped: %s", self.name)

    @property
    def running(self) -> bool:
        return self._proc is not None and self._proc.returncode is None


# ─────────────────────────────────────────────────────────────────────────────
# MCPClientPool
# ─────────────────────────────────────────────────────────────────────────────

class MCPClientPool:
    """
    Manages a pool of MCP server processes.

    Servers are started lazily on the first tool call that requires them.
    Multiple tool calls to different servers within the same agent turn
    are executed in parallel via asyncio.gather().

    Usage (async context manager):
        async with MCPClientPool(cfg) as pool:
            results = await pool.execute_parallel([
                ("query_sentinel", {"query": "..."}),
                ("check_greynoise", {"query": "1.2.3.4", "query_type": "ip"}),
            ])

    Usage (manual lifecycle):
        pool = MCPClientPool(cfg)
        await pool.start()
        result = await pool.call_tool("check_greynoise", {...})
        await pool.shutdown()
    """

    def __init__(self, config: Config | None = None) -> None:
        self._cfg     = config or cfg
        self._servers: dict[str, MCPServerProcess] = {}
        self._lock    = asyncio.Lock()

    # ── context manager ───────────────────────────────────────────────────────

    async def __aenter__(self) -> "MCPClientPool":
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.shutdown()

    # ── server lifecycle ──────────────────────────────────────────────────────

    async def _get_server(self, server_name: str) -> MCPServerProcess:
        """Return a running MCPServerProcess, starting it if necessary."""
        async with self._lock:
            if server_name not in self._servers:
                self._servers[server_name] = MCPServerProcess(server_name, self._cfg)

        proc = self._servers[server_name]
        if not proc.running:
            await proc.start()
        return proc

    async def shutdown(self) -> None:
        """Terminate all running MCP server processes."""
        tasks = [proc.stop() for proc in self._servers.values()]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._servers.clear()

    # ── tool execution ────────────────────────────────────────────────────────

    def _resolve_server(self, tool_name: str, inputs: dict[str, Any]) -> str:
        """
        Map a tool name to its MCP server name.
        Special case: check_compliance resolves to drata or vanta based on inputs.
        """
        if tool_name == "check_compliance":
            return inputs.get("platform", "drata")
        server = self._cfg.tool_to_server.get(tool_name)
        if server is None:
            raise ValueError(
                f"No MCP server mapping for tool '{tool_name}'. "
                "Add it to config.TOOL_TO_SERVER."
            )
        return server

    # MCP tool names sometimes differ from our internal agent tool names.
    # This table maps agent tool name → MCP server's tool name.
    _MCP_TOOL_NAMES: dict[str, str] = {
        "query_sentinel":    "run_kql_query",
        "query_splunk":      "search",
        "query_elastic":     "search_logs",
        "query_datadog":     "query_logs",
        "get_ghas_alerts":   "get_alerts",
        "scan_semgrep":      "scan",
        "check_snyk":        "test",
        "scan_trivy":        "scan",
        "run_prowler":       "scan",
        "check_greynoise":   "lookup",
        "query_opencti":     "search",
        "check_virustotal":  "lookup",
        "check_vault_radar": "scan",
        "manage_vault":      "execute",
        "manage_okta":       "execute",
        "search_detections": "search",
        "query_cloudflare":  "execute",
        "create_jira_ticket":"create_issue",
        "post_slack":        "post_message",
        "check_compliance":  "get_status",
    }

    def _mcp_tool_name(self, agent_tool_name: str) -> str:
        return self._MCP_TOOL_NAMES.get(agent_tool_name, agent_tool_name)

    async def call_tool(self, tool_name: str, inputs: dict[str, Any]) -> str:
        """
        Route a single tool call to the correct MCP server.
        Starts the server lazily if not already running.
        """
        server_name = self._resolve_server(tool_name, inputs)
        mcp_name    = self._mcp_tool_name(tool_name)
        proc        = await self._get_server(server_name)
        logger.debug("MCP call: %s/%s %s", server_name, mcp_name, inputs)
        return await proc.call_tool(mcp_name, inputs)

    async def execute_parallel(
        self,
        calls: list[tuple[str, dict[str, Any]]],
    ) -> list[str]:
        """
        Execute multiple tool calls in parallel via asyncio.gather().
        Returns results in the same order as the input list.
        Errors are caught and returned as error-description strings
        so that a single failing tool does not abort the entire turn.
        """
        async def _safe_call(tool_name: str, inputs: dict[str, Any]) -> str:
            try:
                return await self.call_tool(tool_name, inputs)
            except Exception as exc:
                logger.warning("Tool %s failed: %s", tool_name, exc)
                return f"[{tool_name}] Error: {exc}"

        tasks = [_safe_call(name, inp) for name, inp in calls]
        return list(await asyncio.gather(*tasks))

    async def list_all_tools(self) -> dict[str, list[dict]]:
        """
        Start every configured server and return its tool manifest.
        Used for introspection / health-checks; not called during normal operation.
        """
        results: dict[str, list[dict]] = {}
        for server_name in self._cfg.mcp_config:
            try:
                proc  = await self._get_server(server_name)
                tools = await proc.list_tools()
                results[server_name] = tools
            except Exception as exc:
                results[server_name] = [{"error": str(exc)}]
        return results