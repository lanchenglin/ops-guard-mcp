from __future__ import annotations

import logging
import os
from functools import lru_cache
from typing import Any

from mcp.server import MCPServer

from .dingtalk import build_dingtalk_notifier
from .config import load_gateway_config
from .service import OpsGuardService


LOGGER = logging.getLogger("ops_guard.mcp")
mcp = MCPServer("Ops Guard MCP")


@lru_cache(maxsize=1)
def _service() -> OpsGuardService:
    config_path = os.environ.get("OPS_GUARD_CONFIG", "config/ops-guard.toml")
    config = load_gateway_config(config_path)
    return OpsGuardService(config, notifier=build_dingtalk_notifier(config.dingtalk))


@mcp.tool()
def ops_list_hosts() -> list[dict[str, Any]]:
    """List server targets and their non-secret security posture."""
    return _service().list_hosts()


@mcp.tool()
async def ops_run_command(
    host_id: str,
    argv: list[str],
    reason: str,
    requester: str = "ai",
    cwd: str | None = None,
) -> dict[str, Any]:
    """Submit a structured argv command.

    Known read-only diagnostics may run automatically. Mutations require external approval.
    Unknown commands, shell/interpreter launchers, pipelines, and escape primitives are denied.
    Approval routing is not model-controlled. DingTalk delivery targets come from administrator
    configuration (or a trusted integration path outside the MCP tool schema).
    """
    return await _service().submit_command(
        host_id,
        argv,
        reason,
        requester=requester,
        cwd=cwd,
    )


@mcp.tool()
async def ops_stage_script(
    host_id: str,
    language: str,
    content: str,
    args: list[str],
    reason: str,
    requester: str = "ai",
    cwd: str | None = None,
) -> dict[str, Any]:
    """Stage immutable script content and create an exact-SHA256 approval request.

    Scripts are disabled by default on production hosts. When enabled, every script is treated
    as arbitrary privileged code and never auto-approved.
    """
    return await _service().stage_script(
        host_id,
        language,
        content,
        args,
        reason,
        requester=requester,
        cwd=cwd,
    )


@mcp.tool()
def ops_request_status(request_id: str) -> dict[str, Any]:
    """Get approval and execution status for a request."""
    return _service().status(request_id)


@mcp.tool()
def ops_pending_approvals(limit: int = 50) -> list[dict[str, Any]]:
    """List requests waiting for human approval."""
    return _service().pending(max(1, min(limit, 100)))


@mcp.tool()
async def ops_execute_approved(request_id: str) -> dict[str, Any]:
    """Execute a request only if the immutable digest has already been approved.

    Calling this tool cannot bypass approval. The SQLite state transition, exact digest,
    expiration, and remote agent nonce/signature are checked again.
    """
    return await _service().execute_approved(request_id)


@mcp.tool()
def ops_audit_tail(limit: int = 30) -> list[dict[str, Any]]:
    """Read recent redacted, hash-chained audit records."""
    return _service().audit_tail(max(1, min(limit, 100)))


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("OPS_GUARD_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    # Logging stays on stderr; stdout is reserved for MCP stdio JSON-RPC.
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
