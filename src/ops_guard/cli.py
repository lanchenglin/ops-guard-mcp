from __future__ import annotations

import argparse
import asyncio
import json
import os

from .dingtalk import build_dingtalk_notifier
from .audit import HashChainAuditLog
from .config import load_gateway_config
from .daemon import run_daemon
from .models import RequestKind
from .policy import CommandPolicy
from .service import OpsGuardService


def _service(config_path: str) -> OpsGuardService:
    config = load_gateway_config(config_path)
    return OpsGuardService(config, notifier=build_dingtalk_notifier(config.dingtalk))


def main() -> None:
    parser = argparse.ArgumentParser(description="Ops Guard MCP administration CLI")
    parser.add_argument(
        "--config",
        default=os.environ.get("OPS_GUARD_CONFIG", "config/ops-guard.toml"),
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    sub.add_parser("mcp", help="run the MCP stdio server")
    sub.add_parser("daemon", help="run approval HTTP service and execution worker")

    policy_parser = sub.add_parser("policy", help="evaluate a command without executing it")
    policy_parser.add_argument("host_id")
    policy_parser.add_argument("argv", nargs=argparse.REMAINDER)

    run_parser = sub.add_parser("run", help="submit a command from the administration CLI")
    run_parser.add_argument("host_id")
    run_parser.add_argument("--reason", required=True)
    run_parser.add_argument("--requester", default="admin-cli")
    run_parser.add_argument(
        "--show-approval-links",
        action="store_true",
        help=(
            "include signed approval URLs in this administrator-local CLI response; "
            "never expose this output to an AI/MCP client"
        ),
    )
    run_parser.add_argument("argv", nargs=argparse.REMAINDER)

    decide_parser = sub.add_parser("decide", help="approve or reject a pending request")
    decide_parser.add_argument("request_id")
    decide_parser.add_argument("decision", choices=["approve", "reject"])
    decide_parser.add_argument("--by", required=True)
    decide_parser.add_argument("--comment", default="")

    status_parser = sub.add_parser("status", help="show a request")
    status_parser.add_argument("request_id")

    execute_parser = sub.add_parser("execute", help="execute an already approved request")
    execute_parser.add_argument("request_id")

    sub.add_parser("verify-audit", help="verify the local audit hash chain")

    args = parser.parse_args()
    if args.subcommand == "mcp":
        os.environ["OPS_GUARD_CONFIG"] = args.config
        from .mcp_server import main as mcp_main

        mcp_main()
        return
    if args.subcommand == "daemon":
        run_daemon(load_gateway_config(args.config))
        return

    if args.subcommand == "policy":
        config = load_gateway_config(args.config)
        host = config.get_host(args.host_id)
        decision = CommandPolicy().evaluate(
            args.argv,
            host,
            kind=RequestKind.COMMAND,
        )
        print(json.dumps(decision.to_dict(), ensure_ascii=False, indent=2))
        return

    service = _service(args.config)
    if args.subcommand == "run":
        result = asyncio.run(
            service.submit_command(
                args.host_id,
                args.argv,
                args.reason,
                requester=args.requester,
                include_approval_links=args.show_approval_links,
            )
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.subcommand == "decide":
        status = service.status(args.request_id)
        result = service.decide(
            args.request_id,
            status["request_digest"],
            allow=args.decision == "approve",
            decided_by=args.by,
            comment=args.comment,
        )
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.subcommand == "status":
        print(json.dumps(service.status(args.request_id), ensure_ascii=False, indent=2))
    elif args.subcommand == "execute":
        print(
            json.dumps(
                asyncio.run(service.execute_approved(args.request_id)),
                ensure_ascii=False,
                indent=2,
            )
        )
    elif args.subcommand == "verify-audit":
        ok, count, detail = HashChainAuditLog(
            service.config.state_dir / "audit.jsonl"
        ).verify()
        print(json.dumps({"ok": ok, "records": count, "detail": detail}, indent=2))
        raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
