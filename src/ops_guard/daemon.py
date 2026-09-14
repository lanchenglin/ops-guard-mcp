from __future__ import annotations

import argparse
import asyncio
import html
import logging
import os
import signal
import threading
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .approvals import ApprovalLinkError
from .dingtalk import DingTalkApprovalStream, DingTalkHermesBridge, build_dingtalk_notifier
from .config import GatewayConfig, load_gateway_config
from .service import OpsGuardService


LOGGER = logging.getLogger("ops_guard.daemon")


class ApprovalHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], service: OpsGuardService) -> None:
        super().__init__(address, ApprovalHandler)
        self.service = service
        self.hermes_bridge = DingTalkHermesBridge(service.config.dingtalk, service)


class ApprovalHandler(BaseHTTPRequestHandler):
    server: ApprovalHTTPServer

    def log_message(self, fmt: str, *args: Any) -> None:
        del fmt, args
        path_only = urllib.parse.urlparse(self.path).path
        LOGGER.info(
            "approval-http client=%s method=%s path=%s",
            self.client_address[0],
            self.command,
            path_only,
        )

    def _send_html(self, status: int, title: str, body: str) -> None:
        payload = (
            "<!doctype html><html lang='zh-CN'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title>"
            "<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:40px auto;"
            "padding:0 18px;line-height:1.6}code{word-break:break-all;background:#f4f4f4;"
            "padding:2px 5px}.card{border:1px solid #ddd;border-radius:12px;padding:20px}"
            "button{font-size:16px;padding:10px 20px;margin-right:12px}</style></head>"
            f"<body><div class='card'><h2>{html.escape(title)}</h2>{body}</div></body></html>"
        ).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: int, value: dict[str, Any]) -> None:
        import json

        payload = json.dumps(value, ensure_ascii=False, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    @staticmethod
    def _single(query: dict[str, list[str]]) -> dict[str, str]:
        return {key: values[-1] for key, values in query.items() if values}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok", "time": int(time.time())})
            return
        if parsed.path != "/decision":
            self._send_html(HTTPStatus.NOT_FOUND, "Not Found", "<p>未知路径。</p>")
            return
        params = self._single(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
        try:
            payload = self.server.service.link_signer.verify(params)
            status = self.server.service.status(str(payload["request_id"]))
            if status["request_digest"] != payload["request_digest"]:
                raise ApprovalLinkError("request digest does not match stored request")
        except Exception as exc:
            self._send_html(
                HTTPStatus.BAD_REQUEST,
                "审批链接无效",
                f"<p>{html.escape(str(exc))}</p>",
            )
            return
        request = status["request"]
        decision = str(payload["decision"])
        label = "批准" if decision == "approve" else "拒绝"
        command = (
            f"SCRIPT {request.get('script_language')} sha256={request.get('artifact_sha256')}"
            if request.get("kind") == "script"
            else " ".join(request.get("argv") or [])
        )
        hidden = "".join(
            f"<input type='hidden' name='{html.escape(key)}' value='{html.escape(value)}'>"
            for key, value in params.items()
        )
        body = (
            f"<p><strong>主机：</strong>{html.escape(str(request['host_id']))}</p>"
            f"<p><strong>风险：</strong>{html.escape(str(request['risk']))}</p>"
            f"<p><strong>原因：</strong>{html.escape(str(request['reason']))}</p>"
            f"<p><strong>操作：</strong><code>{html.escape(command)}</code></p>"
            f"<p><strong>摘要：</strong><code>{html.escape(status['request_digest'])}</code></p>"
            "<p>此页面只展示已签名、不可变的审批对象。提交后不可重复使用。</p>"
            "<form method='post' action='/decision'>"
            f"{hidden}<label>备注（可选）<br><input name='comment' maxlength='500' style='width:100%'></label>"
            f"<p><button type='submit'>{label}</button></p></form>"
        )
        self._send_html(HTTPStatus.OK, f"确认{label}", body)

    def _handle_dingtalk_bridge(self) -> None:
        config = self.server.service.config.dingtalk
        if (
            not config.enabled
            or config.mode not in {"interactive", "hybrid"}
            or config.callback_owner != "hermes"
        ):
            self._send_json(HTTPStatus.NOT_FOUND, {"ok": False, "error": "bridge disabled"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 32 * 1024:
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": "invalid body size"})
            return
        try:
            import json

            raw = self.rfile.read(length).decode("utf-8", errors="strict")
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
            signature = self.headers.get("X-Ops-Guard-Signature", "").strip()
            result = self.server.hermes_bridge.verify_and_handle(payload, signature)
            self._send_json(HTTPStatus.OK, result)
        except Exception as exc:
            LOGGER.warning(
                "DingTalk Hermes approval bridge rejected client=%s error=%s",
                self.client_address[0],
                str(exc),
            )
            self._send_json(HTTPStatus.BAD_REQUEST, {"ok": False, "error": str(exc)[:300]})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/integrations/dingtalk/decision":
            self._handle_dingtalk_bridge()
            return
        if parsed.path != "/decision":
            self._send_html(HTTPStatus.NOT_FOUND, "Not Found", "<p>未知路径。</p>")
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 64 * 1024:
            self._send_html(HTTPStatus.BAD_REQUEST, "请求无效", "<p>表单大小无效。</p>")
            return
        raw = self.rfile.read(length).decode("utf-8", errors="strict")
        params = self._single(urllib.parse.parse_qs(raw, keep_blank_values=True))
        comment = params.pop("comment", "")[:500]
        try:
            payload = self.server.service.link_signer.verify(params)
            request_id = str(payload["request_id"])
            digest = str(payload["request_digest"])
            decision = str(payload["decision"])
            header_name = self.server.service.config.trusted_approver_header
            if header_name:
                approver = self.headers.get(header_name)
                if not approver:
                    raise ApprovalLinkError(
                        f"trusted approver header is required: {header_name}"
                    )
                decided_by = f"proxy:{approver[:200]}"
            else:
                decided_by = f"signed-link:{self.client_address[0]}"
            result = self.server.service.decide(
                request_id,
                digest,
                allow=decision == "approve",
                decided_by=decided_by,
                comment=comment,
            )
            label = "已批准，等待执行器领取" if decision == "approve" else "已拒绝"
            self._send_html(
                HTTPStatus.OK,
                "审批完成",
                f"<p>{html.escape(label)}</p><p>请求状态：<code>{html.escape(result['status'])}</code></p>",
            )
        except Exception as exc:
            self._send_html(
                HTTPStatus.BAD_REQUEST,
                "审批失败",
                f"<p>{html.escape(str(exc))}</p>",
            )


async def _worker(service: OpsGuardService, stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            if service.config.auto_execute_on_approval:
                await service.execute_pending_once()
        except Exception:
            LOGGER.exception("approval worker iteration failed")
        await asyncio.sleep(1.0)


def run_daemon(config: GatewayConfig) -> None:
    if (
        config.dingtalk.enabled
        and config.dingtalk.mode in {"interactive", "hybrid"}
        and config.dingtalk.callback_owner == "hermes"
    ):
        config.required_secret(config.dingtalk.bridge_secret_env)
    service = OpsGuardService(config, notifier=build_dingtalk_notifier(config.dingtalk))
    server = ApprovalHTTPServer((config.bind_host, config.bind_port), service)
    stop = threading.Event()

    def shutdown(_signum: int, _frame: object) -> None:
        stop.set()
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)
    http_thread = threading.Thread(target=server.serve_forever, name="approval-http", daemon=True)
    http_thread.start()
    LOGGER.info("approval service listening on %s:%s", config.bind_host, config.bind_port)

    if (
        config.dingtalk.enabled
        and config.dingtalk.mode in {"interactive", "hybrid"}
        and config.dingtalk.callback_owner == "ops_guard"
    ):
        stream = DingTalkApprovalStream(config.dingtalk, service)
        stream.preflight()

        def run_stream() -> None:
            try:
                stream.run_forever()
            except Exception:
                LOGGER.exception("DingTalk standalone approval Stream terminated unexpectedly")
                stop.set()
                threading.Thread(target=server.shutdown, daemon=True).start()

        stream_thread = threading.Thread(
            target=run_stream,
            name="dingtalk-approval-stream",
            daemon=True,
        )
        stream_thread.start()
        LOGGER.info("DingTalk standalone approval Stream thread started")
    elif (
        config.dingtalk.enabled
        and config.dingtalk.mode in {"interactive", "hybrid"}
        and config.dingtalk.callback_owner == "hermes"
    ):
        LOGGER.info(
            "DingTalk card callbacks delegated to Hermes bridge endpoint "
            "/integrations/dingtalk/decision"
        )
    try:
        asyncio.run(_worker(service, stop))
    finally:
        server.shutdown()
        server.server_close()
        http_thread.join(timeout=3)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ops Guard approval callback and execution worker")
    parser.add_argument(
        "--config",
        default=os.environ.get("OPS_GUARD_CONFIG", "config/ops-guard.toml"),
    )
    parser.add_argument("--log-level", default="INFO")
    args = parser.parse_args()
    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    run_daemon(load_gateway_config(args.config))


if __name__ == "__main__":
    main()
