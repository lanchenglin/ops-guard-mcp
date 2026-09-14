#!/usr/bin/env python3
"""Temporarily listen for DingTalk robot messages and print IDs needed by Ops Guard.

Do not run this helper at the same time as ops-guard-daemon when both use the
same DingTalk Client ID/Secret. DingTalk recommends one Stream consumer per app.
"""
from __future__ import annotations

import argparse
import json
import os
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover DingTalk sender_staff_id/conversation_id for Ops Guard standalone Stream")
    parser.add_argument("--client-id-env", default="OPS_GUARD_DINGTALK_CLIENT_ID", help="environment variable name")
    parser.add_argument("--client-secret-env", default="OPS_GUARD_DINGTALK_CLIENT_SECRET", help="environment variable name")
    args = parser.parse_args()
    try:
        import dingtalk_stream
    except ImportError:
        print("dingtalk-stream is not installed. Install with: pip install -e '.[dingtalk]'", file=sys.stderr)
        raise SystemExit(2)
    client_id = os.environ.get(args.client_id_env, "").strip()
    client_secret = os.environ.get(args.client_secret_env, "").strip()
    if not client_id or not client_secret:
        print(f"missing {args.client_id_env} or {args.client_secret_env}", file=sys.stderr)
        raise SystemExit(2)

    class DiscoveryHandler(dingtalk_stream.ChatbotHandler):
        async def process(self, callback):
            message = dingtalk_stream.ChatbotMessage.from_dict(callback.data)
            data = {
                "conversation_type": str(message.conversation_type or ""),
                "conversation_id": str(message.conversation_id or ""),
                "sender_staff_id": str(message.sender_staff_id or ""),
                "sender_nick": str(message.sender_nick or ""),
                "message_id": str(message.message_id or ""),
            }
            print(json.dumps(data, ensure_ascii=False, indent=2), flush=True)
            print("Captured. Press Ctrl+C after you have collected all approver/group IDs.", flush=True)
            return dingtalk_stream.AckMessage.STATUS_OK, "OK"

    credential = dingtalk_stream.Credential(client_id, client_secret)
    client = dingtalk_stream.DingTalkStreamClient(credential)
    client.register_callback_handler(dingtalk_stream.ChatbotMessage.TOPIC, DiscoveryHandler())
    print("Waiting for a DingTalk message to the Ops Guard robot...", flush=True)
    print("For a group: add the robot to the target approval group, then @ it and send any text.", flush=True)
    print("For a user ID: have that approver send the robot a DM, or send a group message.", flush=True)
    client.start_forever()


if __name__ == "__main__":
    main()
