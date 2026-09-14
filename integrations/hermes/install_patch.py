#!/usr/bin/env python3
"""Safely install the Ops Guard DingTalk callback hook into a Hermes source checkout.

Dry-run by default. Use --apply to make changes. A one-time backup of adapter.py is kept.
"""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

IMPORT_LINE = "from .ops_guard_bridge import OpsGuardCardCallbackHandler\n"
REGISTER_MARKER = """        self._stream_client.register_callback_handler(\n            dingtalk_stream.ChatbotMessage.TOPIC, handler\n        )\n"""
REGISTER_BLOCK = REGISTER_MARKER + """\n        # Ops Guard approval cards: deterministic callback transport, not an LLM action.\n        ops_guard_handler = OpsGuardCardCallbackHandler.from_env()\n        if ops_guard_handler is not None:\n            self._stream_client.register_callback_handler(\n                dingtalk_stream.CallbackHandler.TOPIC_CARD_CALLBACK,\n                ops_guard_handler,\n            )\n"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("hermes_root", type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    root = args.hermes_root.expanduser().resolve()
    plugin_dir = root / "plugins" / "platforms" / "dingtalk"
    adapter = plugin_dir / "adapter.py"
    source_bridge = Path(__file__).with_name("ops_guard_bridge.py")
    target_bridge = plugin_dir / "ops_guard_bridge.py"
    if not adapter.is_file():
        raise SystemExit(f"Hermes DingTalk adapter not found: {adapter}")

    text = adapter.read_text(encoding="utf-8")
    already = "OpsGuardCardCallbackHandler.from_env()" in text
    if not already and REGISTER_MARKER not in text:
        raise SystemExit(
            "Hermes adapter layout does not match the tested version; apply HERMES_PATCH.md manually"
        )

    print(f"Hermes adapter: {adapter}")
    print(f"Bridge module:  {target_bridge}")
    print(f"Already patched: {already}")
    if not args.apply:
        print("Dry-run only. Re-run with --apply to modify Hermes.")
        return 0

    backup = adapter.with_suffix(".py.ops-guard.bak")
    if not backup.exists():
        shutil.copy2(adapter, backup)
        print(f"Backup created: {backup}")
    shutil.copy2(source_bridge, target_bridge)

    if not already:
        class_marker = "class DingTalkAdapter(BasePlatformAdapter):"
        if class_marker not in text:
            raise SystemExit("DingTalkAdapter class marker not found")
        text = text.replace(class_marker, IMPORT_LINE + "\n" + class_marker, 1)
        text = text.replace(REGISTER_MARKER, REGISTER_BLOCK, 1)
        adapter.write_text(text, encoding="utf-8")
        print("Hermes adapter patched.")
    else:
        print("Hermes adapter already contains the Ops Guard handler; bridge module refreshed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
