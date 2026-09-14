from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .models import OperationRequest


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def request_digest(request: OperationRequest) -> str:
    return sha256_bytes(canonical_json(request.binding_dict()))


def hmac_hex(secret: bytes, value: Any) -> str:
    return hmac.new(secret, canonical_json(value), hashlib.sha256).hexdigest()


def secure_compare(left: str, right: str) -> bool:
    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))
