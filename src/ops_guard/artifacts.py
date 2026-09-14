from __future__ import annotations

import os
from pathlib import Path

from .canonical import sha256_bytes


class ArtifactError(ValueError):
    pass


class ArtifactStore:
    """Content-addressed, immutable artifact storage."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ArtifactError("invalid SHA-256 digest")
        return self.root / f"{digest}.blob"

    def put(self, data: bytes) -> str:
        digest = sha256_bytes(data)
        path = self._path(digest)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        try:
            fd = os.open(path, flags, 0o600)
        except FileExistsError:
            existing = path.read_bytes()
            if sha256_bytes(existing) != digest or existing != data:
                raise ArtifactError("content-address collision or corrupted artifact")
            return digest
        try:
            with os.fdopen(fd, "wb", closefd=True) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            path.unlink(missing_ok=True)
            raise
        return digest

    def get(self, digest: str) -> bytes:
        path = self._path(digest)
        data = path.read_bytes()
        if sha256_bytes(data) != digest:
            raise ArtifactError("artifact hash mismatch")
        return data
