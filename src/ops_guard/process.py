from __future__ import annotations

import asyncio
import os
import signal
from dataclasses import dataclass
from typing import Any


class OutputLimitExceeded(RuntimeError):
    def __init__(self, stream: str, partial: bytes) -> None:
        super().__init__(f"{stream} exceeded output limit")
        self.stream = stream
        self.partial = partial


@dataclass(frozen=True, slots=True)
class ProcessOutput:
    exit_code: int
    stdout: bytes
    stderr: bytes
    truncated: bool


async def _read_limited(stream: asyncio.StreamReader | None, limit: int, name: str) -> bytes:
    if stream is None:
        return b""
    data = bytearray()
    while True:
        chunk = await stream.read(min(8192, max(1, limit + 1 - len(data))))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
        if len(data) > limit:
            raise OutputLimitExceeded(name, bytes(data[:limit]))


async def _write_input(
    stream: asyncio.StreamWriter | None, input_bytes: bytes | None
) -> None:
    if stream is None:
        return
    try:
        if input_bytes:
            stream.write(input_bytes)
            await stream.drain()
    except (BrokenPipeError, ConnectionResetError):
        # The child may reject the request before consuming all stdin. Its bounded stderr/stdout
        # remains the authoritative result.
        pass
    finally:
        stream.close()
        if hasattr(stream, "wait_closed"):
            try:
                await stream.wait_closed()
            except (BrokenPipeError, ConnectionResetError):
                pass


async def _terminate(process: asyncio.subprocess.Process) -> None:
    if process.returncode is not None:
        return
    try:
        if os.name == "posix" and process.pid:
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=1.0)
        except TimeoutError:
            if os.name == "posix" and process.pid:
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            await process.wait()
    except ProcessLookupError:
        return


async def run_argv(
    argv: list[str] | tuple[str, ...],
    *,
    input_bytes: bytes | None = None,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
    timeout_seconds: int = 30,
    max_output_bytes: int = 1_048_576,
    pass_fds: tuple[int, ...] = (),
) -> ProcessOutput:
    if not argv:
        raise ValueError("empty argv")
    kwargs: dict[str, Any] = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True
        kwargs["pass_fds"] = pass_fds
    process = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=env,
        **kwargs,
    )
    input_task = asyncio.create_task(_write_input(process.stdin, input_bytes))
    stdout_task = asyncio.create_task(_read_limited(process.stdout, max_output_bytes, "stdout"))
    stderr_task = asyncio.create_task(_read_limited(process.stderr, max_output_bytes, "stderr"))
    wait_task = asyncio.create_task(process.wait())
    try:
        _input_done, stdout, stderr, exit_code = await asyncio.wait_for(
            asyncio.gather(input_task, stdout_task, stderr_task, wait_task),
            timeout=timeout_seconds,
        )
        return ProcessOutput(int(exit_code), stdout, stderr, False)
    except OutputLimitExceeded as exc:
        await _terminate(process)
        for task in (input_task, stdout_task, stderr_task, wait_task):
            if not task.done():
                task.cancel()
        stdout = exc.partial if exc.stream == "stdout" else b""
        stderr = exc.partial if exc.stream == "stderr" else b""
        return ProcessOutput(137, stdout, stderr, True)
    except TimeoutError:
        await _terminate(process)
        for task in (input_task, stdout_task, stderr_task, wait_task):
            if not task.done():
                task.cancel()
        return ProcessOutput(
            124,
            b"",
            f"execution timed out after {timeout_seconds}s".encode(),
            False,
        )
    except Exception:
        await _terminate(process)
        raise
