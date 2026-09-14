from __future__ import annotations

import sys
import unittest

from ops_guard.process import run_argv


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    async def test_output_limit_terminates_process(self) -> None:
        result = await run_argv([sys.executable, "-c", "print('x' * 100000)"], timeout_seconds=5, max_output_bytes=1024)
        self.assertTrue(result.truncated); self.assertLessEqual(len(result.stdout), 1024)

    async def test_timeout_terminates_process_group(self) -> None:
        result = await run_argv([sys.executable, "-c", "import time; time.sleep(5)"], timeout_seconds=1, max_output_bytes=1024)
        self.assertEqual(result.exit_code, 124); self.assertIn(b"timed out", result.stderr)

    async def test_arguments_are_not_shell_interpreted(self) -> None:
        result = await run_argv([sys.executable, "-c", "import sys; print(sys.argv[1])", "a;echo injected"], timeout_seconds=5, max_output_bytes=1024)
        self.assertEqual(result.exit_code, 0); self.assertEqual(result.stdout.strip(), b"a;echo injected")


if __name__ == "__main__": unittest.main()
