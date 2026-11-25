"""CLI 冒烟测试：验证 retention.main 能跑通全部场景并以退出码 0 结束。

（不打印完整 JSON，避免污染测试输出；完整结果请运行 `python run.py --json`。）
"""

from __future__ import annotations

import contextlib
import io
import json
import unittest

from retention import main as cli


class CLISmoke(unittest.TestCase):
    def test_cli_all_scenarios_ok(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = cli.main(["--json"])
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["failures"], [])
        self.assertSetEqual(
            set(payload["results"]),
            {"boundary_equal", "late_order", "cross_tenant",
             "unproven_missing", "stress_60k"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
