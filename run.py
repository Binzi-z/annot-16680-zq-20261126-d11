"""根目录便捷运行入口：python run.py [场景...] [--json]

内部转发到 retention.main。适合在 Windows / cmd / PowerShell 下直接运行，
无需关心包导入路径。
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from retention.main import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
