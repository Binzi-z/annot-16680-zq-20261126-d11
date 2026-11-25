"""命令行入口：运行全部场景，打印可复核结果，并以退出码表示是否全部通过。"""

from __future__ import annotations

import argparse
import json
import sys
import time

from .scenarios import ALL_SCENARIOS


def _run_one(name: str) -> dict:
    fn = ALL_SCENARIOS[name]
    t0 = time.perf_counter()
    result = fn()
    result["_seconds"] = round(time.perf_counter() - t0, 3)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="retention", description=__doc__)
    parser.add_argument("scenarios", nargs="*", default=[],
                        help=f"要运行的场景；留空跑全部。可选：{', '.join(ALL_SCENARIOS)}")
    parser.add_argument("--json", action="store_true", help="只输出 JSON 汇总")
    args = parser.parse_args(argv)

    chosen = args.scenarios or list(ALL_SCENARIOS)
    if not args.json:
        print("=" * 78)
        print("应急留存合规复核 —— 双时间轴 / 最少决策片段 / 可独立验证证明")
        print("=" * 78)

    results = {}
    failures = []
    for name in chosen:
        if name not in ALL_SCENARIOS:
            failures.append({"scenario": name, "error": "未知场景"})
            continue
        try:
            results[name] = _run_one(name)
        except AssertionError as exc:
            failures.append({"scenario": name, "error": f"断言失败：{exc}"})
        except Exception as exc:  # noqa: BLE001
            failures.append({"scenario": name, "error": f"{type(exc).__name__}: {exc}"})

        if not args.json and name in results:
            print(f"\n[{name}]  ({results[name]['_seconds']}s)")
            print(json.dumps(results[name], ensure_ascii=False, indent=2, sort_keys=True))

    if args.json:
        print(json.dumps({"results": results, "failures": failures},
                         ensure_ascii=False, indent=2, sort_keys=True))
    else:
        print("\n" + "=" * 78)
        if failures:
            print(f"失败 {len(failures)} 项：")
            for f in failures:
                print(f"  - {f['scenario']}: {f['error']}")
            print("结果：不通过")
        else:
            print(f"全部 {len(results)} 个场景通过。")
            print("结果：通过")
        print("=" * 78)

    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
