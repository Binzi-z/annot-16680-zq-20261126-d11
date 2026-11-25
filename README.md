# 留存期限冲突的合规复核

应急留存程序：判定合成安全事件在**指定时刻**能否清退，处理双时间轴的签批／禁删令／
一对一撤销，把每个事件的时间轴切成**最少决策片段**，并出具能被**独立验证器**核验的
**保留证明**或**未证缺页证明**。已交付的历史片段可按**原接收水位**重现。

- 实现仅用 **Windows + Python 3.12 标准库**（`hashlib / json / bisect / dataclasses /
  enum / argparse / unittest`），无第三方运行时依赖。
- 所有时间用整数秒、半开区间 `[start, end)`，边界精确、无浮点误差。

## 快速开始

```bat
REM 运行全部场景（退出码 0 = 全通过）
python run.py

REM 只跑指定场景
python run.py boundary_equal late_order cross_tenant unproven_missing

REM 机器可读汇总
python run.py --json

REM 标准库单元测试
python -m unittest discover -s tests -v
```

`python -m retention.main` 与 `run.py` 等价。

## 双时间轴与判定规则

每条证据页同时带两个时间：

| 轴 | 字段 | 含义 |
|---|---|---|
| 有效时间 | `eff_from` / `eff_to` | 该页在何时**生效**（`eff_to` 开到无穷） |
| 事务时间 | `received_at` | 该页在何时**被接收入库** |

**任一接收水位 W 下的证据集 = { 页 : received_at ≤ W }**。判定只用这个集合，因此
晚到记录不会改写历史片段——历史重现只要复用原水位即可。

判定优先级（全部可由公开证据独立复算）：

1. `t < occurred_at + 180 天` → `RETAIN`（`BASE_FLOOR`，法定基线，**无条件**，缺页也推不翻）
2. `t` 已过基线且适用证据族**存在缺页** → `UNPROVEN`（缺页可能是隐藏禁删令，
   也可能是撤销某生效页；基线后既不能证保留、也不能证可清退）
3. 生效**禁删令**覆盖 t → `RETAIN`（`HOLD_ACTIVE`）
4. 生效**签批**覆盖 t → `ELIGIBLE`（`APPROVAL_ACTIVE`）
5. 其余 → `ELIGIBLE`（`NO_AUTHORIZATION`）

**撤销是一对一**：一页 `REVOCATION` 只作用于**同族**、`kind ∈ {APPROVAL,HOLD}` 的目标页。
指向撤销页、跨租户、跨族的撤销一律无效并记为 finding（此约束天然无环、良基）。

**租户隔离**：页的“家族”由 `(tenant, event_id, scope_from, scope_to)` 决定；普通租户页
只作用于本租户同名事件。仅管理域（通配租户 `*`）的范围记录可按有效时间范围跨分区作用，
用于表达“覆盖范围变化”。

## 最少决策片段

边界点 = 事件起点 ∪ 基线终点 ∪ 窗口终点 ∪ 所有生效页的 `eff_from/eff_to`（窗口内）。
按判定合并相邻同判定区间，得到**最少决策片段**；验证器独立检查“连续覆盖 + 无相邻同判定”。

## 证书与独立验证

`build_certificate` 生成自包含证书（`retention-cert/v1`），证书类型由**查询时刻 t 的判定**决定：

- `RETENTION_PROOF`：t 处判定为 `RETAIN`/`ELIGIBLE`（确定结论）。
- `UNPROVEN_PROOF`：t 处判定为 `UNPROVEN`（基线后存在缺页），并附缺页证据
  （`MANIFEST_ABSENT` / `MANIFEST_MISMATCH` / `SEQ_GAP` / `DANGLING_TARGET`）。

> 若 t 处于法定基线内、而别处有缺页，仍可出具 `RETENTION_PROOF` 的 `RETAIN`——
> 因为基线保留无条件成立。验证器要求这类“缺页下的确定结论”理由必须是 `BASE_FLOOR`
> （`gap_guard`），杜绝“缺页掩盖撤销”造成的假保留。

证书内嵌**证据快照**与**清单条目**及承诺哈希，`seal = sha256(正文)` 无需密钥即可查篡改。
`verify_certificate` 只依赖证书自带公开数据即可：
封条 → 结构 → 每页自哈希 → 证据承诺 → （可选）与独立台账同水位快照核对 →
从证据**独立复算片段与缺页** → 最少片段性 → 判定与时刻一致 → 证书类型自洽 → 缺页证据自证。

其中“与独立台账快照核对”只需呈递**候选页/清单**，验证器按事件适用性与水位自行筛选，
因此同分区内其它事件的页不会造成假不一致，但被替换/删改的证据会被识破。

## 验收反例（自动断言）

| 反例 | 场景 | 断言 |
|---|---|---|
| 有效期前后相等 | `boundary_equal` | `base_end-1` → `RETAIN/BASE_FLOOR`；`base_end` → `ELIGIBLE/APPROVED`；两端证书均通过 |
| 晚到令 | `late_order` | 旧水位重现仍 `ELIGIBLE` 且证据快照**不含**晚到禁删令；新水位改判 `RETAIN` |
| 跨租户冲突 | `cross_tenant` | A 的跨租户撤销无效（记 `REVOCATION_CROSS_TENANT`），A/B 判定互不影响，证书各只含本租户证据 |
| 未证缺页 | `unproven_missing` | 基线内 `RETAIN`；基线外 `UNPROVEN`；出具 `UNPROVEN_PROOF` 并通过独立验证 |

## 六万分区压力

`stress_60k`：60,000 个租户分区、每分区一条事件（沿有效时间均匀铺开），每事件一页永久签批；
对全部事件在旧水位出“旧报告”（均 `ELIGIBLE`）。随后**追加唯一一条**管理域覆盖范围记录
（禁删令，作用范围 `occurred_at ∈ [0,60d)`）。

- **只重算相关范围**：借有效时间索引二分定位 `[0,60d)` 内事件（2,592 条），只读/重算它们。
  输出以**实际读取计数**对比朴素全量：
  - 受影响：`events_read = 2,592*2 = 5,184`，`pages_read = 2,592*2 = 5,184`，合计 10,368。
  - 朴素全量：`naive_reads = 60,000 + 60,000*2 = 180,000`。
  - 比值 ≈ `0.0576`（< 0.1），且计数**精确**（`read_counts_exact`）。
- **旧报告保原值**：范围外 **57,408** 条旧报告不重算、判定保持 `ELIGIBLE`（精确核对），
  并抽 200 条在新水位独立复核确认未变；范围内 2,592 条全部改判 `RETAIN`。

`index_note`：有效时间索引为一次性 O(事件数) 结构构建，不计入追加读取成本；查询用二分。

## 目录

```
run.py             根目录便捷入口（转发到 retention.main）
retention/
  __init__.py     公共导出
  model.py        双时间轴模型、半开区间、家族/清单/缺页、规范化与承诺
  engine.py       判定内核：收集 → 撤销解析 → 缺页 → 边界 → 最少片段合并
  certificate.py  证书生成 + 独立验证器
  store.py        租户分区追加台账、接收水位、历史重现、有效时间索引、真实读取计数
  scenarios.py    三个验收反例 + 未证缺页 + 六万分区压力
  main.py         CLI
tests/
  __init__.py
  test_retention.py  标准库 unittest 套件（内核/证书/反例/压力）
  test_cli.py        CLI 冒烟（跑通全部场景、退出码 0）
```

## 已验证

`python -m unittest discover -s tests -v` → **22 个测试全部通过**（约 5 秒，含六万分区压力）。
