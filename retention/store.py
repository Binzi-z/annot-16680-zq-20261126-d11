"""分区台账、接收水位、历史重现与真实读取计数。

存储模型：
  * 按租户分区的追加式（append-only）台账；页一旦写入不可修改。
  * 每页带 received_at（事务时间）。任一水位 W 下的证据集 = { p : p.received_at <= W }。
  * 重现：用"原接收水位"重建当时可见的证据集，因此晚到记录不会改写历史片段。

读取计数（ReadLedger）：统计真实发生的事件读取 / 页读取次数，用于压力场景中
*以实际读取计数* 证明"只重算了相关范围"，而非口头声称。
"""

from __future__ import annotations

import bisect
from dataclasses import dataclass

from .engine import Evaluation, evaluate
from .model import ADMIN_TENANT, Event, ManifestEntry, Page


@dataclass
class ReadLedger:
    """真实读取计数器。"""
    events_read: int = 0
    pages_read: int = 0
    partitions_touched: int = 0
    evaluations: int = 0

    def as_dict(self) -> dict:
        return {"events_read": self.events_read, "pages_read": self.pages_read,
                "partitions_touched": self.partitions_touched,
                "evaluations": self.evaluations}


class PartitionStore:
    """按租户分区的追加台账，并维护全局接收水位索引。"""

    def __init__(self) -> None:
        self._pages_by_tenant: dict[str, list[Page]] = {}
        self._events_by_tenant: dict[str, list[Event]] = {}
        self._event_index: dict[tuple[str, str], Event] = {}
        self._manifest_by_tenant: dict[str, list[ManifestEntry]] = {}
        self._seq_by_tenant: dict[str, int] = {}
        self._timeline: list[tuple[int, str, str]] | None = None  # 惰性全局有效时间索引
        self.max_received: int = 0

    # -- 写入 ---------------------------------------------------------------
    def put_event(self, event: Event) -> None:
        key = (event.tenant, event.event_id)
        if key in self._event_index:
            raise KeyError(f"事件重复：{event.key}")
        self._event_index[key] = event
        self._events_by_tenant.setdefault(event.tenant, []).append(event)
        self._timeline = None  # 使有效时间索引失效

    def next_seq(self, tenant: str) -> int:
        s = self._seq_by_tenant.get(tenant, 0)
        self._seq_by_tenant[tenant] = s + 1
        return s

    def append_page(self, page: Page) -> None:
        if page.received_at < 0:
            raise ValueError("received_at 非法")
        self._pages_by_tenant.setdefault(page.tenant, []).append(page)
        self.max_received = max(self.max_received, page.received_at)

    def append_manifest(self, entry: ManifestEntry) -> None:
        self._manifest_by_tenant.setdefault(entry.tenant, []).append(entry)

    # -- 读取（带计数） ------------------------------------------------------
    def get_event(self, tenant: str, event_id: str, ledger: ReadLedger | None = None) -> Event | None:
        if ledger is not None:
            ledger.events_read += 1
        return self._event_index.get((tenant, event_id))

    def events_in(self, tenant: str) -> list[Event]:
        return self._events_by_tenant.get(tenant, [])

    def pages_in(self, tenant: str, ledger: ReadLedger | None = None) -> list[Page]:
        if ledger is not None:
            ledger.pages_read += len(self._pages_by_tenant.get(tenant, []))
            ledger.partitions_touched += 1
        return self._pages_by_tenant.get(tenant, [])

    def admin_pages(self, ledger: ReadLedger | None = None) -> list[Page]:
        """管理域页：独立存储，按需读取（也计入真实读取计数）。"""
        pages = self._pages_by_tenant.get(ADMIN_TENANT, [])
        if ledger is not None:
            ledger.pages_read += len(pages)
            ledger.partitions_touched += 1
        return pages

    def manifest_in(self, tenant: str) -> list[ManifestEntry]:
        return self._manifest_by_tenant.get(tenant, [])

    def watermarks(self) -> list[int]:
        """所有出现过的接收水位（去重升序），用于按原水位重现历史。"""
        wms = {0}
        for plist in self._pages_by_tenant.values():
            for p in plist:
                wms.add(p.received_at)
        for mlist in self._manifest_by_tenant.values():
            for m in mlist:
                wms.add(m.expected_received_by)
        return sorted(wms)

    # -- 判定 ---------------------------------------------------------------
    def evaluate_event(self, event: Event, watermark: int, until: int,
                       ledger: ReadLedger | None = None) -> Evaluation:
        pages = list(self.pages_in(event.tenant, ledger))
        admin = self.admin_pages(ledger) if self._pages_by_tenant.get(ADMIN_TENANT) else []
        pages.extend(admin)
        manifest = list(self.manifest_in(event.tenant))
        if ledger is not None:
            ledger.evaluations += 1
        return evaluate(event, pages, manifest, watermark, until)

    def replay(self, tenant: str, event_id: str, at_watermark: int, until: int,
               ledger: ReadLedger | None = None) -> Evaluation:
        """以原接收水位重现历史判定。"""
        event = self.get_event(tenant, event_id, ledger)
        if event is None:
            raise KeyError(f"未知事件 {tenant}/{event_id}")
        return self.evaluate_event(event, at_watermark, until, ledger)

    # -- 范围化重算 ----------------------------------------------------------
    def _ensure_timeline(self) -> list[tuple[int, str, str]]:
        if self._timeline is None:
            self._timeline = sorted(
                ((e.occurred_at, e.tenant, e.event_id)
                 for evs in self._events_by_tenant.values() for e in evs),
                key=lambda x: (x[0], x[1], x[2]))
        return self._timeline

    def build_valid_time_index(self) -> int:
        """显式构建有效时间索引（非追加读取成本）。返回索引条目数。"""
        self._ensure_timeline()
        return len(self._timeline or [])

    def locate_scope_events(self, page: Page,
                            ledger: ReadLedger | None = None) -> set[tuple[str, str]]:
        """按一条租户级覆盖页的有效范围精确定位受影响事件。

        * 普通租户覆盖页：只覆盖该租户分区（租户隔离）。
        * 管理域（ADMIN_TENANT）覆盖页：按 occurred_at ∈ [scope_from, scope_to) 覆盖
          所有租户分区；用已建好的有效时间索引二分定位，只读取落范围的条目
          （真实读取计数 = 命中条目数）。
        """
        if page.event_id is not None:
            ev = self._event_index.get((page.tenant, page.event_id))
            if ev is None:
                return set()
            if ledger is not None:
                ledger.events_read += 1
            return {(ev.tenant, ev.event_id)}

        if page.scope_from is None or page.scope_to is None:
            return set()

        if page.tenant != ADMIN_TENANT:
            events = self._events_by_tenant.get(page.tenant, [])
            if ledger is not None:
                ledger.events_read += len(events)
            return {(e.tenant, e.event_id) for e in events if page.scope_covers(e.occurred_at)}

        timeline = self._ensure_timeline()
        lo = bisect.bisect_left(timeline, (page.scope_from, "", ""))
        hi = bisect.bisect_left(timeline, (page.scope_to, "", ""))
        hits = timeline[lo:hi]
        if ledger is not None:
            ledger.events_read += len(hits)
        return {(tenant, event_id) for (_t, tenant, event_id) in hits}
