"""数据模型：双时间轴证据、事件、判定结果与规范化序列化。

双时间轴（bitemporal）约定：
  * 有效时间（valid time）  : [eff_from, eff_to)  —— 记录在何时"生效"。
  * 事务时间（transaction）  : received_at        —— 记录在何时"被接收/入库"。
判定只在原接收水位 received_at <= watermark 的证据集合上进行，
因此历史片段可以用原水位精确重现（不被晚到记录改写）。

半开区间：在 t 生效当且仅当 eff_from <= t < eff_to；eff_to 处即失效。
所有时间使用整数秒，保证算术精确、无浮点。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import Enum

# 默认基线保留期：180 天。
RETENTION_SECONDS = 180 * 86400

# 管理域：以通配租户 "*" 承载的"组织级覆盖范围记录"（例如全机构范围的禁删令/政策
# 范围变更）。它按有效时间范围作用于所有租户分区的事件；除此之外任何页都不得跨租户。
ADMIN_TENANT = "*"


class Kind(str, Enum):
    APPROVAL = "APPROVAL"        # 签批（授权清退）
    HOLD = "HOLD"                # 禁删令（保留义务）
    REVOCATION = "REVOCATION"    # 一对一撤销（作用于某一条记录）


class Decision(str, Enum):
    RETAIN = "RETAIN"            # 该时刻不得清退
    ELIGIBLE = "ELIGIBLE"        # 该时刻可以清退
    UNPROVEN = "UNPROVEN"        # 缺页，无法证明（未证）


class Reason(str, Enum):
    HOLD = "HOLD_ACTIVE"             # 生效中的禁删令
    BASE_FLOOR = "BASE_FLOOR"        # 基线保留期未满
    APPROVED = "APPROVAL_ACTIVE"     # 生效中的签批
    NO_AUTH = "NO_AUTHORIZATION"     # 无生效签批（依赖台账完整）
    GAP = "MISSING_EVIDENCE"         # 缺页，基线之后不可证


def canonical(obj) -> str:
    """稳定、可复算的规范化 JSON 文本。"""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def digest_of(obj) -> str:
    return sha256_text(canonical(obj))


def commit_pages(pages) -> str:
    """对一组成员页的承诺：按 (seq, page_id) 排序后对关键字段取哈希。"""
    ordered = sorted(pages, key=lambda p: (p.seq, p.page_id))
    rows = [[p.page_id, p.content_hash, p.seq, p.received_at] for p in ordered]
    return digest_of(rows)


@dataclass(frozen=True)
class Event:
    """一条安全事件。tenant 决定分区归属；occurred_at 是它首次出现在有效时间轴上的时刻。"""
    tenant: str
    event_id: str
    occurred_at: int

    @property
    def key(self) -> str:
        return f"{self.tenant}/{self.event_id}"

    @property
    def base_end(self) -> int:
        return self.occurred_at + RETENTION_SECONDS

    def as_dict(self) -> dict:
        return {"tenant": self.tenant, "event_id": self.event_id,
                "occurred_at": self.occurred_at}

    @staticmethod
    def from_dict(d: dict) -> "Event":
        return Event(d["tenant"], d["event_id"], d["occurred_at"])


@dataclass(frozen=True)
class Page:
    """一页证据。签批 / 禁删令 / 撤销 都是一页。

    * event_id 非空：事件级页，只作用于该事件。
    * event_id 为空：租户级覆盖页，作用于 scope_from <= occurred_at < scope_to 的事件
      （压力场景的"覆盖范围变化"就是追加这样一页）。
    * 撤销页用 target_id 一对一指向被撤销页；跨租户撤销无效（分区天然隔离）。
    """

    page_id: str
    tenant: str
    event_id: str | None
    seq: int
    kind: Kind
    eff_from: int
    eff_to: int | None
    received_at: int
    target_id: str | None = None
    scope_from: int | None = None
    scope_to: int | None = None
    content_hash: str = field(default="")

    def __post_init__(self) -> None:
        if not self.content_hash:
            object.__setattr__(self, "content_hash", digest_of(self._payload()))

    def _payload(self) -> dict:
        return {
            "page_id": self.page_id,
            "tenant": self.tenant,
            "event_id": self.event_id,
            "seq": self.seq,
            "kind": self.kind.value,
            "eff_from": self.eff_from,
            "eff_to": self.eff_to,
            "received_at": self.received_at,
            "target_id": self.target_id,
            "scope_from": self.scope_from,
            "scope_to": self.scope_to,
        }

    def as_dict(self) -> dict:
        d = self._payload()
        d["content_hash"] = self.content_hash
        return d

    @staticmethod
    def from_dict(d: dict) -> "Page":
        return Page(
            page_id=d["page_id"], tenant=d["tenant"], event_id=d["event_id"],
            seq=d["seq"], kind=Kind(d["kind"]), eff_from=d["eff_from"],
            eff_to=d["eff_to"], received_at=d["received_at"],
            target_id=d.get("target_id"), scope_from=d.get("scope_from"),
            scope_to=d.get("scope_to"), content_hash=d.get("content_hash", ""),
        )

    def verify_hash(self) -> bool:
        return self.content_hash == digest_of(self._payload())

    def contains(self, t: int) -> bool:
        """半开有效区间 [eff_from, eff_to)；eff_to=None 表示到无穷。"""
        return self.eff_from <= t and (self.eff_to is None or t < self.eff_to)

    def scope_covers(self, occurred_at: int) -> bool:
        return (
            self.event_id is None
            and self.scope_from is not None
            and self.scope_to is not None
            and self.scope_from <= occurred_at < self.scope_to
        )


def page_id_event(tenant: str, event_id: str, seq: int) -> str:
    return f"{tenant}/{event_id}#{seq}"


def page_id_scope(tenant: str, scope_from: int, scope_to: int, seq: int) -> str:
    return f"{tenant}/*[{scope_from},{scope_to})#{seq}"


def parse_tenant(page_id: str) -> str | None:
    """page_id 以 '<tenant>/...' 命名空间化，用于在分区内识别跨租户引用。"""
    if "/" not in page_id:
        return None
    return page_id.split("/", 1)[0]


# 家族（family）= 同一条证据序列：同租户 + 同事件（或同覆盖范围）。
# 撤销必须与被撤销页处于同一家族；跨家族/跨租户的撤销一律无效。
Family = tuple[str, str | None, int | None, int | None]


def family_of(page: "Page") -> Family:
    return (page.tenant, page.event_id, page.scope_from, page.scope_to)


def family_from(event_id: str | None, tenant: str,
                scope_from: int | None, scope_to: int | None) -> Family:
    return (tenant, event_id, scope_from, scope_to)


def family_applies(fam: "Family", event: "Event") -> bool:
    tenant, event_id, scope_from, scope_to = fam
    # 管理域：仅当它是租户级覆盖页（event_id 为空且有范围）时，按有效范围作用于所有租户。
    if tenant == ADMIN_TENANT and event_id is None:
        if scope_from is None or scope_to is None:
            return False
        return scope_from <= event.occurred_at < scope_to
    # 普通租户：严格同租户隔离。
    if tenant != event.tenant:
        return False
    if event_id is not None:
        return event_id == event.event_id
    if scope_from is None or scope_to is None:
        return False
    return scope_from <= event.occurred_at < scope_to


def family_as_dict(fam: Family) -> dict:
    tenant, event_id, scope_from, scope_to = fam
    return {"tenant": tenant, "event_id": event_id,
            "scope_from": scope_from, "scope_to": scope_to}


def family_from_dict(d: dict) -> Family:
    return (d["tenant"], d.get("event_id"), d.get("scope_from"), d.get("scope_to"))


@dataclass(frozen=True)
class ManifestEntry:
    """清单承诺：某页本应在 expected_received_by 之内送达。

    只承诺 page_id 与 content_hash（不承诺内容属性），因此一旦缺页，
    其生效区间未知 —— 这正是"未证"的来源：缺页可能是禁删令，也可能是撤销。
    """
    page_id: str
    tenant: str
    event_id: str | None
    scope_from: int | None
    scope_to: int | None
    seq: int
    expected_content_hash: str
    expected_received_by: int

    @property
    def family(self) -> Family:
        return (self.tenant, self.event_id, self.scope_from, self.scope_to)

    def as_dict(self) -> dict:
        return {
            "page_id": self.page_id,
            "tenant": self.tenant,
            "event_id": self.event_id,
            "scope_from": self.scope_from,
            "scope_to": self.scope_to,
            "seq": self.seq,
            "expected_content_hash": self.expected_content_hash,
            "expected_received_by": self.expected_received_by,
        }

    @staticmethod
    def from_dict(d: dict) -> "ManifestEntry":
        return ManifestEntry(
            page_id=d["page_id"], tenant=d["tenant"], event_id=d.get("event_id"),
            scope_from=d.get("scope_from"), scope_to=d.get("scope_to"),
            seq=d["seq"], expected_content_hash=d["expected_content_hash"],
            expected_received_by=d["expected_received_by"],
        )


class MissingKind(str, Enum):
    MANIFEST_ABSENT = "MANIFEST_ABSENT"       # 清单承诺的页不在台账
    MANIFEST_MISMATCH = "MANIFEST_MISMATCH"   # 台账中该页哈希与清单不符（被篡改）
    SEQ_GAP = "SEQ_GAP"                       # 家族内序号断档 ⇒ 页丢失
    DANGLING_TARGET = "DANGLING_TARGET"       # 撤销指向了本租户内不存在的页


@dataclass(frozen=True)
class MissingEvidence:
    """一条可独立复核的缺页证据。"""
    kind: MissingKind
    family: Family
    detail: dict

    def as_dict(self) -> dict:
        return {"kind": self.kind.value,
                "family": family_as_dict(self.family),
                "detail": self.detail}

    @staticmethod
    def from_dict(d: dict) -> "MissingEvidence":
        return MissingEvidence(MissingKind(d["kind"]),
                               family_from_dict(d["family"]), d["detail"])
