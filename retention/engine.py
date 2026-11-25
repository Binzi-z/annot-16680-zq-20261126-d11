"""判定内核：在固定接收水位下，对事件时间轴切出最少决策片段。

一页证据的"家族"（family）由 (tenant, event_id, scope_from, scope_to) 决定：
  * 事件级页 event_id 非空，只作用于该事件；scope 字段为 None。
  * 租户覆盖页 event_id 为空，作用于 scope_from <= occurred_at < scope_to 的事件。
一页只可能被"家族适用"的事件收集（family_applies），天然做到租户隔离。

规则（按优先级，全部可从公开证据独立复核）：
  1. t 早于基线保留期终点                    → RETAIN  (BASE_FLOOR)  —— 无条件，缺页推不翻
  2. t 不早于基线终点，且适用证据族存在缺页  → UNPROVEN（缺页可能是隐藏禁删令，也可能是
     撤销某生效页；故基线后既不能证保留、也不能证可清退）
  3. 生效禁删令覆盖 t                        → RETAIN  (HOLD_ACTIVE)
  4. 生效签批覆盖 t                          → ELIGIBLE(APPROVAL_ACTIVE)
  5. 其余（已过基线、无令无签批、无缺页）    → ELIGIBLE(NO_AUTHORIZATION)

撤销一对一：一页 REVOCATION 只作用于同族、kind 为 APPROVAL/HOLD 的目标页；
指向 REVOCATION、跨租户或跨族的撤销一律无效并记为 finding（无环，良基）。

所有时间半开：生效当且仅当 eff_from <= t < eff_to；eff_to 处即失效。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .model import (
    Decision, Event, Kind, ManifestEntry, MissingEvidence, MissingKind, Page,
    Reason, family_applies, family_of, parse_tenant,
)


@dataclass(frozen=True)
class Segment:
    start: int
    end: int
    decision: Decision
    reason: Reason

    @property
    def length(self) -> int:
        return self.end - self.start

    def as_dict(self) -> dict:
        return {"start": self.start, "end": self.end,
                "decision": self.decision.value, "reason": self.reason.value}

    @staticmethod
    def from_dict(d: dict) -> "Segment":
        return Segment(d["start"], d["end"], Decision(d["decision"]), Reason(d["reason"]))

    def covers(self, t: int) -> bool:
        return self.start <= t < self.end


@dataclass
class Evaluation:
    """一次 (event, watermark, horizon) 判定的完整结果。

    片段按"判定"合并（最少决策片段）；单点"理由"由 point_decision 现算，
    因此不会因跨理由合并而张冠李戴。
    """
    event: Event
    watermark: int
    until: int
    segments: list[Segment]
    evidence_pages: list[Page]     # 参与判定的页快照（gathered）
    manifest: list[ManifestEntry]  # 适用族内的清单条目
    missing: list[MissingEvidence]
    findings: list[dict]
    active_pages: list[Page] = field(default_factory=list)
    has_gap: bool = False

    def decision_at(self, t: int) -> Segment:
        for s in self.segments:
            if s.covers(t):
                return s
        raise ValueError(f"t={t} 不在判定窗口 [{self.event.occurred_at},{self.until}) 内")

    def point_decision(self, t: int) -> tuple[Decision, Reason]:
        """该时刻的真实判定与理由（用当前水位、生效页与缺页状态现算）。"""
        if not (self.event.occurred_at <= t < self.until):
            raise ValueError(f"t={t} 不在判定窗口 [{self.event.occurred_at},{self.until}) 内")
        return decision_at(t, self.event, self.active_pages, self.has_gap)


def _gather(event: Event, pages: list[Page], watermark: int) -> list[Page]:
    """接收水位内、家族适用于该事件的页（含撤销页）。"""
    return [p for p in pages
            if p.received_at <= watermark and family_applies(family_of(p), event)]


def _resolve_revocations(subject: list[Page], revs: list[Page]) -> tuple[list[Page], list[dict]]:
    """计算未被有效撤销的 APPROVAL/HOLD 页。返回 (active, findings)。

    subject = 非撤销页（APPROVAL/HOLD）；revs = 撤销页。
    目标页在 subject ∪ revs 中查找，从而既能识别"撤销撤销"并判其无效，
    也能识别指向缺失页的悬空撤销（留给缺页判定）。
    """
    findings: list[dict] = []
    revoked: set[str] = set()
    all_pages = list(subject) + list(revs)
    by_id = {p.page_id: p for p in all_pages}
    for rev in revs:
        if rev.target_id is None:
            findings.append({"code": "REVOCATION_NO_TARGET", "page_id": rev.page_id})
            continue
        owner = parse_tenant(rev.target_id)
        if owner is not None and owner != rev.tenant:
            findings.append({"code": "REVOCATION_CROSS_TENANT", "page_id": rev.page_id,
                             "target_id": rev.target_id, "target_tenant": owner})
            continue
        target = by_id.get(rev.target_id)
        if target is None:
            findings.append({"code": "REVOCATION_TARGET_UNRESOLVED",
                             "page_id": rev.page_id, "target_id": rev.target_id})
            continue
        if target.kind == Kind.REVOCATION:
            findings.append({"code": "REVOCATION_OF_REVOCATION",
                             "page_id": rev.page_id, "target_id": rev.target_id})
            continue
        if family_of(target) != family_of(rev):
            findings.append({"code": "REVOCATION_CROSS_FAMILY",
                             "page_id": rev.page_id, "target_id": rev.target_id})
            continue
        revoked.add(target.page_id)
    active = [p for p in subject if p.page_id not in revoked]
    return active, findings


def _collect_missing(event: Event, gathered: list[Page],
                     manifest_entries: list[ManifestEntry], watermark: int) -> list[MissingEvidence]:
    """在适用范围内、接收水位内应到而缺失的证据。"""
    missing: list[MissingEvidence] = []
    present_ids = {p.page_id for p in gathered}
    applicable_manifest = [m for m in manifest_entries
                           if m.expected_received_by <= watermark
                           and family_applies(m.family, event)]
    for m in applicable_manifest:
        if m.page_id not in present_ids:
            missing.append(MissingEvidence(
                MissingKind.MANIFEST_ABSENT, m.family,
                {"page_id": m.page_id, "seq": m.seq,
                 "expected_content_hash": m.expected_content_hash,
                 "expected_received_by": m.expected_received_by}))
            continue
        p = next(p for p in gathered if p.page_id == m.page_id)
        if p.content_hash != m.expected_content_hash:
            missing.append(MissingEvidence(
                MissingKind.MANIFEST_MISMATCH, m.family,
                {"page_id": m.page_id, "seq": m.seq,
                 "expected_content_hash": m.expected_content_hash,
                 "actual_content_hash": p.content_hash}))

    # 序号断档：家族内部（首个已见 seq 与最大 seq 之间）缺号且清单未登记 ⇒ 页丢失。
    # 不做"从 0 起"的推断：若整族首页就缺失，无清单则无法证明它曾存在，不臆断。
    manifest_ids = {m.page_id for m in applicable_manifest}
    fam_pages: dict[tuple, list[Page]] = {}
    for p in gathered:
        fam_pages.setdefault(family_of(p), []).append(p)
    for fam, plist in fam_pages.items():
        lo = min(p.seq for p in plist)
        hi = max(p.seq for p in plist)
        have = {p.seq for p in plist}
        for s in range(lo, hi + 1):
            if s in have:
                continue
            covered = any(m.seq == s and m.family == fam for m in applicable_manifest)
            if covered:
                continue
            missing.append(MissingEvidence(
                MissingKind.SEQ_GAP, fam, {"missing_seq": s, "min_seq": lo, "max_seq": hi}))

    # 撤销指向本家族内不存在、且清单未登记的目标 ⇒ 目标页丢失。
    for rev in gathered:
        if rev.kind != Kind.REVOCATION or rev.target_id is None:
            continue
        if rev.target_id in present_ids or rev.target_id in manifest_ids:
            continue
        owner = parse_tenant(rev.target_id)
        if owner is not None and owner != rev.tenant:
            continue  # 跨租户冲突已作为 finding，不记为缺页
        missing.append(MissingEvidence(
            MissingKind.DANGLING_TARGET, family_of(rev),
            {"page_id": rev.page_id, "target_id": rev.target_id}))
    return missing


def decision_at(t: int, event: Event, active: list[Page],
                has_gap: bool) -> tuple[Decision, Reason]:
    """单点判定（无分段），供边界求值与验证器共用。

    顺序即语义优先级：
      1) 法定基线内                  → RETAIN/BASE_FLOOR（无条件；缺页也推不翻）
      2) 存在缺页                    → UNPROVEN/GAP（缺页可能是禁删令、也可能是
         撤销某生效页，故基线后既不能证保留、也不能证可清退）
      3) 生效禁删令                  → RETAIN/HOLD
      4) 生效签批                    → ELIGIBLE/APPROVED
      5) 其余                        → ELIGIBLE/NO_AUTH
    """
    if t < event.base_end:
        return Decision.RETAIN, Reason.BASE_FLOOR
    if has_gap:
        return Decision.UNPROVEN, Reason.GAP
    if any(p.kind == Kind.HOLD and p.contains(t) for p in active):
        return Decision.RETAIN, Reason.HOLD
    if any(p.kind == Kind.APPROVAL and p.contains(t) for p in active):
        return Decision.ELIGIBLE, Reason.APPROVED
    return Decision.ELIGIBLE, Reason.NO_AUTH


def _boundaries(event: Event, active: list[Page], until: int) -> list[int]:
    pts = {event.occurred_at, until}
    if event.occurred_at <= event.base_end <= until:
        pts.add(event.base_end)          # 基线终点落在窗口内才切
    for p in active:
        for b in (p.eff_from, p.eff_to):
            if b is not None and event.occurred_at <= b <= until:
                pts.add(b)
    return sorted(pts)


def evaluate(event: Event, pages: list[Page], manifest_entries: list[ManifestEntry],
             watermark: int, until: int) -> Evaluation:
    if until <= event.occurred_at:
        raise ValueError("until 必须晚于 occurred_at")
    gathered = _gather(event, pages, watermark)
    subject = [p for p in gathered if p.kind != Kind.REVOCATION]
    revs = [p for p in gathered if p.kind == Kind.REVOCATION]
    active, findings = _resolve_revocations(subject, revs)
    missing = _collect_missing(event, gathered, manifest_entries, watermark)
    has_gap = bool(missing)

    boundaries = _boundaries(event, active, until)
    segs: list[Segment] = []
    for a, b in zip(boundaries, boundaries[1:]):
        dec, reason = decision_at(a, event, active, has_gap)
        if segs and segs[-1].decision == dec and segs[-1].end == a:
            segs[-1] = Segment(segs[-1].start, b, dec, segs[-1].reason)
        else:
            segs.append(Segment(a, b, dec, reason))

    applicable_manifest = [m for m in manifest_entries
                           if m.expected_received_by <= watermark
                           and family_applies(m.family, event)]
    return Evaluation(event=event, watermark=watermark, until=until, segments=segs,
                      evidence_pages=gathered, manifest=applicable_manifest,
                      missing=missing, findings=findings,
                      active_pages=active, has_gap=has_gap)
