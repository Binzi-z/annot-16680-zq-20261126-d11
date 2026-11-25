"""场景：三个验收反例 + 六万租户分区压力（覆盖范围变化、真实读取计数、旧报告保原值）。

时间基准（对理解"有效期前后相等"很关键）：
  DAY = 86400 秒；事件发生于 occurred_at；基线保留期 180 天 ⇒ base_end = occurred_at + 180d。
  半开区间：t == base_end 处基线已结束，即可清退（"有效期前后相等"两侧各自正确）。
"""

from __future__ import annotations

import hashlib

from .certificate import build_certificate, verify_certificate
from .engine import Evaluation
from .model import (
    ADMIN_TENANT, Decision, Event, Kind, ManifestEntry, Page, Reason,
    page_id_event, page_id_scope,
)
from .store import PartitionStore, ReadLedger

DAY = 86400


# ===========================================================================
# 反例一：有效期前后相等（半开区间边界）
# ===========================================================================

def reversal_boundary_equal() -> dict:
    """事件发生在 t0；在 base_end-1 处应 RETAIN(BASE_FLOOR)，在 base_end 处应 ELIGIBLE。

    两侧"相等"指：判据 `t < base_end` 恰在端点翻转；同一时刻点在两个先后水位下
    判定一致，不做四舍五入、不因晚到记录漂移。
    """
    t0 = 1_000 * DAY
    tenant = "acme"
    e = Event(tenant, "E-boundary", t0)
    store = PartitionStore()
    store.put_event(e)
    # 一页永久签批（覆盖到窗口末端），水位很晚：基线之后应可清退。
    p = Page(page_id=page_id_event(tenant, e.event_id, 0), tenant=tenant,
             event_id=e.event_id, seq=0, kind=Kind.APPROVAL,
             eff_from=t0, eff_to=None, received_at=t0 + 1 * DAY)
    store.append_page(p)

    wm = t0 + 200 * DAY
    until = t0 + 400 * DAY
    ev: Evaluation = store.evaluate_event(e, wm, until)
    assert len(ev.segments) == 2, [s.as_dict() for s in ev.segments]

    t_before = e.base_end - 1
    t_at = e.base_end
    dec_before, reason_before = ev.point_decision(t_before)
    dec_at, reason_at = ev.point_decision(t_at)
    assert (dec_before, reason_before) == (Decision.RETAIN, Reason.BASE_FLOOR)
    assert (dec_at, reason_at) == (Decision.ELIGIBLE, Reason.APPROVED)

    # 证书在两端各自正确、且可独立复核
    cert_before = build_certificate(ev, t_before)
    cert_at = build_certificate(ev, t_at)
    ok_before = verify_certificate(cert_before)
    ok_at = verify_certificate(cert_at)
    assert ok_before.ok and ok_at.ok

    # 同一时刻自洽：base_end 不早于自身 ⇒ 不保留
    assert e.base_end - 1 < e.base_end and not (e.base_end < e.base_end)

    return {
        "name": "boundary_equal",
        "event": e.as_dict(),
        "segments": [s.as_dict() for s in ev.segments],
        "at_minus_1": {"t": t_before, "decision": dec_before.value, "reason": reason_before.value,
                       "cert_ok": ok_before.ok},
        "at_base_end": {"t": t_at, "decision": dec_at.value, "reason": reason_at.value,
                        "cert_ok": ok_at.ok},
    }


# ===========================================================================
# 反例二：晚到令（late-arriving hold）—— 原水位重现 vs 新水位改判
# ===========================================================================

def reversal_late_order() -> dict:
    """历史片段在旧水位 W_old 下已判 ELIGIBLE 并交付；一条更早生效的禁删令
    在 W_new（更晚）才送达。用旧水位重现必须保持 ELIGIBLE；用新水位则改判 RETAIN。
    """
    t0 = 10 * DAY
    tenant = "beta"
    e = Event(tenant, "E-late", t0)
    store = PartitionStore()
    store.put_event(e)
    # 签批（永久），早到
    ap = Page(page_id=page_id_event(tenant, e.event_id, 0), tenant=tenant,
              event_id=e.event_id, seq=0, kind=Kind.APPROVAL,
              eff_from=t0, eff_to=None, received_at=t0 + 1 * DAY)
    store.append_page(ap)
    # 晚到的禁删令：有效区间从更早开始（eff_from < t0），但 received_at 很晚（晚到）
    hold_eff_from = t0 - 2 * DAY
    hold = Page(page_id=page_id_event(tenant, e.event_id, 1), tenant=tenant,
                event_id=e.event_id, seq=1, kind=Kind.HOLD,
                eff_from=hold_eff_from, eff_to=None, received_at=t0 + 300 * DAY)
    store.append_page(hold)

    w_old = t0 + 250 * DAY          # 禁删令尚未到达
    w_new = t0 + 350 * DAY          # 禁删令已到达
    until = t0 + 500 * DAY
    at = t0 + 280 * DAY             # 已交付的历史片段所咨询的时刻

    ev_old = store.replay(tenant, e.event_id, w_old, until)
    ev_new = store.replay(tenant, e.event_id, w_new, until)

    d_old = ev_old.point_decision(at)
    d_new = ev_new.point_decision(at)
    assert d_old == (Decision.ELIGIBLE, Reason.APPROVED), d_old
    assert d_new == (Decision.RETAIN, Reason.HOLD), d_new

    c_old = build_certificate(ev_old, at)
    c_new = build_certificate(ev_new, at)
    ok_old = verify_certificate(c_old)
    ok_new = verify_certificate(c_new)
    assert ok_old.ok and ok_new.ok
    # 旧证书的证据快照里绝不能出现晚到的禁删令
    assert all(p["page_id"] != hold.page_id for p in c_old["evidence"])

    return {
        "name": "late_order",
        "w_old": w_old, "w_new": w_new, "at": at,
        "historical_replay": {"decision": d_old[0].value, "reason": d_old[1].value,
                              "cert_ok": ok_old.ok,
                              "late_hold_present": False},
        "current": {"decision": d_new[0].value, "reason": d_new[1].value,
                    "cert_ok": ok_new.ok, "late_hold_present": True},
    }


# ===========================================================================
# 反例三：跨租户冲突（cross-tenant revocation / collision）
# ===========================================================================

def reversal_cross_tenant() -> dict:
    """租户 A 的撤销试图指向租户 B 的页；A 的审批与 B 的审批都会被提及。

    期望：跨租户撤销无效（A、B 的签批均仍生效），两租户判定互不干扰；
    且同名事件在不同租户下互不串台。
    """
    t0 = 10 * DAY
    store = PartitionStore()
    ev_a = Event("A", "E1", t0)
    ev_b = Event("B", "E1", t0)       # 同名事件、不同租户 ⇒ 必须互不干扰
    store.put_event(ev_a)
    store.put_event(ev_b)

    ap_a = Page(page_id=page_id_event("A", "E1", 0), tenant="A", event_id="E1", seq=0,
                kind=Kind.APPROVAL, eff_from=t0, eff_to=None, received_at=t0 + 1 * DAY)
    ap_b = Page(page_id=page_id_event("B", "E1", 0), tenant="B", event_id="E1", seq=0,
                kind=Kind.APPROVAL, eff_from=t0, eff_to=None, received_at=t0 + 1 * DAY)
    # 恶意/错误撤销：写在 A 的分区里，却指向 B 的页（跨租户冲突）
    evil_rev = Page(page_id=page_id_event("A", "E1", 1), tenant="A", event_id="E1", seq=1,
                    kind=Kind.REVOCATION, eff_from=t0, eff_to=None,
                    received_at=t0 + 2 * DAY, target_id=ap_b.page_id)
    store.append_page(ap_a)
    store.append_page(ap_b)
    store.append_page(evil_rev)

    wm = t0 + 400 * DAY
    until = t0 + 500 * DAY
    at = t0 + 200 * DAY
    evA = store.replay("A", "E1", wm, until)
    evB = store.replay("B", "E1", wm, until)

    # A：跨租户撤销无效 ⇒ 自己的签批仍在，并被记为 finding
    assert any(f["code"] == "REVOCATION_CROSS_TENANT" for f in evA.findings), evA.findings
    assert any(p.page_id == ap_a.page_id for p in evA.active_pages)
    dA = evA.point_decision(at)
    assert dA == (Decision.ELIGIBLE, Reason.APPROVED), dA

    # B：完全不受 A 的证据影响；B 的签批未被撤销 ⇒ ELIGIBLE(APPROVED)
    assert all(p.tenant in ("B",) for p in evB.evidence_pages)
    dB = evB.point_decision(at)
    assert dB == (Decision.ELIGIBLE, Reason.APPROVED), dB

    cA = build_certificate(evA, at)
    cB = build_certificate(evB, at)
    vrA, vrB = verify_certificate(cA), verify_certificate(cB)
    assert vrA.ok and vrB.ok, (vrA.errors, vrB.errors)
    assert all(p["tenant"] == "B" for p in cB["evidence"])
    assert all(p["tenant"] == "A" for p in cA["evidence"])

    return {
        "name": "cross_tenant",
        "tenant_A": {"decision": dA[0].value, "reason": dA[1].value,
                     "findings": evA.findings, "cert_ok": vrA.ok},
        "tenant_B": {"decision": dB[0].value, "reason": dB[1].value,
                     "cert_ok": vrB.ok,
                     "evidence_tenants": sorted({p["tenant"] for p in cB["evidence"]})},
    }


# ===========================================================================
# 未证缺页证明（缺页导致不可证）
# ===========================================================================

def unproven_missing_page() -> dict:
    """清单承诺一页却缺失；基线之后该事件无法被证明可否清退 ⇒ UNPROVEN 证明。"""
    t0 = 10 * DAY
    tenant = "gamma"
    e = Event(tenant, "E-gap", t0)
    store = PartitionStore()
    store.put_event(e)
    ap = Page(page_id=page_id_event(tenant, e.event_id, 0), tenant=tenant,
              event_id=e.event_id, seq=0, kind=Kind.APPROVAL,
              eff_from=t0, eff_to=None, received_at=t0 + 1 * DAY)
    store.append_page(ap)
    # 清单承诺 seq=1 的页应到，但它缺失（可能是隐藏禁删令）
    missing_hash = hashlib.sha256(b"promised page that never arrived").hexdigest()
    m = ManifestEntry(page_id=page_id_event(tenant, e.event_id, 1), tenant=tenant,
                      event_id=e.event_id, scope_from=None, scope_to=None, seq=1,
                      expected_content_hash=missing_hash, expected_received_by=t0 + 5 * DAY)
    store.append_manifest(m)

    wm = t0 + 400 * DAY
    until = t0 + 500 * DAY
    ev = store.evaluate_event(e, wm, until)
    at_in = e.base_end - 1
    at_out = e.base_end + 1
    # 基线内：缺页推不翻法定保留
    assert ev.point_decision(at_in) == (Decision.RETAIN, Reason.BASE_FLOOR)
    # 基线外：缺页 ⇒ UNPROVEN
    assert ev.point_decision(at_out) == (Decision.UNPROVEN, Reason.GAP)

    cert = build_certificate(ev, at_out)
    assert cert["kind"] == "UNPROVEN_PROOF"
    vr = verify_certificate(cert, trusted_manifest=store.manifest_in(tenant))
    assert vr.ok, vr.errors
    # 缺页证据可复核
    assert any(mm.kind.value == "MANIFEST_ABSENT" for mm in ev.missing)

    return {"name": "unproven_missing", "kind": cert["kind"],
            "at_out": at_out, "verdict": cert["verdict"],
            "missing": cert["missing"], "verify_ok": vr.ok}


# ===========================================================================
# 压力场景：六万租户分区 + 覆盖范围变化 + 真实读取计数 + 旧报告保原值
# ===========================================================================

TENANTS = 60_000
STEP = 2000                     # 相邻租户事件的有效时间间隔（秒），使事件沿时间均匀铺开
SCOPE_FROM = 0
SCOPE_TO = 60 * DAY             # 覆盖 occurred_at ∈ [0,60d) 的事件
EXPECTED_AFFECTED = SCOPE_TO // STEP                      # 2592
EXPECTED_PRESERVED = TENANTS - EXPECTED_AFFECTED          # 57408
MAX_OCCURRED = (TENANTS - 1) * STEP                       # 119998000
AT = MAX_OCCURRED + 200 * DAY                             # 所有事件均已过基线后的统一咨询时刻
UNTIL = AT + 365 * DAY
WM_BASE = MAX_OCCURRED + 10 * DAY                         # 旧报告水位（覆盖记录未到）
SCOPE_RECEIVED = WM_BASE + 50 * DAY                       # 覆盖范围变化的送达水位
WM_NEW = SCOPE_RECEIVED + 10 * DAY


def stress_sixty_thousand() -> dict:
    """六万租户分区事件，追加"一条"管理域覆盖范围变化，证明只重算相关范围。

    设计：
      * 每租户 1 个事件，occurred_at = i * STEP，沿有效时间均匀铺开（60k 分区 / 60k 事件）。
      * 每事件一页永久签批（早到）。旧报告在统一咨询时刻 AT（全部事件均已过基线）
        均为 ELIGIBLE(window 内无禁删令)。
      * 追加唯一一条管理域记录：禁删令在有效时间恒生效(eff=[0,+inf))，但作用范围仅
        覆盖 occurred_at ∈ [0,60d) 的事件(scope_from/scope_to)。故只改判范围内事件。

    证明：
      1) 实际读取计数：借有效时间索引二分定位范围，只读/重算落范围的事件；
         朴素全量需重算全部 60k 事件——两者读取计数直接在输出中对比。
      2) 旧报告保原值：范围外旧报告判定不变，数量精确核对为 EXPECTED_PRESERVED。
    """
    store = PartitionStore()
    for i in range(TENANTS):
        tenant = f"t{i:05d}"
        occ = i * STEP
        store.put_event(Event(tenant, "E", occ))
        store.append_page(Page(page_id=page_id_event(tenant, "E", 0), tenant=tenant,
                               event_id="E", seq=0, kind=Kind.APPROVAL,
                               eff_from=occ, eff_to=None, received_at=occ + 1 * DAY))

    # 旧报告：全量事件在旧水位、统一咨询时刻 AT 出判定（均为 ELIGIBLE）。
    old: dict[tuple[str, str], str] = {}
    for tenant, evs in store._events_by_tenant.items():
        for e in evs:
            old[(tenant, e.event_id)] = (
                store.evaluate_event(e, WM_BASE, UNTIL).point_decision(AT)[0].value)
    assert set(old.values()) == {Decision.ELIGIBLE.value}, "旧报告应全为 ELIGIBLE"

    # 有效时间索引在初始全量阶段构建并随台账维护；增量阶段不计为读取成本。
    index_size = store.build_valid_time_index()
    assert index_size == TENANTS

    total_partitions = len(store._pages_by_tenant)
    total_events = sum(len(v) for v in store._events_by_tenant.values())

    # 追加唯一一条管理域覆盖范围记录（有效时间恒生效，作用范围限定 [0,60d)）。
    ledger = ReadLedger()
    scope_page = Page(page_id=page_id_scope(ADMIN_TENANT, SCOPE_FROM, SCOPE_TO, 0),
                      tenant=ADMIN_TENANT, event_id=None, seq=0, kind=Kind.HOLD,
                      eff_from=0, eff_to=None, received_at=SCOPE_RECEIVED,
                      scope_from=SCOPE_FROM, scope_to=SCOPE_TO)
    store.append_page(scope_page)
    affected_keys = store.locate_scope_events(scope_page, ledger)

    # 只重算受影响事件（真实读取计数）；范围外旧报告保留原值，绝不重算。
    new: dict[tuple[str, str], str] = {}
    for tenant, event_id in affected_keys:
        e = store.get_event(tenant, event_id, ledger)
        new[(tenant, event_id)] = (
            store.evaluate_event(e, WM_NEW, UNTIL, ledger).point_decision(AT)[0].value)

    changed = sum(1 for k in affected_keys if new[k] != old[k])
    preserved = sum(1 for k in old if k not in affected_keys)

    assert len(affected_keys) == EXPECTED_AFFECTED, (len(affected_keys), EXPECTED_AFFECTED)
    assert preserved == EXPECTED_PRESERVED, (preserved, EXPECTED_PRESERVED)
    assert changed == EXPECTED_AFFECTED, changed
    for key in affected_keys:
        assert old[key] == Decision.ELIGIBLE.value, (key, old[key])
        assert new[key] == Decision.RETAIN.value, (key, new[key])
    assert preserved + changed == total_events
    assert ledger.evaluations == EXPECTED_AFFECTED

    # 独立复核"保原值"：抽取范围外样本，在新水位重新判定，必须仍等于旧值。
    preserved_keys = [k for k in old if k not in affected_keys]
    sample = preserved_keys[::max(1, len(preserved_keys) // 200)][:200]
    for tenant, event_id in sample:
        e = store.get_event(tenant, event_id)
        now = store.evaluate_event(e, WM_NEW, UNTIL).point_decision(AT)[0].value
        assert now == old[(tenant, event_id)], (tenant, event_id, now, old[(tenant, event_id)])
    assert all(old[k] == Decision.ELIGIBLE.value for k in sample)

    events_read = ledger.events_read        # 定位(仅范围内) + 逐事件取事件
    pages_read = ledger.pages_read          # 仅受影响事件所属分区(租户页+管理域页)
    total_reads = events_read + pages_read
    # 精确读取计数：定位 affected 条 + 取事件 affected 条 + 每事件 2 页(租户1+管理域1)。
    assert events_read == EXPECTED_AFFECTED * 2, events_read
    assert pages_read == EXPECTED_AFFECTED * 2, pages_read

    # 朴素全量重算：重算全部 60k 事件，每事件取事件 1 次 + 读 2 页。
    naive_evaluations = TENANTS
    naive_reads = TENANTS + TENANTS * 2
    ratio = total_reads / naive_reads

    assert total_reads < naive_reads

    return {
        "name": "stress_60k",
        "partitions": total_partitions,
        "events": total_events,
        "appended_scope_records": 1,
        "scope": {"tenant": ADMIN_TENANT,
                  "eff": [0, None], "covers_occurred_at": [SCOPE_FROM, SCOPE_TO]},
        "affected_events": len(affected_keys),
        "read_counts": {
            "events_read": events_read, "pages_read": pages_read,
            "partitions_touched": ledger.partitions_touched,
            "evaluations": ledger.evaluations, "total_reads": total_reads,
        },
        "naive_full_recompute": {"evaluations": naive_evaluations, "reads": naive_reads},
        "read_ratio_vs_naive": round(ratio, 4),
        "index_note": "有效时间索引为一次性 O(事件数) 结构构建，非追加读取成本；"
                      "查询用二分，只读取落范围条目。",
        "old_reports_preserved": preserved,
        "old_reports_changed": changed,
        "assertions": {
            "affected_only": len(affected_keys) == EXPECTED_AFFECTED,
            "reads_below_naive": total_reads < naive_reads,
            "read_counts_exact": (events_read == EXPECTED_AFFECTED * 2 and
                                  pages_read == EXPECTED_AFFECTED * 2),
            "old_preserved_exact": preserved == EXPECTED_PRESERVED,
            "preserved_plus_changed_is_all": preserved + changed == total_events,
            "affected_all_flipped": changed == EXPECTED_AFFECTED,
        },
    }


ALL_SCENARIOS = {
    "boundary_equal": reversal_boundary_equal,
    "late_order": reversal_late_order,
    "cross_tenant": reversal_cross_tenant,
    "unproven_missing": unproven_missing_page,
    "stress_60k": stress_sixty_thousand,
}
