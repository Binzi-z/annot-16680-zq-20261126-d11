"""标准库 unittest 测试套件（零第三方依赖）。

运行：  python -m unittest discover -s tests -v
或：    python -m unittest tests.test_retention -v

覆盖：三个验收反例 + 未证缺页 + 六万分区压力；并直接验证内核规则
（半开边界、最少片段合并、一对一撤销及无效撤销、晚到记录的历史重现、
 缺页未证、跨租户隔离、证书封条篡改检测、证书与独立台账快照核对）。
"""

from __future__ import annotations

import copy
import json
import unittest

from retention.certificate import (
    CERT_UNPROVEN, build_certificate, verify_certificate,
)
from retention.engine import evaluate
from retention.model import (
    Decision, Event, Kind, ManifestEntry, Page, Reason,
    canonical, page_id_event, sha256_text, RETENTION_SECONDS,
)
from retention.scenarios import (
    ALL_SCENARIOS, reversal_boundary_equal, reversal_cross_tenant,
    reversal_late_order, stress_sixty_thousand, unproven_missing_page,
    EXPECTED_AFFECTED, EXPECTED_PRESERVED, TENANTS,
)

DAY = 86400


def ev(event, pages, manifest=(), wm=None, until=None):
    wm = wm if wm is not None else event.occurred_at + 10_000 * DAY
    until = until if until is not None else event.occurred_at + RETENTION_SECONDS + 100 * DAY
    return evaluate(event, list(pages), list(manifest), wm, until)


class KernelRules(unittest.TestCase):
    def test_base_floor_half_open(self):
        e = Event("T", "E", 0)
        evl = ev(e, [])
        self.assertEqual(evl.point_decision(e.base_end - 1), (Decision.RETAIN, Reason.BASE_FLOOR))
        self.assertEqual(evl.point_decision(e.base_end), (Decision.ELIGIBLE, Reason.NO_AUTH))
        self.assertEqual(len(evl.segments), 2)

    def test_hold_wins_over_approval(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        hold = Page(page_id_event("T", "E", 1), "T", "E", 1, Kind.HOLD, 0, None, 1)
        evl = ev(e, [ap, hold])
        self.assertEqual(evl.point_decision(e.base_end + 5), (Decision.RETAIN, Reason.HOLD))

    def test_eff_to_exclusive(self):
        e = Event("T", "E", 0)
        hold = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.HOLD,
                    0, e.base_end + 10 * DAY, 1)
        ap = Page(page_id_event("T", "E", 1), "T", "E", 1, Kind.APPROVAL, e.base_end, None, 1)
        evl = ev(e, [hold, ap])
        self.assertEqual(
            evl.point_decision(e.base_end + 10 * DAY - 1), (Decision.RETAIN, Reason.HOLD))
        self.assertEqual(
            evl.point_decision(e.base_end + 10 * DAY), (Decision.ELIGIBLE, Reason.APPROVED))

    def test_minimal_segment_merging(self):
        e = Event("T", "E", 0)
        h1 = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.HOLD, 0, 100 * DAY, 1)
        h2 = Page(page_id_event("T", "E", 1), "T", "E", 1, Kind.HOLD, 100 * DAY, None, 1)
        evl = ev(e, [h1, h2])
        self.assertEqual(len(evl.segments), 1)
        self.assertEqual(evl.segments[0].decision, Decision.RETAIN)

    def test_one_to_one_revocation(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        rev = Page(page_id_event("T", "E", 1), "T", "E", 1, Kind.REVOCATION,
                   0, None, 2, target_id=ap.page_id)
        evl = ev(e, [ap, rev])
        self.assertFalse(any(p.page_id == ap.page_id for p in evl.active_pages))
        self.assertEqual(evl.point_decision(e.base_end + 5), (Decision.ELIGIBLE, Reason.NO_AUTH))

    def test_revocation_of_revocation_invalid(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        rev = Page(page_id_event("T", "E", 1), "T", "E", 1, Kind.REVOCATION,
                   0, None, 2, target_id=ap.page_id)
        rev2 = Page(page_id_event("T", "E", 2), "T", "E", 2, Kind.REVOCATION,
                    0, None, 3, target_id=rev.page_id)
        evl = ev(e, [ap, rev, rev2])
        self.assertTrue(any(f["code"] == "REVOCATION_OF_REVOCATION" for f in evl.findings))
        # 撤销撤销无效：签批仍被撤销 ⇒ 无授权
        self.assertEqual(evl.point_decision(e.base_end + 5), (Decision.ELIGIBLE, Reason.NO_AUTH))

    def test_late_hold_visibility(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        hold = Page(page_id_event("T", "E", 1), "T", "E", 1, Kind.HOLD, -5 * DAY, None, 300 * DAY)
        old = ev(e, [ap, hold], wm=200 * DAY)
        new = ev(e, [ap, hold], wm=400 * DAY)
        self.assertEqual(old.point_decision(e.base_end + 50 * DAY)[0], Decision.ELIGIBLE)
        self.assertEqual(new.point_decision(e.base_end + 50 * DAY)[0], Decision.RETAIN)

    def test_missing_manifest_unproven_after_base(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        m = ManifestEntry(page_id_event("T", "E", 1), "T", "E", None, None, 1,
                          "deadbeef" * 8, 5 * DAY)
        evl = ev(e, [ap], [m])
        self.assertEqual(evl.point_decision(e.base_end - 1)[0], Decision.RETAIN)
        self.assertEqual(evl.point_decision(e.base_end + 1), (Decision.UNPROVEN, Reason.GAP))
        cert = build_certificate(evl, e.base_end + 1)
        self.assertEqual(cert["kind"], CERT_UNPROVEN)
        self.assertTrue(verify_certificate(cert).ok)

    def test_seq_gap_detected(self):
        e = Event("T", "E", 0)
        p0 = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        p2 = Page(page_id_event("T", "E", 2), "T", "E", 2, Kind.APPROVAL, 0, None, 1)
        evl = ev(e, [p0, p2])
        self.assertTrue(any(m.kind.value == "SEQ_GAP" for m in evl.missing))

    def test_cross_tenant_isolation_same_event_id(self):
        from retention.store import PartitionStore
        store = PartitionStore()
        e_a = Event("A", "E", 0)
        e_b = Event("B", "E", 0)
        store.put_event(e_a)
        store.put_event(e_b)
        store.append_page(Page(page_id_event("A", "E", 0), "A", "E", 0, Kind.HOLD, 0, None, 1))
        evb = store.replay("B", "E", 10 * DAY, 200 * DAY)
        self.assertTrue(all(p.tenant == "B" for p in evb.evidence_pages))
        self.assertEqual(evb.point_decision(e_b.base_end + 1)[0], Decision.ELIGIBLE)


class Certificates(unittest.TestCase):
    def test_bytes_roundtrip_and_verify(self):
        """证书经字节序列化→重新解析后，独立验证仍通过（模拟真实交付/接收）。"""
        from retention.certificate import certificate_bytes
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        cert = build_certificate(ev(e, [ap]), e.base_end + 5)
        raw = certificate_bytes(cert)
        self.assertIsInstance(raw, bytes)
        parsed = json.loads(raw.decode("utf-8"))
        self.assertTrue(verify_certificate(parsed).ok)

    def test_seal_detects_tampering(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        cert = build_certificate(ev(e, [ap]), e.base_end + 5)
        self.assertTrue(verify_certificate(cert).ok)
        tampered = copy.deepcopy(cert)
        tampered["verdict"] = "RETAIN"
        vr = verify_certificate(tampered)
        self.assertFalse(vr.ok)
        self.assertTrue(any("seal" in err for err in vr.errors))

    def test_trusted_snapshot_mismatch(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        cert = build_certificate(ev(e, [ap]), e.base_end + 5)
        vr = verify_certificate(cert, trusted_pages=[])
        self.assertFalse(vr.ok)
        self.assertTrue(any("trusted_evidence" in err for err in vr.errors))

    def test_trusted_snapshot_match(self):
        """呈递同水位、含本分区其它事件页的整分区快照：验证器自行筛选后仍应通过。"""
        from retention.store import PartitionStore
        store = PartitionStore()
        e = Event("T", "E", 0)
        store.put_event(e)
        store.put_event(Event("T", "OTHER", 5 * DAY))
        store.append_page(Page(page_id_event("T", "E", 0), "T", "E", 0,
                               Kind.APPROVAL, 0, None, 1))
        store.append_page(Page(page_id_event("T", "OTHER", 1), "T", "OTHER", 1,
                               Kind.HOLD, 0, None, 2))
        eval_ = store.evaluate_event(e, 50 * DAY, e.base_end + 100 * DAY)
        cert = build_certificate(eval_, e.base_end + 5)
        vr = verify_certificate(cert, trusted_pages=store.pages_in("T"))
        self.assertTrue(vr.ok, vr.errors)

    def test_rejects_non_minimal_segments(self):
        e = Event("T", "E", 0)
        ap = Page(page_id_event("T", "E", 0), "T", "E", 0, Kind.APPROVAL, 0, None, 1)
        cert = build_certificate(ev(e, [ap]), e.base_end + 5)
        tampered = copy.deepcopy(cert)
        first = tampered["segments"][0]
        mid = (first["start"] + first["end"]) // 2
        tampered["segments"] = [{**first, "end": mid}, {**first, "start": mid}] \
            + tampered["segments"][1:]
        tampered.pop("seal", None)
        tampered["seal"] = sha256_text(canonical(tampered))  # 使封条自洽
        vr = verify_certificate(tampered)
        self.assertFalse(vr.ok)
        failed = [n for (n, ok, _d) in vr.checks if not ok]
        self.assertTrue(set(failed) & {"minimal_segments", "recompute_segments"}, failed)


class AcceptanceReversals(unittest.TestCase):
    def test_boundary_equal(self):
        r = reversal_boundary_equal()
        self.assertEqual(r["at_minus_1"]["decision"], Decision.RETAIN.value)
        self.assertEqual(r["at_minus_1"]["reason"], Reason.BASE_FLOOR.value)
        self.assertEqual(r["at_base_end"]["decision"], Decision.ELIGIBLE.value)
        self.assertEqual(r["at_base_end"]["reason"], Reason.APPROVED.value)
        self.assertTrue(r["at_minus_1"]["cert_ok"] and r["at_base_end"]["cert_ok"])

    def test_late_order(self):
        r = reversal_late_order()
        self.assertEqual(r["historical_replay"]["decision"], Decision.ELIGIBLE.value)
        self.assertFalse(r["historical_replay"]["late_hold_present"])
        self.assertEqual(r["current"]["decision"], Decision.RETAIN.value)
        self.assertTrue(r["current"]["late_hold_present"])

    def test_cross_tenant(self):
        r = reversal_cross_tenant()
        self.assertEqual(r["tenant_A"]["decision"], Decision.ELIGIBLE.value)
        self.assertTrue(any(f["code"] == "REVOCATION_CROSS_TENANT"
                            for f in r["tenant_A"]["findings"]))
        self.assertEqual(r["tenant_B"]["decision"], Decision.ELIGIBLE.value)
        self.assertEqual(r["tenant_B"]["evidence_tenants"], ["B"])

    def test_unproven_missing(self):
        r = unproven_missing_page()
        self.assertEqual(r["kind"], CERT_UNPROVEN)
        self.assertEqual(r["verdict"], Decision.UNPROVEN.value)
        self.assertTrue(r["verify_ok"])


class Stress(unittest.TestCase):
    def test_sixty_thousand(self):
        r = stress_sixty_thousand()
        self.assertEqual(r["partitions"], TENANTS)
        self.assertEqual(r["events"], TENANTS)
        self.assertEqual(r["affected_events"], EXPECTED_AFFECTED)
        self.assertEqual(r["old_reports_preserved"], EXPECTED_PRESERVED)
        self.assertEqual(r["old_reports_changed"], EXPECTED_AFFECTED)
        a = r["assertions"]
        for key in ("affected_only", "reads_below_naive", "read_counts_exact",
                    "old_preserved_exact", "preserved_plus_changed_is_all",
                    "affected_all_flipped"):
            self.assertTrue(a[key], key)
        self.assertLess(r["read_counts"]["total_reads"], r["naive_full_recompute"]["reads"])
        self.assertLess(r["read_ratio_vs_naive"], 0.1)


class AllScenarios(unittest.TestCase):
    def test_all_runnable(self):
        for name, fn in ALL_SCENARIOS.items():
            with self.subTest(scenario=name):
                self.assertIsInstance(fn(), dict)


if __name__ == "__main__":
    unittest.main(verbosity=2)
