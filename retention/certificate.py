"""保留证明 / 未证缺页证明：自包含且可被独立验证器复算的证书。

证书类型：
  * RETENTION_PROOF  —— 在查询时刻给出确定判定（RETAIN 或 ELIGIBLE），证据完整。
  * UNPROVEN_PROOF   —— 因缺页，无法证明该时刻可否清退（UNPROVEN），并附缺页证据。

自包含性：证书内嵌"接收水位下的相关证据快照"与"适用清单条目"，验证器无需访问
私有状态即可从这些公开数据复算判定；同时给出承诺哈希，可对照独立台账复核。
完整性封条 seal = sha256(body)，无需任何密钥即可检测篡改。
"""

from __future__ import annotations

from dataclasses import dataclass

from .engine import Evaluation, Segment, evaluate
from .model import (
    Decision, Event, ManifestEntry, MissingEvidence, Page, Reason,
    canonical, commit_pages, digest_of, family_applies, family_of, sha256_text,
)

SCHEMA = "retention-cert/v1"
CERT_RETENTION = "RETENTION_PROOF"
CERT_UNPROVEN = "UNPROVEN_PROOF"


class CertificateError(Exception):
    pass


def _missing_key(m: MissingEvidence) -> str:
    # 用规范化字符串避免 None 与 int/str 混排导致的 TypeError，且保证全序稳定。
    return canonical({"kind": m.kind.value, "family": list(m.family), "detail": m.detail})


def certificate_kind(evaluation: Evaluation, at: int) -> str:
    """证书类型由*t 处的判定*决定，而非"全局是否有缺页"。

    判定为 UNPROVEN ⇒ 未证缺页证明；否则（RETAIN/ELIGIBLE）⇒ 保留证明。
    注意：t 处于法定基线内时即便别处有缺页，也可出具 RETAIN 的保留证明——
    因为基线保留是无条件的（缺页推不翻）。这类"缺页下的 RETAIN"必为 BASE_FLOOR，
    验证器会额外核对其理由以杜绝"缺页掩盖撤销"的假保留。
    """
    dec, _reason = evaluation.point_decision(at)
    return CERT_UNPROVEN if dec == Decision.UNPROVEN else CERT_RETENTION


def _body(evaluation: Evaluation, at: int) -> dict:
    dec, reason = evaluation.point_decision(at)
    kind = certificate_kind(evaluation, at)
    pages = sorted(evaluation.evidence_pages, key=lambda p: (p.seq, p.page_id))
    manifest = sorted(evaluation.manifest, key=lambda m: (m.seq, m.page_id))
    missing = sorted(evaluation.missing, key=_missing_key)
    body = {
        "schema": SCHEMA,
        "kind": kind,
        "event": evaluation.event.as_dict(),
        "watermark": evaluation.watermark,
        "until": evaluation.until,
        "at": at,
        "verdict": dec.value,
        "reason": reason.value,
        "segments": [s.as_dict() for s in evaluation.segments],
        "evidence": [p.as_dict() for p in pages],
        "manifest": [m.as_dict() for m in manifest],
        "missing": [m.as_dict() for m in missing],
        "findings": list(evaluation.findings),
        "commitments": {
            "evidence": commit_pages(pages),
            "manifest": digest_of([m.as_dict() for m in manifest]),
        },
    }
    return body


def build_certificate(evaluation: Evaluation, at: int) -> dict:
    """生成证书。at 必须落在判定窗口内，证书只陈述该时刻的判定及支撑。"""
    body = _body(evaluation, at)
    seal = sha256_text(canonical(body))
    cert = dict(body)
    cert["seal"] = seal
    return cert


def certificate_bytes(cert: dict) -> bytes:
    """稳定的字节序列化（用于写入磁盘 / 对外交付）。"""
    return canonical(cert).encode("utf-8")


# ---------------------------------------------------------------------------
# 独立验证器
# ---------------------------------------------------------------------------

@dataclass
class VerifyResult:
    ok: bool
    certificate_kind: str | None
    verdict: str | None
    at: int | None
    checks: list[tuple[str, bool, str]]
    errors: list[str]

    def as_dict(self) -> dict:
        return {
            "ok": self.ok,
            "kind": self.certificate_kind,
            "verdict": self.verdict,
            "at": self.at,
            "checks": [{"name": n, "pass": p, "detail": d}
                       for (n, p, d) in self.checks],
            "errors": self.errors,
        }


def _minimal_segments_ok(segments: list[Segment], start: int, end: int) -> tuple[bool, str]:
    if not segments:
        return False, "无片段"
    if segments[0].start != start:
        return False, f"首片段起点 {segments[0].start} != {start}"
    if segments[-1].end != end:
        return False, f"末片段终点 {segments[-1].end} != {end}"
    for a, b in zip(segments, segments[1:]):
        if a.end != b.start:
            return False, f"片段不连续：{a.end} != {b.start}"
        if a.decision == b.decision:
            return False, f"相邻片段判定相同（未合并），非最少：{a.start}-{b.end}"
    for s in segments:
        if s.end <= s.start:
            return False, f"空片段 {s.start}-{s.end}"
    return True, "连续覆盖且无相邻同判定"


def verify_certificate(cert: dict, *,
                       trusted_pages: list[Page] | None = None,
                       trusted_manifest: list[ManifestEntry] | None = None) -> VerifyResult:
    """独立复算证书。

    只依赖证书自带的公开证据；若提供 trusted_pages/trusted_manifest（来自独立台账
    在同水位下的快照），则额外核对承诺哈希，从而确认"证据未被替换或删改"。
    """
    checks: list[tuple[str, bool, str]] = []
    errors: list[str] = []

    def add(name: str, ok: bool, detail: str) -> None:
        checks.append((name, ok, detail))
        if not ok:
            errors.append(f"{name}: {detail}")

    # 1. 封条完整性
    body = {k: v for k, v in cert.items() if k != "seal"}
    add("seal", cert.get("seal") == sha256_text(canonical(body)),
        "封条与正文哈希一致" if cert.get("seal") == sha256_text(canonical(body))
        else "封条与正文不匹配（疑似被篡改）")

    # 2. 结构
    try:
        kind = cert["kind"]
        event = Event.from_dict(cert["event"])
        watermark = int(cert["watermark"])
        until = int(cert["until"])
        at = int(cert["at"])
        segments = [Segment.from_dict(d) for d in cert["segments"]]
        pages = [Page.from_dict(d) for d in cert["evidence"]]
        manifest = [ManifestEntry.from_dict(d) for d in cert["manifest"]]
        missing = [MissingEvidence.from_dict(d) for d in cert["missing"]]
        verdict = Decision(cert["verdict"])
    except (KeyError, ValueError, TypeError) as exc:
        add("schema", False, f"字段缺失或非法：{exc!r}")
        return VerifyResult(False, cert.get("kind"), cert.get("verdict"),
                            cert.get("at"), checks, errors)
    add("schema", kind in (CERT_RETENTION, CERT_UNPROVEN),
        f"kind={kind}")

    # 3. 每页自哈希
    bad = [p.page_id for p in pages if not p.verify_hash()]
    add("page_hashes", not bad, "全部页内容哈希自洽" if not bad else f"哈希不符：{bad}")

    # 4. 证据承诺（对缺键的证书以失败项处理，绝不崩溃）
    commitments = cert.get("commitments") if isinstance(cert.get("commitments"), dict) else {}
    evidence_commit = commit_pages(pages)
    declared_ev = commitments.get("evidence")
    add("evidence_commitment",
        evidence_commit == declared_ev,
        "证据承诺可复算" if evidence_commit == declared_ev else "证据承诺缺失或不符")

    # 5. 与独立台账快照核对（可选）。
    # 快照为"候选页 + 清单"的原始集合；验证器按事件适用性与水位自行筛选，
    # 因此同一租户分区内其它事件的页不会造成假不一致。
    if trusted_pages is not None:
        applicable = sorted(
            (p for p in trusted_pages
             if p.received_at <= watermark and family_applies(family_of(p), event)),
            key=lambda p: (p.seq, p.page_id))
        add("trusted_evidence",
            commit_pages(applicable) == evidence_commit,
            "证书证据与独立台账在同水位快照一致"
            if commit_pages(applicable) == evidence_commit
            else "证书证据与独立台账快照不一致（证据被替换/删改）")
    if trusted_manifest is not None:
        applicable_m = sorted(
            (m for m in trusted_manifest
             if m.expected_received_by <= watermark and family_applies(m.family, event)),
            key=lambda m: (m.seq, m.page_id))
        declared_m = commitments.get("manifest")
        got_m = digest_of([m.as_dict() for m in applicable_m])
        add("trusted_manifest",
            got_m == declared_m,
            "清单承诺与独立台账一致" if got_m == declared_m else "清单承诺缺失或不一致")

    # 6. 从嵌入证据独立复算
    recomputed = evaluate(event, pages, manifest, watermark, until)
    add("recompute_segments",
        [s.as_dict() for s in recomputed.segments] == [s.as_dict() for s in segments],
        "从公开证据复算的片段与证书一致"
        if [s.as_dict() for s in recomputed.segments] == [s.as_dict() for s in segments]
        else "复算片段与证书不一致")
    recomputed_missing = sorted(recomputed.missing, key=_missing_key)
    add("recompute_missing",
        [m.as_dict() for m in recomputed_missing] == [m.as_dict() for m in missing],
        "复算缺页项与证书一致"
        if [m.as_dict() for m in recomputed_missing] == [m.as_dict() for m in missing]
        else "复算缺页项与证书不一致")

    # 7. 最少片段性
    ok, detail = _minimal_segments_ok(segments, event.occurred_at, until)
    add("minimal_segments", ok, detail)

    # 8. 判定与声明时刻一致，并与证书类型 & 缺页情形自洽
    seg_at = next((s for s in segments if s.covers(at)), None)
    if seg_at is None:
        add("verdict_at", False, f"t={at} 不在片段覆盖范围内")
    else:
        point = recomputed.point_decision(at)
        add("verdict_at", seg_at.decision == verdict and point[0] == verdict,
            f"t={at} 复算判定 {point[0].value}，声明 {verdict.value}")
        expected_kind = CERT_UNPROVEN if verdict == Decision.UNPROVEN else CERT_RETENTION
        add("kind_consistency", kind == expected_kind,
            f"证书类型 {kind} 与判定 {verdict.value} 对应"
            if kind == expected_kind else f"证书类型 {kind} 与判定 {verdict.value} 不符")
        if verdict == Decision.UNPROVEN:
            add("unproven_requires_gap", bool(missing),
                "未证证明必须确有缺页" if missing else "未证证明却缺页为空")
        elif missing:
            # 缺页却给出确定判定：只允许"法定基线内 RETAIN"这类无条件结论。
            add("gap_guard", point[1] == Reason.BASE_FLOOR,
                "缺页下仅允许法定基线的 RETAIN" if point[1] == Reason.BASE_FLOOR
                else f"缺页下给出 {verdict.value}/{point[1].value}，不可证")

    # 9. 缺页证据自身可复核（清单承诺的页确实不在证据集中）
    present = {p.page_id for p in pages}
    for m in missing:
        if m.kind.value == "MANIFEST_ABSENT":
            okm = m.detail["page_id"] not in present
            add(f"missing:{m.detail['page_id']}", okm,
                "清单承诺页确实缺失" if okm else "清单承诺页实际上存在，缺页证据不成立")

    return VerifyResult(all(ok for _, ok, _ in checks), kind, verdict.value, at, checks, errors)
