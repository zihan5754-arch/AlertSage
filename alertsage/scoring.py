"""打分：把"命中了什么"变成"要不要处理"。

这一层是整个项目最该被面试官追问的地方。设计原则：
1. 每个加减分都写进 Evidence，输出能解释；
2. 风险分（要不要处置）和误报概率（是不是噪音）是两个维度，不能混；
3. 规则只负责"是不是",打分负责"有多严重"，职责分离；
4. 所有调整走同一个账本（_Ledger），避免"乘一次又加一次"这类重复计分。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import Settings
from .models import SEVERITY_BASE, Alert, Detection, Evidence, Incident, severity_rank

ASSET_DEFAULT = 1.0

_SCANNER_UA = re.compile(
    r"(nikto|nmap|sqlmap|acunetix|nessus|masscan|zgrab|nuclei|awvs|appscan)", re.I
)

# 告警文本里出现这些词，说明"上游认为这里有攻击"，没有命中也不能直接判误报
_SUSPICIOUS_HINTS = (
    "suspicious",
    "unknown",
    "anomal",
    "attack",
    "exploit",
    "injection",
    "brute",
    "scan",
    "malware",
    "beacon",
    "exfil",
    "c2",
    "异常",
    "可疑",
    "攻击",
)


@dataclass(slots=True)
class ScoreResult:
    risk_score: int
    fp_probability: float
    confidence: float
    verdict: str
    evidence: list[Evidence]
    breakdown: list[dict] = field(default_factory=list)


class _Ledger:
    """分数账本：每一次调整都留痕，最后能原样打印出分数构成。"""

    def __init__(self) -> None:
        self.risk = 0.0
        self.evidence: list[Evidence] = []
        self.breakdown: list[dict] = []

    def start(self, value: float, label: str, detail: str) -> None:
        self.risk = value
        self.breakdown.append(
            {"label": label, "detail": detail, "delta": 0, "total": round(value, 1)}
        )

    def add(self, delta: float, label: str, detail: str, kind: str = "rule") -> None:
        self.risk += delta
        self.evidence.append(Evidence(kind=kind, code=label, detail=detail, weight=int(round(delta))))
        self.breakdown.append(
            {
                "label": label,
                "detail": detail,
                "delta": round(delta, 1),
                "total": round(self.risk, 1),
            }
        )

    def scale(self, factor: float, label: str, detail: str, extra: float = 0.0, kind: str = "rule") -> None:
        target = self.risk * factor + extra
        self.add(target - self.risk, label, detail, kind)


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def asset_multiplier(settings: Settings, asset: str | None) -> float:
    if not asset:
        return ASSET_DEFAULT
    table = settings.asset_criticality
    if asset in table:
        return float(table[asset])
    for key, weight in table.items():
        if key.endswith("*") and asset.startswith(key[:-1]):
            return float(weight)
    return ASSET_DEFAULT


def is_allowlisted(settings: Settings, src_ip: str | None) -> bool:
    if not src_ip:
        return False
    for pattern in settings.allowlist:
        try:
            if re.search(pattern, src_ip):
                return True
        except re.error:
            if pattern == src_ip:
                return True
    return False


def _looks_benign(alert: Alert) -> tuple[bool, str]:
    """没有命中时，判断"上游告警本身是否像正常业务"。

    这条区分很重要：健康检查/拨测进研判队列本身就是上游规则的问题，
    直接判误报能省人力；但带 attack/suspicious 字样的告警即使没命中，
    也必须交给人看——宁可多看一条，不可放过一条。
    """
    blob = " ".join(
        filter(None, [alert.alert_type, alert.raw_log, alert.payload, alert.target_url])
    ).lower()

    if any(hint in blob for hint in _SUSPICIOUS_HINTS):
        return False, "没有任何检测命中，但告警本身含攻击语义，不能自动判为误报"

    if alert.status_code and alert.status_code >= 400:
        return False, "没有任何检测命中，但请求返回错误状态码，可能是被探测"

    return True, "没有任何检测命中，且响应正常（2xx、无攻击语义），大概是上游噪声"


def score(
    alert: Alert,
    detections: list[Detection],
    settings: Settings,
    *,
    duplicate: bool = False,
    incident: Incident | None = None,
) -> ScoreResult:
    ledger = _Ledger()

    # ---------------------------------------------------------- 无命中
    if not detections:
        benign, why = _looks_benign(alert)
        risk = 15.0 if alert.alert_type else 8.0
        fp = 0.7 if benign else 0.55
        if alert.action == "blocked":
            fp = min(0.85, fp + 0.1)
        ledger.start(risk, "NO-MATCH", why)
        return ScoreResult(
            risk_score=int(round(risk)),
            fp_probability=round(fp, 2),
            confidence=0.25 if benign else 0.35,
            verdict="false_positive" if benign else "needs_review",
            evidence=ledger.evidence,
            breakdown=ledger.breakdown,
        )

    # ---------------------------------------------------------- 主命中
    primary = max(
        detections,
        key=lambda d: (SEVERITY_BASE[d.severity] * d.confidence, severity_rank(d.severity)),
    )
    ledger.start(
        SEVERITY_BASE[primary.severity] * primary.confidence,
        "BASE",
        f"{primary.rule_id} 严重度={primary.severity} 置信度={primary.confidence:.2f}",
    )
    fp = 1.0 - primary.confidence

    # 独立证据：排除正则兜底命中，它和规则命中是同一条证据
    independent = [d for d in detections if d.category != "regex"]
    distinct_rules = {d.rule_id for d in independent}
    if len(distinct_rules) > 1:
        bonus = min(6 * (len(distinct_rules) - 1), 18)
        ledger.add(bonus, "MULTI-RULE", f"另有 {len(distinct_rules) - 1} 条规则独立命中")

    categories = {d.category for d in independent}
    if len(categories) > 1:
        ledger.add(4, "CROSS-CATEGORY", f"跨类别交叉证据 {sorted(categories)}")
        fp -= 0.08

    weight_delta = sum(e.weight for d in detections for e in d.evidence if e.kind == "rule")
    if weight_delta:
        ledger.add(weight_delta, "RULE-WEIGHT", f"规则权重合计 {weight_delta:+d}")

    anomaly_ids = [d.rule_id for d in detections if d.category == "anomaly"]
    if "ANOM-AUTH-BRUTE" in anomaly_ids:
        ledger.add(10, "ANOMALY", "认证失败聚集，行为证据较强")
    elif anomaly_ids:
        ledger.add(4, "ANOMALY", f"行为异常 {anomaly_ids}")

    # ---------------------------------------------------------- 资产与抑制
    mult = asset_multiplier(settings, alert.asset)
    if mult != 1.0:
        label = f"资产 {alert.asset}" if alert.asset else "全局资产系数"
        ledger.scale(mult, "ASSET", f"{label} 重要度系数 {mult:.2f}")
        if mult >= 1.1:
            fp -= 0.05

    if is_allowlisted(settings, alert.src_ip):
        ledger.scale(0.35, "SUP-ALLOWLIST", f"来源 {alert.src_ip} 命中白名单", kind="suppression")
        fp += 0.45

    if duplicate:
        ledger.scale(0.85, "SUP-DUPLICATE", "与窗口内既有告警指纹重复，去重降权", kind="suppression")
        fp += 0.12

    if incident and incident.burst:
        # 持续行为更可信，但要区分：低危盲扫刷屏不能因此被抬成高危
        big = severity_rank(primary.severity) >= 2
        ledger.add(
            12 if big else 4,
            "CORRELATION",
            f"同指纹 {incident.count} 次，判定为持续性行为",
            kind="correlation",
        )
        fp -= 0.12 if big else 0.04

    if alert.action == "blocked":
        ledger.scale(0.85, "ACTION", "WAF/IPS 已拦截，实际危害与紧迫度下降", extra=-4, kind="suppression")
        fp += 0.08

    if (
        alert.user_agent
        and _SCANNER_UA.search(alert.user_agent)
        and severity_rank(primary.severity) <= 1
    ):
        ledger.add(-6, "UA-SCANNER", "低危告警且 UA 为公开扫描器，常见于资产测绘", kind="suppression")
        fp += 0.2

    if primary.category == "recon" and alert.status_code == 404:
        ledger.add(-4, "RECON-404", "低危探测 + 404，多为盲目扫描", kind="suppression")
        fp += 0.15

    # ---------------------------------------------------------- 收尾
    risk = _clamp(ledger.risk, 0, 100)
    fp = _clamp(fp, 0.02, 0.98)
    risk_int = int(round(risk))

    if fp >= 0.7:
        verdict = "false_positive"
    elif risk_int >= settings.true_positive_threshold:
        verdict = "true_positive"
    elif risk_int <= settings.false_positive_threshold and fp >= 0.5:
        verdict = "false_positive"
    else:
        verdict = "needs_review"

    confidence = (
        primary.confidence
        + 0.05 * (len(distinct_rules) - 1)
        + (0.08 if len(categories) > 1 else 0)
    )
    if fp > 0.5:
        confidence *= 1 - 0.6 * (fp - 0.5)
    confidence = _clamp(confidence, 0.05, 0.99)

    return ScoreResult(
        risk_score=risk_int,
        fp_probability=round(fp, 2),
        confidence=round(confidence, 2),
        verdict=verdict,
        evidence=ledger.evidence,
        breakdown=ledger.breakdown,
    )


def build_recommendations(detections: list[Detection], verdict: str, severity: str) -> list[str]:
    """合并规则建议 + 结论级建议，去重保序。"""
    merged: list[str] = []
    for detection in detections:
        for item in detection.recommendations:
            if item not in merged:
                merged.append(item)

    if verdict == "true_positive":
        merged.append(
            "建议立即升级为安全事件，按应急预案联系业务方确认影响面"
            if severity in ("critical", "high")
            else "建议纳入当班处理队列，24 小时内闭环"
        )
    elif verdict == "false_positive":
        merged.append("建议关闭该告警；若为长期噪声，补充白名单或调整规则阈值，避免重复消耗人力")
    else:
        merged.append("证据不足以自动定性，建议人工复核原始日志后再决定处置")
    return merged[:8]
