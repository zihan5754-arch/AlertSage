"""数据模型。

全部用 dataclass，不引入 pydantic —— 核心引擎要能在只有标准库的机器上跑
（很多甲方跳板机/隔离网环境装不了第三方包，这是真实场景下的约束）。
HTTP 层需要 schema 校验时，再由 api 层用 pydantic 包一层。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# 严重度从低到高，索引即等级
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
VERDICTS = ["true_positive", "false_positive", "needs_review"]

# 严重度基础分：决定一条命中的"底分"
SEVERITY_BASE = {
    "critical": 90,
    "high": 72,
    "medium": 48,
    "low": 22,
    "info": 6,
}


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0


@dataclass(slots=True)
class Alert:
    """归一化后的告警。字段名刻意贴合 WAF/EDR/IDS 的公共交集。"""

    alert_id: str
    source: str = "unknown"
    alert_type: str = ""
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    target_url: str | None = None
    http_method: str | None = None
    status_code: int | None = None
    user_agent: str | None = None
    payload: str | None = None
    raw_log: str | None = None
    asset: str | None = None
    action: str | None = None  # blocked / allowed / logged
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

    def text(self) -> str:
        """把所有可能承载攻击载荷的字段拼成一段可检索文本。"""
        parts = [self.payload, self.raw_log, self.target_url, self.user_agent, self.alert_type]
        return " \n ".join(p for p in parts if p)

    def fingerprint(self) -> str:
        """关联指纹：同源 + 同目标端口 + 同类告警算一条线。

        刻意不把 target_url 放进指纹：现场最常见的是"一个 IP 刷几百个路径"，
        如果按 URL 分组，每个路径都是新告警，去重和突发识别全部失效。
        目标列表由 Incident.targets 记录，需要细粒度时看那里。
        """
        raw = "|".join(
            [
                str(self.src_ip or ""),
                str(self.dst_ip or ""),
                str(self.dst_port or ""),
                str(self.alert_type or ""),
            ]
        )
        return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(slots=True)
class Evidence:
    """单条证据。weight 是对分值的贡献，正数加风险，负数减风险。"""

    kind: str  # rule / anomaly / suppression / asset / correlation / llm
    code: str
    detail: str
    weight: int = 0
    mitre: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Detection:
    """一次规则命中。"""

    rule_id: str
    title: str
    severity: str
    category: str
    confidence: float
    mitre: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Incident:
    """关联后的告警簇。同指纹在多长时间窗口内合并，超过阈值升级为 incident。"""

    incident_id: str
    fingerprint: str
    first_seen: datetime
    last_seen: datetime
    count: int
    src_ips: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    rule_ids: list[str] = field(default_factory=list)
    max_risk: int = 0
    burst: bool = False


@dataclass(slots=True)
class TriageResult:
    alert_id: str
    verdict: str
    attack_type: str
    severity: str
    risk_score: int
    fp_probability: float
    confidence: float
    detections: list[Detection] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    analysis: str = ""
    narrative_source: str = "template"  # template / llm / none
    degraded: bool = False
    incident: Incident | None = None
    duplicate_of: str | None = None
    elapsed_ms: float = 0.0
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON 友好；datetime 统一转 ISO8601。"""

        def conv(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return obj.isoformat()
            if isinstance(obj, list):
                return [conv(x) for x in obj]
            if isinstance(obj, dict):
                return {k: conv(v) for k, v in obj.items()}
            if hasattr(obj, "__dataclass_fields__"):
                return {k: conv(getattr(obj, k)) for k in obj.__dataclass_fields__}
            return obj

        return conv(self)

    @property
    def mitre_techniques(self) -> list[str]:
        seen: list[str] = []
        for det in self.detections:
            for tech in det.mitre:
                if tech not in seen:
                    seen.append(tech)
        return seen
