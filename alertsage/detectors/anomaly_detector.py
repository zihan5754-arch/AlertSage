"""行为异常检测器。

单条告警看不出问题，但"同一个 IP 5 分钟内打了 30 个不同路径"很明显。
这是纯规则做不到的部分，也是把项目从"正则匹配器"抬到"研判系统"的关键。

实现用内存滑动窗口（每条流一个 deque），足够支撑单机/单实例场景；
多实例部署时把 StateStore 换成 Redis 即可，接口不变。
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Deque

from ..models import Alert, Detection, Evidence
from .base import DetectorContext


@dataclass(slots=True)
class _Point:
    ts: datetime
    target: str
    port: int | None
    failed: bool


class AnomalyDetector:
    name = "anomaly"

    def __init__(self) -> None:
        self._streams: dict[str, Deque[_Point]] = defaultdict(deque)
        self._max_seen: datetime | None = None

    # ------------------------------------------------------------ 状态
    def reset(self) -> None:
        self._streams.clear()
        self._max_seen = None

    def _prune(self, stream: Deque[_Point], now: datetime, window: timedelta) -> None:
        reference = max(now, self._max_seen) if self._max_seen else now
        cutoff = reference - window
        while stream and stream[0].ts < cutoff:
            stream.popleft()

    # ------------------------------------------------------------ 检测
    def detect(self, alert: Alert, ctx: DetectorContext) -> list[Detection]:
        settings = ctx.settings
        if not alert.src_ip:
            return []

        self._max_seen = (
            max(self._max_seen, alert.timestamp) if self._max_seen else alert.timestamp
        )
        window = timedelta(seconds=max(settings.rate_window_seconds, 30))
        stream = self._streams[alert.src_ip]
        self._prune(stream, alert.timestamp, window)
        failed = _looks_failed(alert)
        stream.append(
            _Point(
                ts=alert.timestamp,
                target=alert.target_url or alert.dst_ip or "",
                port=alert.dst_port,
                failed=failed,
            )
        )
        # 防止内存被单 IP 洪水撑爆
        if len(stream) > 2000:
            for _ in range(len(stream) - 2000):
                stream.popleft()

        points = list(stream)
        total = len(points)
        distinct_targets = len({p.target for p in points if p.target})
        distinct_ports = len({p.port for p in points if p.port})
        failed_count = sum(1 for p in points if p.failed)

        detections: list[Detection] = []
        if total >= settings.burst_threshold:
            detections.append(
                _make(
                    "ANOM-BURST",
                    "同源高频请求",
                    "medium",
                    0.6,
                    ["T1595"],
                    f"{window.total_seconds():.0f}s 内同源请求 {total} 次（阈值 {settings.burst_threshold}）",
                    ["按 IP 限流并确认是否为业务压测/自动化任务"],
                )
            )
        if distinct_targets >= settings.rate_distinct_targets:
            detections.append(
                _make(
                    "ANOM-FANOUT",
                    "单源目标发散（疑似目录爆破/爬取）",
                    "medium",
                    0.65,
                    ["T1595.002"],
                    f"{window.total_seconds():.0f}s 内访问 {distinct_targets} 个不同目标",
                    ["统计 404 比例，确认是否为目录爆破", "必要时封禁该 IP"],
                )
            )
        if distinct_ports >= 15:
            detections.append(
                _make(
                    "ANOM-PORTSCAN",
                    "单源端口扫描",
                    "medium",
                    0.7,
                    ["T1046"],
                    f"{window.total_seconds():.0f}s 内探测 {distinct_ports} 个端口",
                    ["确认扫描是否获得授权", "封禁非授权来源并检查被扫端口暴露面"],
                )
            )
        if failed_count >= 6:
            detections.append(
                _make(
                    "ANOM-AUTH-BRUTE",
                    "认证失败聚集（疑似爆破）",
                    "high",
                    0.72,
                    ["T1110.001"],
                    f"{window.total_seconds():.0f}s 内认证失败 {failed_count} 次",
                    ["检查是否有成功登录", "封禁来源 IP 并开启账号锁定策略"],
                )
            )
        return detections


def _make(
    rule_id: str,
    title: str,
    severity: str,
    confidence: float,
    mitre: list[str],
    detail: str,
    recommendations: list[str],
) -> Detection:
    return Detection(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="anomaly",
        confidence=confidence,
        mitre=mitre,
        evidence=[Evidence(kind="anomaly", code=rule_id, detail=detail, weight=0, mitre=mitre)],
        recommendations=recommendations,
    )


_FAILED_HINTS = ("failed", "failure", "denied", "invalid", "失败", "拒绝")


def _looks_failed(alert: Alert) -> bool:
    if alert.status_code in (401, 403):
        return True
    blob = f"{alert.alert_type} {alert.raw_log or ''}".lower()
    return any(hint in blob for hint in _FAILED_HINTS)
