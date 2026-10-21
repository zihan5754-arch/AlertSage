"""关联与去重。

护网现场最大的感受是"告警刷屏"：同一个 IP 扫一个路径能打出上百条。
这里做两件事：
1. 指纹去重：同源+同目标+同类 → 合并计数，后续告警降权；
2. 突发识别：窗口内计数超过阈值 → 标记 burst，反向提升风险（持续攻击更可信）。

状态同样放在内存；接口留了 snapshot/restore，方便以后接 Redis 或落盘。
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta

from .models import Alert, Incident


class Correlator:
    def __init__(self, window_seconds: int = 600, burst_threshold: int = 8) -> None:
        self.window_seconds = window_seconds
        self.burst_threshold = burst_threshold
        self._incidents: dict[str, Incident] = {}
        # 记录见过的最大时间戳：乱序输入时也能正确裁剪窗口
        self._max_seen: datetime | None = None
        # 序列号：同一指纹在窗口过期后会重新开一条线，id 不能复用
        self._seq = 0

    # ------------------------------------------------------------ 内部
    def _prune(self, now: datetime) -> None:
        reference = max(now, self._max_seen) if self._max_seen else now
        cutoff = reference - timedelta(seconds=self.window_seconds)
        stale = [fp for fp, inc in self._incidents.items() if inc.last_seen < cutoff]
        for fp in stale:
            del self._incidents[fp]

    # ------------------------------------------------------------ 对外
    def reset(self) -> None:
        self._incidents.clear()
        self._max_seen = None
        self._seq = 0

    def observe(self, alert: Alert, rule_ids: list[str] | None = None, risk: int = 0) -> tuple[Incident, bool]:
        """返回 (关联结果, 是否为窗口内重复告警)。"""
        self._max_seen = max(self._max_seen, alert.timestamp) if self._max_seen else alert.timestamp
        self._prune(alert.timestamp)
        fp = alert.fingerprint()
        incident = self._incidents.get(fp)

        if incident is None:
            self._seq += 1
            incident = Incident(
                incident_id=f"INC-{self._seq:04d}-{hashlib.sha1(fp.encode()).hexdigest()[:6]}",
                fingerprint=fp,
                first_seen=alert.timestamp,
                last_seen=alert.timestamp,
                count=1,
                src_ips=[alert.src_ip] if alert.src_ip else [],
                targets=[alert.target_url] if alert.target_url else [],
                rule_ids=list(rule_ids or []),
                max_risk=risk,
            )
            self._incidents[fp] = incident
            return incident, False

        incident.count += 1
        incident.last_seen = alert.timestamp
        incident.max_risk = max(incident.max_risk, risk)
        if alert.src_ip and alert.src_ip not in incident.src_ips:
            incident.src_ips.append(alert.src_ip)
        if alert.target_url and alert.target_url not in incident.targets:
            incident.targets.append(alert.target_url)
        for rule_id in rule_ids or []:
            if rule_id not in incident.rule_ids:
                incident.rule_ids.append(rule_id)
        if incident.count >= self.burst_threshold:
            incident.burst = True
        return incident, True

    def stats(self) -> dict[str, int]:
        incidents = list(self._incidents.values())
        return {
            "tracked_fingerprints": len(incidents),
            "burst_incidents": sum(1 for i in incidents if i.burst),
            "total_observations": sum(i.count for i in incidents),
        }

    def snapshot(self) -> dict[str, dict]:
        return {
            fp: {
                "incident_id": inc.incident_id,
                "count": inc.count,
                "last_seen": inc.last_seen.isoformat(),
                "burst": inc.burst,
            }
            for fp, inc in self._incidents.items()
        }
