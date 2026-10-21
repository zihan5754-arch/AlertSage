"""基于声明式规则的检测器。

规则从 rules/*.json 加载，匹配成功转成 Detection。
一条告警可能同时命中多条规则（例如既是 SQL 注入又是扫描），全部保留，
后面由 scoring 决定谁主导分数——不在这里"先到先得"。
"""

from __future__ import annotations

from ..models import Alert, Detection, Evidence
from ..rules import Rule, rule_to_detection
from .base import DetectorContext


class RuleDetector:
    name = "rule_engine"

    def __init__(self, rules: list[Rule]) -> None:
        self.rules = [r for r in rules if r.enabled]

    def detect(self, alert: Alert, ctx: DetectorContext) -> list[Detection]:
        hits: list[Detection] = []
        for rule in self.rules:
            matched, reasons = rule.matches(alert)
            if not matched:
                continue
            detection = rule_to_detection(rule, reasons)
            detection.evidence.append(
                Evidence(
                    kind="rule",
                    code=rule.id,
                    detail=f"规则自带权重调整 {rule.weight_delta:+d}",
                    weight=rule.weight_delta,
                    mitre=list(rule.mitre),
                )
            )
            hits.append(detection)
        return hits
