"""检测器集合。pipeline 只依赖这个工厂函数，不感知具体实现。"""

from __future__ import annotations

from ..rules import Rule, load_rules
from .anomaly_detector import AnomalyDetector
from .base import Detector, DetectorContext
from .regex_detector import RegexDetector
from .rule_detector import RuleDetector

__all__ = [
    "Detector",
    "DetectorContext",
    "AnomalyDetector",
    "RegexDetector",
    "RuleDetector",
    "build_detectors",
]


def build_detectors(rules: list[Rule] | None = None, include_anomaly: bool = True) -> list[Detector]:
    rule_list = rules if rules is not None else load_rules()
    detectors: list[Detector] = [RuleDetector(rule_list), RegexDetector()]
    if include_anomaly:
        detectors.append(AnomalyDetector())
    return detectors
