"""正则检测器：v0.1 的能力，保留但降级为"兜底"。

为什么还留着：规则引擎再全，也会遇到甲方临时加的野特征（某个自研 OA 的
特殊参数名、某次应急时才知道的 IOC）。这时候分析师能直接塞一条正则，
不用等发版。定位是补充，不承担主检测职责。
"""

from __future__ import annotations

import re

from ..models import Alert, Detection, Evidence
from .base import DetectorContext

# 与 v0.1 的 ATTACK_PATTERNS 保持兼容，方便老用户平滑迁移
LEGACY_PATTERNS: list[dict] = [
    {
        "id": "REGEX-SQLI",
        "title": "SQL 注入（正则兜底）",
        "pattern": re.compile(r"('|\")\s*(or|and)\s+\d+\s*=\s*\d+", re.I),
        "severity": "high",
        "mitre": ["T1190"],
    },
    {
        "id": "REGEX-XSS",
        "title": "XSS（正则兜底）",
        "pattern": re.compile(r"<script.*?>|javascript:|onerror\s*=", re.I),
        "severity": "medium",
        "mitre": ["T1059.007"],
    },
    {
        "id": "REGEX-CMDI",
        "title": "命令注入（正则兜底）",
        "pattern": re.compile(r"[;&|`]\s*(cat|ls|whoami|id|curl|wget|bash|sh)\b", re.I),
        "severity": "high",
        "mitre": ["T1059.004"],
    },
    {
        "id": "REGEX-TRAVERSAL",
        "title": "路径穿越（正则兜底）",
        "pattern": re.compile(r"\.\./|\.\.\\", re.I),
        "severity": "medium",
        "mitre": ["T1083"],
    },
    {
        "id": "REGEX-SCANNER",
        "title": "扫描器特征（正则兜底）",
        "pattern": re.compile(r"(nikto|nmap|sqlmap|acunetix|nessus)", re.I),
        "severity": "low",
        "mitre": ["T1595"],
    },
]


class RegexDetector:
    name = "regex"

    def __init__(self, patterns: list[dict] | None = None) -> None:
        self.patterns = patterns if patterns is not None else LEGACY_PATTERNS

    def detect(self, alert: Alert, ctx: DetectorContext) -> list[Detection]:
        text = alert.text()
        if not text:
            return []
        hits: list[Detection] = []
        for spec in self.patterns:
            match = spec["pattern"].search(text)
            if not match:
                continue
            hits.append(
                Detection(
                    rule_id=spec["id"],
                    title=spec["title"],
                    severity=spec["severity"],
                    category="regex",
                    confidence=0.55,  # 正则兜底置信度刻意压低，避免盖过规则引擎
                    mitre=list(spec.get("mitre", [])),
                    evidence=[
                        Evidence(
                            kind="rule",
                            code=spec["id"],
                            detail=f"正则命中片段 {match.group(0)[:80]!r}",
                            weight=0,
                            mitre=list(spec.get("mitre", [])),
                        )
                    ],
                    recommendations=["人工确认该特征是否为已知业务行为"],
                )
            )
        return hits
