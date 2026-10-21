"""Prompt 设计。

核心约束（也是防幻觉的工程手段）：
1. 只允许使用给定证据，明确写"不要补充证据里没有的 IP、域名、日志"；
2. 输出必须是固定 JSON schema，方便校验；
3. 强调"不要改变系统给出的 verdict"——判定权留在确定性引擎手里。
"""

from __future__ import annotations

import json
from typing import Any

SYSTEM_PROMPT = """你是蓝队安全运营中心（SOC）的资深分析师。
你会收到一条已经过规则引擎研判的告警，包含归一化字段、命中规则、行为证据、风险分和建议。

要求：
1. 只使用给定证据，禁止补充证据中不存在的 IP、域名、文件路径、日志内容；
2. 不要推翻给定的 verdict 与 risk_score，它们是确定性引擎的结果；
3. 用中文写，面向值班同学，先给结论再给依据，总长度不超过 300 字；
4. 只输出 JSON，不要 Markdown 代码块，格式：
{"analysis": "一段话分析", "why": ["证据1", "证据2"], "next_actions": ["动作1"]}"""


def build_user_prompt(alert: Any, result: Any) -> str:
    """把结构化事实压成 JSON。字段名用英文减小歧义，值保留中文原文。"""
    payload = {
        "alert": {
            "alert_id": alert.alert_id,
            "source": alert.source,
            "alert_type": alert.alert_type,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "dst_port": alert.dst_port,
            "target_url": alert.target_url,
            "http_method": alert.http_method,
            "status_code": alert.status_code,
            "user_agent": alert.user_agent,
            "asset": alert.asset,
            "action": alert.action,
            "payload": (alert.payload or "")[:500],
            "raw_log": (alert.raw_log or "")[:800],
        },
        "verdict": result.verdict,
        "risk_score": result.risk_score,
        "fp_probability": result.fp_probability,
        "severity": result.severity,
        "findings": [d.title for d in result.detections],
        "mitre": result.mitre_techniques,
        "evidence": [e.detail for e in result.evidence if e.kind != "baseline"][:8],
        "recommendations": result.recommendations[:5],
    }
    return json.dumps(payload, ensure_ascii=False, indent=None)
