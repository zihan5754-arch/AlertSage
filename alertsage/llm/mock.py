"""离线 Provider。

没有 API Key 时用它，产出的是"确定性模板"而不是真模型输出。
存在的意义有两个：
1. 让整条链路在没有外网/没预算的环境里能被测试和演示；
2. 作为降级兜底——真模型超时/输出非法时，至少还有一份可读的分析。
"""

from __future__ import annotations

import json

from ..models import Alert, TriageResult


class MockProvider:
    name = "mock"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        """从 user_prompt 里还原结构化输入，套模板生成一段中文分析。"""
        try:
            payload = json.loads(user_prompt)
        except json.JSONDecodeError:
            payload = {}

        risk = payload.get("risk_score", 0)
        verdict = payload.get("verdict", "needs_review")
        techniques = payload.get("mitre", [])
        findings = payload.get("findings", [])
        evidence = payload.get("evidence", [])

        headline = {
            "true_positive": "综合证据判断为真实攻击",
            "false_positive": "综合证据判断大概率为误报/低价值噪音",
            "needs_review": "证据不足，需要人工复核后才能定性",
        }.get(verdict, "无法定性")

        parts = [
            f"{headline}（风险 {risk}/100，误报概率 {payload.get('fp_probability', 0)}）。",
        ]
        if findings:
            parts.append("命中：" + "、".join(findings[:4]) + "。")
        if techniques:
            parts.append("对应 ATT&CK 技术：" + "、".join(techniques[:4]) + "。")
        if evidence:
            parts.append("关键证据：" + "；".join(evidence[:3]) + "。")

        return json.dumps(
            {
                "analysis": "".join(parts),
                "why": evidence[:5],
                "next_actions": payload.get("recommendations", [])[:4],
                "generated_by": "mock",
            },
            ensure_ascii=False,
        )


def render_template(alert: Alert, result: TriageResult) -> str:
    """不经过 Provider 的本地叙述，用于 LLM 完全不可用时的兜底。"""
    findings = "、".join(d.title for d in result.detections[:3]) or "无明确命中"
    techniques = "、".join(result.mitre_techniques[:4]) or "未映射"
    verdict_text = {
        "true_positive": "倾向真实攻击",
        "false_positive": "倾向误报",
        "needs_review": "需要人工复核",
    }.get(result.verdict, result.verdict)

    lines = [
        f"【{verdict_text}】{findings}；ATT&CK：{techniques}。",
        f"风险分 {result.risk_score}/100，误报概率 {result.fp_probability:.0%}，置信度 {result.confidence:.0%}。",
    ]
    if alert.src_ip:
        src = f"来源 {alert.src_ip}"
        if alert.asset:
            src += f"，目标资产 {alert.asset}"
        lines.append(src + "。")
    key_evidence = [e.detail for e in result.evidence if e.kind in ("rule", "anomaly", "correlation")][:2]
    if key_evidence:
        lines.append("依据：" + "；".join(key_evidence) + "。")
    return "".join(lines)
