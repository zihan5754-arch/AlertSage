"""LLM 叙述层：调用 + 校验 + 降级。

这一层刻意不做"判决"，只做"解释"。原因：
- 判定要可复现、可审计，LLM 有随机性；
- 幻觉成本很高（编造一个不存在的 IOC 可能让值班同学追一天）；
- 真出问题时能一键关掉 LLM，系统照常工作。

所以流程是：确定性引擎给结论 → LLM 把结论写成给人看的话 → 校验不过就退回模板。
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ..config import Settings
from ..errors import LLMError
from ..models import Alert, TriageResult
from .base import LLMProvider
from .mock import MockProvider, render_template
from .openai_compat import OpenAICompatProvider
from .prompts import SYSTEM_PROMPT, build_user_prompt

# 形如 WEB-SQLI-001 / ANOM-BURST 的规则编号
_RULE_ID_RE = re.compile(r"\b[A-Z][A-Z0-9]*(?:-[A-Z0-9]+){1,2}-\d{3}\b|\bANOM-[A-Z]+\b")


@dataclass(slots=True)
class Narrative:
    analysis: str
    source: str  # llm / template
    degraded: bool
    reason: str = ""
    why: list[str] | None = None
    next_actions: list[str] | None = None


def build_provider(settings: Settings) -> LLMProvider:
    if settings.llm_provider == "openai":
        return OpenAICompatProvider(
            base_url=settings.llm_base_url,
            api_key=settings.llm_api_key,
            model=settings.llm_model,
            timeout=settings.llm_timeout_seconds,
            max_retries=settings.llm_max_retries,
        )
    return MockProvider()


class LLMReporter:
    def __init__(self, settings: Settings, provider: LLMProvider | None = None) -> None:
        self.settings = settings
        self.provider = provider or build_provider(settings)

    @property
    def enabled(self) -> bool:
        return self.settings.llm_enabled

    def should_call(self, result: TriageResult) -> bool:
        """不是每条告警都值得花 token：低风险/明确误报走模板。"""
        if not self.enabled:
            return False
        if result.verdict == "false_positive":
            return False
        return result.risk_score >= self.settings.llm_min_risk_for_call

    def narrate(self, alert: Alert, result: TriageResult) -> Narrative:
        if not self.should_call(result):
            return Narrative(analysis=render_template(alert, result), source="template", degraded=False)

        try:
            raw = self.provider.complete(SYSTEM_PROMPT, build_user_prompt(alert, result))
            parsed = self._parse_and_validate(raw, result)
            return Narrative(
                analysis=parsed["analysis"],
                source="llm",
                degraded=False,
                why=parsed.get("why"),
                next_actions=parsed.get("next_actions"),
            )
        except LLMError as exc:
            return Narrative(
                analysis=render_template(alert, result),
                source="template",
                degraded=True,
                reason=str(exc),
            )
        except Exception as exc:  # noqa: BLE001 - 兜底，绝不能让叙述层拖垮研判
            return Narrative(
                analysis=render_template(alert, result),
                source="template",
                degraded=True,
                reason=f"未预期错误: {type(exc).__name__}: {exc}",
            )

    # ------------------------------------------------------------ 校验
    def _parse_and_validate(self, raw: str, result: TriageResult) -> dict:
        text = raw.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text).strip()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise LLMError(f"输出不是合法 JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise LLMError("输出必须是 JSON 对象")

        analysis = str(data.get("analysis") or "").strip()
        if not analysis:
            raise LLMError("analysis 为空")
        if len(analysis) > 2000:
            raise LLMError("analysis 过长，可能是模型跑偏")

        # 防幻觉：文中引用的规则编号必须真实存在
        known = {e.code for e in result.evidence} | {d.rule_id for d in result.detections}
        cited = set(_RULE_ID_RE.findall(analysis))
        phantom = {c for c in cited if c not in known}
        if phantom:
            raise LLMError(f"引用了不存在的规则/证据: {sorted(phantom)}")

        why = data.get("why")
        actions = data.get("next_actions")
        return {
            "analysis": analysis,
            "why": [str(x) for x in why][:5] if isinstance(why, list) else [],
            "next_actions": [str(x) for x in actions][:5] if isinstance(actions, list) else [],
        }
