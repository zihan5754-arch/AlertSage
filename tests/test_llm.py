"""LLM 层测试：重点是"降级不崩溃"和"防幻觉校验"。"""

from __future__ import annotations

import json
import unittest

from alertsage.errors import LLMError
from alertsage.llm import LLMReporter, MockProvider
from alertsage.llm.openai_compat import OpenAICompatProvider
from alertsage.pipeline import TriagePipeline
from tests.helpers import make_settings


class _FailingProvider:
    name = "failing"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        raise LLMError("模拟超时")


class _PhantomProvider:
    name = "phantom"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return json.dumps({"analysis": "根据 WEB-FAKE-999 可以确定这是攻击", "why": [], "next_actions": []})


class _FencedProvider:
    name = "fenced"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        payload = {"analysis": "这是被拦截的注入尝试。", "why": ["规则命中"], "next_actions": ["复核日志"]}
        return "```json\n" + json.dumps(payload, ensure_ascii=False) + "\n```"


class _GarbageProvider:
    name = "garbage"

    def complete(self, system_prompt: str, user_prompt: str) -> str:
        return "抱歉，我不能帮助分析这个告警。"


def _result(pipeline: TriagePipeline):
    return pipeline.triage_raw(
        {
            "alert_type": "SQL Injection",
            "timestamp": "2026-09-10T10:00:00+08:00",
            "src_ip": "45.134.26.17",
            "payload": "1 union select 1,2",
            "target_url": "/api/x",
            "asset": "order-api",
        }
    )


class MockProviderTest(unittest.TestCase):
    def test_returns_valid_json(self) -> None:
        payload = {"risk_score": 60, "verdict": "true_positive", "findings": ["SQL 注入"], "mitre": ["T1190"]}
        raw = MockProvider().complete("sys", json.dumps(payload, ensure_ascii=False))
        data = json.loads(raw)
        self.assertIn("SQL 注入", data["analysis"])
        self.assertIn("T1190", data["analysis"])

    def test_handles_broken_input(self) -> None:
        data = json.loads(MockProvider().complete("sys", "not json"))
        self.assertTrue(data["analysis"])


class ReporterTest(unittest.TestCase):
    def test_disabled_uses_template(self) -> None:
        pipeline = TriagePipeline(make_settings(llm_enabled=False))
        result = _result(pipeline)
        self.assertEqual(result.narrative_source, "template")
        self.assertFalse(result.degraded)
        self.assertTrue(result.analysis)

    def test_enabled_uses_provider(self) -> None:
        settings = make_settings(llm_enabled=True, llm_provider="mock", llm_min_risk_for_call=0)
        pipeline = TriagePipeline(settings)
        result = _result(pipeline)
        self.assertEqual(result.narrative_source, "llm")
        self.assertFalse(result.degraded)

    def test_below_risk_threshold_skips_llm(self) -> None:
        settings = make_settings(llm_enabled=True, llm_provider="mock", llm_min_risk_for_call=100)
        pipeline = TriagePipeline(settings)
        self.assertEqual(_result(pipeline).narrative_source, "template")

    def test_provider_failure_degrades(self) -> None:
        settings = make_settings(llm_enabled=True, llm_min_risk_for_call=0)
        pipeline = TriagePipeline(settings)
        pipeline.reporter = LLMReporter(settings, provider=_FailingProvider())
        result = _result(pipeline)
        self.assertTrue(result.degraded)
        self.assertEqual(result.narrative_source, "template")
        self.assertIn("模拟超时", result.meta.get("narrative_fallback_reason", ""))

    def test_phantom_rule_id_rejected(self) -> None:
        settings = make_settings(llm_enabled=True, llm_min_risk_for_call=0)
        pipeline = TriagePipeline(settings)
        pipeline.reporter = LLMReporter(settings, provider=_PhantomProvider())
        result = _result(pipeline)
        self.assertTrue(result.degraded)
        self.assertIn("不存在", result.meta.get("narrative_fallback_reason", ""))

    def test_fenced_json_accepted(self) -> None:
        settings = make_settings(llm_enabled=True, llm_min_risk_for_call=0)
        pipeline = TriagePipeline(settings)
        pipeline.reporter = LLMReporter(settings, provider=_FencedProvider())
        result = _result(pipeline)
        self.assertFalse(result.degraded)
        self.assertIn("拦截", result.analysis)

    def test_garbage_output_degrades(self) -> None:
        settings = make_settings(llm_enabled=True, llm_min_risk_for_call=0)
        pipeline = TriagePipeline(settings)
        pipeline.reporter = LLMReporter(settings, provider=_GarbageProvider())
        result = _result(pipeline)
        self.assertTrue(result.degraded)


class OpenAICompatTest(unittest.TestCase):
    def test_endpoint_normalisation(self) -> None:
        provider = OpenAICompatProvider("https://api.example.com/v1", "k", "m")
        self.assertEqual(provider._endpoint(), "https://api.example.com/v1/chat/completions")
        full = OpenAICompatProvider("https://api.example.com/v1/chat/completions", "k", "m")
        self.assertEqual(full._endpoint(), "https://api.example.com/v1/chat/completions")

    def test_connection_error_raises_llm_error(self) -> None:
        provider = OpenAICompatProvider(
            "http://127.0.0.1:9/v1", "k", "m", timeout=0.5, max_retries=0
        )
        with self.assertRaises(LLMError):
            provider.complete("sys", "user")


if __name__ == "__main__":
    unittest.main()
