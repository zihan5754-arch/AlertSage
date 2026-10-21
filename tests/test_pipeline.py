"""端到端测试：pipeline 是最终交付的入口，这一层必须是绿的。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from alertsage.pipeline import TriagePipeline
from tests.helpers import make_pipeline, make_settings

DEMO = {
    "alert_type": "SQL Injection",
    "timestamp": "2026-09-10T14:22:31+08:00",
    "src_ip": "45.134.26.17",
    "dst_ip": "10.20.3.8",
    "dst_port": 443,
    "target_url": "/api/order?id=1 union select 1,2,3--",
    "status_code": 500,
    "user_agent": "sqlmap/1.7.2",
    "payload": "1 union select username,password from users--",
    "asset": "order-api",
}


class PipelineTest(unittest.TestCase):
    def setUp(self) -> None:
        self.pipeline = make_pipeline()

    def test_full_triage(self) -> None:
        result = self.pipeline.triage_raw(DEMO)
        self.assertEqual(result.verdict, "true_positive")
        self.assertGreaterEqual(result.risk_score, 45)
        self.assertTrue(result.detections)
        self.assertTrue(result.analysis)
        self.assertIn("T1190", result.mitre_techniques)
        self.assertTrue(result.recommendations)
        self.assertGreaterEqual(result.elapsed_ms, 0)
        self.assertEqual(result.narrative_source, "template")

    def test_result_serialisable(self) -> None:
        payload = self.pipeline.triage_raw(DEMO).to_dict()
        text = json.dumps(payload, ensure_ascii=False)
        self.assertIn("risk_score", text)
        self.assertIn("score_breakdown", payload["meta"])

    def test_duplicate_alert_gets_flagged(self) -> None:
        first = self.pipeline.triage_raw(DEMO)
        second = self.pipeline.triage_raw(DEMO)
        self.assertIsNotNone(second.duplicate_of)
        self.assertEqual(first.incident.incident_id, second.incident.incident_id)
        self.assertLessEqual(second.risk_score, first.risk_score)

    def test_state_is_pipeline_scoped(self) -> None:
        self.pipeline.triage_raw(DEMO)
        fresh = make_pipeline()
        self.assertIsNone(fresh.triage_raw(DEMO).duplicate_of)

    def test_deterministic(self) -> None:
        a = make_pipeline().triage_raw(DEMO)
        b = make_pipeline().triage_raw(DEMO)
        self.assertEqual(a.risk_score, b.risk_score)
        self.assertEqual(a.verdict, b.verdict)

    def test_batch_collects_parse_errors(self) -> None:
        results, summary = self.pipeline.triage_batch([DEMO, ["not", "an", "alert"], DEMO])
        self.assertEqual(len(results), 2)
        self.assertEqual(len(summary["errors"]), 1)
        self.assertEqual(summary["total"], 2)
        self.assertIn("auto_triage_rate", summary)

    def test_batch_summary_has_latency(self) -> None:
        _, summary = self.pipeline.triage_batch([DEMO, DEMO])
        self.assertIn("p50_ms", summary)
        self.assertIn("p95_ms", summary)
        self.assertIn("verdicts", summary)

    def test_triage_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "alerts.jsonl"
            path.write_text(
                "\n".join(json.dumps(DEMO, ensure_ascii=False) for _ in range(3)),
                encoding="utf-8",
            )
            results, summary = self.pipeline.triage_file(path)
            self.assertEqual(len(results), 3)
            self.assertEqual(summary["total"], 3)

    def test_reset_clears_state(self) -> None:
        self.pipeline.triage_raw(DEMO)
        self.assertEqual(self.pipeline.stats()["processed"], 1)
        self.pipeline.reset()
        self.assertEqual(self.pipeline.stats()["processed"], 0)

    def test_stats(self) -> None:
        stats = self.pipeline.stats()
        self.assertGreaterEqual(stats["rules"], 16)
        self.assertIn("rule_engine", stats["detectors"])
        self.assertIn("anomaly", stats["detectors"])

    def test_llm_enabled_pipeline(self) -> None:
        pipeline = TriagePipeline(
            make_settings(llm_enabled=True, llm_provider="mock", llm_min_risk_for_call=0)
        )
        result = pipeline.triage_raw(DEMO)
        self.assertEqual(result.narrative_source, "llm")

    def test_unknown_alert_type(self) -> None:
        result = self.pipeline.triage_raw(
            {
                "alert_type": "Unknown Event",
                "timestamp": "2026-09-10T10:00:00Z",
                "src_ip": "8.8.8.8",
                "raw_log": "something odd",
            }
        )
        self.assertEqual(result.verdict, "needs_review")
        self.assertEqual(result.detections, [])


if __name__ == "__main__":
    unittest.main()
