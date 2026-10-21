"""评估模块测试：混淆矩阵不能算错，否则 README 上的数字就是假的。"""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from alertsage.evaluate import evaluate, load_labeled, render_eval_markdown
from tests.helpers import make_pipeline

SAMPLES = [
    {
        "alert_type": "SQL Injection",
        "timestamp": "2026-09-10T10:00:00+08:00",
        "src_ip": "45.134.26.17",
        "payload": "1 union select 1",
        "_label": "true_positive",
        "_category": "sqli",
    },
    {
        "alert_type": "HTTP 200",
        "timestamp": "2026-09-10T10:01:00+08:00",
        "src_ip": "10.0.0.5",
        "target_url": "/health",
        "_label": "false_positive",
        "_category": "health_check",
    },
    {
        "alert_type": "Unknown Event",
        "timestamp": "2026-09-10T10:02:00+08:00",
        "src_ip": "8.8.8.8",
        "raw_log": "odd",
        "_label": "needs_review",
        "_category": "unknown",
    },
]


class EvaluateTest(unittest.TestCase):
    def test_confusion_matrix_complete(self) -> None:
        report = evaluate(make_pipeline(), SAMPLES)
        self.assertEqual(report.total, 3)
        total_from_matrix = sum(
            count for row in report.confusion.values() for count in row.values()
        )
        self.assertEqual(total_from_matrix, 3)

    def test_metrics_in_range(self) -> None:
        report = evaluate(make_pipeline(), SAMPLES)
        for value in (report.accuracy, report.precision, report.recall, report.f1):
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 1.0)

    def test_perfect_predictions_give_accuracy_one(self) -> None:
        report = evaluate(make_pipeline(), SAMPLES)
        self.assertEqual(report.accuracy, 1.0)
        self.assertEqual(report.mistakes, [])

    def test_mistakes_recorded(self) -> None:
        wrong = dict(SAMPLES[1])
        wrong["_label"] = "true_positive"  # 健康检查被标成攻击，系统应该判误报
        report = evaluate(make_pipeline(), [SAMPLES[0], wrong])
        self.assertTrue(report.mistakes)
        self.assertEqual(report.mistakes[0]["truth"], "true_positive")

    def test_per_category(self) -> None:
        report = evaluate(make_pipeline(), SAMPLES)
        self.assertIn("sqli", report.per_category)
        self.assertEqual(report.per_category["sqli"]["samples"], 1)

    def test_latency(self) -> None:
        report = evaluate(make_pipeline(), SAMPLES)
        self.assertIn("p95_ms", report.latency)
        self.assertGreaterEqual(report.latency["p95_ms"], 0)

    def test_markdown_render(self) -> None:
        text = render_eval_markdown(evaluate(make_pipeline(), SAMPLES))
        self.assertIn("混淆矩阵", text)
        self.assertIn("三分类准确率", text)


class LoadLabeledTest(unittest.TestCase):
    def test_load_ok(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "d.jsonl"
            path.write_text(
                "\n".join(json.dumps(s, ensure_ascii=False) for s in SAMPLES),
                encoding="utf-8",
            )
            self.assertEqual(len(load_labeled(path)), 3)

    def test_missing_label_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.jsonl"
            path.write_text(json.dumps({"alert_type": "x"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_labeled(path)

    def test_bad_label_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad2.jsonl"
            path.write_text(json.dumps({"alert_type": "x", "_label": "maybe"}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_labeled(path)


if __name__ == "__main__":
    unittest.main()
