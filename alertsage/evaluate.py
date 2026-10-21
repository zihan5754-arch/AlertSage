"""离线评估：把"感觉挺准"变成可复现的数字。

评估集的每条样本带人工标签（true_positive / false_positive / needs_review），
输出三分类混淆矩阵 + 二分类指标 + 各攻击类型召回 + 误报抑制率 + 延迟。

注意：data/samples 里是合成数据，指标只用于回归对比，不代表真实护网效果。
这句话必须写进 README，面试时也要主动说——比吹一个虚高的数字可信。
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .errors import NormalizeError
from .models import VERDICTS
from .normalize import parse_timestamp
from .pipeline import TriagePipeline


@dataclass(slots=True)
class EvalReport:
    total: int = 0
    accuracy: float = 0.0
    auto_triage_rate: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    fp_leak_rate: float = 0.0
    confusion: dict[str, dict[str, int]] = field(default_factory=dict)
    per_category: dict[str, dict[str, float]] = field(default_factory=dict)
    latency: dict[str, float] = field(default_factory=dict)
    mistakes: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "accuracy": self.accuracy,
            "auto_triage_rate": self.auto_triage_rate,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "fp_leak_rate": self.fp_leak_rate,
            "confusion": self.confusion,
            "per_category": self.per_category,
            "latency": self.latency,
            "mistakes": self.mistakes,
        }


def load_labeled(path: Path | str) -> list[dict[str, Any]]:
    """每行一个对象：告警字段 + _label（+ 可选 _category / _label_reason）。"""
    samples: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if "_label" not in item:
                raise ValueError(f"第 {line_no} 行缺少 _label")
            if item["_label"] not in VERDICTS:
                raise ValueError(f"第 {line_no} 行 _label 非法: {item['_label']}")
            samples.append(item)
    return samples


def _time_key(sample: dict[str, Any]) -> tuple[int, float]:
    """按时间排序的 key；解析不了时间的样本排到最后，不静默丢数据。"""
    for field in ("timestamp", "@timestamp", "event.created", "date"):
        value = sample.get(field)
        if value:
            try:
                return (0, parse_timestamp(value).timestamp())
            except NormalizeError:
                continue
    return (1, 0.0)


def evaluate(pipeline: TriagePipeline, samples: Iterable[dict[str, Any]]) -> EvalReport:
    pipeline.reset()
    # 按时间顺序回放：行为基线和关联窗口都是时间相关的，
    # 乱序回放会产生虚假的突发/重复，指标就没有意义了。
    ordered = sorted(samples, key=_time_key)
    report = EvalReport()
    report.confusion = {actual: {pred: 0 for pred in VERDICTS} for actual in VERDICTS}

    correct = 0
    latencies: list[float] = []
    per_category: dict[str, list[bool]] = {}
    tp = fp = fn = 0
    fp_total = 0
    fp_suppressed = 0
    auto = 0

    for sample in ordered:
        item = dict(sample)
        truth = item.pop("_label")
        category = item.pop("_category", "unknown")
        item.pop("_label_reason", None)

        result = pipeline.triage_raw(item)
        latencies.append(result.elapsed_ms)
        report.total += 1
        report.confusion[truth][result.verdict] += 1

        if result.verdict == truth:
            correct += 1
        else:
            report.mistakes.append(
                {
                    "alert_id": result.alert_id,
                    "truth": truth,
                    "predicted": result.verdict,
                    "risk": result.risk_score,
                    "rules": [d.rule_id for d in result.detections],
                }
            )

        if result.verdict != "needs_review":
            auto += 1

        per_category.setdefault(category, []).append(result.verdict == truth)

        if truth == "true_positive":
            tp += result.verdict == "true_positive"
            fn += result.verdict != "true_positive"
        elif truth == "false_positive":
            fp_total += 1
            fp += result.verdict == "true_positive"
            fp_suppressed += result.verdict == "false_positive"

    if report.total:
        report.accuracy = round(correct / report.total, 4)
        report.auto_triage_rate = round(auto / report.total, 4)
        report.latency = {
            "p50_ms": _pct(latencies, 50),
            "p95_ms": _pct(latencies, 95),
            "max_ms": round(max(latencies), 2),
        }

    # 把 needs_review 当作"未报警"的保守口径
    report.precision = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
    report.recall = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
    report.f1 = (
        round(2 * report.precision * report.recall / (report.precision + report.recall), 4)
        if (report.precision + report.recall)
        else 0.0
    )
    report.fp_leak_rate = round(fp / fp_total, 4) if fp_total else 0.0
    report.per_category = {
        name: {"accuracy": round(sum(hits) / len(hits), 4), "samples": len(hits)}
        for name, hits in sorted(per_category.items())
    }
    return report


def _pct(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return round(ordered[index], 2)


def render_eval_markdown(report: EvalReport) -> str:
    lines = [
        "## 评估结果（合成数据集）",
        "",
        f"- 样本数：**{report.total}**",
        f"- 三分类准确率：**{report.accuracy:.2%}**",
        f"- 自动定性率（不需要人工介入）：**{report.auto_triage_rate:.2%}**",
        f"- 真实攻击查准率 / 查全率 / F1：**{report.precision:.2%}** / **{report.recall:.2%}** / **{report.f1:.2%}**",
        f"- 误报漏放率（误报被打成真实攻击）：**{report.fp_leak_rate:.2%}**",
        f"- 单条耗时：p50 {report.latency.get('p50_ms', 0)} ms，p95 {report.latency.get('p95_ms', 0)} ms",
        "",
        "### 混淆矩阵（行=人工标签，列=系统结论）",
        "",
        "| 标签 \\ 结论 | true_positive | false_positive | needs_review |",
        "| --- | ---: | ---: | ---: |",
    ]
    for actual in VERDICTS:
        row = report.confusion.get(actual, {})
        lines.append(
            f"| {actual} | {row.get('true_positive', 0)} | {row.get('false_positive', 0)} | {row.get('needs_review', 0)} |"
        )

    if report.per_category:
        lines += ["", "### 分类型准确率", "", "| 类型 | 样本 | 准确率 |", "| --- | ---: | ---: |"]
        for name, stats in report.per_category.items():
            lines.append(f"| {name} | {stats['samples']} | {stats['accuracy']:.2%} |")

    if report.mistakes:
        lines += ["", "### 判定偏差样本（最多 5 条）", ""]
        for item in report.mistakes[:5]:
            lines.append(
                f"- `{item['alert_id']}` 人工={item['truth']} 系统={item['predicted']} "
                f"风险={item['risk']} 规则={item['rules']}"
            )
    return "\n".join(lines) + "\n"
