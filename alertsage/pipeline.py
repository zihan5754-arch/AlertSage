"""研判主流程编排。

一条告警的完整生命周期：

    原始 JSON
      → normalize        统一字段、解析时间、IP 归类
      → detect           规则引擎 + 正则兜底 + 行为异常（并行产出证据）
      → correlate        指纹去重、突发识别
      → score            风险分 + 误报概率 + 结论（可解释）
      → narrate          模板或 LLM 写成人话（可降级）
      → TriageResult     可直接进工单/报告/接口

每一步都只依赖上一步的数据结构，所以任何一步都能单独替换、单独测试。
"""

from __future__ import annotations

import json
import time
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from .config import Settings, load_settings
from .correlate import Correlator
from .detectors import Detector, DetectorContext, build_detectors
from .errors import AlertsageError, NormalizeError
from .llm import LLMReporter
from .models import SEVERITY_BASE, Alert, Detection, TriageResult, severity_rank
from .normalize import ip_scope, normalize_alert
from .rules import Rule, load_rules
from .scoring import build_recommendations, score


class TriagePipeline:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        rules: list[Rule] | None = None,
        detectors: list[Detector] | None = None,
        reporter: LLMReporter | None = None,
    ) -> None:
        self.settings = settings or load_settings()
        self.rules = rules if rules is not None else load_rules(self.settings.rules_dir)
        self.detectors = detectors if detectors is not None else build_detectors(self.rules)
        self.reporter = reporter if reporter is not None else LLMReporter(self.settings)
        self.correlator = Correlator(
            window_seconds=self.settings.correlate_window_seconds,
            burst_threshold=self.settings.burst_threshold,
        )
        self._processed = 0
        self._errors: list[str] = []

    # ------------------------------------------------------------ 对外
    def reset(self) -> None:
        """清空行为基线/关联状态，测试和长驻服务切换批次时用。"""
        for detector in self.detectors:
            reset = getattr(detector, "reset", None)
            if callable(reset):
                reset()
        self.correlator.reset()
        self._processed = 0
        self._errors.clear()

    def triage_raw(self, raw: dict[str, Any], source: str | None = None) -> TriageResult:
        return self.triage(normalize_alert(raw, source))

    def triage(self, alert: Alert) -> TriageResult:
        started = time.perf_counter()
        ctx = DetectorContext(settings=self.settings, state={})

        detections: list[Detection] = []
        for detector in self.detectors:
            try:
                detections.extend(detector.detect(alert, ctx))
            except Exception as exc:  # noqa: BLE001 - 单个检测器异常不能拖垮整批
                self._errors.append(f"{getattr(detector, 'name', 'detector')}: {exc}")

        incident, duplicate = self.correlator.observe(
            alert, [d.rule_id for d in detections], risk=0
        )
        scored = score(
            alert,
            detections,
            self.settings,
            duplicate=duplicate,
            incident=incident,
        )
        incident.max_risk = max(incident.max_risk, scored.risk_score)

        primary = _primary(detections)
        severity = primary.severity if primary else "info"
        attack_type = primary.title if primary else (alert.alert_type or "未知")
        recommendations = build_recommendations(detections, scored.verdict, severity)

        result = TriageResult(
            alert_id=alert.alert_id,
            verdict=scored.verdict,
            attack_type=attack_type,
            severity=severity,
            risk_score=scored.risk_score,
            fp_probability=scored.fp_probability,
            confidence=scored.confidence,
            detections=detections,
            evidence=scored.evidence,
            recommendations=recommendations,
            incident=incident,
            duplicate_of=incident.incident_id if duplicate else None,
            meta={
                "source": alert.source,
                "src_scope": ip_scope(alert.src_ip),
                "score_breakdown": scored.breakdown,
                "detector_errors": len(self._errors),
            },
        )

        narrative = self.reporter.narrate(alert, result)
        result.analysis = narrative.analysis
        result.narrative_source = narrative.source
        result.degraded = narrative.degraded
        if narrative.reason:
            result.meta["narrative_fallback_reason"] = narrative.reason

        result.elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        self._processed += 1
        return result

    def triage_batch(
        self, raws: Iterable[dict[str, Any]], source: str | None = None
    ) -> tuple[list[TriageResult], dict[str, Any]]:
        results: list[TriageResult] = []
        errors: list[dict[str, str]] = []
        for index, raw in enumerate(raws):
            try:
                results.append(self.triage_raw(raw, source))
            except NormalizeError as exc:
                errors.append({"index": str(index), "error": str(exc)})
            except AlertsageError as exc:
                errors.append({"index": str(index), "error": str(exc)})
        return results, self.summarize(results, errors)

    def triage_file(self, path: Path | str) -> tuple[list[TriageResult], dict[str, Any]]:
        raws = []
        with Path(path).open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    raws.append(json.loads(line))
        return self.triage_batch(raws)

    # ------------------------------------------------------------ 统计
    def summarize(
        self, results: list[TriageResult], errors: list[dict[str, str]] | None = None
    ) -> dict[str, Any]:
        verdicts = Counter(r.verdict for r in results)
        severities = Counter(r.severity for r in results)
        techniques = Counter(t for r in results for t in r.mitre_techniques)
        exposures = sum(1 for r in results if r.mitre_techniques)
        return {
            "total": len(results),
            "verdicts": dict(verdicts),
            "severities": dict(severities),
            "auto_triage_rate": round(
                sum(1 for r in results if r.verdict != "needs_review") / len(results), 4
            )
            if results
            else 0.0,
            "needs_review_rate": round(verdicts.get("needs_review", 0) / len(results), 4)
            if results
            else 0.0,
            "top_techniques": techniques.most_common(8),
            "avg_risk": round(sum(r.risk_score for r in results) / len(results), 1) if results else 0,
            "p50_ms": _percentile([r.elapsed_ms for r in results], 50),
            "p95_ms": _percentile([r.elapsed_ms for r in results], 95),
            "llm_used": sum(1 for r in results if r.narrative_source == "llm"),
            "degraded": sum(1 for r in results if r.degraded),
            "errors": errors or [],
            "correlation": self.correlator.stats(),
        }

    def stats(self) -> dict[str, Any]:
        return {
            "rules": len(self.rules),
            "detectors": [getattr(d, "name", "?") for d in self.detectors],
            "processed": self._processed,
            "detector_errors": list(self._errors),
            "correlation": self.correlator.stats(),
        }


def _primary(detections: list[Detection]) -> Detection | None:
    if not detections:
        return None
    return max(
        detections,
        key=lambda d: (SEVERITY_BASE[d.severity] * d.confidence, severity_rank(d.severity)),
    )


def _percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((pct / 100) * (len(ordered) - 1)))))
    return round(ordered[index], 2)
