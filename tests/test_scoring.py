"""打分逻辑测试。这些断言就是"产品规则"的可执行文档。"""

from __future__ import annotations

import unittest

from alertsage.models import Detection, Evidence, Incident
from alertsage.scoring import (
    asset_multiplier,
    build_recommendations,
    is_allowlisted,
    score,
)
from tests.helpers import make_alert, make_settings


def detection(
    rule_id: str = "WEB-SQLI-001",
    severity: str = "high",
    confidence: float = 0.86,
    category: str = "web",
    recommendations: list[str] | None = None,
    weight: int = 0,
) -> Detection:
    return Detection(
        rule_id=rule_id,
        title="测试命中",
        severity=severity,
        category=category,
        confidence=confidence,
        mitre=["T1190"],
        evidence=[Evidence(kind="rule", code=rule_id, detail="d", weight=weight)],
        recommendations=recommendations or ["处置"],
    )


class NoMatchTest(unittest.TestCase):
    def test_benign_no_match_is_false_positive(self) -> None:
        settings = make_settings()
        alert = make_alert(alert_type="HTTP 200", target_url="/health", payload=None, raw_log=None)
        result = score(alert, [], settings)
        self.assertEqual(result.verdict, "false_positive")
        self.assertGreaterEqual(result.fp_probability, 0.6)

    def test_suspicious_no_match_needs_review(self) -> None:
        settings = make_settings()
        alert = make_alert(alert_type="Suspicious DNS Query", payload=None, raw_log="query x")
        result = score(alert, [], settings)
        self.assertEqual(result.verdict, "needs_review")

    def test_error_status_no_match_needs_review(self) -> None:
        result = score(make_alert(status_code=500, payload=None, raw_log=None), [], make_settings())
        self.assertEqual(result.verdict, "needs_review")

    def test_unknown_attack_wording_needs_review(self) -> None:
        result = score(make_alert(alert_type="Web Attack - Evasion"), [], make_settings())
        self.assertEqual(result.verdict, "needs_review")


class DetectionScoreTest(unittest.TestCase):
    def test_high_severity_is_true_positive(self) -> None:
        result = score(make_alert(), [detection()], make_settings())
        self.assertEqual(result.verdict, "true_positive")
        self.assertGreaterEqual(result.risk_score, 45)

    def test_low_severity_single_hit_is_not_actionable(self) -> None:
        result = score(
            make_alert(target_url="/wp-login.php", status_code=404),
            [detection("WEB-SCAN-001", "low", 0.62, "recon")],
            make_settings(),
        )
        self.assertNotEqual(result.verdict, "true_positive")

    def test_multi_rule_increases_risk(self) -> None:
        one = score(make_alert(), [detection()], make_settings())
        two = score(
            make_alert(),
            [detection(), detection("WEB-SQLI-002", "critical", 0.9)],
            make_settings(),
        )
        self.assertGreater(two.risk_score, one.risk_score)

    def test_regex_fallback_does_not_double_count(self) -> None:
        base = score(make_alert(), [detection()], make_settings())
        with_regex = score(
            make_alert(),
            [detection(), detection("REGEX-SQLI", "high", 0.55, "regex")],
            make_settings(),
        )
        self.assertEqual(base.risk_score, with_regex.risk_score)

    def test_breakdown_matches_risk(self) -> None:
        result = score(make_alert(), [detection()], make_settings())
        last = result.breakdown[-1]["total"]
        self.assertAlmostEqual(last, result.risk_score, delta=1.0)

    def test_risk_never_exceeds_100(self) -> None:
        many = [detection(f"R-{i}", "critical", 0.95) for i in range(6)]
        result = score(make_alert(), many, make_settings())
        self.assertLessEqual(result.risk_score, 100)


class SuppressionTest(unittest.TestCase):
    def test_allowlist_drops_to_false_positive(self) -> None:
        settings = make_settings(allowlist=(r"^10\.0\.0\.",))
        alert = make_alert(src_ip="10.0.0.21", payload="1 union select 1")
        result = score(alert, [detection()], settings)
        self.assertEqual(result.verdict, "false_positive")
        self.assertIn("SUP-ALLOWLIST", [e.code for e in result.evidence])

    def test_duplicate_lowers_risk(self) -> None:
        one = score(make_alert(), [detection()], make_settings())
        dup = score(make_alert(), [detection()], make_settings(), duplicate=True)
        self.assertLess(dup.risk_score, one.risk_score)
        self.assertGreater(dup.fp_probability, one.fp_probability)

    def test_blocked_lowers_risk(self) -> None:
        one = score(make_alert(), [detection()], make_settings())
        blocked = score(make_alert(action="blocked"), [detection()], make_settings())
        self.assertLess(blocked.risk_score, one.risk_score)
        self.assertIn("ACTION", [e.code for e in blocked.evidence])

    def test_scanner_ua_lowers_low_severity(self) -> None:
        alert = make_alert(user_agent="nikto/2.5", status_code=404, target_url="/x")
        result = score(alert, [detection("WEB-SCAN-001", "low", 0.62, "recon")], make_settings())
        self.assertIn("UA-SCANNER", [e.code for e in result.evidence])

    def test_burst_raises_risk(self) -> None:
        incident = Incident(
            incident_id="INC-1",
            fingerprint="fp",
            first_seen=make_alert().timestamp,
            last_seen=make_alert().timestamp,
            count=12,
            burst=True,
        )
        without = score(make_alert(), [detection()], make_settings())
        with_burst = score(make_alert(), [detection()], make_settings(), incident=incident)
        self.assertGreater(with_burst.risk_score, without.risk_score)


class HelperTest(unittest.TestCase):
    def test_asset_multiplier_exact_and_wildcard(self) -> None:
        settings = make_settings(asset_criticality={"pay-api": 1.15, "prod-*": 1.3})
        self.assertAlmostEqual(asset_multiplier(settings, "pay-api"), 1.15)
        self.assertAlmostEqual(asset_multiplier(settings, "prod-db"), 1.3)
        self.assertAlmostEqual(asset_multiplier(settings, "wiki"), 1.0)
        self.assertAlmostEqual(asset_multiplier(settings, None), 1.0)

    def test_asset_multiplier_affects_score(self) -> None:
        plain = score(make_alert(asset="wiki"), [detection()], make_settings())
        critical = score(
            make_alert(asset="pay-api"),
            [detection()],
            make_settings(asset_criticality={"pay-api": 1.2}),
        )
        self.assertGreater(critical.risk_score, plain.risk_score)

    def test_allowlist_regex_and_plain(self) -> None:
        settings = make_settings(allowlist=("^10\\.", "203.0.113.9"))
        self.assertTrue(is_allowlisted(settings, "10.1.2.3"))
        self.assertTrue(is_allowlisted(settings, "203.0.113.9"))
        self.assertFalse(is_allowlisted(settings, "8.8.8.8"))
        self.assertFalse(is_allowlisted(settings, None))

    def test_recommendations_dedup_and_verdict_hint(self) -> None:
        merged = build_recommendations(
            [detection(recommendations=["封禁", "封禁"]), detection("B", recommendations=["封禁", "排查"])],
            "true_positive",
            "high",
        )
        self.assertEqual(merged.count("封禁"), 1)
        self.assertTrue(any("升级为安全事件" in item for item in merged))

    def test_false_positive_recommendation(self) -> None:
        merged = build_recommendations([detection()], "false_positive", "low")
        self.assertTrue(any("关闭该告警" in item for item in merged))


if __name__ == "__main__":
    unittest.main()
