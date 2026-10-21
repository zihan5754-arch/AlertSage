"""关联与去重测试。"""

from __future__ import annotations

import unittest
from datetime import timedelta

from alertsage.correlate import Correlator
from tests.helpers import BASE_TIME, make_alert


class CorrelatorTest(unittest.TestCase):
    def test_duplicate_detection(self) -> None:
        correlator = Correlator(window_seconds=600, burst_threshold=8)
        first, dup_first = correlator.observe(make_alert())
        self.assertFalse(dup_first)
        second, dup_second = correlator.observe(make_alert(alert_id="test-0002"))
        self.assertTrue(dup_second)
        self.assertEqual(first.incident_id, second.incident_id)
        self.assertEqual(second.count, 2)

    def test_same_ip_different_target_same_incident(self) -> None:
        """同一 IP 刷不同路径必须归到一条线，否则去重和突发识别都会失效。"""
        correlator = Correlator()
        first, _ = correlator.observe(make_alert(target_url="/a"))
        incident, duplicate = correlator.observe(make_alert(target_url="/b"))
        self.assertTrue(duplicate)
        self.assertEqual(first.incident_id, incident.incident_id)
        self.assertEqual(incident.targets, ["/a", "/b"])

    def test_different_alert_type_is_not_duplicate(self) -> None:
        correlator = Correlator()
        correlator.observe(make_alert(alert_type="SQL Injection"))
        _, duplicate = correlator.observe(make_alert(alert_type="XSS"))
        self.assertFalse(duplicate)

    def test_burst_flag(self) -> None:
        correlator = Correlator(window_seconds=600, burst_threshold=3)
        for index in range(3):
            incident, _ = correlator.observe(
                make_alert(alert_id=f"b{index}", timestamp=BASE_TIME + timedelta(seconds=index))
            )
        self.assertTrue(incident.burst)
        self.assertEqual(incident.count, 3)

    def test_window_expiry_creates_new_incident(self) -> None:
        correlator = Correlator(window_seconds=60)
        first, _ = correlator.observe(make_alert(timestamp=BASE_TIME))
        later, duplicate = correlator.observe(
            make_alert(alert_id="late", timestamp=BASE_TIME + timedelta(minutes=5))
        )
        self.assertFalse(duplicate)
        self.assertNotEqual(first.incident_id, later.incident_id)

    def test_rule_ids_and_targets_accumulate(self) -> None:
        correlator = Correlator()
        correlator.observe(make_alert(target_url="/a"), ["R-1"])
        incident, _ = correlator.observe(make_alert(alert_id="x", target_url="/b"), ["R-2"])
        self.assertEqual(incident.rule_ids, ["R-1", "R-2"])
        self.assertEqual(incident.targets, ["/a", "/b"])

    def test_risk_updates_max(self) -> None:
        correlator = Correlator()
        correlator.observe(make_alert(), risk=20)
        incident, _ = correlator.observe(make_alert(alert_id="y"), risk=60)
        self.assertEqual(incident.max_risk, 60)
        correlator.observe(make_alert(alert_id="z"), risk=10)
        self.assertEqual(incident.max_risk, 60)

    def test_stats_and_reset(self) -> None:
        correlator = Correlator(burst_threshold=2)
        correlator.observe(make_alert())
        correlator.observe(make_alert(alert_id="b"))
        stats = correlator.stats()
        self.assertEqual(stats["tracked_fingerprints"], 1)
        self.assertEqual(stats["total_observations"], 2)
        correlator.reset()
        self.assertEqual(correlator.stats()["tracked_fingerprints"], 0)

    def test_snapshot(self) -> None:
        correlator = Correlator()
        correlator.observe(make_alert())
        snapshot = correlator.snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertIn("count", next(iter(snapshot.values())))


if __name__ == "__main__":
    unittest.main()
