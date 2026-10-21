"""规则引擎测试：加载、校验、条件 DSL。"""

from __future__ import annotations

import unittest
from pathlib import Path

from alertsage.errors import RuleError
from alertsage.rules import (
    DEFAULT_RULES_DIR,
    lint_rules,
    load_rules,
    parse_rule,
    rule_to_detection,
)
from tests.helpers import make_alert


def _rule(match: dict, **kwargs) -> "object":
    payload = {
        "id": "TEST-001",
        "title": "测试规则",
        "severity": "high",
        "match": match,
        "mitre": ["T1190"],
        "recommendations": ["看看"],
        "description": "测试用",
    }
    payload.update(kwargs)
    return parse_rule(payload)


class LoadRulesTest(unittest.TestCase):
    def test_default_rules_loaded(self) -> None:
        rules = load_rules()
        self.assertGreaterEqual(len(rules), 16)
        self.assertTrue(all(r.id for r in rules))

    def test_ids_unique(self) -> None:
        ids = [r.id for r in load_rules()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_lint_is_clean(self) -> None:
        self.assertEqual(lint_rules(load_rules()), [])

    def test_sorted_by_severity(self) -> None:
        rules = load_rules()
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        ranks = [order[r.severity] for r in rules]
        self.assertEqual(ranks, sorted(ranks, reverse=True))

    def test_missing_dir_raises(self) -> None:
        with self.assertRaises(RuleError):
            load_rules(Path(DEFAULT_RULES_DIR) / "not-exists")


class ValidateRuleTest(unittest.TestCase):
    def test_missing_field(self) -> None:
        with self.assertRaises(RuleError):
            parse_rule({"id": "X", "title": "t", "severity": "high"})

    def test_bad_severity(self) -> None:
        with self.assertRaises(RuleError):
            _rule({"text": "x"}, severity="apocalyptic")

    def test_bad_regex(self) -> None:
        with self.assertRaises(RuleError):
            _rule({"text": "regex:([unclosed"})

    def test_bad_operator(self) -> None:
        with self.assertRaises(RuleError):
            _rule({"field": "payload", "starts_with": "x"})

    def test_empty_any(self) -> None:
        with self.assertRaises(RuleError):
            _rule({"any": []})

    def test_bad_confidence(self) -> None:
        with self.assertRaises(RuleError):
            _rule({"text": "x"}, confidence=2.0)


class ConditionTest(unittest.TestCase):
    def test_text_regex(self) -> None:
        rule = _rule({"text": "regex:(?i)union\\s+select"})
        ok, reasons = rule.matches(make_alert(payload="1 UNION SELECT 2"))
        self.assertTrue(ok)
        self.assertTrue(reasons)

    def test_text_plain(self) -> None:
        rule = _rule({"text": "php://filter"})
        self.assertTrue(rule.matches(make_alert(payload="page=php://filter/x"))[0])
        self.assertFalse(rule.matches(make_alert(payload="normal"))[0])

    def test_all_and_any(self) -> None:
        rule = _rule(
            {
                "all": [
                    {"field": "status_code", "equals": 200},
                    {"any": [{"field": "payload", "contains": "sleep"}, {"field": "payload", "contains": "benchmark"}]},
                ]
            }
        )
        self.assertTrue(rule.matches(make_alert(status_code=200, payload="SELECT sleep(5)"))[0])
        self.assertFalse(rule.matches(make_alert(status_code=500, payload="SELECT sleep(5)"))[0])
        self.assertFalse(rule.matches(make_alert(status_code=200, payload="SELECT 1"))[0])

    def test_not(self) -> None:
        rule = _rule({"not": {"field": "user_agent", "contains": "googlebot"}})
        self.assertTrue(rule.matches(make_alert(user_agent="curl/8"))[0])
        self.assertFalse(rule.matches(make_alert(user_agent="Googlebot/2.1"))[0])

    def test_contains_any(self) -> None:
        rule = _rule({"field": "alert_type", "contains_any": ["brute", "暴力"]})
        self.assertTrue(rule.matches(make_alert(alert_type="SSH Brute Force"))[0])
        self.assertFalse(rule.matches(make_alert(alert_type="DNS"))[0])

    def test_in_and_numeric(self) -> None:
        rule = _rule({"all": [{"field": "status_code", "in": [401, 403]}, {"field": "dst_port", "gt": 100}]})
        self.assertTrue(rule.matches(make_alert(status_code=401, dst_port=443))[0])
        self.assertFalse(rule.matches(make_alert(status_code=200, dst_port=443))[0])

    def test_startswith_endswith(self) -> None:
        rule = _rule({"all": [{"field": "target_url", "startswith": "/api"}, {"field": "target_url", "endswith": ".php"}]})
        self.assertTrue(rule.matches(make_alert(target_url="/api/x.php"))[0])
        self.assertFalse(rule.matches(make_alert(target_url="/api/x.jsp"))[0])

    def test_exists(self) -> None:
        rule = _rule({"field": "payload", "exists": True})
        self.assertTrue(rule.matches(make_alert(payload="x"))[0])
        self.assertFalse(rule.matches(make_alert(payload=None))[0])

    def test_missing_field_fails(self) -> None:
        rule = _rule({"field": "payload", "contains": "x"})
        self.assertFalse(rule.matches(make_alert(payload=None))[0])

    def test_weight_delta_and_recommendations(self) -> None:
        rule = _rule({"text": "x"}, weight_delta=-8)
        detection = rule_to_detection(rule, ["命中说明"])
        self.assertEqual(detection.rule_id, "TEST-001")
        self.assertEqual(detection.evidence[0].detail, "命中说明")
        self.assertEqual(detection.mitre, ["T1190"])


if __name__ == "__main__":
    unittest.main()
