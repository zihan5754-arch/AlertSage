"""归一化与字段映射测试。这一层错了，后面所有检测都会跟着错。"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from alertsage.errors import NormalizeError
from alertsage.normalize import (
    detect_source,
    ip_scope,
    normalize_alert,
    parse_port,
    parse_status,
    parse_timestamp,
)


class TimestampTest(unittest.TestCase):
    def test_iso_with_z(self) -> None:
        dt = parse_timestamp("2026-09-10T06:22:31Z")
        self.assertEqual(dt, datetime(2026, 9, 10, 6, 22, 31, tzinfo=timezone.utc))

    def test_iso_with_offset(self) -> None:
        dt = parse_timestamp("2026-09-10T14:22:31+08:00")
        self.assertEqual(dt.astimezone(timezone.utc).hour, 6)

    def test_space_separated(self) -> None:
        dt = parse_timestamp("2026-09-10 14:22:31")
        self.assertEqual(dt.tzinfo, timezone.utc)
        self.assertEqual(dt.hour, 14)

    def test_epoch_seconds(self) -> None:
        dt = parse_timestamp(1789000000)
        self.assertEqual(dt.year, 2026)

    def test_epoch_milliseconds(self) -> None:
        seconds = parse_timestamp(1789000000)
        millis = parse_timestamp(1789000000000)
        self.assertEqual(seconds.year, millis.year)
        self.assertLess(abs((millis - seconds).total_seconds()), 1)

    def test_epoch_microseconds(self) -> None:
        dt = parse_timestamp(1789000000000000)
        self.assertEqual(dt.year, 2026)

    def test_numeric_string(self) -> None:
        self.assertEqual(parse_timestamp("1789000000").year, 2026)

    def test_nginx_format(self) -> None:
        dt = parse_timestamp("10/Sep/2026:14:22:31 +0800")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.hour, 14)

    def test_invalid_raises(self) -> None:
        with self.assertRaises(NormalizeError):
            parse_timestamp("昨天下午")
        with self.assertRaises(NormalizeError):
            parse_timestamp(None)


class FieldMappingTest(unittest.TestCase):
    def test_elastic_nested_source(self) -> None:
        raw = {
            "_id": "abc123",
            "_source": {
                "@timestamp": "2026-09-10T06:00:00Z",
                "source": {"ip": "185.220.101.4"},
                "destination": {"ip": "10.20.3.8", "port": 443},
                "url": {"path": "/login"},
                "http": {"request": {"method": "POST"}},
                "event": {"category": "web", "outcome": "blocked"},
                "user_agent": "curl/8.0",
            },
        }
        alert = normalize_alert(raw)
        self.assertEqual(alert.source, "elastic")
        self.assertEqual(alert.src_ip, "185.220.101.4")
        self.assertEqual(alert.dst_ip, "10.20.3.8")
        self.assertEqual(alert.dst_port, 443)
        self.assertEqual(alert.target_url, "/login")
        self.assertEqual(alert.http_method, "POST")
        self.assertEqual(alert.action, "blocked")
        self.assertEqual(alert.alert_id, "abc123")

    def test_wazuh_flat_source(self) -> None:
        raw = {
            "timestamp": "2026-09-10T06:00:00Z",
            "rule": {"id": "5710", "description": "sshd: bruteforce"},
            "agent": {"name": "pay-api"},
            "data": {"srcip": "91.240.118.5", "dstport": 22},
            "full_log": "Failed password for root",
        }
        alert = normalize_alert(raw)
        self.assertEqual(alert.source, "wazuh")
        self.assertEqual(alert.alert_type, "sshd: bruteforce")
        self.assertEqual(alert.asset, "pay-api")
        self.assertEqual(alert.src_ip, "91.240.118.5")
        self.assertEqual(alert.dst_port, 22)

    def test_missing_timestamp_uses_now(self) -> None:
        alert = normalize_alert({"src_ip": "1.1.1.1"})
        self.assertIn("+00:00", alert.timestamp.isoformat())

    def test_unknown_source_is_generic(self) -> None:
        self.assertEqual(detect_source({"foo": "bar"}), "generic")

    def test_source_override(self) -> None:
        alert = normalize_alert({"src_ip": "1.1.1.1", "timestamp": "2026-09-10"}, source="custom")
        self.assertEqual(alert.source, "custom")

    def test_non_dict_raises(self) -> None:
        with self.assertRaises(NormalizeError):
            normalize_alert(["not", "a", "dict"])  # type: ignore[arg-type]

    def test_alert_id_is_stable(self) -> None:
        raw = {"src_ip": "1.1.1.1", "timestamp": "2026-09-10T00:00:00Z", "payload": "x"}
        self.assertEqual(normalize_alert(raw).alert_id, normalize_alert(dict(raw)).alert_id)


class HelperTest(unittest.TestCase):
    def test_ip_scope(self) -> None:
        self.assertEqual(ip_scope("10.0.0.1"), "private")
        self.assertEqual(ip_scope("192.168.1.1"), "private")
        self.assertEqual(ip_scope("8.8.8.8"), "public")
        self.assertEqual(ip_scope("127.0.0.1"), "loopback")
        self.assertEqual(ip_scope("not-an-ip"), "unknown")
        self.assertEqual(ip_scope(None), "unknown")

    def test_parse_port(self) -> None:
        self.assertEqual(parse_port("443"), 443)
        self.assertIsNone(parse_port("70000"))
        self.assertIsNone(parse_port("abc"))

    def test_parse_status(self) -> None:
        self.assertEqual(parse_status(404), 404)
        self.assertEqual(parse_status("500 Internal"), 500)
        self.assertIsNone(parse_status("nope"))

    def test_fingerprint_same_for_same_target(self) -> None:
        base = {
            "alert_id": "a",
            "timestamp": "2026-09-10T00:00:00Z",
            "src_ip": "1.1.1.1",
            "target_url": "/login",
        }
        first = normalize_alert(dict(base))
        other = normalize_alert({**base, "alert_id": "b"})
        self.assertEqual(first.fingerprint(), other.fingerprint())


if __name__ == "__main__":
    unittest.main()
