"""测试公共工具。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from alertsage.config import load_settings
from alertsage.models import Alert
from alertsage.pipeline import TriagePipeline
from alertsage.rules import load_rules

TZ = timezone(timedelta(hours=8))
BASE_TIME = datetime(2026, 9, 10, 10, 0, 0, tzinfo=TZ)


def make_alert(**overrides) -> Alert:
    payload = {
        "alert_id": "test-0001",
        "source": "generic",
        "alert_type": "Web Attack",
        "timestamp": BASE_TIME,
        "src_ip": "45.134.26.17",
        "dst_ip": "10.20.3.8",
        "dst_port": 443,
        "target_url": "/api/order",
        "http_method": "GET",
        "status_code": 200,
        "user_agent": "Mozilla/5.0",
        "payload": None,
        "raw_log": None,
        "asset": "order-api",
        "action": "logged",
    }
    payload.update(overrides)
    return Alert(**payload)


def make_settings(**overrides):
    defaults = {"true_positive_threshold": 45, "false_positive_threshold": 22}
    defaults.update(overrides)
    return load_settings(**defaults)


def make_pipeline(**settings_overrides) -> TriagePipeline:
    return TriagePipeline(make_settings(**settings_overrides), rules=load_rules())
