"""多源告警归一化。

真实环境里告警来自 WAF、EDR、IDS、云审计，字段名完全不一样。
这一步的价值在于：后面的规则引擎只认一套字段，新增数据源只要加一张别名表，
而不是去改检测逻辑。面试时这也是"为什么要有这一层"的答案。
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from typing import Any

from .errors import NormalizeError
from .models import Alert

# ---------------------------------------------------------------- 字段别名表
# key: 归一化后的字段名；value: 各数据源里可能出现的字段路径（支持点号取嵌套）
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "alert_type": (
        "alert_type",
        "rule_description",
        "rule.description",
        "signature",
        "event.action",
        "event.category",
        "threat.technique.name",
    ),
    "src_ip": ("src_ip", "source_ip", "srcip", "source.ip", "src.ip", "data.srcip", "client_ip"),
    "dst_ip": ("dst_ip", "dest_ip", "destination_ip", "destination.ip", "dest.ip", "data.dstip"),
    "dst_port": ("dst_port", "dest_port", "destination.port", "dest.port", "data.dstport"),
    "target_url": (
        "target_url",
        "url.full",
        "url.path",
        "http.url",
        "request.uri",
        "uri",
        "url",  # 放最后：Elastic 的 url 是对象，前面几个更具体
    ),
    "http_method": ("http_method", "method", "http.request.method", "http.method"),
    "status_code": ("status_code", "status", "http.response.status_code", "http.status_code"),
    "user_agent": ("user_agent", "user-agent", "http.user_agent", "http.request.headers.user-agent"),
    "payload": ("payload", "http.request.body", "request.body", "data.payload", "matched_data"),
    "raw_log": ("raw_log", "full_log", "raw", "message", "log", "original"),
    "asset": ("asset", "host", "host.name", "agent.name", "server", "app"),
    "action": ("action", "event.outcome", "rule.action", "verdict"),
    "alert_id": ("alert_id", "id", "event.id", "_id"),
}

# 用于自动识别数据源的特征字段
SOURCE_SIGNATURES: dict[str, tuple[str, ...]] = {
    "wazuh": ("rule.id", "agent.name", "full_log"),
    "elastic": ("_source", "event.category", "kibana"),
    "suricata": ("event_type", "flow_id", "dest_ip"),
    "waf": ("attack_type", "matched_data", "client_ip"),
}

# 时间戳字段候选
TIME_FIELDS = ("timestamp", "@timestamp", "event.ingested", "event.created", "date", "time")

_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y/%m/%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y-%m-%d",
)


def _get_path(data: dict[str, Any], path: str) -> Any:
    """支持 "source.ip" 这种点号路径；取不到返回 None。"""
    if path in data:
        return data[path]
    cur: Any = data
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _first(data: dict[str, Any], names: tuple[str, ...]) -> Any:
    for name in names:
        value = _get_path(data, name)
        if value not in (None, "", [], {}):
            return value
    return None


def detect_source(raw: dict[str, Any]) -> str:
    if "_source" in raw and isinstance(raw["_source"], dict):
        return "elastic"
    for source, signatures in SOURCE_SIGNATURES.items():
        if all(_get_path(raw, sig) is not None for sig in signatures):
            return source
    return "generic"


def parse_timestamp(value: Any) -> datetime:
    """尽量宽容地解析时间；解析不了就抛错，绝不悄悄用 now() 顶替。"""
    if value is None:
        raise NormalizeError("缺少时间戳")
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        # 按数量级判断秒/毫秒/微秒/纳秒
        ts = float(value)
        if ts > 1e17:
            ts /= 1e9
        elif ts > 1e14:
            ts /= 1e6
        elif ts > 1e11:
            ts /= 1e3
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    text = str(value).strip()
    if not text:
        raise NormalizeError("时间戳为空")
    if text.isdigit():
        return parse_timestamp(float(text))
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _TIME_FORMATS:
        try:
            dt = datetime.strptime(text, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise NormalizeError(f"无法解析时间戳: {value!r}")


def parse_port(value: Any) -> int | None:
    if value is None:
        return None
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 < port < 65536 else None


def parse_status(value: Any) -> int | None:
    if value is None:
        return None
    try:
        code = int(str(value).strip()[:3])
    except (TypeError, ValueError):
        return None
    return code if 100 <= code <= 599 else None


def normalize_action(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    mapping = {
        "blocked": "blocked",
        "block": "blocked",
        "deny": "blocked",
        "denied": "blocked",
        "drop": "blocked",
        "allowed": "allowed",
        "allow": "allowed",
        "pass": "allowed",
        "success": "allowed",
        "logged": "logged",
        "alert": "logged",
        "detected": "logged",
    }
    return mapping.get(text, text)


def ip_scope(ip: str | None) -> str:
    """把 IP 归类，这件事直接决定误报判断：内网扫描器打内网 == 大概率误报。"""
    if not ip:
        return "unknown"
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return "unknown"
    if addr.is_loopback:
        return "loopback"
    if addr.is_private:
        return "private"
    if addr.is_link_local or addr.is_multicast or addr.is_reserved:
        return "reserved"
    return "public"


def is_public(ip: str | None) -> bool:
    return ip_scope(ip) == "public"


def _unwrap(raw: dict[str, Any]) -> dict[str, Any]:
    """Elastic 的文档在 _source 里，先拆一层。"""
    if isinstance(raw.get("_source"), dict):
        merged = dict(raw["_source"])
        if "_id" in raw:
            merged.setdefault("_id", raw["_id"])
        return merged
    return raw


def _make_alert_id(raw: dict[str, Any], source: str) -> str:
    canonical = json.dumps(raw, sort_keys=True, ensure_ascii=False, default=str)
    return f"{source}-{hashlib.sha1(canonical.encode('utf-8')).hexdigest()[:12]}"


def normalize_alert(raw: dict[str, Any], source: str | None = None) -> Alert:
    """把任意数据源的原始字典变成 Alert。

    抛 NormalizeError 的场景：不是 dict、无法确定时间戳。
    缺少 IP/URL 不算错误——很多主机告警本来就没有网络字段。
    """
    if not isinstance(raw, dict):
        raise NormalizeError(f"告警必须是 dict，收到 {type(raw).__name__}")
    src = source or detect_source(raw)  # 先按原始结构识别来源，再拆 _source
    data = _unwrap(raw)

    timestamp_raw = _first(data, TIME_FIELDS)
    timestamp = parse_timestamp(timestamp_raw) if timestamp_raw is not None else datetime.now(
        timezone.utc
    )

    alert_id = _first(data, FIELD_ALIASES["alert_id"])
    alert = Alert(
        alert_id=str(alert_id) if alert_id else _make_alert_id(data, src),
        source=src,
        alert_type=str(_first(data, FIELD_ALIASES["alert_type"]) or ""),
        timestamp=timestamp,
        src_ip=_as_str(_first(data, FIELD_ALIASES["src_ip"])),
        dst_ip=_as_str(_first(data, FIELD_ALIASES["dst_ip"])),
        dst_port=parse_port(_first(data, FIELD_ALIASES["dst_port"])),
        target_url=_as_str(_first(data, FIELD_ALIASES["target_url"])),
        http_method=_as_str(_first(data, FIELD_ALIASES["http_method"])),
        status_code=parse_status(_first(data, FIELD_ALIASES["status_code"])),
        user_agent=_as_str(_first(data, FIELD_ALIASES["user_agent"])),
        payload=_as_str(_first(data, FIELD_ALIASES["payload"])),
        raw_log=_as_str(_first(data, FIELD_ALIASES["raw_log"])),
        asset=_as_str(_first(data, FIELD_ALIASES["asset"])),
        action=normalize_action(_first(data, FIELD_ALIASES["action"])),
        tags=[str(t) for t in (data.get("tags") or []) if isinstance(t, (str, int))],
        extra={k: v for k, v in data.items() if k not in _CONSUMED_KEYS},
    )
    return alert


_CONSUMED_KEYS = {name for names in FIELD_ALIASES.values() for name in names} | set(TIME_FIELDS)


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    text = str(value).strip()
    return text or None
