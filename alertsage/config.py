"""运行配置。

优先级：显式传参 > 环境变量 > 默认值。没有配置文件也能跑，
这是刻意的：让它能直接扔进 CI、容器、或者别人电脑上做 demo。
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .errors import ConfigError

ENV_PREFIX = "ALERTSAGE_"

# 默认阈值：risk_score >= 判定线即认为需要处置，<= 误报线即认为可关闭
DEFAULT_TRUE_POSITIVE_THRESHOLD = 45
DEFAULT_FALSE_POSITIVE_THRESHOLD = 22


def _env(name: str, default: str | None = None) -> str | None:
    return os.environ.get(ENV_PREFIX + name, default)


def _env_int(name: str, default: int) -> int:
    raw = _env(name)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise ConfigError(f"环境变量 {ENV_PREFIX}{name} 需要整数，收到 {raw!r}") from exc


def _env_float(name: str, default: float) -> float:
    raw = _env(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as exc:
        raise ConfigError(f"环境变量 {ENV_PREFIX}{name} 需要数字，收到 {raw!r}") from exc


def _env_bool(name: str, default: bool) -> bool:
    raw = _env(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "y"}


@dataclass(slots=True)
class Settings:
    # --- 规则与资产 ---
    rules_dir: Path | None = None
    asset_criticality: dict[str, float] = field(default_factory=dict)

    # --- 判定阈值 ---
    true_positive_threshold: int = DEFAULT_TRUE_POSITIVE_THRESHOLD
    false_positive_threshold: int = DEFAULT_FALSE_POSITIVE_THRESHOLD

    # --- 关联与去重 ---
    correlate_window_seconds: int = 600
    burst_threshold: int = 8

    # --- 行为基线 ---
    rate_window_seconds: int = 300
    rate_distinct_targets: int = 10

    # --- 白名单（正则，匹配 src_ip）---
    allowlist: tuple[str, ...] = ()

    # --- LLM ---
    llm_enabled: bool = False
    llm_provider: str = "mock"  # mock / openai
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"
    llm_timeout_seconds: float = 20.0
    llm_max_retries: int = 1
    llm_min_risk_for_call: int = 40  # 低危告警不值得花 token

    def validate(self) -> "Settings":
        if not 0 <= self.false_positive_threshold < self.true_positive_threshold <= 100:
            raise ConfigError("阈值需满足 0 <= false_positive < true_positive <= 100")
        if self.correlate_window_seconds <= 0:
            raise ConfigError("correlate_window_seconds 必须为正")
        if self.llm_provider not in {"mock", "openai"}:
            raise ConfigError(f"未知 LLM provider: {self.llm_provider}")
        if self.llm_provider == "openai" and self.llm_enabled and not self.llm_api_key:
            raise ConfigError("启用 openai provider 时必须提供 ALERTSAGE_LLM_API_KEY")
        return self

    def with_overrides(self, **kwargs: Any) -> "Settings":
        return replace(self, **kwargs)


def load_settings(**overrides: Any) -> Settings:
    asset_table: dict[str, float] = {}
    raw_assets = _env("ASSETS")
    if raw_assets:
        try:
            asset_table = {str(k): float(v) for k, v in json.loads(raw_assets).items()}
        except (ValueError, TypeError, AttributeError) as exc:
            raise ConfigError(f"环境变量 {ENV_PREFIX}ASSETS 需要 JSON 对象") from exc

    settings = Settings(
        rules_dir=Path(_env("RULES_DIR")) if _env("RULES_DIR") else None,
        asset_criticality=asset_table,
        true_positive_threshold=_env_int("TP_THRESHOLD", DEFAULT_TRUE_POSITIVE_THRESHOLD),
        false_positive_threshold=_env_int("FP_THRESHOLD", DEFAULT_FALSE_POSITIVE_THRESHOLD),
        correlate_window_seconds=_env_int("CORRELATE_WINDOW", 600),
        burst_threshold=_env_int("BURST_THRESHOLD", 8),
        rate_window_seconds=_env_int("RATE_WINDOW", 300),
        rate_distinct_targets=_env_int("RATE_DISTINCT_TARGETS", 10),
        allowlist=tuple(
            p.strip() for p in (_env("ALLOWLIST", "") or "").split(",") if p.strip()
        ),
        llm_enabled=_env_bool("LLM_ENABLED", False),
        llm_provider=_env("LLM_PROVIDER", "mock") or "mock",
        llm_base_url=_env("LLM_BASE_URL", "https://api.openai.com/v1") or "",
        llm_api_key=_env("LLM_API_KEY", "") or "",
        llm_model=_env("LLM_MODEL", "gpt-4o-mini") or "",
        llm_timeout_seconds=_env_float("LLM_TIMEOUT", 20.0),
        llm_max_retries=_env_int("LLM_MAX_RETRIES", 1),
        llm_min_risk_for_call=_env_int("LLM_MIN_RISK", 40),
    )
    if overrides:
        settings = replace(settings, **overrides)
    return settings.validate()
